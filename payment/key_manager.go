package payment

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/godrealms/go-google-sdk/utils/logs"
)

// newRequestWithContext is overridable in tests.
var newRequestWithContext = http.NewRequestWithContext

// rootKey is an internal cache entry that remembers the per-key expiration
// delivered by Google. ExpiresAt may be the zero Time when Google omitted it.
type rootKey struct {
	PublicKey *ecdsa.PublicKey
	ExpiresAt time.Time
}

// KeyManager loads the merchant's ECDSA private key and the rotating set of
// Google payment root public keys.
type KeyManager struct {
	config *Config
	logger logs.Logger

	privateKey *ecdsa.PrivateKey

	mu         sync.RWMutex
	rootKeys   map[string]rootKey
	lastUpdate time.Time

	httpClient *http.Client
}

// NewKeyManager constructs a KeyManager, loading the merchant private key and
// performing the first Google root-key fetch.
func NewKeyManager(config *Config, logger logs.Logger) (*KeyManager, error) {
	if config == nil {
		return nil, errors.New("config is nil")
	}
	if logger == nil {
		logger = logs.NewLogger(logs.LogLevelInfo, false)
	}
	if config.Timeout <= 0 {
		config.Timeout = 30 * time.Second
	}

	km := &KeyManager{
		config:     config,
		logger:     logger,
		rootKeys:   make(map[string]rootKey),
		httpClient: &http.Client{Timeout: config.Timeout},
	}

	if err := km.loadPrivateKey(); err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}
	if err := km.loadRootKeys(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to load root keys: %w", err)
	}
	return km, nil
}

// loadPrivateKey populates km.privateKey from either PrivateKeyData or
// PrivateKeyPath. Supports PEM-encoded "EC PRIVATE KEY" (SEC1) and
// "PRIVATE KEY" (PKCS8) blocks.
func (km *KeyManager) loadPrivateKey() error {
	var keyData []byte
	var err error

	switch {
	case len(km.config.PrivateKeyData) > 0:
		keyData = km.config.PrivateKeyData
	case km.config.PrivateKeyPath != "":
		keyData, err = os.ReadFile(km.config.PrivateKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read private key file: %w", err)
		}
	default:
		return errors.New("no private key provided")
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return errors.New("failed to decode PEM block")
	}

	switch block.Type {
	case "EC PRIVATE KEY":
		km.privateKey, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			return fmt.Errorf("failed to parse PKCS8 private key: %w", parseErr)
		}
		var ok bool
		km.privateKey, ok = key.(*ecdsa.PrivateKey)
		if !ok {
			return errors.New("private key is not ECDSA")
		}
	default:
		return fmt.Errorf("unsupported private key type: %s", block.Type)
	}
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	km.logger.Info("Private key loaded successfully")
	return nil
}

// loadRootKeys fetches and parses Google's payment root keys. Entries whose
// keyExpiration has already passed are dropped. Results are cached for 1h.
func (km *KeyManager) loadRootKeys(ctx context.Context) error {
	if km.logger == nil {
		km.logger = logs.NewLogger(logs.LogLevelInfo, false)
	}
	km.mu.RLock()
	if time.Since(km.lastUpdate) < 1*time.Hour && len(km.rootKeys) > 0 {
		km.mu.RUnlock()
		return nil
	}
	km.mu.RUnlock()

	url := TestRootKeysURL
	if km.config.Environment == EnvironmentProduction {
		url = ProdRootKeysURL
	}

	req, err := newRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := km.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch root keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	var response struct {
		Keys []struct {
			KeyID         string `json:"keyId"`
			KeyValue      string `json:"keyValue"`
			Algorithm     string `json:"algorithm"`
			KeyExpiration string `json:"keyExpiration"`
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("failed to unmarshal root keys response: %w", err)
	}

	now := time.Now()
	next := make(map[string]rootKey)
	for _, k := range response.Keys {
		publicKey, err := km.parsePublicKey(k.KeyValue)
		if err != nil {
			km.logger.Warn("Failed to parse public key", "keyId", k.KeyID, "error", err)
			continue
		}

		entry := rootKey{PublicKey: publicKey}
		if k.KeyExpiration != "" {
			expiry, err := parseMsTimestamp(k.KeyExpiration)
			if err != nil {
				km.logger.Warn("Invalid keyExpiration", "keyId", k.KeyID, "value", k.KeyExpiration)
				continue
			}
			if !now.Before(expiry) {
				km.logger.Debug("Skipping expired root key", "keyId", k.KeyID)
				continue
			}
			entry.ExpiresAt = expiry
		}

		id := k.KeyID
		if id == "" {
			// Google's production keys.json omits keyId — synthesise one so
			// multiple entries don't collide in the map.
			id = fmt.Sprintf("%s-%d", k.Algorithm, len(next))
		}
		next[id] = entry
	}

	if len(next) == 0 {
		return errors.New("no valid root keys found")
	}

	km.mu.Lock()
	km.rootKeys = next
	km.lastUpdate = time.Now()
	km.mu.Unlock()

	km.logger.Info("Root keys loaded successfully", "count", len(next))
	return nil
}

// parsePublicKey parses a PEM-encoded ECDSA SubjectPublicKeyInfo.
func (km *KeyManager) parsePublicKey(keyValue string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(keyValue))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not ECDSA")
	}
	return ecdsaPub, nil
}

// GetPrivateKey returns the merchant ECDSA private key (nil before init).
func (km *KeyManager) GetPrivateKey() *ecdsa.PrivateKey { return km.privateKey }

// GetRootKey returns the Google root public key for a specific keyId.
func (km *KeyManager) GetRootKey(keyID string) (*ecdsa.PublicKey, error) {
	if keyID == "" {
		return nil, errors.New("root key id is empty")
	}
	km.mu.RLock()
	defer km.mu.RUnlock()
	entry, ok := km.rootKeys[keyID]
	if !ok {
		return nil, fmt.Errorf("root key not found: %s", keyID)
	}
	return entry.PublicKey, nil
}

// AllRootKeys returns a snapshot of all currently-cached, non-expired Google
// root public keys. Used by the token handler when a token does not include a
// keyId (ECv2) and we must try each key.
func (km *KeyManager) AllRootKeys() []*ecdsa.PublicKey {
	km.mu.RLock()
	defer km.mu.RUnlock()
	out := make([]*ecdsa.PublicKey, 0, len(km.rootKeys))
	now := time.Now()
	for _, entry := range km.rootKeys {
		if !entry.ExpiresAt.IsZero() && !now.Before(entry.ExpiresAt) {
			continue
		}
		out = append(out, entry.PublicKey)
	}
	return out
}

// RefreshRootKeys forces a refetch of the Google root keys.
func (km *KeyManager) RefreshRootKeys(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	km.mu.Lock()
	km.lastUpdate = time.Time{}
	km.mu.Unlock()
	return km.loadRootKeys(ctx)
}

// Health reports whether the key manager has usable material.
func (km *KeyManager) Health(_ context.Context) error {
	if km.privateKey == nil {
		return errors.New("private key not loaded")
	}
	km.mu.RLock()
	count := len(km.rootKeys)
	km.mu.RUnlock()
	if count == 0 {
		return errors.New("no root keys loaded")
	}
	return nil
}

// Close clears cached key material.
func (km *KeyManager) Close() error {
	km.mu.Lock()
	defer km.mu.Unlock()
	km.rootKeys = make(map[string]rootKey)
	km.privateKey = nil
	return nil
}

// Well-known root key endpoints.
const (
	TestRootKeysURL = "https://payments.developers.google.com/paymentmethodtoken/test/keys.json"
	ProdRootKeysURL = "https://payments.developers.google.com/paymentmethodtoken/keys.json"
)
