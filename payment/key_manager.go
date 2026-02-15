package payment

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/godrealms/go-google-sdk/utils/logs"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

var newRequestWithContext = http.NewRequestWithContext

// KeyManager 密钥管理器
type KeyManager struct {
	config *Config
	logger logs.Logger

	// 私钥
	privateKey *ecdsa.PrivateKey

	// Google根密钥
	mu         sync.RWMutex
	rootKeys   map[string]*ecdsa.PublicKey
	lastUpdate time.Time

	// HTTP客户端
	httpClient *http.Client
}

// NewKeyManager 创建密钥管理器
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
		config:   config,
		logger:   logger,
		rootKeys: make(map[string]*ecdsa.PublicKey),
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
	}

	// 加载私钥
	if err := km.loadPrivateKey(); err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	// 加载Google根密钥
	if err := km.loadRootKeys(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to load root keys: %w", err)
	}

	return km, nil
}

// loadPrivateKey 加载私钥
func (km *KeyManager) loadPrivateKey() error {
	var keyData []byte
	var err error

	// 优先使用配置中的密钥数据
	if len(km.config.PrivateKeyData) > 0 {
		keyData = km.config.PrivateKeyData
	} else if km.config.PrivateKeyPath != "" {
		keyData, err = os.ReadFile(km.config.PrivateKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read private key file: %w", err)
		}
	} else {
		return errors.New("no private key provided")
	}

	// 解析PEM格式
	block, _ := pem.Decode(keyData)
	if block == nil {
		return errors.New("failed to decode PEM block")
	}

	// 解析私钥
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

	if km.logger != nil {
		km.logger.Info("Private key loaded successfully")
	}
	return nil
}

// loadRootKeys 加载Google根密钥
func (km *KeyManager) loadRootKeys(ctx context.Context) error {
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

	var rootKeysResponse struct {
		Keys []struct {
			KeyID    string `json:"keyId"`
			KeyValue string `json:"keyValue"`
			// Algorithm 字段目前未被使用，保留兼容性
			Algorithm string `json:"algorithm"`
		} `json:"keys"`
	}

	if err := json.Unmarshal(body, &rootKeysResponse); err != nil {
		return fmt.Errorf("failed to unmarshal root keys response: %w", err)
	}

	// 解析密钥
	newRootKeys := make(map[string]*ecdsa.PublicKey)
	for _, key := range rootKeysResponse.Keys {
		if key.KeyID == "" {
			continue
		}

		publicKey, err := km.parsePublicKey(key.KeyValue)
		if err != nil {
			if km.logger != nil {
				km.logger.Warn("Failed to parse public key", "keyId", key.KeyID, "error", err)
			}
			continue
		}
		newRootKeys[key.KeyID] = publicKey
	}

	if len(newRootKeys) == 0 {
		return errors.New("no valid root keys found")
	}

	km.mu.Lock()
	defer km.mu.Unlock()
	km.rootKeys = newRootKeys
	km.lastUpdate = time.Now()

	if km.logger != nil {
		km.logger.Info("Root keys loaded successfully", "count", len(newRootKeys))
	}
	return nil
}

// parsePublicKey 解析公钥
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

// GetPrivateKey 获取私钥
func (km *KeyManager) GetPrivateKey() *ecdsa.PrivateKey {
	return km.privateKey
}

// GetRootKey 获取根密钥
func (km *KeyManager) GetRootKey(keyID string) (*ecdsa.PublicKey, error) {
	if keyID == "" {
		return nil, errors.New("root key id is empty")
	}

	km.mu.RLock()
	defer km.mu.RUnlock()

	key, exists := km.rootKeys[keyID]
	if !exists {
		return nil, fmt.Errorf("root key not found: %s", keyID)
	}

	return key, nil
}

// RefreshRootKeys 刷新根密钥
func (km *KeyManager) RefreshRootKeys(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	km.mu.Lock()
	km.lastUpdate = time.Time{} // 强制更新
	km.mu.Unlock()

	return km.loadRootKeys(ctx)
}

// Health 健康检查
func (km *KeyManager) Health(ctx context.Context) error {
	if km.privateKey == nil {
		return errors.New("private key not loaded")
	}

	km.mu.RLock()
	rootKeysCount := len(km.rootKeys)
	km.mu.RUnlock()

	if rootKeysCount == 0 {
		return errors.New("no root keys loaded")
	}

	return nil
}

// Close 关闭密钥管理器
func (km *KeyManager) Close() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	km.rootKeys = make(map[string]*ecdsa.PublicKey)
	km.privateKey = nil

	return nil
}

// 常量定义
const (
	TestRootKeysURL = "https://payments.developers.google.com/paymentmethodtoken/test/keys.json"
	ProdRootKeysURL = "https://payments.developers.google.com/paymentmethodtoken/keys.json"
)
