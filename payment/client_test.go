package payment

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/godrealms/go-google-sdk/utils/cache"
	"github.com/godrealms/go-google-sdk/utils/logs"
)

func TestClientTokenCacheKeyIsHashed(t *testing.T) {
	t.Parallel()

	c := &Client{}
	key := c.tokenCacheKey("raw-token")
	expected := sha256.Sum256([]byte("raw-token"))

	if key != hex.EncodeToString(expected[:]) {
		t.Fatalf("unexpected cache key, got %s", key)
	}

	if c.tokenCacheKey("") != "" {
		t.Fatalf("expected empty token to return empty cache key")
	}
}

func TestClientDecryptPaymentTokenRequiresInit(t *testing.T) {
	t.Parallel()

	c := &Client{logger: logs.NewLogger(logs.LogLevelInfo, false)}
	_, err := c.DecryptPaymentToken(context.Background(), "token")
	if err == nil {
		t.Fatalf("expected error when client is not initialized")
	}
}

func TestClientDecryptPaymentTokenReturnsCachedValue(t *testing.T) {
	t.Parallel()

	cacheStore := cache.NewMemoryCache(time.Minute)
	token := &PaymentToken{MessageID: "msg-123"}

	c := &Client{
		initialized: true,
		cache:       cacheStore,
		logger:      logs.NewLogger(logs.LogLevelInfo, false),
	}

	raw := "encrypted-token-string"
	cacheStore.Set(c.tokenCacheKey(raw), token)

	result, err := c.DecryptPaymentToken(context.Background(), raw)
	if err != nil {
		t.Fatalf("expected cached token path to succeed: %v", err)
	}

	if result != token {
		t.Fatalf("expected cached token instance, got different value")
	}
}

func TestClientHealthChecksInitStatus(t *testing.T) {
	t.Parallel()

	c := &Client{}
	if err := c.Health(context.Background()); err == nil || err.Error() != "client not initialized" {
		t.Fatalf("expected not initialized error, got %v", err)
	}
}

func TestClientCloseIsIdempotent(t *testing.T) {
	t.Parallel()

	c := &Client{
		initialized: true,
		cache:       cache.NewNoOpCache(),
		keyManager:  &KeyManager{},
		logger:      logs.NewLogger(logs.LogLevelInfo, false),
		lastError:   errors.New("cached state"),
	}

	if err := c.Close(); err != nil {
		t.Fatalf("expected first close to succeed: %v", err)
	}

	if c.initialized {
		t.Fatalf("expected client to be uninitialized after close")
	}

	if err := c.Close(); err != nil {
		t.Fatalf("expected idempotent close to succeed: %v", err)
	}
}

func TestNewClientNilConfigReturnsValidationError(t *testing.T) {
	c, err := NewClient(nil)
	if err == nil {
		t.Fatalf("expected nil config error")
	}
	if c != nil {
		t.Fatalf("expected client to be nil")
	}
	if !strings.Contains(err.Error(), "invalid config") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClientInitializeSkipsWhenAlreadyInitialized(t *testing.T) {
	c := &Client{initialized: true}

	if err := c.initialize(); err != nil {
		t.Fatalf("expected no-op initialize to succeed: %v", err)
	}

	if c.keyManager != nil || c.tokenHandler != nil || c.cache != nil {
		t.Fatalf("expected already-initialized client to remain untouched")
	}
}

func TestNewClientInitializesComponentsWithMemoryCache(t *testing.T) {
	rootKey := newECKeyPair(t)
	leafKey := newECKeyPair(t)
	rootResp := rootKeysJSONResponse(t, "root-1", rootKey)

	config := &Config{
		Environment:    EnvironmentSandbox,
		MerchantID:     "merchant-id",
		PrivateKeyData: ecPrivateKeyPEM(t, leafKey),
		CacheEnabled:   true,
	}

	withStubbedDefaultTransport(t, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return responseWithBody(t, http.StatusOK, rootResp), nil
	}), func() {
		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("expected new client success: %v", err)
		}
		if client == nil {
			t.Fatalf("expected non-nil client")
		}
		if client.keyManager == nil || client.tokenHandler == nil {
			t.Fatalf("expected dependencies initialized")
		}
		if _, ok := client.cache.(*cache.MemoryCache); !ok {
			t.Fatalf("expected memory cache when CacheEnabled is true")
		}

		if err := client.Health(context.Background()); err != nil {
			t.Fatalf("expected healthy client: %v", err)
		}

		if err := client.Close(); err != nil {
			t.Fatalf("expected close success: %v", err)
		}
	})
}

func TestNewClientInitializesComponentsWithNoOpCache(t *testing.T) {
	rootKey := newECKeyPair(t)
	leafKey := newECKeyPair(t)
	rootResp := rootKeysJSONResponse(t, "root-1", rootKey)

	config := &Config{
		Environment:    EnvironmentSandbox,
		MerchantID:     "merchant-id",
		PrivateKeyData: ecPrivateKeyPEM(t, leafKey),
		CacheEnabled:   false,
	}

	withStubbedDefaultTransport(t, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return responseWithBody(t, http.StatusOK, rootResp), nil
	}), func() {
		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("expected new client success: %v", err)
		}
		if _, ok := client.cache.(*cache.NoOpCache); !ok {
			t.Fatalf("expected no-op cache when CacheEnabled is false")
		}
		if err := client.Close(); err != nil {
			t.Fatalf("expected close success: %v", err)
		}
	})
}

func TestClientValidatePaymentTokenAndGetPaymentMethodInfo(t *testing.T) {
	client := &Client{tokenHandler: &TokenHandler{}, logger: logs.NewLogger(logs.LogLevelInfo, false)}

	if err := client.ValidatePaymentToken(context.Background(), nil); err == nil {
		t.Fatalf("expected nil token error")
	}

	if err := client.ValidatePaymentToken(context.Background(), &PaymentToken{ExpiresAt: time.Now().Add(-time.Minute)}); err == nil {
		t.Fatalf("expected expired token error")
	}

	expiry := time.Now().Add(time.Minute).Format(time.RFC3339)
	paymentToken := &PaymentToken{
		ExpiresAt:                time.Now().Add(time.Minute),
		MessageExpiration:        expiry,
		PaymentMethodType:        "CARD",
		PaymentMethodDescription: "Visa",
		PaymentNetwork:           "visa",
		PaymentMethodDetails:     CardDetails{PAN: "4111111111111111"},
	}

	if err := client.ValidatePaymentToken(context.Background(), paymentToken); err != nil {
		t.Fatalf("expected token validation success: %v", err)
	}

	info, err := client.GetPaymentMethodInfo(context.Background(), paymentToken)
	if err != nil {
		t.Fatalf("expected payment method info to succeed: %v", err)
	}
	if info.Type != paymentToken.PaymentMethodType {
		t.Fatalf("expected payment method type %s, got %s", paymentToken.PaymentMethodType, info.Type)
	}
	if info.Network != paymentToken.PaymentNetwork {
		t.Fatalf("expected payment network %s, got %s", paymentToken.PaymentNetwork, info.Network)
	}
}

func TestClientGetPaymentMethodInfoRejectsNilToken(t *testing.T) {
	c := &Client{tokenHandler: &TokenHandler{}, logger: logs.NewLogger(logs.LogLevelInfo, false)}
	if _, err := c.GetPaymentMethodInfo(context.Background(), nil); err == nil {
		t.Fatalf("expected nil token error")
	}
}

func TestClientInitializeFailsWithoutConfig(t *testing.T) {
	c := &Client{}

	if err := c.initialize(); err == nil {
		t.Fatalf("expected initialize to fail when config is nil")
	}
}

func TestClientInitializePropagatesTokenHandlerFailure(t *testing.T) {
	leaf := newECKeyPair(t)
	root := newECKeyPair(t)
	config := &Config{
		Environment:    EnvironmentSandbox,
		MerchantID:     "merchant",
		PrivateKeyData: ecPrivateKeyPEM(t, leaf),
	}

	oldCreateTokenHandler := createTokenHandler
	createTokenHandler = func(_ *Config, _ *KeyManager, _ logs.Logger) (*TokenHandler, error) {
		return nil, errors.New("token handler init failure")
	}
	defer func() {
		createTokenHandler = oldCreateTokenHandler
	}()

	client := &Client{config: config}
	withStubbedDefaultTransport(t, roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
		return responseWithBody(t, http.StatusOK, rootKeysJSONResponse(t, "root-1", root)), nil
	}), func() {
		if err := client.initialize(); err == nil || !strings.Contains(err.Error(), "failed to create token handler") {
			t.Fatalf("expected token handler creation failure, got %v", err)
		}
	})
}

func TestClientDecryptPaymentTokenReturnsWrappedErrorWhenDecryptFails(t *testing.T) {
	c := &Client{
		initialized:  true,
		cache:        cache.NewNoOpCache(),
		tokenHandler: &TokenHandler{keyManager: &KeyManager{}},
		logger:       logs.NewLogger(logs.LogLevelInfo, false),
	}

	if _, err := c.DecryptPaymentToken(context.Background(), "{}"); err == nil || !strings.Contains(err.Error(), "decrypt token failed") {
		t.Fatalf("expected wrapped decrypt failure error, got %v", err)
	}
}

func TestClientDecryptPaymentTokenCachesDecryptedToken(t *testing.T) {
	rootKey := newECKeyPair(t)
	leafKey := newECKeyPair(t)
	encryptedToken := buildEncryptedTokenFromPayload(t, leafKey, rootKey, map[string]any{
		"paymentMethodType": "CARD",
	}, EcV1, "root-1")

	store := cache.NewMemoryCache(time.Minute)
	keyManager := &KeyManager{
		privateKey: leafKey,
		rootKeys:   map[string]*ecdsa.PublicKey{"root-1": &rootKey.PublicKey},
	}

	c := &Client{
		initialized:  true,
		cache:        store,
		tokenHandler: &TokenHandler{keyManager: keyManager, logger: logs.NewLogger(logs.LogLevelInfo, false)},
		logger:       logs.NewLogger(logs.LogLevelInfo, false),
	}

	first, err := c.DecryptPaymentToken(context.Background(), encryptedToken)
	if err != nil {
		t.Fatalf("expected first decryption success: %v", err)
	}

	if _, ok := store.Get(c.tokenCacheKey(encryptedToken)).(*PaymentToken); !ok {
		t.Fatalf("expected decrypted token cached")
	}

	second, err := c.DecryptPaymentToken(context.Background(), encryptedToken)
	if err != nil {
		t.Fatalf("expected cached decryption success: %v", err)
	}

	if second != first {
		t.Fatalf("expected cached token to be returned")
	}
}

func TestClientValidatePaymentTokenRejectsInvalidMessageExpiration(t *testing.T) {
	c := &Client{tokenHandler: &TokenHandler{}, logger: logs.NewLogger(logs.LogLevelInfo, false)}

	if err := c.ValidatePaymentToken(context.Background(), &PaymentToken{ExpiresAt: nowWithOffset(time.Hour), MessageExpiration: "not-rfc3339"}); err == nil {
		t.Fatalf("expected invalid expiration error")
	}
}

func TestNewClientInitializeFailure(t *testing.T) {
	leaf := newECKeyPair(t)
	config := &Config{
		Environment:    EnvironmentSandbox,
		MerchantID:     "merchant",
		PrivateKeyData: ecPrivateKeyPEM(t, leaf),
	}

	withStubbedDefaultTransport(t, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return responseWithBody(t, http.StatusInternalServerError, `{"keys":[]}`), nil
	}), func() {
		if _, err := NewClient(config); err == nil {
			t.Fatalf("expected initialize failure")
		}
	})
}

func TestClientHealthSurfacesTokenHandlerFailure(t *testing.T) {
	leaf := newECKeyPair(t)

	c := &Client{
		initialized: true,
		keyManager: &KeyManager{
			privateKey: leaf,
			rootKeys:   map[string]*ecdsa.PublicKey{"k": &leaf.PublicKey},
		},
		tokenHandler: &TokenHandler{},
		logger:       logs.NewLogger(logs.LogLevelInfo, false),
	}

	if err := c.Health(context.Background()); err == nil || !strings.Contains(err.Error(), "token handler unhealthy") {
		t.Fatalf("expected token handler health error, got %v", err)
	}
}

func TestClientHealthSurfacesKeyManagerFailure(t *testing.T) {
	leaf := newECKeyPair(t)

	c := &Client{
		initialized:  true,
		keyManager:   &KeyManager{},
		tokenHandler: &TokenHandler{keyManager: &KeyManager{privateKey: leaf}},
		logger:       logs.NewLogger(logs.LogLevelInfo, false),
	}

	if err := c.Health(context.Background()); err == nil || !strings.Contains(err.Error(), "key manager unhealthy") {
		t.Fatalf("expected key manager health error, got %v", err)
	}
}
