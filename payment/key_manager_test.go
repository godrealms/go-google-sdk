package payment

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/godrealms/go-google-sdk/utils/logs"
)

type failingReadCloser struct {
	err error
}

func (f failingReadCloser) Read(_ []byte) (int, error) {
	return 0, f.err
}

func (f failingReadCloser) Close() error {
	return nil
}

func TestKeyManagerNewRejectsNilConfig(t *testing.T) {
	_, err := NewKeyManager(nil, logs.NewLogger(logs.LogLevelInfo, false))
	if err == nil || err.Error() != "config is nil" {
		t.Fatalf("expected config-is-nil error, got %v", err)
	}
}

func TestKeyManagerNewUsesDefaultsAndLoadsRootKeys(t *testing.T) {
	leaf := newECKeyPair(t)
	root := newECKeyPair(t)

	rootResponse := rootKeysJSONResponse(t, "test-key", root)
	requestCount := 0

	withStubbedDefaultTransport(t, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		requestCount++
		if req.Method != http.MethodGet {
			t.Fatalf("expected GET request for root keys, got %s", req.Method)
		}

		return responseWithBody(t, http.StatusOK, rootResponse), nil
	}), func() {
		config := &Config{
			Environment:    EnvironmentSandbox,
			MerchantID:     "merchant",
			PrivateKeyData: ecPrivateKeyPEM(t, leaf),
			Timeout:        0,
		}

		km, err := NewKeyManager(config, nil)
		if err != nil {
			t.Fatalf("unexpected key manager init error: %v", err)
		}

		if km.GetPrivateKey() == nil {
			t.Fatalf("expected private key to be loaded")
		}

		rootKey, err := km.GetRootKey("test-key")
		if err != nil {
			t.Fatalf("expected root key to be loaded: %v", err)
		}
		if rootKey == nil {
			t.Fatalf("expected non-nil root key")
		}

		if requestCount != 1 {
			t.Fatalf("expected one root keys request, got %d", requestCount)
		}
		if config.Timeout != 30*time.Second {
			t.Fatalf("expected timeout default to 30s, got %v", config.Timeout)
		}
	})
}

func TestKeyManagerLoadPrivateKeyRejectsMissingKey(t *testing.T) {
	config := &Config{MerchantID: "merchant", Timeout: 10 * time.Second}
	_, err := NewKeyManager(config, logs.NewLogger(logs.LogLevelInfo, false))
	if err == nil || !strings.Contains(err.Error(), "no private key provided") {
		t.Fatalf("expected missing-key error, got %v", err)
	}
}

func TestKeyManagerLoadPrivateKeyRejectsUnsupportedType(t *testing.T) {
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("invalid")})
	config := &Config{MerchantID: "merchant", PrivateKeyData: badPEM, Timeout: 10 * time.Second}

	_, err := NewKeyManager(config, logs.NewLogger(logs.LogLevelInfo, false))
	if err == nil {
		t.Fatalf("expected unsupported key type error")
	}
}

func TestKeyManagerLoadPrivateKeyRejectsMalformedPEM(t *testing.T) {
	config := &Config{MerchantID: "merchant", PrivateKeyData: []byte("not-a-pem-block"), Timeout: 10 * time.Second}

	_, err := NewKeyManager(config, logs.NewLogger(logs.LogLevelInfo, false))
	if err == nil || !strings.Contains(err.Error(), "failed to load private key") {
		t.Fatalf("expected malformed PEM error, got: %v", err)
	}
}

func TestKeyManagerLoadPrivateKeyRejectsMalformedECKey(t *testing.T) {
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("bad-ec-private-key")})
	config := &Config{MerchantID: "merchant", PrivateKeyData: badPEM, Timeout: 10 * time.Second}

	_, err := NewKeyManager(config, logs.NewLogger(logs.LogLevelInfo, false))
	if err == nil || !strings.Contains(err.Error(), "failed to load private key") {
		t.Fatalf("expected private key parse error, got: %v", err)
	}
}

func TestKeyManagerLoadPrivateKeyRejectsUnreadableKeyFile(t *testing.T) {
	config := &Config{MerchantID: "merchant", PrivateKeyPath: "/does/not/exist.pem", Timeout: 10 * time.Second}

	_, err := NewKeyManager(config, logs.NewLogger(logs.LogLevelInfo, false))
	if err == nil || !strings.Contains(err.Error(), "failed to load private key") {
		t.Fatalf("expected private key file read error, got: %v", err)
	}
}

func TestKeyManagerLoadPrivateKeyRejectsMalformedPKCS8(t *testing.T) {
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not-a-pkcs8-key")})
	config := &Config{MerchantID: "merchant", PrivateKeyData: badPEM, Timeout: 10 * time.Second}

	_, err := NewKeyManager(config, logs.NewLogger(logs.LogLevelInfo, false))
	if err == nil || !strings.Contains(err.Error(), "failed to load private key") {
		t.Fatalf("expected malformed PKCS8 parse error, got: %v", err)
	}
}

func TestKeyManagerLoadPrivateKeyRejectsNonECDSAPKCS8Key(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("marshal rsa pkcs8 key: %v", err)
	}
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes})

	config := &Config{MerchantID: "merchant", PrivateKeyData: badPEM, Timeout: 10 * time.Second}
	_, err = NewKeyManager(config, logs.NewLogger(logs.LogLevelInfo, false))
	if err == nil || !strings.Contains(err.Error(), "failed to load private key") {
		t.Fatalf("expected non-ecdsa pkcs8 parse error, got: %v", err)
	}
}

func TestKeyManagerLoadRootKeysSkipsEmptyEntriesAndRefreshes(t *testing.T) {
	rootA := newECKeyPair(t)
	rootB := newECKeyPair(t)

	first := rootKeysJSONResponse(t, "old", rootA)
	second := rootKeysJSONResponse(t, "new", rootB)

	requestCount := 0
	km := &KeyManager{
		config: &Config{Environment: EnvironmentSandbox},
		rootKeys: map[string]*ecdsa.PublicKey{
			"old": &rootA.PublicKey,
		},
		httpClient: &http.Client{},
	}

	withStubbedDefaultTransport(t, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		requestCount++
		if requestCount == 1 {
			return responseWithBody(t, http.StatusOK, first), nil
		}
		return responseWithBody(t, http.StatusOK, second), nil
	}), func() {
		if err := km.RefreshRootKeys(context.Background()); err != nil {
			t.Fatalf("expected refresh to succeed: %v", err)
		}

		if _, err := km.GetRootKey("old"); err != nil {
			t.Fatalf("expected old key to remain after first refresh: %v", err)
		}

		if err := km.RefreshRootKeys(context.Background()); err != nil {
			t.Fatalf("expected second refresh to succeed: %v", err)
		}

		if _, err := km.GetRootKey("old"); err == nil {
			t.Fatalf("expected old key to be replaced after refresh")
		}

		newRoot, err := km.GetRootKey("new")
		if err != nil {
			t.Fatalf("expected new root key after refresh: %v", err)
		}
		if newRoot == nil {
			t.Fatalf("expected non-nil new root key")
		}

		if requestCount != 2 {
			t.Fatalf("expected two root key requests after two refreshes, got %d", requestCount)
		}
	})

}

func TestKeyManagerLoadRootKeysRejectsNonOKStatus(t *testing.T) {
	rootKey := newECKeyPair(t)
	km := &KeyManager{
		config:     &Config{Environment: EnvironmentSandbox},
		rootKeys:   map[string]*ecdsa.PublicKey{"cached": &rootKey.PublicKey},
		httpClient: &http.Client{},
	}

	withStubbedDefaultTransport(t, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return responseWithBody(t, http.StatusBadGateway, `{}`), nil
	}), func() {
		if err := km.loadRootKeys(context.Background()); err == nil {
			t.Fatalf("expected non-200 status to fail")
		}
	})
}

func TestKeyManagerLoadRootKeysPropagatesRequestError(t *testing.T) {
	km := &KeyManager{
		config:   &Config{Environment: EnvironmentSandbox},
		rootKeys: map[string]*ecdsa.PublicKey{},
		httpClient: &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("request failed")
		})},
	}

	if err := km.loadRootKeys(context.Background()); err == nil || !strings.Contains(err.Error(), "failed to fetch root keys") {
		t.Fatalf("expected request error propagation, got %v", err)
	}
}

func TestKeyManagerLoadRootKeysPropagatesBodyReadError(t *testing.T) {
	km := &KeyManager{
		config:   &Config{Environment: EnvironmentSandbox},
		rootKeys: map[string]*ecdsa.PublicKey{},
		httpClient: &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       failingReadCloser{err: io.ErrUnexpectedEOF},
			}, nil
		})},
	}

	if err := km.loadRootKeys(context.Background()); err == nil || !strings.Contains(err.Error(), "failed to read response body") {
		t.Fatalf("expected response body read error propagation, got %v", err)
	}
}

func TestKeyManagerGetRootKeyValidatesInput(t *testing.T) {
	km := &KeyManager{rootKeys: map[string]*ecdsa.PublicKey{"k": nil}}
	if _, err := km.GetRootKey(""); err == nil {
		t.Fatalf("expected empty id error")
	}
	if _, err := km.GetRootKey("missing"); err == nil {
		t.Fatalf("expected missing key error")
	}
}

func TestKeyManagerParsePublicKeyRejectsInvalidData(t *testing.T) {
	km := &KeyManager{}
	if _, err := km.parsePublicKey("not-a-pem"); err == nil {
		t.Fatalf("expected invalid pem decode error")
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key generation failed: %v", err)
	}
	rsaBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("rsa public key marshal failed: %v", err)
	}
	raMismatched := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rsaBytes}))
	if _, err := km.parsePublicKey(raMismatched); err == nil {
		t.Fatalf("expected non-ecdsa public key error")
	}
}

func TestKeyManagerParsePublicKeyRejectsMalformedPKIX(t *testing.T) {
	km := &KeyManager{}
	bad := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("bad-pkix")}))

	if _, err := km.parsePublicKey(bad); err == nil {
		t.Fatalf("expected malformed PKIX parse error")
	}
}

func TestKeyManagerHealth(t *testing.T) {
	km := &KeyManager{}
	if err := km.Health(context.Background()); err == nil {
		t.Fatalf("expected missing-private-key error")
	}

	km.privateKey = newECKeyPair(t)
	if err := km.Health(context.Background()); err == nil {
		t.Fatalf("expected missing-root-keys error")
	}

	km.rootKeys = map[string]*ecdsa.PublicKey{"k": nil}
	if err := km.Health(context.Background()); err != nil {
		t.Fatalf("expected healthy key manager: %v", err)
	}

	if err := km.Close(); err != nil {
		t.Fatalf("expected close success: %v", err)
	}
	if err := km.Health(context.Background()); err == nil {
		t.Fatalf("expected error after close due empty state")
	}
}

func TestKeyManagerLoadRootKeysRejectsNoValidKeys(t *testing.T) {
	km := &KeyManager{
		config:     &Config{Environment: EnvironmentSandbox},
		httpClient: &http.Client{},
		rootKeys:   map[string]*ecdsa.PublicKey{},
	}

	resp := responseWithBody(t, http.StatusOK, `{"keys":[{"keyId":"","keyValue":"invalid","algorithm":"ECDSA"}]}`)
	withStubbedDefaultTransport(t, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return resp, nil
	}), func() {
		if err := km.loadRootKeys(context.Background()); err == nil {
			t.Fatalf("expected no-valid-keys error")
		}
	})
}

func TestKeyManagerLoadRootKeysRejectsMalformedJSON(t *testing.T) {
	km := &KeyManager{
		config:     &Config{Environment: EnvironmentSandbox},
		httpClient: &http.Client{},
		rootKeys:   map[string]*ecdsa.PublicKey{},
	}

	withStubbedDefaultTransport(t, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return responseWithBody(t, http.StatusOK, `{"keys":[{`), nil
	}), func() {
		if err := km.loadRootKeys(context.Background()); err == nil {
			t.Fatalf("expected malformed json error")
		}
	})
}

func TestKeyManagerLoadRootKeysSkipsInvalidAndKeepsValid(t *testing.T) {
	valid := newECKeyPair(t)

	keys := map[string]any{
		"keys": []map[string]any{
			{
				"keyId":     "invalid",
				"keyValue":  "not-a-pem-key",
				"algorithm": "ECDSA",
			},
			{
				"keyId":     "valid",
				"keyValue":  ecdsaPublicKeyPEM(t, &valid.PublicKey),
				"algorithm": "ECDSA",
			},
		},
	}

	b, err := json.Marshal(keys)
	if err != nil {
		t.Fatalf("marshal root keys payload: %v", err)
	}

	km := &KeyManager{
		config:     &Config{Environment: EnvironmentSandbox},
		httpClient: &http.Client{},
		rootKeys:   map[string]*ecdsa.PublicKey{},
	}

	withStubbedDefaultTransport(t, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return responseWithBody(t, http.StatusOK, string(b)), nil
	}), func() {
		if err := km.loadRootKeys(context.Background()); err != nil {
			t.Fatalf("expected loadRootKeys success: %v", err)
		}

		if _, err := km.GetRootKey("invalid"); err == nil {
			t.Fatalf("expected invalid key to be skipped")
		}

		if _, err := km.GetRootKey("valid"); err != nil {
			t.Fatalf("expected valid key to be loaded: %v", err)
		}
	})
}

func TestKeyManagerLoadRootKeysWarnsOnInvalidKey(t *testing.T) {
	root := newECKeyPair(t)

	keys := map[string]any{
		"keys": []map[string]any{
			{
				"keyId":     "invalid",
				"keyValue":  "not-a-pem-key",
				"algorithm": "ECDSA",
			},
			{
				"keyId":     "valid",
				"keyValue":  ecdsaPublicKeyPEM(t, &root.PublicKey),
				"algorithm": "ECDSA",
			},
		},
	}

	b, err := json.Marshal(keys)
	if err != nil {
		t.Fatalf("marshal root keys response: %v", err)
	}

	km := &KeyManager{
		config:     &Config{Environment: EnvironmentSandbox},
		rootKeys:   map[string]*ecdsa.PublicKey{},
		httpClient: &http.Client{},
		logger:     logs.NewLogger(logs.LogLevelInfo, false),
	}

	withStubbedDefaultTransport(t, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return responseWithBody(t, http.StatusOK, string(b)), nil
	}), func() {
		if err := km.loadRootKeys(context.Background()); err != nil {
			t.Fatalf("expected loadRootKeys success: %v", err)
		}

		if _, err := km.GetRootKey("invalid"); err == nil {
			t.Fatalf("expected invalid root key to be skipped")
		}
		if _, err := km.GetRootKey("valid"); err != nil {
			t.Fatalf("expected valid root key to load: %v", err)
		}
	})
}

func TestKeyManagerLoadPrivateKeyReadsFromFile(t *testing.T) {
	leaf := newECKeyPair(t)
	root := newECKeyPair(t)
	rootResp := rootKeysJSONResponse(t, "root-1", root)

	tmpDir := t.TempDir()
	keyPath := tmpDir + "/ec-private-key.pem"
	if err := os.WriteFile(keyPath, ecPrivateKeyPEM(t, leaf), 0o600); err != nil {
		t.Fatalf("write private key file failed: %v", err)
	}

	config := &Config{
		Environment:    EnvironmentSandbox,
		MerchantID:     "merchant",
		PrivateKeyPath: keyPath,
	}

	withStubbedDefaultTransport(t, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return responseWithBody(t, http.StatusOK, rootResp), nil
	}), func() {
		km, err := NewKeyManager(config, nil)
		if err != nil {
			t.Fatalf("expected key manager initialization success: %v", err)
		}
		if km.privateKey == nil {
			t.Fatalf("expected private key loaded from file")
		}
	})
}

func TestKeyManagerLoadPrivateKeySupportsPKCS8(t *testing.T) {
	leaf := newECKeyPair(t)
	root := newECKeyPair(t)
	rootResp := rootKeysJSONResponse(t, "root-1", root)

	config := &Config{
		Environment:    EnvironmentSandbox,
		MerchantID:     "merchant",
		PrivateKeyData: ecPrivateKeyPKCS8PEM(t, leaf),
	}

	withStubbedDefaultTransport(t, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return responseWithBody(t, http.StatusOK, rootResp), nil
	}), func() {
		km, err := NewKeyManager(config, nil)
		if err != nil {
			t.Fatalf("expected key manager initialization success: %v", err)
		}
		if km.privateKey == nil {
			t.Fatalf("expected PKCS8 private key loaded")
		}
	})
}

func TestKeyManagerLoadRootKeysUsesProductionURL(t *testing.T) {
	root := newECKeyPair(t)
	requestURL := ""

	km := &KeyManager{
		config:     &Config{Environment: EnvironmentProduction},
		rootKeys:   map[string]*ecdsa.PublicKey{},
		privateKey: newECKeyPair(t),
		httpClient: &http.Client{},
	}

	withStubbedDefaultTransport(t, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		requestURL = req.URL.String()
		return responseWithBody(t, http.StatusOK, rootKeysJSONResponse(t, "root-1", root)), nil
	}), func() {
		if err := km.loadRootKeys(context.Background()); err != nil {
			t.Fatalf("expected production URL load to succeed: %v", err)
		}
		if requestURL != ProdRootKeysURL {
			t.Fatalf("expected production root keys URL %s, got %s", ProdRootKeysURL, requestURL)
		}
	})
}

func TestKeyManagerLoadRootKeysReturnsRequestCreationError(t *testing.T) {
	oldNewRequestWithContext := newRequestWithContext
	newRequestWithContext = func(_ context.Context, _ string, _ string, _ io.Reader) (*http.Request, error) {
		return nil, errors.New("request creation failed")
	}
	defer func() {
		newRequestWithContext = oldNewRequestWithContext
	}()

	km := &KeyManager{
		config:     &Config{Environment: EnvironmentSandbox},
		rootKeys:   map[string]*ecdsa.PublicKey{},
		privateKey: newECKeyPair(t),
		httpClient: &http.Client{},
	}

	if err := km.loadRootKeys(context.Background()); err == nil || !strings.Contains(err.Error(), "failed to create request") {
		t.Fatalf("expected request creation failure, got %v", err)
	}
}

func TestKeyManagerRefreshRootKeysSkipsNilContext(t *testing.T) {
	root := newECKeyPair(t)
	requestCount := 0

	km := &KeyManager{
		config: &Config{Environment: EnvironmentSandbox},
		rootKeys: map[string]*ecdsa.PublicKey{
			"old": &root.PublicKey,
		},
		privateKey: newECKeyPair(t),
		httpClient: &http.Client{},
		lastUpdate: time.Now(),
	}

	withStubbedDefaultTransport(t, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		requestCount++
		return responseWithBody(t, http.StatusOK, rootKeysJSONResponse(t, "new", root)), nil
	}), func() {
		if err := km.RefreshRootKeys(nil); err != nil {
			t.Fatalf("expected refresh with nil context to succeed: %v", err)
		}
		if requestCount != 1 {
			t.Fatalf("expected one refresh request, got %d", requestCount)
		}
	})
}

func TestKeyManagerLoadRootKeysSkipsRecentCache(t *testing.T) {
	cached := newECKeyPair(t)
	km := &KeyManager{
		config: &Config{Environment: EnvironmentSandbox},
		rootKeys: map[string]*ecdsa.PublicKey{
			"cached": &cached.PublicKey,
		},
		lastUpdate: time.Now(),
		httpClient: &http.Client{},
	}

	withStubbedDefaultTransport(t, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatalf("loadRootKeys should skip request when cache is fresh")
		return responseWithBody(t, http.StatusOK, `{}`), nil
	}), func() {
		if err := km.loadRootKeys(context.Background()); err != nil {
			t.Fatalf("expected loadRootKeys skip to succeed: %v", err)
		}
	})
}
