package payment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (rt roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return rt(req)
}

var testTransportMu sync.Mutex

func withStubbedDefaultTransport(t *testing.T, rt http.RoundTripper, fn func()) {
	t.Helper()
	testTransportMu.Lock()
	orig := http.DefaultTransport
	http.DefaultTransport = rt
	t.Cleanup(func() {
		http.DefaultTransport = orig
		testTransportMu.Unlock()
	})

	fn()
}

func newECKeyPair(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}

	return key
}

func ecPrivateKeyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()

	bytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal EC private key: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: bytes})
}

func ecPrivateKeyPKCS8PEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()

	bytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS8 private key: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: bytes})
}

func ecdsaPublicKeyPEM(t *testing.T, key *ecdsa.PublicKey) string {
	t.Helper()

	bytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatalf("marshal ECDSA public key: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: bytes}))
}

func rootKeysJSONResponse(t *testing.T, keyID string, key *ecdsa.PrivateKey) string {
	t.Helper()

	type rootKeyEntry struct {
		KeyID    string `json:"keyId"`
		KeyValue string `json:"keyValue"`
		// Algorithm is currently not used by parser but kept for compatibility.
		Algorithm string `json:"algorithm"`
	}

	payload := struct {
		Keys []rootKeyEntry `json:"keys"`
	}{
		Keys: []rootKeyEntry{
			{
				KeyID:    keyID,
				KeyValue: ecdsaPublicKeyPEM(t, &key.PublicKey),
				// Algorithm is currently not used by parser but kept for compatibility.
				Algorithm: "ECDSA",
			},
		},
	}

	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal root keys response: %v", err)
	}

	return string(b)
}

func responseWithBody(t *testing.T, status int, body string) *http.Response {
	t.Helper()

	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

func responseFromJSON(t *testing.T, status int, body interface{}) *http.Response {
	t.Helper()

	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal response body: %v", err)
	}

	return responseWithBody(t, status, string(b))
}

func nowWithOffset(d time.Duration) time.Time {
	return time.Now().Add(d)
}
