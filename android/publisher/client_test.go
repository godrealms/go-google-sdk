package publisher

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestNewClientWithStringPathReturnsErrorForInvalidJSON(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "invalid.json")
	if err := os.WriteFile(path, []byte("not-json"), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	if _, err := NewClient(path); err == nil {
		t.Fatalf("expected JSON parse error")
	}
}

func TestNewClientWithStringPathReturnsErrorForMissingFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "missing.json")
	if _, err := NewClient(path); err == nil {
		t.Fatalf("expected read error for missing file")
	}
}

func TestNewClientWithByteSliceReturnsErrorForInvalidJSON(t *testing.T) {
	t.Parallel()

	if _, err := NewClient([]byte("not-json")); err == nil {
		t.Fatalf("expected JSON parse error")
	}
}

func TestNewClientWithOAuth2InputsDoNotPanic(t *testing.T) {
	t.Parallel()

	structInput := OAuth2{Type: "service_account"}
	if _, err := NewClient(structInput); err != nil {
		// keep behavior flexible for different credential library environments
		// if invalid credentials are rejected, this path should return an error.
		t.Logf("expected branch reached with struct input, got error: %v", err)
	}

	ptrInput := &OAuth2{Type: "service_account"}
	if _, err := NewClient(ptrInput); err != nil {
		t.Logf("expected branch reached with pointer input, got error: %v", err)
	}
}

func TestNewClientWithReaderReturnsErrorForInvalidJSON(t *testing.T) {
	t.Parallel()

	if _, err := NewClient(bytes.NewBufferString("not-json")); err == nil {
		t.Fatalf("expected invalid reader data error")
	}
}
func TestNewClientWithUnsupportedTypeFallsBackToDefaultClient(t *testing.T) {
	originalDefaultHTTPClient := defaultHTTPClient
	t.Cleanup(func() {
		defaultHTTPClient = originalDefaultHTTPClient
	})

	var called bool
	client := &http.Client{}
	defaultHTTPClient = func(ctx context.Context) (*http.Client, error) {
		called = true
		return client, nil
	}

	actualClient, err := NewClient(struct{}{})
	if err != nil {
		t.Fatalf("expected fallback to default client, got error: %v", err)
	}
	if actualClient != client {
		t.Fatalf("expected injected default client to be used")
	}
	if !called {
		t.Fatalf("expected default client factory to be used")
	}
}

func TestNewClientWithUnsupportedTypeReturnsDefaultClientError(t *testing.T) {
	originalDefaultHTTPClient := defaultHTTPClient
	t.Cleanup(func() {
		defaultHTTPClient = originalDefaultHTTPClient
	})

	defaultHTTPClient = func(ctx context.Context) (*http.Client, error) {
		return nil, errors.New("default client unavailable")
	}

	if _, err := NewClient(struct{}{}); err == nil || err.Error() != "default client unavailable" {
		t.Fatalf("expected default client error, got: %v", err)
	}
}

func TestNewClientWithNilFallsBackToDefaultClient(t *testing.T) {
	originalDefaultHTTPClient := defaultHTTPClient
	t.Cleanup(func() {
		defaultHTTPClient = originalDefaultHTTPClient
	})

	var called bool
	client := &http.Client{}
	defaultHTTPClient = func(ctx context.Context) (*http.Client, error) {
		called = true
		return client, nil
	}

	actualClient, err := NewClient(nil)
	if err != nil {
		t.Fatalf("expected fallback default client with nil input, got error: %v", err)
	}
	if actualClient != client {
		t.Fatalf("expected injected default client to be used for nil input")
	}
	if !called {
		t.Fatalf("expected default client factory to be used for nil input")
	}
}
