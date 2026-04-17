package systemapks_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/api/androidpublisher/v3"
	"google.golang.org/api/option"

	"github.com/godrealms/go-google-sdk/android/publisher/systemapks"
)

const pkg = "com.example.app"

func TestCreate(t *testing.T) {
	t.Parallel()
	path := "/androidpublisher/v3/applications/" + pkg + "/systemApks/42/variants"
	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.Create(context.Background(), pkg, 42, &androidpublisher.Variant{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGet(t *testing.T) {
	t.Parallel()
	path := "/androidpublisher/v3/applications/" + pkg + "/systemApks/42/variants/7"
	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.Get(context.Background(), pkg, 42, 7); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestList(t *testing.T) {
	t.Parallel()
	path := "/androidpublisher/v3/applications/" + pkg + "/systemApks/42/variants"
	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.List(context.Background(), pkg, 42); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDownload(t *testing.T) {
	t.Parallel()
	path := "/androidpublisher/v3/applications/" + pkg + "/systemApks/42/variants/7:download"
	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `bytes`)
	defer closeFunc()
	r, err := svc.Download(context.Background(), pkg, 42, 7)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r.Close()
}

func TestValidation(t *testing.T) {
	t.Parallel()
	svc, closeFunc := newTestService(t, "/unused", http.MethodGet, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.Create(context.Background(), "", 1, &androidpublisher.Variant{}); err == nil {
		t.Fatalf("expected missing pkg")
	}
	if _, err := svc.Create(context.Background(), pkg, 1, nil); err == nil {
		t.Fatalf("expected missing variant")
	}
	if _, err := svc.Get(context.Background(), pkg, 1, 0); err == nil {
		t.Fatalf("expected missing variant id")
	}
}

func newTestService(t *testing.T, expectedPath, expectedMethod string, status int, body string) (*systemapks.Service, func()) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != expectedMethod {
			t.Errorf("expected %s, got %s", expectedMethod, r.Method)
		}
		if r.URL.Path != expectedPath {
			t.Errorf("unexpected path: got %q, want %q", r.URL.Path, expectedPath)
		}
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	raw, err := androidpublisher.NewService(context.Background(),
		option.WithEndpoint(server.URL),
		option.WithoutAuthentication(),
	)
	if err != nil {
		t.Fatalf("create raw service: %v", err)
	}
	return systemapks.New(raw), server.Close
}
