package generatedapks_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/api/androidpublisher/v3"
	"google.golang.org/api/option"

	"github.com/godrealms/go-google-sdk/android/publisher/generatedapks"
)

const pkg = "com.example.app"

func TestList(t *testing.T) {
	t.Parallel()
	path := "/androidpublisher/v3/applications/" + pkg + "/generatedApks/42"
	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.List(context.Background(), pkg, 42); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDownload(t *testing.T) {
	t.Parallel()
	path := "/androidpublisher/v3/applications/" + pkg + "/generatedApks/42/downloads/d1:download"
	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `apkbytes`)
	defer closeFunc()
	r, err := svc.Download(context.Background(), pkg, 42, "d1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer r.Close()
	b, _ := io.ReadAll(r)
	if string(b) != "apkbytes" {
		t.Fatalf("unexpected body %q", string(b))
	}
}

func TestValidation(t *testing.T) {
	t.Parallel()
	svc, closeFunc := newTestService(t, "/unused", http.MethodGet, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.List(context.Background(), "", 1); err == nil {
		t.Fatalf("expected missing pkg")
	}
	if _, err := svc.List(context.Background(), pkg, 0); err == nil {
		t.Fatalf("expected missing version")
	}
	if _, err := svc.Download(context.Background(), pkg, 1, ""); err == nil {
		t.Fatalf("expected missing download id")
	}
}

func newTestService(t *testing.T, expectedPath, expectedMethod string, status int, body string) (*generatedapks.Service, func()) {
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
	return generatedapks.New(raw), server.Close
}
