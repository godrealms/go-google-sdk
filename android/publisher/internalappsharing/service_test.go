package internalappsharing_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/api/androidpublisher/v3"
	"google.golang.org/api/option"

	"github.com/godrealms/go-google-sdk/android/publisher/internalappsharing"
)

const pkg = "com.example.app"

func TestUploadAPK(t *testing.T) {
	t.Parallel()
	svc, closeFunc := newTestService(t, "/upload/androidpublisher/v3/applications/internalappsharing/"+pkg+"/artifacts/apk", http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.UploadAPK(context.Background(), pkg, bytes.NewReader([]byte("apk"))); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUploadBundle(t *testing.T) {
	t.Parallel()
	svc, closeFunc := newTestService(t, "/upload/androidpublisher/v3/applications/internalappsharing/"+pkg+"/artifacts/bundle", http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.UploadBundle(context.Background(), pkg, bytes.NewReader([]byte("aab"))); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidation(t *testing.T) {
	t.Parallel()
	svc, closeFunc := newTestService(t, "/unused", http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.UploadAPK(context.Background(), "", bytes.NewReader(nil)); err == nil {
		t.Fatalf("expected missing pkg")
	}
	if _, err := svc.UploadAPK(context.Background(), pkg, nil); err == nil {
		t.Fatalf("expected missing media")
	}
	if _, err := svc.UploadBundle(context.Background(), pkg, nil); err == nil {
		t.Fatalf("expected missing media")
	}
}

func newTestService(t *testing.T, expectedPathPrefix string, status int, body string) (*internalappsharing.Service, func()) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, expectedPathPrefix) {
			t.Errorf("unexpected path: got %q, want prefix %q", r.URL.Path, expectedPathPrefix)
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
	return internalappsharing.New(raw), server.Close
}
