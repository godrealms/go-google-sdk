package voidedpurchases_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/api/androidpublisher/v3"
	"google.golang.org/api/option"

	"github.com/godrealms/go-google-sdk/android/publisher/voidedpurchases"
)

func TestListSucceeds(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	path := "/androidpublisher/v3/applications/" + pkg + "/purchases/voidedpurchases"

	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{"voidedPurchases":[]}`)
	defer closeFunc()

	resp, err := svc.List(context.Background(), pkg)
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if resp == nil {
		t.Fatalf("expected non-nil response")
	}
}

func TestListWithOptions(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	path := "/androidpublisher/v3/applications/" + pkg + "/purchases/voidedpurchases"

	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{"voidedPurchases":[]}`)
	defer closeFunc()

	now := time.Now()
	resp, err := svc.List(context.Background(), pkg,
		voidedpurchases.WithStartTime(now.Add(-24*time.Hour)),
		voidedpurchases.WithEndTime(now),
		voidedpurchases.WithMaxResults(50),
	)
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if resp == nil {
		t.Fatalf("expected non-nil response")
	}
}

func TestListRequiresPackageName(t *testing.T) {
	t.Parallel()

	svc, closeFunc := newTestService(t, "/unused", http.MethodGet, http.StatusOK, `{}`)
	defer closeFunc()

	_, err := svc.List(context.Background(), "")
	if err == nil {
		t.Fatalf("expected error for missing packageName")
	}
}

func TestListPropagatesAPIError(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	path := "/androidpublisher/v3/applications/" + pkg + "/purchases/voidedpurchases"

	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusForbidden, `{"error":{"code":403}}`)
	defer closeFunc()

	_, err := svc.List(context.Background(), pkg)
	if err == nil {
		t.Fatalf("expected error from API 403")
	}
}

func newTestService(t *testing.T, expectedPath, expectedMethod string, status int, body string) (*voidedpurchases.Service, func()) {
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

	return voidedpurchases.New(raw), server.Close
}
