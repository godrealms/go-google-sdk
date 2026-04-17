package grants_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/api/androidpublisher/v3"
	"google.golang.org/api/option"

	"github.com/godrealms/go-google-sdk/android/publisher/grants"
)

const parent = "developers/12345/users/admin@example.com"
const grantName = parent + "/grants/com.example.app"

func TestCreate(t *testing.T) {
	t.Parallel()
	path := "/androidpublisher/v3/" + parent + "/grants"
	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.Create(context.Background(), parent, &androidpublisher.Grant{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPatch(t *testing.T) {
	t.Parallel()
	path := "/androidpublisher/v3/" + grantName
	svc, closeFunc := newTestService(t, path, http.MethodPatch, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.Patch(context.Background(), grantName, "appLevelPermissions", &androidpublisher.Grant{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDelete(t *testing.T) {
	t.Parallel()
	path := "/androidpublisher/v3/" + grantName
	svc, closeFunc := newTestService(t, path, http.MethodDelete, http.StatusOK, ``)
	defer closeFunc()
	if err := svc.Delete(context.Background(), grantName); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidation(t *testing.T) {
	t.Parallel()
	svc, closeFunc := newTestService(t, "/unused", http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.Create(context.Background(), "", &androidpublisher.Grant{}); err == nil {
		t.Fatalf("expected missing parent")
	}
	if err := svc.Delete(context.Background(), ""); err == nil {
		t.Fatalf("expected missing name")
	}
}

func newTestService(t *testing.T, expectedPath, expectedMethod string, status int, body string) (*grants.Service, func()) {
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
	return grants.New(raw), server.Close
}
