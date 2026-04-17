package users_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/api/androidpublisher/v3"
	"google.golang.org/api/option"

	"github.com/godrealms/go-google-sdk/android/publisher/users"
)

const parent = "developers/12345"
const userName = parent + "/users/admin@example.com"

func TestCreate(t *testing.T) {
	t.Parallel()
	path := "/androidpublisher/v3/" + parent + "/users"
	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.Create(context.Background(), parent, &androidpublisher.User{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestList(t *testing.T) {
	t.Parallel()
	path := "/androidpublisher/v3/" + parent + "/users"
	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.List(context.Background(), parent, users.ListOptions{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPatch(t *testing.T) {
	t.Parallel()
	path := "/androidpublisher/v3/" + userName
	svc, closeFunc := newTestService(t, path, http.MethodPatch, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.Patch(context.Background(), userName, "accessState", &androidpublisher.User{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDelete(t *testing.T) {
	t.Parallel()
	path := "/androidpublisher/v3/" + userName
	svc, closeFunc := newTestService(t, path, http.MethodDelete, http.StatusOK, ``)
	defer closeFunc()
	if err := svc.Delete(context.Background(), userName); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidation(t *testing.T) {
	t.Parallel()
	svc, closeFunc := newTestService(t, "/unused", http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.Create(context.Background(), "", &androidpublisher.User{}); err == nil {
		t.Fatalf("expected missing parent")
	}
	if _, err := svc.Create(context.Background(), "p", nil); err == nil {
		t.Fatalf("expected missing user body")
	}
	if err := svc.Delete(context.Background(), ""); err == nil {
		t.Fatalf("expected missing name")
	}
}

func newTestService(t *testing.T, expectedPath, expectedMethod string, status int, body string) (*users.Service, func()) {
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
	return users.New(raw), server.Close
}
