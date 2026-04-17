package apprecovery_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/api/androidpublisher/v3"
	"google.golang.org/api/option"

	"github.com/godrealms/go-google-sdk/android/publisher/apprecovery"
)

const pkg = "com.example.app"

func TestAddTargeting(t *testing.T) {
	t.Parallel()
	path := "/androidpublisher/v3/applications/" + pkg + "/appRecoveries/7:addTargeting"
	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.AddTargeting(context.Background(), pkg, 7, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCancel(t *testing.T) {
	t.Parallel()
	path := "/androidpublisher/v3/applications/" + pkg + "/appRecoveries/7:cancel"
	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.Cancel(context.Background(), pkg, 7, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreate(t *testing.T) {
	t.Parallel()
	path := "/androidpublisher/v3/applications/" + pkg + "/appRecoveries"
	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.Create(context.Background(), pkg, &androidpublisher.CreateDraftAppRecoveryRequest{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeploy(t *testing.T) {
	t.Parallel()
	path := "/androidpublisher/v3/applications/" + pkg + "/appRecoveries/7:deploy"
	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.Deploy(context.Background(), pkg, 7, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestList(t *testing.T) {
	t.Parallel()
	path := "/androidpublisher/v3/applications/" + pkg + "/appRecoveries"
	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.List(context.Background(), pkg, apprecovery.ListOptions{VersionCode: 42}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidation(t *testing.T) {
	t.Parallel()
	svc, closeFunc := newTestService(t, "/unused", http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.AddTargeting(context.Background(), "", 1, nil); err == nil {
		t.Fatalf("expected missing package")
	}
	if _, err := svc.AddTargeting(context.Background(), pkg, 0, nil); err == nil {
		t.Fatalf("expected missing id")
	}
	if _, err := svc.Create(context.Background(), pkg, nil); err == nil {
		t.Fatalf("expected missing request")
	}
}

func newTestService(t *testing.T, expectedPath, expectedMethod string, status int, body string) (*apprecovery.Service, func()) {
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
	return apprecovery.New(raw), server.Close
}
