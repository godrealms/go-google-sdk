package applications_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/api/androidpublisher/v3"
	"google.golang.org/api/option"

	"github.com/godrealms/go-google-sdk/android/publisher/applications"
)

const pkg = "com.example.app"

func TestDataSafety(t *testing.T) {
	t.Parallel()
	path := "/androidpublisher/v3/applications/" + pkg + "/dataSafety"
	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.DataSafety(context.Background(), pkg, &androidpublisher.SafetyLabelsUpdateRequest{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreateDeviceTierConfig(t *testing.T) {
	t.Parallel()
	path := "/androidpublisher/v3/applications/" + pkg + "/deviceTierConfigs"
	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.CreateDeviceTierConfig(context.Background(), pkg, &androidpublisher.DeviceTierConfig{}, applications.CreateDeviceTierConfigOptions{AllowUnknownDevices: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetDeviceTierConfig(t *testing.T) {
	t.Parallel()
	path := "/androidpublisher/v3/applications/" + pkg + "/deviceTierConfigs/42"
	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.GetDeviceTierConfig(context.Background(), pkg, 42); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListDeviceTierConfigs(t *testing.T) {
	t.Parallel()
	path := "/androidpublisher/v3/applications/" + pkg + "/deviceTierConfigs"
	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.ListDeviceTierConfigs(context.Background(), pkg, applications.ListDeviceTierConfigsOptions{PageSize: 5}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListTrackReleases(t *testing.T) {
	t.Parallel()
	parent := "applications/" + pkg + "/tracks/production"
	path := "/androidpublisher/v3/" + parent + "/releases"
	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.ListTrackReleases(context.Background(), parent); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidation(t *testing.T) {
	t.Parallel()
	svc, closeFunc := newTestService(t, "/unused", http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.DataSafety(context.Background(), "", &androidpublisher.SafetyLabelsUpdateRequest{}); err == nil {
		t.Fatalf("expected missing package")
	}
	if _, err := svc.DataSafety(context.Background(), pkg, nil); err == nil {
		t.Fatalf("expected missing request")
	}
	if _, err := svc.CreateDeviceTierConfig(context.Background(), pkg, nil, applications.CreateDeviceTierConfigOptions{}); err == nil {
		t.Fatalf("expected missing config")
	}
	if _, err := svc.GetDeviceTierConfig(context.Background(), pkg, 0); err == nil {
		t.Fatalf("expected missing id")
	}
	if _, err := svc.ListTrackReleases(context.Background(), ""); err == nil {
		t.Fatalf("expected missing parent")
	}
}

func newTestService(t *testing.T, expectedPath, expectedMethod string, status int, body string) (*applications.Service, func()) {
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
	return applications.New(raw), server.Close
}
