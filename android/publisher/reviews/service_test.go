package reviews_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/api/androidpublisher/v3"
	"google.golang.org/api/option"

	"github.com/godrealms/go-google-sdk/android/publisher/reviews"
)

func TestGetHitsExpectedPath(t *testing.T) {
	t.Parallel()
	const pkg, rev = "com.example.app", "rev-1"
	path := "/androidpublisher/v3/applications/" + pkg + "/reviews/" + rev
	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{"reviewId":"rev-1"}`)
	defer closeFunc()
	if _, err := svc.Get(context.Background(), pkg, rev, ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListHitsExpectedPath(t *testing.T) {
	t.Parallel()
	const pkg = "com.example.app"
	path := "/androidpublisher/v3/applications/" + pkg + "/reviews"
	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.List(context.Background(), pkg, reviews.ListOptions{MaxResults: 10}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReplyHitsExpectedPath(t *testing.T) {
	t.Parallel()
	const pkg, rev = "com.example.app", "rev-1"
	path := "/androidpublisher/v3/applications/" + pkg + "/reviews/" + rev + ":reply"
	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.Reply(context.Background(), pkg, rev, "thanks"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidationErrors(t *testing.T) {
	t.Parallel()
	svc, closeFunc := newTestService(t, "/unused", http.MethodGet, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.Reply(context.Background(), "pkg", "rev", ""); err == nil {
		t.Fatalf("expected missing reply")
	}
	if _, err := svc.Get(context.Background(), "", "rev", ""); err == nil {
		t.Fatalf("expected missing package")
	}
}

func newTestService(t *testing.T, expectedPath, expectedMethod string, status int, body string) (*reviews.Service, func()) {
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
	return reviews.New(raw), server.Close
}
