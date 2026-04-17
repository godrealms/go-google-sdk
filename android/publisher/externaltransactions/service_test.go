package externaltransactions_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/api/androidpublisher/v3"
	"google.golang.org/api/option"

	"github.com/godrealms/go-google-sdk/android/publisher/externaltransactions"
)

const parent = "applications/com.example.app"
const txnName = parent + "/externalTransactions/txn-1"

func TestCreate(t *testing.T) {
	t.Parallel()
	path := "/androidpublisher/v3/" + parent + "/externalTransactions"
	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.Create(context.Background(), parent, &androidpublisher.ExternalTransaction{}, externaltransactions.CreateOptions{ExternalTransactionID: "txn-1"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGet(t *testing.T) {
	t.Parallel()
	path := "/androidpublisher/v3/" + txnName
	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.Get(context.Background(), txnName); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRefund(t *testing.T) {
	t.Parallel()
	path := "/androidpublisher/v3/" + txnName + ":refund"
	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.Refund(context.Background(), txnName, &androidpublisher.RefundExternalTransactionRequest{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidation(t *testing.T) {
	t.Parallel()
	svc, closeFunc := newTestService(t, "/unused", http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.Create(context.Background(), "", &androidpublisher.ExternalTransaction{}, externaltransactions.CreateOptions{}); err == nil {
		t.Fatalf("expected missing parent")
	}
	if _, err := svc.Create(context.Background(), "p", nil, externaltransactions.CreateOptions{}); err == nil {
		t.Fatalf("expected missing txn")
	}
	if _, err := svc.Get(context.Background(), ""); err == nil {
		t.Fatalf("expected missing name")
	}
	if _, err := svc.Refund(context.Background(), "n", nil); err == nil {
		t.Fatalf("expected missing refund req")
	}
}

func newTestService(t *testing.T, expectedPath, expectedMethod string, status int, body string) (*externaltransactions.Service, func()) {
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
	return externaltransactions.New(raw), server.Close
}
