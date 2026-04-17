package purchases_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/api/androidpublisher/v3"
	"google.golang.org/api/option"

	"github.com/godrealms/go-google-sdk/android/publisher/purchases"
)

func TestAcknowledgeRequiresFields(t *testing.T) {
	t.Parallel()

	svc := purchases.New(nil)
	if err := svc.Acknowledge(context.Background(), "", "prod", "token"); err == nil {
		t.Fatalf("expected error for nil service")
	}

	svc2, closeFunc := newTestService(t, "/unused", http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()

	if err := svc2.Acknowledge(context.Background(), "", "prod", "token"); err == nil {
		t.Fatalf("expected error for missing packageName")
	}
	if err := svc2.Acknowledge(context.Background(), "com.example", "", "token"); err == nil {
		t.Fatalf("expected error for missing productID")
	}
	if err := svc2.Acknowledge(context.Background(), "com.example", "prod", ""); err == nil {
		t.Fatalf("expected error for missing purchaseToken")
	}
}

func TestAcknowledgeSucceeds(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	const prod = "product-1"
	const tok = "token-1"
	path := "/androidpublisher/v3/applications/" + pkg + "/purchases/products/" + prod + "/tokens/" + tok + ":acknowledge"

	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()

	if err := svc.Acknowledge(context.Background(), pkg, prod, tok); err != nil {
		t.Fatalf("expected success: %v", err)
	}
}

func TestConsumeSucceeds(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	const prod = "product-1"
	const tok = "token-1"
	path := "/androidpublisher/v3/applications/" + pkg + "/purchases/products/" + prod + "/tokens/" + tok + ":consume"

	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()

	if err := svc.Consume(context.Background(), pkg, prod, tok); err != nil {
		t.Fatalf("expected success: %v", err)
	}
}

func TestConsumeRequiresFields(t *testing.T) {
	t.Parallel()

	svc, closeFunc := newTestService(t, "/unused", http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()

	if err := svc.Consume(context.Background(), "", "prod", "token"); err == nil {
		t.Fatalf("expected error for missing packageName")
	}
	if err := svc.Consume(context.Background(), "com.example", "", "token"); err == nil {
		t.Fatalf("expected error for missing productID")
	}
	if err := svc.Consume(context.Background(), "com.example", "prod", ""); err == nil {
		t.Fatalf("expected error for missing purchaseToken")
	}
}

func TestQueryByTokenReturnsProductPurchase(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	const prod = "product-1"
	const tok = "token-1"
	path := "/androidpublisher/v3/applications/" + pkg + "/purchases/products/" + prod + "/tokens/" + tok

	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{"purchaseState":0}`)
	defer closeFunc()

	purchase, err := svc.Query(context.Background(), purchases.PurchaseQuery{
		PackageName: pkg, ProductID: prod, PurchaseToken: tok,
	})
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if purchase == nil {
		t.Fatalf("expected non-nil purchase")
	}
}

func TestQueryRequiresFields(t *testing.T) {
	t.Parallel()

	svc, closeFunc := newTestService(t, "/unused", http.MethodGet, http.StatusOK, `{}`)
	defer closeFunc()

	if _, err := svc.Query(context.Background(), purchases.PurchaseQuery{
		ProductID: "p", PurchaseToken: "t",
	}); err == nil {
		t.Fatalf("expected error for missing packageName")
	}
	if _, err := svc.Query(context.Background(), purchases.PurchaseQuery{
		PackageName: "com.example", PurchaseToken: "t",
	}); err == nil {
		t.Fatalf("expected error for missing productID")
	}
	if _, err := svc.Query(context.Background(), purchases.PurchaseQuery{
		PackageName: "com.example", ProductID: "p",
	}); err == nil {
		t.Fatalf("expected error for missing purchaseToken")
	}
}

func TestGetV2ReturnsProductPurchaseV2(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	const tok = "token-v2"
	path := "/androidpublisher/v3/applications/" + pkg + "/purchases/productsv2/tokens/" + tok

	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{"kind":"androidpublisher#productPurchaseV2"}`)
	defer closeFunc()

	purchase, err := svc.GetV2(context.Background(), pkg, tok)
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if purchase == nil {
		t.Fatalf("expected non-nil purchase")
	}
}

func TestGetV2RequiresFields(t *testing.T) {
	t.Parallel()

	svc, closeFunc := newTestService(t, "/unused", http.MethodGet, http.StatusOK, `{}`)
	defer closeFunc()

	if _, err := svc.GetV2(context.Background(), "", "tok"); err == nil {
		t.Fatalf("expected error for missing packageName")
	}
	if _, err := svc.GetV2(context.Background(), "com.example", ""); err == nil {
		t.Fatalf("expected error for missing purchaseToken")
	}
}

func TestRefundSucceeds(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	const orderID = "order-123"
	path := "/androidpublisher/v3/applications/" + pkg + "/orders/" + orderID + ":refund"

	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()

	if err := svc.Refund(context.Background(), pkg, orderID); err != nil {
		t.Fatalf("expected success: %v", err)
	}
}

func TestRefundPropagatesAPIError(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	const orderID = "order-err"
	path := "/androidpublisher/v3/applications/" + pkg + "/orders/" + orderID + ":refund"

	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusBadRequest, `{"error":{"code":400}}`)
	defer closeFunc()

	err := svc.Refund(context.Background(), pkg, orderID)
	if err == nil {
		t.Fatalf("expected error from API 400")
	}
}

func newTestService(t *testing.T, expectedPath, expectedMethod string, status int, body string) (*purchases.Service, func()) {
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

	return purchases.New(raw), server.Close
}
