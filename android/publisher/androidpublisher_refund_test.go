package publisher

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/api/option"
)

func TestServiceRefundPurchaseRequiresNilSafeInputs(t *testing.T) {
	t.Parallel()

	var nilService *Service
	if err := nilService.RefundPurchase(context.Background(), "com.example", "order-1"); err == nil {
		t.Fatalf("expected error for nil service")
	}

	if err := new(Service).RefundPurchase(context.Background(), "", ""); err == nil {
		t.Fatalf("expected error for missing package and order IDs")
	}

	service := &Service{}
	if err := service.RefundPurchase(context.Background(), "", "order-123"); err == nil {
		t.Fatalf("expected error for missing package name")
	}

	if err := service.RefundPurchase(context.Background(), "com.example", ""); err == nil {
		t.Fatalf("expected error for missing order ID")
	}
}

func TestServiceRefundPurchaseSucceedsOn200(t *testing.T) {
	t.Parallel()

	const packageName = "com.example.app"
	const orderID = "order-123"
	expectedPath := "/androidpublisher/v3/applications/" + packageName + "/orders/" + orderID + ":refund"

	service, closeServer := newTestRefundService(t, expectedPath, http.StatusOK)
	defer closeServer()

	err := service.RefundPurchase(context.Background(), packageName, orderID)
	if err != nil {
		t.Fatalf("expected refund purchase success, got: %v", err)
	}
}

func TestServiceRefundPurchaseReturnsErrorOnFailure(t *testing.T) {
	t.Parallel()

	const packageName = "com.example.app"
	const orderID = "order-400"
	expectedPath := "/androidpublisher/v3/applications/" + packageName + "/orders/" + orderID + ":refund"

	service, closeServer := newTestRefundService(t, expectedPath, http.StatusBadRequest)
	defer closeServer()

	err := service.RefundPurchase(context.Background(), packageName, orderID)
	if err == nil {
		t.Fatalf("expected refund purchase API failure")
	}
	if !strings.Contains(err.Error(), "refund purchase failed") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestServiceRefundSubscriptionSucceedsOn200(t *testing.T) {
	t.Parallel()

	const packageName = "com.example.app"
	const subscriptionID = "sub-987"
	const purchaseToken = "token-abc"
	expectedPath := "/androidpublisher/v3/applications/" + packageName + "/purchases/subscriptions/" + subscriptionID + "/tokens/" + purchaseToken + ":refund"

	service, closeServer := newTestRefundService(t, expectedPath, http.StatusOK)
	defer closeServer()

	err := service.RefundSubscription(context.Background(), packageName, subscriptionID, purchaseToken)
	if err != nil {
		t.Fatalf("expected refund subscription success, got: %v", err)
	}
}

func TestServiceRefundSubscriptionReturnsErrorOnFailure(t *testing.T) {
	t.Parallel()

	const packageName = "com.example.app"
	const subscriptionID = "sub-987"
	const purchaseToken = "token-err"
	expectedPath := "/androidpublisher/v3/applications/" + packageName + "/purchases/subscriptions/" + subscriptionID + "/tokens/" + purchaseToken + ":refund"

	service, closeServer := newTestRefundService(t, expectedPath, http.StatusBadRequest)
	defer closeServer()

	err := service.RefundSubscription(context.Background(), packageName, subscriptionID, purchaseToken)
	if err == nil {
		t.Fatalf("expected refund subscription API failure")
	}
	if !strings.Contains(err.Error(), "refund subscription failed") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestServiceRefundSubscriptionRequiresValidInput(t *testing.T) {
	t.Parallel()

	var nilService *Service
	if err := nilService.RefundSubscription(context.Background(), "com.example", "sub-1", "token-1"); err == nil {
		t.Fatalf("expected error for nil service")
	}

	service := &Service{}
	if err := service.RefundSubscription(context.Background(), "", "sub-1", "token-1"); err == nil {
		t.Fatalf("expected error for missing package name")
	}

	if err := service.RefundSubscription(context.Background(), "com.example", "", "token-1"); err == nil {
		t.Fatalf("expected error for missing subscription ID")
	}

	if err := service.RefundSubscription(context.Background(), "com.example", "sub-1", ""); err == nil {
		t.Fatalf("expected error for missing purchase token")
	}
}

func newTestRefundService(t *testing.T, expectedPath string, status int) (*Service, func()) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST request, got %s", r.Method)
		}

		if r.URL.Path != expectedPath {
			t.Fatalf("unexpected path: got %q", r.URL.Path)
		}

		if r.URL.Query().Get("alt") != "json" || r.URL.Query().Get("prettyPrint") != "false" {
			t.Fatalf("unexpected query: %v", r.URL.RawQuery)
		}

		w.WriteHeader(status)
		fmt.Fprintf(w, `{"result":"ok"}`)
	}))

	service, err := NewService(context.Background(), option.WithEndpoint(server.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("create test service: %v", err)
	}

	close := server.Close
	return service, close
}
