package subscriptions_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/api/androidpublisher/v3"
	"google.golang.org/api/option"

	"github.com/godrealms/go-google-sdk/android/publisher/subscriptions"
)

func TestQueryByTokenV2ReturnsV2Result(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	const subID = "sub-1"
	const tok = "token-1"
	// v2 endpoint uses token directly (no subscriptionID in path)
	path := "/androidpublisher/v3/applications/" + pkg + "/purchases/subscriptionsv2/tokens/" + tok

	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{"kind":"androidpublisher#subscriptionPurchaseV2"}`)
	defer closeFunc()

	_, result, err := svc.Query(context.Background(), subscriptions.SubscriptionQuery{
		PackageName: pkg, SubscriptionID: subID, PurchaseToken: tok,
	})
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if result == nil || result.V2 == nil {
		t.Fatalf("expected V2 result, got %+v", result)
	}
	if result.V1 != nil {
		t.Fatalf("expected V1 to be nil for default v2 query")
	}
}

func TestQueryByTokenV1ReturnsV1Result(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	const subID = "sub-1"
	const tok = "token-1"
	path := "/androidpublisher/v3/applications/" + pkg + "/purchases/subscriptions/" + subID + "/tokens/" + tok

	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{"kind":"androidpublisher#subscriptionPurchase"}`)
	defer closeFunc()

	_, result, err := svc.Query(context.Background(), subscriptions.SubscriptionQuery{
		PackageName: pkg, SubscriptionID: subID, PurchaseToken: tok, UseV1: true,
	})
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if result == nil || result.V1 == nil {
		t.Fatalf("expected V1 result, got %+v", result)
	}
}

func TestQueryByOrderIDReturnsOrder(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	const orderID = "order-123"
	path := "/androidpublisher/v3/applications/" + pkg + "/orders/" + orderID

	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{"orderId":"`+orderID+`"}`)
	defer closeFunc()

	order, _, err := svc.Query(context.Background(), subscriptions.SubscriptionQuery{
		PackageName: pkg, OrderID: orderID,
	})
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if order.OrderId != orderID {
		t.Fatalf("expected order ID %q, got %q", orderID, order.OrderId)
	}
}

func TestQueryRejectsMixedInputs(t *testing.T) {
	t.Parallel()

	svc, closeFunc := newTestService(t, "/unused", http.MethodGet, http.StatusOK, `{}`)
	defer closeFunc()

	_, _, err := svc.Query(context.Background(), subscriptions.SubscriptionQuery{
		PackageName: "com.example", OrderID: "o1", SubscriptionID: "s1",
	})
	if err == nil {
		t.Fatalf("expected ErrMixedOrderSubscriptionInput")
	}
}

func TestRefundSucceeds(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	const subID = "sub-987"
	const tok = "token-abc"
	path := "/androidpublisher/v3/applications/" + pkg + "/purchases/subscriptions/" + subID + "/tokens/" + tok + ":refund"

	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()

	if err := svc.Refund(context.Background(), pkg, subID, tok); err != nil {
		t.Fatalf("expected success: %v", err)
	}
}

func TestRefundPropagatesAPIError(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	const subID = "sub-err"
	const tok = "token-err"
	path := "/androidpublisher/v3/applications/" + pkg + "/purchases/subscriptions/" + subID + "/tokens/" + tok + ":refund"

	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusBadRequest, `{"error":{"code":400}}`)
	defer closeFunc()

	err := svc.Refund(context.Background(), pkg, subID, tok)
	if err == nil {
		t.Fatalf("expected error from API 400")
	}
}

func newTestService(t *testing.T, expectedPath, expectedMethod string, status int, body string) (*subscriptions.Service, func()) {
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

	return subscriptions.New(raw), server.Close
}
