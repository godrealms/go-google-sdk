package publisher_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/api/androidpublisher/v3"
	"google.golang.org/api/option"

	publisher "github.com/godrealms/go-google-sdk/android/publisher"
)

func TestVerifyRequiresPackageName(t *testing.T) {
	t.Parallel()

	client, closeFunc := newTestClient(t, "/unused", http.MethodGet, http.StatusOK, `{}`)
	defer closeFunc()

	_, err := client.Verify(context.Background(), publisher.VerifyRequest{PurchaseToken: "token"})
	if err == nil {
		t.Fatalf("expected error for missing package name")
	}
}

func TestVerifyRoutesToProduct(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	const prod = "product-1"
	const tok = "token-1"
	path := "/androidpublisher/v3/applications/" + pkg + "/purchases/products/" + prod + "/tokens/" + tok

	client, closeFunc := newTestClient(t, path, http.MethodGet, http.StatusOK, `{"kind":"androidpublisher#productPurchase"}`)
	defer closeFunc()

	result, err := client.Verify(context.Background(), publisher.VerifyRequest{
		PackageName: pkg, ProductID: prod, PurchaseToken: tok,
	})
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if result.Type != publisher.VerifyTypeProduct {
		t.Fatalf("expected product type, got %s", result.Type)
	}
}

func TestVerifyRoutesToSubscription(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	const subID = "sub-1"
	const tok = "token-1"
	// Default routes to v2 endpoint
	path := "/androidpublisher/v3/applications/" + pkg + "/purchases/subscriptionsv2/tokens/" + tok

	client, closeFunc := newTestClient(t, path, http.MethodGet, http.StatusOK, `{"kind":"androidpublisher#subscriptionPurchaseV2"}`)
	defer closeFunc()

	result, err := client.Verify(context.Background(), publisher.VerifyRequest{
		PackageName: pkg, SubscriptionID: subID, PurchaseToken: tok,
	})
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if result.Type != publisher.VerifyTypeSubscription {
		t.Fatalf("expected subscription type, got %s", result.Type)
	}
}

func TestVerifyReturnsOrderForProductOrderID(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	const orderID = "order-123"
	path := "/androidpublisher/v3/applications/" + pkg + "/orders/" + orderID

	client, closeFunc := newTestClient(t, path, http.MethodGet, http.StatusOK, `{"orderId":"`+orderID+`"}`)
	defer closeFunc()

	result, err := client.Verify(context.Background(), publisher.VerifyRequest{
		PackageName: pkg, OrderID: orderID, Type: publisher.VerifyTypeProduct,
	})
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if result.Type != publisher.VerifyTypeProduct {
		t.Fatalf("expected product type, got %s", result.Type)
	}
	order, ok := result.Raw.(*androidpublisher.Order)
	if !ok {
		t.Fatalf("expected *Order raw, got %T", result.Raw)
	}
	if order.OrderId != orderID {
		t.Fatalf("expected order ID %q, got %q", orderID, order.OrderId)
	}
}

func TestVerifyReturnsOrderForSubscriptionOrderID(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	const orderID = "order-456"
	path := "/androidpublisher/v3/applications/" + pkg + "/orders/" + orderID

	client, closeFunc := newTestClient(t, path, http.MethodGet, http.StatusOK, `{"orderId":"`+orderID+`"}`)
	defer closeFunc()

	result, err := client.Verify(context.Background(), publisher.VerifyRequest{
		PackageName: pkg, OrderID: orderID, Type: publisher.VerifyTypeSubscription,
	})
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if result.Type != publisher.VerifyTypeSubscription {
		t.Fatalf("expected subscription type, got %s", result.Type)
	}
	order, ok := result.Raw.(*androidpublisher.Order)
	if !ok {
		t.Fatalf("expected *Order raw, got %T", result.Raw)
	}
	if order.OrderId != orderID {
		t.Fatalf("expected order ID %q, got %q", orderID, order.OrderId)
	}
}

func TestVerifyOrderIDOnlyAutoResolvesProduct(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	const orderID = "order-product-789"
	path := "/androidpublisher/v3/applications/" + pkg + "/orders/" + orderID

	client, closeFunc := newTestClient(t, path, http.MethodGet, http.StatusOK,
		`{"orderId":"`+orderID+`","lineItems":[{"oneTimePurchaseDetails":{"quantity":1}}]}`)
	defer closeFunc()

	result, err := client.Verify(context.Background(), publisher.VerifyRequest{
		PackageName: pkg, OrderID: orderID,
		// No Type — auto-resolve
	})
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if result.Type != publisher.VerifyTypeProduct {
		t.Fatalf("expected product type, got %s", result.Type)
	}
}

func TestVerifyOrderIDOnlyAutoResolvesSubscription(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	const orderID = "order-sub-789"
	path := "/androidpublisher/v3/applications/" + pkg + "/orders/" + orderID

	client, closeFunc := newTestClient(t, path, http.MethodGet, http.StatusOK,
		`{"orderId":"`+orderID+`","lineItems":[{"subscriptionDetails":{"subscriptionId":"sub-1"}}]}`)
	defer closeFunc()

	result, err := client.Verify(context.Background(), publisher.VerifyRequest{
		PackageName: pkg, OrderID: orderID,
	})
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if result.Type != publisher.VerifyTypeSubscription {
		t.Fatalf("expected subscription type, got %s", result.Type)
	}
}

func TestVerifyOrderIDOnlyUnknownTypeReturnsErrRouteUnknown(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	const orderID = "order-unknown"
	path := "/androidpublisher/v3/applications/" + pkg + "/orders/" + orderID

	client, closeFunc := newTestClient(t, path, http.MethodGet, http.StatusOK,
		`{"orderId":"`+orderID+`","lineItems":[{"productId":"whatever"}]}`)
	defer closeFunc()

	_, err := client.Verify(context.Background(), publisher.VerifyRequest{
		PackageName: pkg, OrderID: orderID,
	})
	if !errors.Is(err, publisher.ErrRouteUnknown) {
		t.Fatalf("expected ErrRouteUnknown, got %v", err)
	}
}

func TestVerifyNoFieldsReturnsErrRouteUnknown(t *testing.T) {
	t.Parallel()

	client, closeFunc := newTestClient(t, "/unused", http.MethodGet, http.StatusOK, `{}`)
	defer closeFunc()

	_, err := client.Verify(context.Background(), publisher.VerifyRequest{PackageName: "com.example"})
	if !errors.Is(err, publisher.ErrRouteUnknown) {
		t.Fatalf("expected ErrRouteUnknown, got %v", err)
	}
}

func newTestClient(t *testing.T, expectedPath, expectedMethod string, status int, body string) (*publisher.Client, func()) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != expectedMethod {
			t.Errorf("expected %s, got %s", expectedMethod, r.Method)
		}
		if r.URL.Path != expectedPath {
			t.Errorf("unexpected path: got %q, want %q", r.URL.Path, expectedPath)
		}
		if r.URL.Query().Get("alt") != "json" || r.URL.Query().Get("prettyPrint") != "false" {
			t.Errorf("unexpected query: %v", r.URL.RawQuery)
		}
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))

	client, err := publisher.NewClient(context.Background(),
		option.WithEndpoint(server.URL),
		option.WithoutAuthentication(),
	)
	if err != nil {
		t.Fatalf("create test client: %v", err)
	}

	return client, server.Close
}
