package publisher

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/api/androidpublisher/v3"
	"google.golang.org/api/option"
)

func TestVerifyRequestRequiresPackageName(t *testing.T) {
	t.Parallel()

	_, err := new(Service).Verify(context.Background(), VerifyRequest{PurchaseToken: "token"})
	if err == nil {
		t.Fatalf("expected error for missing package name")
	}
}

func TestVerifyRoutesToSubscription(t *testing.T) {
	t.Parallel()

	const packageName = "com.example.app"
	const subID = "sub-1"
	const token = "token-1"
	expectedPath := "/androidpublisher/v3/applications/" + packageName + "/purchases/subscriptions/" + subID + "/tokens/" + token

	service, closeServer := newTestPublisherService(t, expectedPath, http.MethodGet, http.StatusOK, `{"kind":"androidpublisher#subscriptionPurchase"}`)
	defer closeServer()

	result, err := service.Verify(context.Background(), VerifyRequest{PackageName: packageName, SubscriptionID: subID, PurchaseToken: token})
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if result.Type != VerifyTypeSubscription {
		t.Fatalf("expected subscription type, got %s", result.Type)
	}
}

func TestVerifyReturnsOrderForProductOrderID(t *testing.T) {
	t.Parallel()

	const packageName = "com.example.app"
	const orderID = "order-123"
	expectedPath := "/androidpublisher/v3/applications/" + packageName + "/orders/" + orderID

	service, closeServer := newTestPublisherService(t, expectedPath, http.MethodGet, http.StatusOK, `{"orderId":"`+orderID+`"}`)
	defer closeServer()

	result, err := service.Verify(context.Background(), VerifyRequest{PackageName: packageName, OrderID: orderID, Type: VerifyTypeProduct})
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if result.Type != VerifyTypeProduct {
		t.Fatalf("expected product type, got %s", result.Type)
	}
	order, ok := result.Raw.(*androidpublisher.Order)
	if !ok {
		t.Fatalf("expected order raw, got %T", result.Raw)
	}
	if order.OrderId != orderID {
		t.Fatalf("expected order ID %q, got %q", orderID, order.OrderId)
	}
}

func TestVerifyReturnsOrderForSubscriptionOrderID(t *testing.T) {
	t.Parallel()

	const packageName = "com.example.app"
	const orderID = "order-456"
	expectedPath := "/androidpublisher/v3/applications/" + packageName + "/orders/" + orderID

	service, closeServer := newTestPublisherService(t, expectedPath, http.MethodGet, http.StatusOK, `{"orderId":"`+orderID+`"}`)
	defer closeServer()

	result, err := service.Verify(context.Background(), VerifyRequest{PackageName: packageName, OrderID: orderID, Type: VerifyTypeSubscription})
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if result.Type != VerifyTypeSubscription {
		t.Fatalf("expected subscription type, got %s", result.Type)
	}
	order, ok := result.Raw.(*androidpublisher.Order)
	if !ok {
		t.Fatalf("expected order raw, got %T", result.Raw)
	}
	if order.OrderId != orderID {
		t.Fatalf("expected order ID %q, got %q", orderID, order.OrderId)
	}
}

func TestQueryPurchaseRequiresInput(t *testing.T) {
	t.Parallel()

	service, closeServer := newTestPublisherService(t, "/unused", http.MethodGet, http.StatusOK, `{}`)
	defer closeServer()

	_, _, err := service.QueryPurchase(context.Background(), PurchaseQuery{ProductID: "product", PurchaseToken: "token"})
	if err == nil {
		t.Fatalf("expected error for missing package name")
	}

	_, _, err = service.QueryPurchase(context.Background(), PurchaseQuery{PackageName: "com.example.app"})
	if err == nil {
		t.Fatalf("expected error for missing product ID and purchase token")
	}
}

func TestQueryPurchaseByOrderIDUsesOrdersEndpoint(t *testing.T) {
	t.Parallel()

	const packageName = "com.example.app"
	const orderID = "order-123"
	expectedPath := "/androidpublisher/v3/applications/" + packageName + "/orders/" + orderID

	service, closeServer := newTestPublisherService(t, expectedPath, http.MethodGet, http.StatusOK, `{"orderId":"`+orderID+`"}`)
	defer closeServer()

	_, _, err := service.QueryPurchase(context.Background(), PurchaseQuery{PackageName: packageName, OrderID: orderID})
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
}

func TestQueryPurchaseByTokenUsesProductsEndpoint(t *testing.T) {
	t.Parallel()

	const packageName = "com.example.app"
	const productID = "product-123"
	const purchaseToken = "token-456"
	expectedPath := "/androidpublisher/v3/applications/" + packageName + "/purchases/products/" + productID + "/tokens/" + purchaseToken

	service, closeServer := newTestPublisherService(t, expectedPath, http.MethodGet, http.StatusOK, `{}`)
	defer closeServer()

	_, _, err := service.QueryPurchase(context.Background(), PurchaseQuery{PackageName: packageName, ProductID: productID, PurchaseToken: purchaseToken})
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
}

func newTestPublisherService(t *testing.T, expectedPath, expectedMethod string, status int, body string) (*Service, func()) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != expectedMethod {
			t.Fatalf("expected %s request, got %s", expectedMethod, r.Method)
		}

		if r.URL.Path != expectedPath {
			t.Fatalf("unexpected path: got %q", r.URL.Path)
		}

		if r.URL.Query().Get("alt") != "json" || r.URL.Query().Get("prettyPrint") != "false" {
			t.Fatalf("unexpected query: %v", r.URL.RawQuery)
		}

		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))

	service, err := NewService(context.Background(), option.WithEndpoint(server.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("create test service: %v", err)
	}

	close := server.Close
	return service, close
}
