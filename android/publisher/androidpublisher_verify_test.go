package publisher

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"google.golang.org/api/androidpublisher/v3"
	"google.golang.org/api/option"
)

type countingRoundTripper struct {
	count atomic.Int32
}

func (c *countingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	c.count.Add(1)
	body := io.NopCloser(strings.NewReader(`{}`))
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       body,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Request:    req,
	}, nil
}

func TestVerifyRequestRequiresPackageName(t *testing.T) {
	t.Parallel()

	_, err := new(Service).Verify(context.Background(), VerifyRequest{PurchaseToken: "token"})
	if err == nil {
		t.Fatalf("expected error for missing package name")
	}
}

func TestVerifyRoutesToProduct(t *testing.T) {
	t.Parallel()

	const packageName = "com.example.app"
	const productID = "product-1"
	const token = "token-1"
	expectedPath := "/androidpublisher/v3/applications/" + packageName + "/purchases/products/" + productID + "/tokens/" + token

	service, closeServer := newTestPublisherService(t, expectedPath, http.MethodGet, http.StatusOK, `{"kind":"androidpublisher#productPurchase"}`)
	defer closeServer()

	result, err := service.Verify(context.Background(), VerifyRequest{PackageName: packageName, ProductID: productID, PurchaseToken: token})
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if result.Type != VerifyTypeProduct {
		t.Fatalf("expected product type, got %s", result.Type)
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

func TestQuerySubscriptionByOrderIDUsesOrdersEndpoint(t *testing.T) {
	t.Parallel()

	const packageName = "com.example.app"
	const orderID = "order-123"
	expectedPath := "/androidpublisher/v3/applications/" + packageName + "/orders/" + orderID

	service, closeServer := newTestPublisherService(t, expectedPath, http.MethodGet, http.StatusOK, `{"orderId":"`+orderID+`"}`)
	defer closeServer()

	_, _, err := service.QuerySubscription(context.Background(), SubscriptionQuery{PackageName: packageName, OrderID: orderID})
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
}

func TestQuerySubscriptionByTokenUsesSubscriptionsEndpoint(t *testing.T) {
	t.Parallel()

	const packageName = "com.example.app"
	const subID = "sub-123"
	const purchaseToken = "token-456"
	expectedPath := "/androidpublisher/v3/applications/" + packageName + "/purchases/subscriptions/" + subID + "/tokens/" + purchaseToken

	service, closeServer := newTestPublisherService(t, expectedPath, http.MethodGet, http.StatusOK, `{}`)
	defer closeServer()

	_, _, err := service.QuerySubscription(context.Background(), SubscriptionQuery{PackageName: packageName, SubscriptionID: subID, PurchaseToken: purchaseToken})
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
}

func newCountingService(t *testing.T) (*Service, *countingRoundTripper) {
	t.Helper()

	rt := &countingRoundTripper{}
	client := &http.Client{Transport: rt}
	service, err := NewService(context.Background(), option.WithHTTPClient(client), option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("create test service: %v", err)
	}

	return service, rt
}

func assertMixedInputRejected(t *testing.T, err error, rt *countingRoundTripper, expectedErr error) {
	t.Helper()
	if rt == nil {
		t.Fatalf("rt is required")
	}
	if expectedErr == nil {
		t.Fatalf("expectedErr is required: got %v, want non-nil error", expectedErr)
	}
	if err == nil {
		t.Fatalf("expected error: got %v, want %v", err, expectedErr)
	}

	count := rt.count.Load()
	if count != 0 {
		t.Fatalf("unexpected request count: got %d, want %d", count, 0)
	}
	if !errors.Is(err, expectedErr) {
		t.Fatalf("unexpected error: got %v, want %v", err, expectedErr)
	}
}

func TestQueryPurchaseRejectsMixedInputs(t *testing.T) {
	t.Parallel()

	const packageName = "com.example.app"
	const orderID = "order-123"

	service, rt := newCountingService(t)
	_, _, err := service.QueryPurchase(context.Background(), PurchaseQuery{
		PackageName:   packageName,
		OrderID:       orderID,
		ProductID:     "product-123",
		PurchaseToken: "token-123",
	})
	assertMixedInputRejected(t, err, rt, ErrMixedOrderProductInput)
}

func TestQuerySubscriptionRejectsMixedInputs(t *testing.T) {
	t.Parallel()

	const packageName = "com.example.app"
	const orderID = "order-123"

	service, rt := newCountingService(t)
	_, _, err := service.QuerySubscription(context.Background(), SubscriptionQuery{
		PackageName:    packageName,
		OrderID:        orderID,
		SubscriptionID: "sub-123",
		PurchaseToken:  "token-123",
	})
	assertMixedInputRejected(t, err, rt, ErrMixedOrderSubscriptionInput)
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
