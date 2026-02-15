package publisher

import (
	"context"
	"net/http"
	"testing"
)

func TestVerifyRequestRequiresPackageName(t *testing.T) {
	t.Parallel()

	_, err := new(Service).Verify(context.Background(), VerifyRequest{PurchaseToken: "token"})
	if err == nil {
		t.Fatalf("expected error for missing package name")
	}
}

func TestQueryPurchaseRequiresInput(t *testing.T) {
	t.Parallel()

	_, err := new(Service).QueryPurchase(context.Background(), PurchaseQuery{})
	if err == nil {
		t.Fatalf("expected error for missing fields")
	}
}

func TestQueryPurchaseByOrderIDUsesOrdersEndpoint(t *testing.T) {
	t.Parallel()

	const packageName = "com.example.app"
	const orderID = "order-123"
	expectedPath := "/androidpublisher/v3/applications/" + packageName + "/orders/" + orderID

	service, closeServer := newTestPublisherService(t, expectedPath, http.MethodGet, http.StatusOK, `{"orderId":"`+orderID+`"}`)
	defer closeServer()

	_, err := service.QueryPurchase(context.Background(), PurchaseQuery{PackageName: packageName, OrderID: orderID})
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
}
