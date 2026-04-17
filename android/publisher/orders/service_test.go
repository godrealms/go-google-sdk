package orders_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/api/androidpublisher/v3"
	"google.golang.org/api/option"

	"github.com/godrealms/go-google-sdk/android/publisher/orders"
)

func TestGetRequiresPackageName(t *testing.T) {
	t.Parallel()

	svc := orders.New(nil)
	_, err := svc.Get(context.Background(), "", "order-1")
	if err == nil {
		t.Fatalf("expected error for nil raw service")
	}
}

func TestGetRequiresOrderID(t *testing.T) {
	t.Parallel()

	svc, closeFunc := newTestService(t, "/unused", http.StatusOK, `{}`)
	defer closeFunc()

	_, err := svc.Get(context.Background(), "com.example.app", "")
	if err == nil {
		t.Fatalf("expected error for missing order ID")
	}
}

func TestGetReturnsOrder(t *testing.T) {
	t.Parallel()

	const packageName = "com.example.app"
	const orderID = "order-123"
	expectedPath := "/androidpublisher/v3/applications/" + packageName + "/orders/" + orderID

	svc, closeFunc := newTestService(t, expectedPath, http.StatusOK, `{"orderId":"`+orderID+`"}`)
	defer closeFunc()

	order, err := svc.Get(context.Background(), packageName, orderID)
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if order.OrderId != orderID {
		t.Fatalf("expected order ID %q, got %q", orderID, order.OrderId)
	}
}

func TestGetPropagatesAPIError(t *testing.T) {
	t.Parallel()

	svc, closeFunc := newTestService(t, "/androidpublisher/v3/applications/com.example.app/orders/order-err", http.StatusNotFound, `{"error":{"code":404}}`)
	defer closeFunc()

	_, err := svc.Get(context.Background(), "com.example.app", "order-err")
	if err == nil {
		t.Fatalf("expected error from API 404")
	}
}

func newTestService(t *testing.T, expectedPath string, status int, body string) (*orders.Service, func()) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	return orders.New(raw), server.Close
}
