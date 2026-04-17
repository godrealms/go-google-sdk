//go:build integration

package publisher_test

import (
	"context"
	"os"
	"testing"

	publisher "github.com/godrealms/go-google-sdk/android/publisher"
	"github.com/godrealms/go-google-sdk/android/publisher/inappproducts"
	"github.com/godrealms/go-google-sdk/android/publisher/voidedpurchases"
	"google.golang.org/api/option"
)

// Run with: go test -tags=integration ./android/publisher/ -v
// Required env: GOOGLE_APPLICATION_CREDENTIALS, TEST_PACKAGE_NAME

func integrationClient(t *testing.T) (*publisher.Client, string) {
	t.Helper()

	pkg := os.Getenv("TEST_PACKAGE_NAME")
	if pkg == "" {
		t.Skip("TEST_PACKAGE_NAME not set")
	}
	creds := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if creds == "" {
		t.Skip("GOOGLE_APPLICATION_CREDENTIALS not set")
	}

	client, err := publisher.NewClient(context.Background(),
		option.WithCredentialsFile(creds),
	)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	return client, pkg
}

func TestIntegration_InAppProductsList(t *testing.T) {
	client, pkg := integrationClient(t)

	resp, err := client.InAppProducts.List(context.Background(), pkg, inappproducts.WithMaxResults(10))
	if err != nil {
		t.Fatalf("InAppProducts.List: %v", err)
	}
	t.Logf("InAppProducts.List returned %d items", len(resp.Inappproduct))
}

func TestIntegration_VoidedPurchasesList(t *testing.T) {
	client, pkg := integrationClient(t)

	resp, err := client.VoidedPurchases.List(context.Background(), pkg, voidedpurchases.WithMaxResults(10))
	if err != nil {
		t.Fatalf("VoidedPurchases.List: %v", err)
	}
	t.Logf("VoidedPurchases.List returned %d items", len(resp.VoidedPurchases))
}

func TestIntegration_OrdersGetInvalidID(t *testing.T) {
	client, pkg := integrationClient(t)

	// Expect a 404 for a non-existent order — verifies connectivity and auth work.
	_, err := client.Orders.Get(context.Background(), pkg, "nonexistent-order-id")
	if err == nil {
		t.Fatalf("expected error for non-existent order")
	}
	t.Logf("Orders.Get (404 expected): %v", err)
}
