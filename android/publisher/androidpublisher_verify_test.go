package publisher

import (
	"context"
	"testing"
)

func TestVerifyRequestRequiresPackageName(t *testing.T) {
	t.Parallel()

	_, err := new(Service).Verify(context.Background(), VerifyRequest{PurchaseToken: "token"})
	if err == nil {
		t.Fatalf("expected error for missing package name")
	}
}
