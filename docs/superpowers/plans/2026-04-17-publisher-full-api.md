# Publisher Full API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all critical/important bugs in the `android/publisher` package and extend it to a complete sub-package architecture with purchases, subscriptions (v2 default), orders, inappproducts, and voidedpurchases.

**Architecture:** Rename `publisher.Service` → `publisher.Client` (aggregator); each Google Play resource domain becomes its own sub-package with a `Service` struct wrapping `*androidpublisher.Service`. The top-level `Client` owns `Verify()` routing logic (including OrderID auto-resolution) and delegates everything else to sub-services.

**Tech Stack:** Go 1.23, `google.golang.org/api/androidpublisher/v3`, `golang.org/x/oauth2`, `net/http/httptest` for unit tests, `//go:build integration` tag for live smoke tests.

---

## File Map

**Modify existing:**
- `android/publisher/errors.go` — add sentinel errors, remove unused `ErrNotFound`
- `android/publisher/androidpublisher.go` — fix constructor bug; in Task 11 becomes empty stub
- `android/publisher/client.go` — add `ctx` parameter
- `android/publisher/RTDN-Listener.go` — replace `log.Fatalf` with `errCh`
- `android/publisher/androidpublisher_verify_test.go` — fix helpers; in Task 11 updated to test `Client`
- `android/publisher/androidpublisher_refund_test.go` — rename `close` → `closeFunc`

**Create new:**
- `android/publisher/publisher.go` — `Client` struct + constructors + `Verify()`
- `android/publisher/orders/service.go` + `service_test.go`
- `android/publisher/purchases/types.go` + `service.go` + `service_test.go`
- `android/publisher/subscriptions/types.go` + `service.go` + `service_test.go`
- `android/publisher/inappproducts/types.go` + `service.go` + `service_test.go`
- `android/publisher/voidedpurchases/types.go` + `service.go` + `service_test.go`
- `android/publisher/integration_test.go`

---

## Task 1: Fix errors.go + test helper bugs

**Files:**
- Modify: `android/publisher/errors.go`
- Modify: `android/publisher/androidpublisher_verify_test.go` (lines 235–237, 308–309)
- Modify: `android/publisher/androidpublisher_refund_test.go` (lines 155–156)

- [ ] **Step 1: Replace errors.go**

```go
package publisher

import "errors"

var (
	ErrRouteUnknown                = errors.New("publisher: cannot determine verification type")
	ErrMissingPackageName          = errors.New("publisher: package name is required")
	ErrMissingPurchaseToken        = errors.New("publisher: purchase token is required")
	ErrMissingProductID            = errors.New("publisher: product ID is required")
	ErrMissingSubscriptionID       = errors.New("publisher: subscription ID is required")
	ErrMissingOrderID              = errors.New("publisher: order ID is required")
	ErrMixedOrderProductInput      = errors.New("publisher: order ID and product ID are mutually exclusive")
	ErrMixedOrderSubscriptionInput = errors.New("publisher: order ID and subscription ID are mutually exclusive")
)
```

- [ ] **Step 2: Fix assertMixedInputRejected format string** in `androidpublisher_verify_test.go:235`

Replace:
```go
	if expectedErr == nil {
		t.Fatalf("expectedErr is required: got %v, want non-nil error", expectedErr)
	}
```
With:
```go
	if expectedErr == nil {
		t.Fatalf("assertMixedInputRejected: expectedErr must not be nil")
	}
```

- [ ] **Step 3: Rename `close` → `closeFunc` in verify test** at `androidpublisher_verify_test.go:308`

Replace:
```go
	close := server.Close
	return service, close
```
With:
```go
	closeFunc := server.Close
	return service, closeFunc
```

- [ ] **Step 4: Rename `close` → `closeFunc` in refund test** at `androidpublisher_refund_test.go:155`

Replace:
```go
	close := server.Close
	return service, close
```
With:
```go
	closeFunc := server.Close
	return service, closeFunc
```

- [ ] **Step 5: Run tests**

```bash
cd /Volumes/Fanxiang-S790-1TB-Media/Personal/sdk/go-google-sdk
go test ./android/publisher/ -v -count=1 2>&1 | tail -20
```
Expected: all existing tests PASS

- [ ] **Step 6: Commit**

```bash
git add android/publisher/errors.go android/publisher/androidpublisher_verify_test.go android/publisher/androidpublisher_refund_test.go
git commit -m "fix(publisher): consolidate errors, fix test helper bugs"
```

---

## Task 2: Fix NewServiceWithTokenSource silent error swallow

**Files:**
- Modify: `android/publisher/androidpublisher.go` (lines 235–241)

- [ ] **Step 1: Write the failing test** — add to `androidpublisher_verify_test.go`

```go
func TestNewServiceWithTokenSourceReturnsErrorOnBadConfig(t *testing.T) {
	t.Parallel()

	// An empty oauth2.Config has an empty TokenURL, which causes Exchange to fail.
	cfg := &oauth2.Config{}
	_, err := NewServiceWithTokenSource(context.Background(), cfg, "bad-code")
	if err == nil {
		t.Fatalf("expected error for invalid oauth2 config, got nil")
	}
}
```

- [ ] **Step 2: Run to confirm it fails**

```bash
cd /Volumes/Fanxiang-S790-1TB-Media/Personal/sdk/go-google-sdk
go test ./android/publisher/ -run TestNewServiceWithTokenSourceReturnsErrorOnBadConfig -v
```
Expected: PASS (the Exchange error already propagates). If it passes, verify the constructor error path on line 235 is the one we want to fix — check that a `NewService` failure is handled.

- [ ] **Step 3: Fix the silent error swallow** in `androidpublisher.go` lines 235–241

Replace:
```go
	androidpublisherService, err := androidpublisher.NewService(ctx, option.WithTokenSource(config.TokenSource(ctx, token)))

	service := &Service{
		Androidpublisher: androidpublisherService,
	}

	return service, nil
```
With:
```go
	androidpublisherService, err := androidpublisher.NewService(ctx, option.WithTokenSource(config.TokenSource(ctx, token)))
	if err != nil {
		return nil, err
	}

	return &Service{Androidpublisher: androidpublisherService}, nil
```

- [ ] **Step 4: Run all tests**

```bash
go test ./android/publisher/ -v -count=1 2>&1 | tail -20
```
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add android/publisher/androidpublisher.go android/publisher/androidpublisher_verify_test.go
git commit -m "fix(publisher): return error from NewServiceWithTokenSource on service init failure"
```

---

## Task 3: Fix client.go hardcoded context.Background()

**Files:**
- Modify: `android/publisher/client.go`

- [ ] **Step 1: Rewrite client.go with ctx parameter**

```go
package publisher

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/androidpublisher/v3"
)

// NewClient creates an HTTP client from various credential sources.
// Accepts a string path, []byte JSON, OAuth2 struct, io.Reader, or nil for ADC.
func NewClient(ctx context.Context, config any) (*http.Client, error) {
	var jsonKey []byte
	var err error

	switch v := config.(type) {
	case string:
		jsonKey, err = os.ReadFile(v)
		if err != nil {
			return nil, err
		}
	case []byte:
		jsonKey = v
	case OAuth2, *OAuth2:
		jsonKey, err = json.Marshal(v)
		if err != nil {
			return nil, err
		}
	case io.Reader:
		jsonKey, err = io.ReadAll(v)
		if err != nil {
			return nil, err
		}
	default:
		return google.DefaultClient(ctx, androidpublisher.AndroidpublisherScope)
	}

	credentials, err := google.CredentialsFromJSON(ctx, jsonKey, androidpublisher.AndroidpublisherScope)
	if err != nil {
		return nil, err
	}
	return oauth2.NewClient(ctx, credentials.TokenSource), nil
}
```

- [ ] **Step 2: Run tests**

```bash
go test ./android/publisher/ -v -count=1 2>&1 | tail -20
```
Expected: all PASS (NewClient is not called in unit tests, so no breakage)

- [ ] **Step 3: Commit**

```bash
git add android/publisher/client.go
git commit -m "fix(publisher): propagate context through NewClient credential resolution"
```

---

## Task 4: Fix RTDN-Listener log.Fatalf → errCh

**Files:**
- Modify: `android/publisher/RTDN-Listener.go`

- [ ] **Step 1: Rewrite StartSubscriptionMonitor signature**

Replace the entire `StartSubscriptionMonitor` function (lines 107–137) with:

```go
// StartSubscriptionMonitor starts a Google Cloud Pub/Sub listener for RTDN notifications.
// Errors from the listener are sent to errCh; callers decide how to handle them.
// The function blocks until ctx is cancelled.
func StartSubscriptionMonitor(ctx context.Context, config *Config, errCh chan<- error, fun func(ctx context.Context, msg *pubsub.Message)) {
	if config == nil {
		if errCh != nil {
			errCh <- errors.New("publisher: config is nil")
		}
		return
	}

	var client *pubsub.Client
	var err error
	if config.JsonKey != "" {
		client, err = pubsub.NewClient(ctx, config.ProjectID, option.WithCredentialsJSON([]byte(config.JsonKey)))
	} else {
		client, err = pubsub.NewClient(ctx, config.ProjectID)
	}
	if err != nil {
		if errCh != nil {
			errCh <- fmt.Errorf("publisher: pubsub client: %w", err)
		}
		return
	}
	defer client.Close()

	sub := client.Subscription(config.SubscriptionID)
	if err = sub.Receive(ctx, fun); err != nil {
		if errCh != nil {
			errCh <- fmt.Errorf("publisher: receive: %w", err)
		}
	}
}
```

Also update the import block at the top of `RTDN-Listener.go`:

```go
import (
	"context"
	"errors"
	"fmt"

	"cloud.google.com/go/pubsub"
	"google.golang.org/api/option"
)
```

Remove `"log"` from imports.

- [ ] **Step 2: Run tests**

```bash
go test ./android/publisher/ -v -count=1 2>&1 | tail -20
```
Expected: all PASS

- [ ] **Step 3: Commit**

```bash
git add android/publisher/RTDN-Listener.go
git commit -m "fix(publisher): replace log.Fatalf with errCh in StartSubscriptionMonitor"
```

---

## Task 5: Fix legacy methods + add missing test coverage

**Files:**
- Modify: `android/publisher/androidpublisher.go` (VerifyPurchase, VerifySubscriptions)
- Modify: `android/publisher/androidpublisher_verify_test.go` (add tests)

- [ ] **Step 1: Add context to VerifyPurchase + fix comment**

Replace lines 145–160 in `androidpublisher.go`:

```go
// Deprecated: Use Verify instead.
func (s *Service) VerifyPurchase(ctx context.Context, packageName, productId, purchaseToken string) (*androidpublisher.ProductPurchase, error) {
	purchase, err := s.Androidpublisher.Purchases.Products.Get(packageName, productId, purchaseToken).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	if purchase.PurchaseState == 0 { // PurchaseState: 0 = purchased, 1 = canceled
		return purchase, nil
	}
	return purchase, fmt.Errorf("purchase not valid")
}
```

- [ ] **Step 2: Add context to VerifySubscriptions + fix comment**

Replace lines 162–176 in `androidpublisher.go`:

```go
// Deprecated: Use Verify instead.
func (s *Service) VerifySubscriptions(ctx context.Context, packageName, subscriptionId, purchaseToken string) (*androidpublisher.SubscriptionPurchase, error) {
	purchase, err := s.Androidpublisher.Purchases.Subscriptions.Get(packageName, subscriptionId, purchaseToken).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	if purchase.AcknowledgementState == 1 && purchase.PaymentState != nil { // AcknowledgementState: 0 = not acknowledged, 1 = acknowledged
		return purchase, nil
	}
	return purchase, fmt.Errorf("purchase not valid")
}
```

- [ ] **Step 3: Add tests for deprecated methods and Verify(OrderID-only)**

Append to `androidpublisher_verify_test.go`:

```go
func TestVerifyPurchaseSucceeds(t *testing.T) {
	t.Parallel()

	const packageName = "com.example.app"
	const productID = "product-1"
	const token = "token-1"
	expectedPath := "/androidpublisher/v3/applications/" + packageName + "/purchases/products/" + productID + "/tokens/" + token

	service, closeFunc := newTestPublisherService(t, expectedPath, http.MethodGet, http.StatusOK, `{"purchaseState":0}`)
	defer closeFunc()

	purchase, err := service.VerifyPurchase(context.Background(), packageName, productID, token)
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if purchase == nil {
		t.Fatalf("expected non-nil purchase")
	}
}

func TestVerifySubscriptionsSucceeds(t *testing.T) {
	t.Parallel()

	const packageName = "com.example.app"
	const subID = "sub-1"
	const token = "token-1"
	expectedPath := "/androidpublisher/v3/applications/" + packageName + "/purchases/subscriptions/" + subID + "/tokens/" + token
	paymentState := int64(1)
	_ = paymentState

	service, closeFunc := newTestPublisherService(t, expectedPath, http.MethodGet, http.StatusOK, `{"acknowledgementState":1,"paymentState":1}`)
	defer closeFunc()

	purchase, err := service.VerifySubscriptions(context.Background(), packageName, subID, token)
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if purchase == nil {
		t.Fatalf("expected non-nil purchase")
	}
}

func TestVerifyOrderIDOnlyReturnsErrRouteUnknown(t *testing.T) {
	t.Parallel()

	service, closeFunc := newTestPublisherService(t, "/unused", http.MethodGet, http.StatusOK, `{}`)
	defer closeFunc()

	_, err := service.Verify(context.Background(), VerifyRequest{
		PackageName: "com.example.app",
		OrderID:     "order-123",
		// No Type, no PurchaseToken, no ProductID, no SubscriptionID
	})
	if !errors.Is(err, ErrRouteUnknown) {
		t.Fatalf("expected ErrRouteUnknown, got %v", err)
	}
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./android/publisher/ -v -count=1 2>&1 | tail -30
```
Expected: all PASS including the three new tests

- [ ] **Step 5: Commit**

```bash
git add android/publisher/androidpublisher.go android/publisher/androidpublisher_verify_test.go
git commit -m "fix(publisher): add context to deprecated methods, fix comments, add missing tests"
```

---

## Task 6: Create orders/ sub-package

**Files:**
- Create: `android/publisher/orders/service.go`
- Create: `android/publisher/orders/service_test.go`

- [ ] **Step 1: Write the failing test**

Create `android/publisher/orders/service_test.go`:

```go
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
```

- [ ] **Step 2: Run to confirm it fails**

```bash
go test ./android/publisher/orders/ -v 2>&1 | head -10
```
Expected: compile error — package `orders` does not exist yet

- [ ] **Step 3: Create service.go**

Create `android/publisher/orders/service.go`:

```go
package orders

import (
	"context"
	"errors"

	"google.golang.org/api/androidpublisher/v3"
)

type Service struct {
	raw *androidpublisher.Service
}

func New(raw *androidpublisher.Service) *Service {
	return &Service{raw: raw}
}

func (s *Service) Get(ctx context.Context, packageName, orderID string) (*androidpublisher.Order, error) {
	if s == nil || s.raw == nil {
		return nil, errors.New("orders: service is nil")
	}
	if packageName == "" {
		return nil, errors.New("orders: packageName is required")
	}
	if orderID == "" {
		return nil, errors.New("orders: orderID is required")
	}
	return s.raw.Orders.Get(packageName, orderID).Context(ctx).Do()
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./android/publisher/orders/ -v -count=1
```
Expected: all 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add android/publisher/orders/
git commit -m "feat(publisher/orders): add orders sub-package with Get method"
```

---

## Task 7: Create purchases/ sub-package

**Files:**
- Create: `android/publisher/purchases/types.go`
- Create: `android/publisher/purchases/service.go`
- Create: `android/publisher/purchases/service_test.go`

- [ ] **Step 1: Write the failing tests**

Create `android/publisher/purchases/service_test.go`:

```go
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

	_, purchase, err := svc.Query(context.Background(), purchases.PurchaseQuery{
		PackageName: pkg, ProductID: prod, PurchaseToken: tok,
	})
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if purchase == nil {
		t.Fatalf("expected non-nil purchase")
	}
}

func TestQueryByOrderIDReturnsOrder(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	const orderID = "order-123"
	path := "/androidpublisher/v3/applications/" + pkg + "/orders/" + orderID

	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{"orderId":"`+orderID+`"}`)
	defer closeFunc()

	order, _, err := svc.Query(context.Background(), purchases.PurchaseQuery{
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

	_, _, err := svc.Query(context.Background(), purchases.PurchaseQuery{
		PackageName: "com.example", OrderID: "o1", ProductID: "p1",
	})
	if err == nil {
		t.Fatalf("expected ErrMixedOrderProductInput")
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
```

- [ ] **Step 2: Run to confirm compile failure**

```bash
go test ./android/publisher/purchases/ 2>&1 | head -5
```
Expected: compile error

- [ ] **Step 3: Create types.go**

Create `android/publisher/purchases/types.go`:

```go
package purchases

import "errors"

var ErrMixedOrderProductInput = errors.New("purchases: orderID and productID are mutually exclusive")

type PurchaseQuery struct {
	PackageName   string
	ProductID     string
	PurchaseToken string
	OrderID       string
}
```

- [ ] **Step 4: Create service.go**

Create `android/publisher/purchases/service.go`:

```go
package purchases

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/api/androidpublisher/v3"
)

type Service struct {
	raw *androidpublisher.Service
}

func New(raw *androidpublisher.Service) *Service {
	return &Service{raw: raw}
}

func (s *Service) Acknowledge(ctx context.Context, packageName, productID, purchaseToken string) error {
	if s == nil || s.raw == nil {
		return errors.New("purchases: service is nil")
	}
	if packageName == "" {
		return errors.New("purchases: packageName is required")
	}
	if productID == "" {
		return errors.New("purchases: productID is required")
	}
	if purchaseToken == "" {
		return errors.New("purchases: purchaseToken is required")
	}
	return s.raw.Purchases.Products.Acknowledge(packageName, productID, purchaseToken,
		&androidpublisher.ProductPurchasesAcknowledgeRequest{}).Context(ctx).Do()
}

func (s *Service) Consume(ctx context.Context, packageName, productID, purchaseToken string) error {
	if s == nil || s.raw == nil {
		return errors.New("purchases: service is nil")
	}
	if packageName == "" {
		return errors.New("purchases: packageName is required")
	}
	if productID == "" {
		return errors.New("purchases: productID is required")
	}
	if purchaseToken == "" {
		return errors.New("purchases: purchaseToken is required")
	}
	return s.raw.Purchases.Products.Consume(packageName, productID, purchaseToken).Context(ctx).Do()
}

func (s *Service) Query(ctx context.Context, q PurchaseQuery) (*androidpublisher.Order, *androidpublisher.ProductPurchase, error) {
	if s == nil || s.raw == nil {
		return nil, nil, errors.New("purchases: service is nil")
	}
	if q.PackageName == "" {
		return nil, nil, errors.New("purchases: packageName is required")
	}
	if q.OrderID != "" && (q.ProductID != "" || q.PurchaseToken != "") {
		return nil, nil, ErrMixedOrderProductInput
	}
	if q.OrderID != "" {
		order, err := s.raw.Orders.Get(q.PackageName, q.OrderID).Context(ctx).Do()
		if err != nil {
			return nil, nil, err
		}
		return order, nil, nil
	}
	if q.ProductID == "" || q.PurchaseToken == "" {
		return nil, nil, errors.New("purchases: productID and purchaseToken are required")
	}
	purchase, err := s.raw.Purchases.Products.Get(q.PackageName, q.ProductID, q.PurchaseToken).Context(ctx).Do()
	if err != nil {
		return nil, nil, err
	}
	return nil, purchase, nil
}

func (s *Service) Refund(ctx context.Context, packageName, orderID string) error {
	if s == nil || s.raw == nil {
		return errors.New("purchases: service is nil")
	}
	if packageName == "" {
		return errors.New("purchases: packageName is required")
	}
	if orderID == "" {
		return errors.New("purchases: orderID is required")
	}
	if err := s.raw.Orders.Refund(packageName, orderID).Context(ctx).Do(); err != nil {
		return fmt.Errorf("purchases: refund failed: %w", err)
	}
	return nil
}

// Deprecated: Use the parent Client.Verify instead.
func (s *Service) VerifyPurchase(ctx context.Context, packageName, productID, purchaseToken string) (*androidpublisher.ProductPurchase, error) {
	purchase, err := s.raw.Purchases.Products.Get(packageName, productID, purchaseToken).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	if purchase.PurchaseState == 0 { // PurchaseState: 0 = purchased, 1 = canceled
		return purchase, nil
	}
	return purchase, fmt.Errorf("purchases: purchase not valid")
}
```

- [ ] **Step 5: Run tests**

```bash
go test ./android/publisher/purchases/ -v -count=1
```
Expected: all tests PASS

- [ ] **Step 6: Commit**

```bash
git add android/publisher/purchases/
git commit -m "feat(publisher/purchases): add purchases sub-package with Acknowledge, Consume, Query, Refund"
```

---

## Task 8: Create subscriptions/ sub-package

**Files:**
- Create: `android/publisher/subscriptions/types.go`
- Create: `android/publisher/subscriptions/service.go`
- Create: `android/publisher/subscriptions/service_test.go`

- [ ] **Step 1: Write the failing tests**

Create `android/publisher/subscriptions/service_test.go`:

```go
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
```

- [ ] **Step 2: Create types.go**

Create `android/publisher/subscriptions/types.go`:

```go
package subscriptions

import (
	"errors"

	"google.golang.org/api/androidpublisher/v3"
)

var ErrMixedOrderSubscriptionInput = errors.New("subscriptions: orderID and subscriptionID are mutually exclusive")

type SubscriptionQuery struct {
	PackageName    string
	SubscriptionID string
	PurchaseToken  string
	OrderID        string
	UseV1          bool // true → use v1 Purchases.Subscriptions API instead of v2
}

type SubscriptionResult struct {
	V1 *androidpublisher.SubscriptionPurchase   // non-nil when UseV1=true
	V2 *androidpublisher.SubscriptionPurchaseV2 // non-nil by default
}
```

- [ ] **Step 3: Create service.go**

Create `android/publisher/subscriptions/service.go`:

```go
package subscriptions

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/api/androidpublisher/v3"
)

type Service struct {
	raw *androidpublisher.Service
}

func New(raw *androidpublisher.Service) *Service {
	return &Service{raw: raw}
}

func (s *Service) Query(ctx context.Context, q SubscriptionQuery) (*androidpublisher.Order, *SubscriptionResult, error) {
	if s == nil || s.raw == nil {
		return nil, nil, errors.New("subscriptions: service is nil")
	}
	if q.PackageName == "" {
		return nil, nil, errors.New("subscriptions: packageName is required")
	}
	if q.OrderID != "" && (q.SubscriptionID != "" || q.PurchaseToken != "") {
		return nil, nil, ErrMixedOrderSubscriptionInput
	}
	if q.OrderID != "" {
		order, err := s.raw.Orders.Get(q.PackageName, q.OrderID).Context(ctx).Do()
		if err != nil {
			return nil, nil, err
		}
		return order, nil, nil
	}
	if q.SubscriptionID == "" || q.PurchaseToken == "" {
		return nil, nil, errors.New("subscriptions: subscriptionID and purchaseToken are required")
	}
	if q.UseV1 {
		purchase, err := s.raw.Purchases.Subscriptions.Get(q.PackageName, q.SubscriptionID, q.PurchaseToken).Context(ctx).Do()
		if err != nil {
			return nil, nil, err
		}
		return nil, &SubscriptionResult{V1: purchase}, nil
	}
	purchase, err := s.raw.Purchases.Subscriptionsv2.Get(q.PackageName, q.PurchaseToken).Context(ctx).Do()
	if err != nil {
		return nil, nil, err
	}
	return nil, &SubscriptionResult{V2: purchase}, nil
}

func (s *Service) Refund(ctx context.Context, packageName, subscriptionID, purchaseToken string) error {
	if s == nil || s.raw == nil {
		return errors.New("subscriptions: service is nil")
	}
	if packageName == "" {
		return errors.New("subscriptions: packageName is required")
	}
	if subscriptionID == "" {
		return errors.New("subscriptions: subscriptionID is required")
	}
	if purchaseToken == "" {
		return errors.New("subscriptions: purchaseToken is required")
	}
	if err := s.raw.Purchases.Subscriptions.Refund(packageName, subscriptionID, purchaseToken).Context(ctx).Do(); err != nil {
		return fmt.Errorf("subscriptions: refund failed: %w", err)
	}
	return nil
}

// Deprecated: Use the parent Client.Verify instead.
func (s *Service) VerifySubscriptions(ctx context.Context, packageName, subscriptionID, purchaseToken string) (*androidpublisher.SubscriptionPurchase, error) {
	purchase, err := s.raw.Purchases.Subscriptions.Get(packageName, subscriptionID, purchaseToken).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	if purchase.AcknowledgementState == 1 && purchase.PaymentState != nil { // AcknowledgementState: 0 = not acknowledged, 1 = acknowledged
		return purchase, nil
	}
	return purchase, fmt.Errorf("subscriptions: purchase not valid")
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./android/publisher/subscriptions/ -v -count=1
```
Expected: all tests PASS

- [ ] **Step 5: Commit**

```bash
git add android/publisher/subscriptions/
git commit -m "feat(publisher/subscriptions): add subscriptions sub-package with v2 default, v1 opt-in"
```

---

## Task 9: Create inappproducts/ sub-package

**Files:**
- Create: `android/publisher/inappproducts/types.go`
- Create: `android/publisher/inappproducts/service.go`
- Create: `android/publisher/inappproducts/service_test.go`

- [ ] **Step 1: Write the failing tests**

Create `android/publisher/inappproducts/service_test.go`:

```go
package inappproducts_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/api/androidpublisher/v3"
	"google.golang.org/api/option"

	"github.com/godrealms/go-google-sdk/android/publisher/inappproducts"
)

func TestListSucceeds(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	path := "/androidpublisher/v3/applications/" + pkg + "/inappproducts"

	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{"inappproduct":[]}`)
	defer closeFunc()

	resp, err := svc.List(context.Background(), pkg)
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if resp == nil {
		t.Fatalf("expected non-nil response")
	}
}

func TestGetSucceeds(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	const sku = "sword_001"
	path := "/androidpublisher/v3/applications/" + pkg + "/inappproducts/" + sku

	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{"sku":"`+sku+`"}`)
	defer closeFunc()

	product, err := svc.Get(context.Background(), pkg, sku)
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if product.Sku != sku {
		t.Fatalf("expected sku %q, got %q", sku, product.Sku)
	}
}

func TestInsertSucceeds(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	path := "/androidpublisher/v3/applications/" + pkg + "/inappproducts"

	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{"sku":"new_item"}`)
	defer closeFunc()

	product, err := svc.Insert(context.Background(), pkg, &androidpublisher.InAppProduct{Sku: "new_item"})
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if product == nil {
		t.Fatalf("expected non-nil product")
	}
}

func TestUpdateSucceeds(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	const sku = "sword_001"
	path := "/androidpublisher/v3/applications/" + pkg + "/inappproducts/" + sku

	svc, closeFunc := newTestService(t, path, http.MethodPut, http.StatusOK, `{"sku":"`+sku+`"}`)
	defer closeFunc()

	product, err := svc.Update(context.Background(), pkg, sku, &androidpublisher.InAppProduct{Sku: sku})
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if product == nil {
		t.Fatalf("expected non-nil product")
	}
}

func TestDeleteSucceeds(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	const sku = "sword_001"
	path := "/androidpublisher/v3/applications/" + pkg + "/inappproducts/" + sku

	svc, closeFunc := newTestService(t, path, http.MethodDelete, http.StatusOK, `{}`)
	defer closeFunc()

	if err := svc.Delete(context.Background(), pkg, sku); err != nil {
		t.Fatalf("expected success: %v", err)
	}
}

func TestBatchGetSucceeds(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	path := "/androidpublisher/v3/applications/" + pkg + "/inappproducts:batchGet"

	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{"inappproduct":[]}`)
	defer closeFunc()

	resp, err := svc.BatchGet(context.Background(), pkg, []string{"sku1", "sku2"})
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if resp == nil {
		t.Fatalf("expected non-nil response")
	}
}

func TestBatchUpdateSucceeds(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	path := "/androidpublisher/v3/applications/" + pkg + "/inappproducts:batchUpdate"

	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{"inappproducts":[]}`)
	defer closeFunc()

	req := &androidpublisher.InappproductsBatchUpdateRequest{}
	resp, err := svc.BatchUpdate(context.Background(), pkg, req)
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if resp == nil {
		t.Fatalf("expected non-nil response")
	}
}

func TestRequiresPackageName(t *testing.T) {
	t.Parallel()

	svc, closeFunc := newTestService(t, "/unused", http.MethodGet, http.StatusOK, `{}`)
	defer closeFunc()

	if _, err := svc.List(context.Background(), ""); err == nil {
		t.Fatalf("expected error for missing packageName in List")
	}
	if _, err := svc.Get(context.Background(), "", "sku"); err == nil {
		t.Fatalf("expected error for missing packageName in Get")
	}
	if err := svc.Delete(context.Background(), "", "sku"); err == nil {
		t.Fatalf("expected error for missing packageName in Delete")
	}
}

func newTestService(t *testing.T, expectedPath, expectedMethod string, status int, body string) (*inappproducts.Service, func()) {
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

	return inappproducts.New(raw), server.Close
}
```

- [ ] **Step 2: Create types.go**

Create `android/publisher/inappproducts/types.go`:

```go
package inappproducts

import "google.golang.org/api/androidpublisher/v3"

// ListOption configures an inappproducts list call.
type ListOption func(*androidpublisher.InappproductsListCall)

// WithMaxResults limits the number of results returned.
func WithMaxResults(n int64) ListOption {
	return func(c *androidpublisher.InappproductsListCall) {
		c.MaxResults(uint64(n))
	}
}

// WithToken sets the pagination token for the next page.
func WithToken(token string) ListOption {
	return func(c *androidpublisher.InappproductsListCall) {
		c.Token(token)
	}
}
```

- [ ] **Step 3: Create service.go**

Create `android/publisher/inappproducts/service.go`:

```go
package inappproducts

import (
	"context"
	"errors"

	"google.golang.org/api/androidpublisher/v3"
)

type Service struct {
	raw *androidpublisher.Service
}

func New(raw *androidpublisher.Service) *Service {
	return &Service{raw: raw}
}

func (s *Service) List(ctx context.Context, packageName string, opts ...ListOption) (*androidpublisher.InappproductsListResponse, error) {
	if s == nil || s.raw == nil {
		return nil, errors.New("inappproducts: service is nil")
	}
	if packageName == "" {
		return nil, errors.New("inappproducts: packageName is required")
	}
	call := s.raw.Inappproducts.List(packageName).Context(ctx)
	for _, o := range opts {
		o(call)
	}
	return call.Do()
}

func (s *Service) Get(ctx context.Context, packageName, sku string) (*androidpublisher.InAppProduct, error) {
	if s == nil || s.raw == nil {
		return nil, errors.New("inappproducts: service is nil")
	}
	if packageName == "" {
		return nil, errors.New("inappproducts: packageName is required")
	}
	if sku == "" {
		return nil, errors.New("inappproducts: sku is required")
	}
	return s.raw.Inappproducts.Get(packageName, sku).Context(ctx).Do()
}

func (s *Service) Insert(ctx context.Context, packageName string, product *androidpublisher.InAppProduct) (*androidpublisher.InAppProduct, error) {
	if s == nil || s.raw == nil {
		return nil, errors.New("inappproducts: service is nil")
	}
	if packageName == "" {
		return nil, errors.New("inappproducts: packageName is required")
	}
	return s.raw.Inappproducts.Insert(packageName, product).Context(ctx).Do()
}

func (s *Service) Update(ctx context.Context, packageName, sku string, product *androidpublisher.InAppProduct) (*androidpublisher.InAppProduct, error) {
	if s == nil || s.raw == nil {
		return nil, errors.New("inappproducts: service is nil")
	}
	if packageName == "" {
		return nil, errors.New("inappproducts: packageName is required")
	}
	if sku == "" {
		return nil, errors.New("inappproducts: sku is required")
	}
	return s.raw.Inappproducts.Update(packageName, sku, product).Context(ctx).Do()
}

func (s *Service) Delete(ctx context.Context, packageName, sku string) error {
	if s == nil || s.raw == nil {
		return errors.New("inappproducts: service is nil")
	}
	if packageName == "" {
		return errors.New("inappproducts: packageName is required")
	}
	if sku == "" {
		return errors.New("inappproducts: sku is required")
	}
	return s.raw.Inappproducts.Delete(packageName, sku).Context(ctx).Do()
}

func (s *Service) BatchGet(ctx context.Context, packageName string, skus []string) (*androidpublisher.InappproductsBatchGetResponse, error) {
	if s == nil || s.raw == nil {
		return nil, errors.New("inappproducts: service is nil")
	}
	if packageName == "" {
		return nil, errors.New("inappproducts: packageName is required")
	}
	return s.raw.Inappproducts.BatchGet(packageName).Sku(skus...).Context(ctx).Do()
}

func (s *Service) BatchUpdate(ctx context.Context, packageName string, req *androidpublisher.InappproductsBatchUpdateRequest) (*androidpublisher.InappproductsBatchUpdateResponse, error) {
	if s == nil || s.raw == nil {
		return nil, errors.New("inappproducts: service is nil")
	}
	if packageName == "" {
		return nil, errors.New("inappproducts: packageName is required")
	}
	return s.raw.Inappproducts.Batchupdate(packageName, req).Context(ctx).Do()
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./android/publisher/inappproducts/ -v -count=1
```
Expected: all tests PASS

- [ ] **Step 5: Commit**

```bash
git add android/publisher/inappproducts/
git commit -m "feat(publisher/inappproducts): add inappproducts sub-package with full CRUD and batch"
```

---

## Task 10: Create voidedpurchases/ sub-package

**Files:**
- Create: `android/publisher/voidedpurchases/types.go`
- Create: `android/publisher/voidedpurchases/service.go`
- Create: `android/publisher/voidedpurchases/service_test.go`

- [ ] **Step 1: Write the failing tests**

Create `android/publisher/voidedpurchases/service_test.go`:

```go
package voidedpurchases_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/api/androidpublisher/v3"
	"google.golang.org/api/option"

	"github.com/godrealms/go-google-sdk/android/publisher/voidedpurchases"
)

func TestListSucceeds(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	path := "/androidpublisher/v3/applications/" + pkg + "/purchases/voidedpurchases"

	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{"voidedPurchases":[]}`)
	defer closeFunc()

	resp, err := svc.List(context.Background(), pkg)
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if resp == nil {
		t.Fatalf("expected non-nil response")
	}
}

func TestListWithOptions(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	path := "/androidpublisher/v3/applications/" + pkg + "/purchases/voidedpurchases"

	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{"voidedPurchases":[]}`)
	defer closeFunc()

	now := time.Now()
	resp, err := svc.List(context.Background(), pkg,
		voidedpurchases.WithStartTime(now.Add(-24*time.Hour)),
		voidedpurchases.WithEndTime(now),
		voidedpurchases.WithMaxResults(50),
	)
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if resp == nil {
		t.Fatalf("expected non-nil response")
	}
}

func TestListRequiresPackageName(t *testing.T) {
	t.Parallel()

	svc, closeFunc := newTestService(t, "/unused", http.MethodGet, http.StatusOK, `{}`)
	defer closeFunc()

	_, err := svc.List(context.Background(), "")
	if err == nil {
		t.Fatalf("expected error for missing packageName")
	}
}

func TestListPropagatesAPIError(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	path := "/androidpublisher/v3/applications/" + pkg + "/purchases/voidedpurchases"

	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusForbidden, `{"error":{"code":403}}`)
	defer closeFunc()

	_, err := svc.List(context.Background(), pkg)
	if err == nil {
		t.Fatalf("expected error from API 403")
	}
}

func newTestService(t *testing.T, expectedPath, expectedMethod string, status int, body string) (*voidedpurchases.Service, func()) {
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

	return voidedpurchases.New(raw), server.Close
}
```

- [ ] **Step 2: Create types.go**

Create `android/publisher/voidedpurchases/types.go`:

```go
package voidedpurchases

import (
	"time"

	"google.golang.org/api/androidpublisher/v3"
)

// ListOption configures a voidedpurchases list call.
type ListOption func(*androidpublisher.PurchasesVoidedpurchasesListCall)

func WithStartTime(t time.Time) ListOption {
	return func(c *androidpublisher.PurchasesVoidedpurchasesListCall) {
		c.StartTime(t.UnixMilli())
	}
}

func WithEndTime(t time.Time) ListOption {
	return func(c *androidpublisher.PurchasesVoidedpurchasesListCall) {
		c.EndTime(t.UnixMilli())
	}
}

func WithMaxResults(n int64) ListOption {
	return func(c *androidpublisher.PurchasesVoidedpurchasesListCall) {
		c.MaxResults(uint64(n))
	}
}

func WithPageToken(token string) ListOption {
	return func(c *androidpublisher.PurchasesVoidedpurchasesListCall) {
		c.Token(token)
	}
}

func WithType(purchaseType int64) ListOption {
	return func(c *androidpublisher.PurchasesVoidedpurchasesListCall) {
		c.Type(purchaseType)
	}
}
```

- [ ] **Step 3: Create service.go**

Create `android/publisher/voidedpurchases/service.go`:

```go
package voidedpurchases

import (
	"context"
	"errors"

	"google.golang.org/api/androidpublisher/v3"
)

type Service struct {
	raw *androidpublisher.Service
}

func New(raw *androidpublisher.Service) *Service {
	return &Service{raw: raw}
}

func (s *Service) List(ctx context.Context, packageName string, opts ...ListOption) (*androidpublisher.VoidedPurchasesListResponse, error) {
	if s == nil || s.raw == nil {
		return nil, errors.New("voidedpurchases: service is nil")
	}
	if packageName == "" {
		return nil, errors.New("voidedpurchases: packageName is required")
	}
	call := s.raw.Purchases.Voidedpurchases.List(packageName).Context(ctx)
	for _, o := range opts {
		o(call)
	}
	return call.Do()
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./android/publisher/voidedpurchases/ -v -count=1
```
Expected: all tests PASS

- [ ] **Step 5: Commit**

```bash
git add android/publisher/voidedpurchases/
git commit -m "feat(publisher/voidedpurchases): add voidedpurchases sub-package"
```

---

## Task 11: Refactor top-level publisher.go → Client aggregator

This task replaces the old `Service`-based API with `Client`, wires all sub-packages together, and fixes the `Verify(OrderID-only)` routing bug.

**Files:**
- Create: `android/publisher/publisher.go`
- Modify: `android/publisher/androidpublisher.go` → clear to just `package publisher`
- Modify: `android/publisher/androidpublisher_verify_test.go` → update to test `Client`
- Modify: `android/publisher/androidpublisher_refund_test.go` → remove (refund tested in sub-packages)

- [ ] **Step 1: Create publisher.go**

Create `android/publisher/publisher.go`:

```go
package publisher

import (
	"context"
	"errors"

	"golang.org/x/oauth2"
	"google.golang.org/api/androidpublisher/v3"
	"google.golang.org/api/option"

	"github.com/godrealms/go-google-sdk/android/publisher/inappproducts"
	"github.com/godrealms/go-google-sdk/android/publisher/orders"
	"github.com/godrealms/go-google-sdk/android/publisher/purchases"
	"github.com/godrealms/go-google-sdk/android/publisher/subscriptions"
	"github.com/godrealms/go-google-sdk/android/publisher/voidedpurchases"
)

// Client is the top-level Google Play Publisher client.
// Use its sub-service fields for resource-specific operations.
type Client struct {
	Purchases       *purchases.Service
	Subscriptions   *subscriptions.Service
	Orders          *orders.Service
	InAppProducts   *inappproducts.Service
	VoidedPurchases *voidedpurchases.Service
	raw             *androidpublisher.Service
}

func newClient(raw *androidpublisher.Service) *Client {
	return &Client{
		Purchases:       purchases.New(raw),
		Subscriptions:   subscriptions.New(raw),
		Orders:          orders.New(raw),
		InAppProducts:   inappproducts.New(raw),
		VoidedPurchases: voidedpurchases.New(raw),
		raw:             raw,
	}
}

// NewClient creates a Client using Application Default Credentials or the provided options.
func NewClient(ctx context.Context, opts ...option.ClientOption) (*Client, error) {
	raw, err := androidpublisher.NewService(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return newClient(raw), nil
}

// NewClientWithTokenSource creates a Client from an OAuth2 authorization code exchange.
func NewClientWithTokenSource(ctx context.Context, config *oauth2.Config, code string, opts ...oauth2.AuthCodeOption) (*Client, error) {
	if config == nil {
		return nil, errors.New("publisher: config is nil")
	}
	token, err := config.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, err
	}
	raw, err := androidpublisher.NewService(ctx, option.WithTokenSource(config.TokenSource(ctx, token)))
	if err != nil {
		return nil, err
	}
	return newClient(raw), nil
}

// NewClientWithKey creates a Client authenticated with an API key.
func NewClientWithKey(ctx context.Context, apiKey string) (*Client, error) {
	raw, err := androidpublisher.NewService(ctx, option.WithAPIKey(apiKey))
	if err != nil {
		return nil, err
	}
	return newClient(raw), nil
}

// Verify routes a purchase verification request to the appropriate sub-service.
// When only OrderID is provided (no Type, no PurchaseToken), Verify calls the Orders
// API to inspect LineItems and auto-resolves the product type.
func (c *Client) Verify(ctx context.Context, req VerifyRequest) (*VerifyResult, error) {
	if c == nil || c.raw == nil {
		return nil, errors.New("publisher: client is nil")
	}
	if req.PackageName == "" {
		return nil, ErrMissingPackageName
	}

	resolved := req.Type
	if resolved == "" {
		switch {
		case req.SubscriptionID != "":
			resolved = VerifyTypeSubscription
		case req.ProductID != "":
			resolved = VerifyTypeProduct
		case req.OrderID != "":
			// Auto-resolve by fetching the order and inspecting its line items.
			order, err := c.Orders.Get(ctx, req.PackageName, req.OrderID)
			if err != nil {
				return nil, err
			}
			if len(order.LineItems) == 0 {
				return nil, ErrRouteUnknown
			}
			switch order.LineItems[0].ProductType {
			case "TYPE_IN_APP_PRODUCT":
				return &VerifyResult{Type: VerifyTypeProduct, Raw: order}, nil
			case "TYPE_SUBSCRIPTION":
				return &VerifyResult{Type: VerifyTypeSubscription, Raw: order}, nil
			default:
				return nil, ErrRouteUnknown
			}
		default:
			return nil, ErrRouteUnknown
		}
	}

	switch resolved {
	case VerifyTypeProduct:
		order, purchase, err := c.Purchases.Query(ctx, purchases.PurchaseQuery{
			PackageName:   req.PackageName,
			ProductID:     req.ProductID,
			PurchaseToken: req.PurchaseToken,
			OrderID:       req.OrderID,
		})
		if err != nil {
			return nil, err
		}
		if order != nil {
			return &VerifyResult{Type: VerifyTypeProduct, Raw: order}, nil
		}
		return &VerifyResult{Type: VerifyTypeProduct, Raw: purchase}, nil

	case VerifyTypeSubscription:
		order, result, err := c.Subscriptions.Query(ctx, subscriptions.SubscriptionQuery{
			PackageName:    req.PackageName,
			SubscriptionID: req.SubscriptionID,
			PurchaseToken:  req.PurchaseToken,
			OrderID:        req.OrderID,
		})
		if err != nil {
			return nil, err
		}
		if order != nil {
			return &VerifyResult{Type: VerifyTypeSubscription, Raw: order}, nil
		}
		return &VerifyResult{Type: VerifyTypeSubscription, Raw: result}, nil

	default:
		return nil, ErrRouteUnknown
	}
}
```

- [ ] **Step 2: Clear androidpublisher.go**

Replace entire content of `android/publisher/androidpublisher.go` with:

```go
package publisher
```

- [ ] **Step 3: Rewrite androidpublisher_verify_test.go to test Client**

Replace the full content of `android/publisher/androidpublisher_verify_test.go` with:

```go
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
		`{"orderId":"`+orderID+`","lineItems":[{"productType":"TYPE_IN_APP_PRODUCT"}]}`)
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
		`{"orderId":"`+orderID+`","lineItems":[{"productType":"TYPE_SUBSCRIPTION"}]}`)
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
		`{"orderId":"`+orderID+`","lineItems":[{"productType":"UNKNOWN"}]}`)
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
```

- [ ] **Step 4: Delete androidpublisher_refund_test.go** (refund tests now live in purchases/ and subscriptions/)

```bash
rm android/publisher/androidpublisher_refund_test.go
```

- [ ] **Step 5: Run all tests**

```bash
go test ./android/publisher/... -v -count=1 2>&1 | tail -40
```
Expected: all tests PASS across all sub-packages

- [ ] **Step 6: Check coverage**

```bash
go test ./android/publisher/... -coverprofile=cover.out -count=1
go tool cover -func=cover.out | grep -E "(publisher\.|total)"
```
Expected: sub-packages ≥ 80%, total ≥ 70%

- [ ] **Step 7: Commit**

```bash
git add android/publisher/publisher.go android/publisher/androidpublisher.go \
  android/publisher/androidpublisher_verify_test.go
git rm android/publisher/androidpublisher_refund_test.go
git commit -m "feat(publisher): refactor Service→Client aggregator, fix Verify OrderID auto-resolution"
```

---

## Task 12: Integration test scaffold

**Files:**
- Create: `android/publisher/integration_test.go`

- [ ] **Step 1: Create integration_test.go**

Create `android/publisher/integration_test.go`:

```go
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
```

- [ ] **Step 2: Verify build tag compiles but doesn't run in normal test**

```bash
go test ./android/publisher/ -v -count=1 2>&1 | grep -i integration
```
Expected: no integration tests appear (build tag excludes them)

```bash
go build -tags=integration ./android/publisher/ 2>&1
```
Expected: compiles without error

- [ ] **Step 3: Commit**

```bash
git add android/publisher/integration_test.go
git commit -m "test(publisher): add integration test scaffold with build tag"
```

---

## Task 13: Update README + CHANGELOG

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md` (create if absent)

- [ ] **Step 1: Update README** — replace the Quick Start and API table sections

Find the Quick Start section in `README.md` and replace the example that calls `NewService`/`VerifyPurchase` with:

```go
// Create a client (uses Application Default Credentials)
client, err := publisher.NewClient(ctx)
if err != nil {
    log.Fatal(err)
}

// Verify a purchase (auto-routes by ProductID/SubscriptionID/OrderID)
result, err := client.Verify(ctx, publisher.VerifyRequest{
    PackageName:   "com.example.app",
    ProductID:     "sword_001",
    PurchaseToken: "purchase-token-from-google-play",
})

// Acknowledge a one-time product (required within 3 days)
err = client.Purchases.Acknowledge(ctx, "com.example.app", "sword_001", "purchase-token")

// Query subscription details (v2 by default)
_, result, err := client.Subscriptions.Query(ctx, subscriptions.SubscriptionQuery{
    PackageName:    "com.example.app",
    SubscriptionID: "monthly_pro",
    PurchaseToken:  "sub-token",
})
// result.V2 contains SubscriptionPurchaseV2

// List in-app products
resp, err := client.InAppProducts.List(ctx, "com.example.app")

// List voided purchases for fraud detection
resp, err := client.VoidedPurchases.List(ctx, "com.example.app",
    voidedpurchases.WithMaxResults(100))
```

Update the API table to reflect the new sub-package structure:

| Sub-package | Methods |
|---|---|
| `client.Purchases` | `Acknowledge`, `Consume`, `Query`, `Refund` |
| `client.Subscriptions` | `Query` (v2/v1), `Refund` |
| `client.Orders` | `Get` |
| `client.InAppProducts` | `List`, `Get`, `Insert`, `Update`, `Delete`, `BatchGet`, `BatchUpdate` |
| `client.VoidedPurchases` | `List` |
| `client` (top-level) | `Verify` (unified routing) |

- [ ] **Step 2: Add CHANGELOG entry**

Append to `CHANGELOG.md` (create file if absent):

```markdown
## v0.0.4 — 2026-04-17

### Breaking Changes

- `publisher.Service` renamed to `publisher.Client`
- `NewService` / `NewServiceWithTokenSource` / `NewServiceWithKey` replaced by `NewClient` / `NewClientWithTokenSource` / `NewClientWithKey`
- `ErrNotFound` removed from `publisher` package
- `NewClient(config)` now requires `ctx context.Context` as first argument
- `StartSubscriptionMonitor` now requires `ctx context.Context` and `errCh chan<- error` parameters
- Sub-package import paths: `publisher/purchases`, `publisher/subscriptions`, `publisher/orders`, `publisher/inappproducts`, `publisher/voidedpurchases`

### New Features

- `purchases.Acknowledge` — acknowledge one-time product purchases (required within 3 days)
- `purchases.Consume` — consume consumable in-app products
- `subscriptions.Query` — defaults to Subscriptions v2 API; opt into v1 via `UseV1: true`
- `inappproducts` sub-package — full CRUD + `BatchGet` / `BatchUpdate`
- `voidedpurchases` sub-package — list voided purchases for fraud detection
- `client.Verify` with `OrderID`-only now auto-resolves product type via Orders API

### Bug Fixes

- `NewClientWithTokenSource` no longer silently discards service constructor errors
- Legacy `VerifyPurchase` / `VerifySubscriptions` now accept and propagate `context.Context`
- `StartSubscriptionMonitor` no longer calls `log.Fatalf`; errors returned via channel
- Fixed misleading `AcknowledgementState` comment (was describing `PurchaseState` semantics)
- Fixed `close` built-in shadowing in test helpers
```

- [ ] **Step 3: Run full test suite one last time**

```bash
go test ./... -count=1 2>&1 | tail -20
```
Expected: all PASS, no compile errors

- [ ] **Step 4: Commit**

```bash
git add README.md CHANGELOG.md
git commit -m "docs: update README and CHANGELOG for v0.0.4 sub-package architecture"
```

---

## Self-Review Checklist

| Spec requirement | Task |
|---|---|
| Fix `NewServiceWithTokenSource` silent error | Task 2 |
| Fix `Verify(OrderID-only)` → ErrRouteUnknown | Task 11 |
| Add context to legacy methods | Task 5 |
| Fix AcknowledgementState comment | Task 5 |
| Fix `client.go` context.Background() | Task 3 |
| Remove `ErrNotFound` | Task 1 |
| Fix test coverage gaps | Tasks 2, 5, 11 |
| Fix `assertMixedInputRejected` message | Task 1 |
| Fix `close` shadowing | Task 1 |
| Fix `log.Fatalf` in RTDN | Task 4 |
| `purchases.Acknowledge` + `Consume` | Task 7 |
| `subscriptions.Query` v2 default, v1 opt-in | Task 8 |
| `orders.Get` for OrderID auto-resolution | Task 6 |
| `inappproducts` full CRUD + batch | Task 9 |
| `voidedpurchases.List` | Task 10 |
| `Client` aggregator with `Verify()` | Task 11 |
| Integration test scaffold | Task 12 |
| README + CHANGELOG | Task 13 |
