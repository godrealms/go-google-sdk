# Publisher Full API Design

**Date:** 2026-04-17  
**Scope:** Bug fixes + full Google Play Publisher API surface  
**Status:** Approved

---

## Background

The `android/publisher` package currently provides a unified `Verify()` entry point and basic refund methods. A code review identified two critical bugs and seven important issues, plus seven missing API capabilities. This spec covers fixing all issues and extending the SDK to a complete sub-package architecture.

---

## Architecture

### Package Structure

```
android/publisher/
├── publisher.go              # Client struct (aggregator) + constructors (bug fixes)
├── config.go                 # Unchanged
├── errors.go                 # Consolidated errors, remove unused ErrNotFound
├── types.go                  # Shared: VerifyRequest, VerifyResult, VerifyType
├── RTDN-Listener.go          # Fix: log.Fatalf → error channel/callback
├── client.go                 # Fix: context.Background() → accept ctx parameter
│
├── purchases/
│   ├── service.go            # Acknowledge, Consume, Query, Refund, VerifyPurchase(deprecated)
│   ├── types.go              # PurchaseQuery, AcknowledgeRequest
│   └── service_test.go
│
├── subscriptions/
│   ├── service.go            # Query (v2 default, v1 opt-in), Refund, VerifySubscriptions(deprecated)
│   ├── types.go              # SubscriptionQuery (UseV1 field), SubscriptionResult
│   └── service_test.go
│
├── orders/
│   ├── service.go            # Get — used by Verify() for OrderID auto-resolution
│   ├── types.go
│   └── service_test.go
│
├── inappproducts/
│   ├── service.go            # List, Get, Insert, Update, Delete, BatchGet, BatchUpdate
│   ├── types.go              # ListOption
│   └── service_test.go
│
├── voidedpurchases/
│   ├── service.go            # List
│   ├── types.go              # ListOption (StartTime, EndTime, MaxResults, Token, Type)
│   └── service_test.go
│
└── integration_test.go       # //go:build integration
```

### Top-Level Client (Aggregator)

`publisher.Service` is renamed to `publisher.Client`. It holds references to all sub-services and owns the cross-cutting `Verify()` routing logic.

```go
type Client struct {
    Purchases       *purchases.Service
    Subscriptions   *subscriptions.Service
    Orders          *orders.Service
    InAppProducts   *inappproducts.Service
    VoidedPurchases *voidedpurchases.Service
    raw             *androidpublisher.Service
}

func NewClient(ctx context.Context, cfg Config) (*Client, error)
func NewClientWithTokenSource(ctx context.Context, cfg Config, token *oauth2.Token) (*Client, error)
func NewClientWithKey(ctx context.Context, cfg Config, key []byte) (*Client, error)

func (c *Client) Verify(ctx context.Context, req VerifyRequest) (*VerifyResult, error)
```

---

## Bug Fixes

### Critical

**1. `NewServiceWithTokenSource` silently swallows constructor error**
- File: `android/publisher/androidpublisher.go:232`
- Fix: Add `if err != nil { return nil, err }` after `androidpublisher.NewService()` call.

**2. `Verify(OrderID-only)` always returns `ErrRouteUnknown`**
- File: `android/publisher/androidpublisher.go:103`
- Fix: When only `OrderID` is provided, call `orders.Get()` → inspect `LineItems[0].ProductType` → auto-route to purchases or subscriptions.

### Important

**3. Legacy methods skip `context.Context`**
- `VerifyPurchase` and `VerifySubscriptions` call `.Do()` without context.
- Fix: Pass `ctx` through to all API calls. Mark both methods `// Deprecated:` in godoc.

**4. Misleading comment on `AcknowledgementState` check**
- File: `android/publisher/androidpublisher.go:168`
- Fix: Correct comment to "0 = not acknowledged, 1 = acknowledged".

**5. `client.go` hardcodes `context.Background()`**
- Fix: Add `ctx context.Context` as first parameter to `NewClient()`.

**6. `ErrNotFound` declared but never used**
- Fix: Remove from `errors.go`. Document as Breaking Change in CHANGELOG.

**7. Test coverage gaps**
- `VerifyPurchase`, `VerifySubscriptions`, all constructors at 0%.
- Fix: Add tests for constructor error paths, deprecated legacy methods, and `Verify(OrderID-only)` → `ErrRouteUnknown` case.

**8. `assertMixedInputRejected` prints confusing nil message**
- File: `android/publisher/androidpublisher_verify_test.go:235`
- Fix: Correct format string to clearly indicate the helper misuse.

**9. `close` shadows built-in in test helper**
- Fix: Rename to `closeFunc` or `shutdown`.

**10. `log.Fatalf` in `StartSubscriptionMonitor`**
- File: `RTDN-Listener.go:135`
- Fix: Return error via `errCh chan error` parameter so callers control lifecycle.

---

## API Surface — Sub-Packages

### purchases.Service

```go
// New
func (s *Service) Acknowledge(ctx context.Context, packageName, productID, purchaseToken string) error
func (s *Service) Consume(ctx context.Context, packageName, productID, purchaseToken string) error

// Migrated (signatures unchanged)
func (s *Service) Query(ctx context.Context, q PurchaseQuery) (*androidpublisher.Order, *androidpublisher.ProductPurchase, error)
func (s *Service) Refund(ctx context.Context, packageName, orderID string) error

// Deprecated
func (s *Service) VerifyPurchase(ctx context.Context, packageName, productID, purchaseToken string) (*androidpublisher.ProductPurchase, error)
```

### subscriptions.Service

```go
// v2 default, v1 opt-in via UseV1 field
type SubscriptionQuery struct {
    PackageName    string
    SubscriptionID string
    PurchaseToken  string
    OrderID        string
    UseV1          bool
}

type SubscriptionResult struct {
    V1 *androidpublisher.SubscriptionPurchase           // non-nil when UseV1=true
    V2 *androidpublisher.SubscriptionPurchaseV2         // non-nil by default
}

func (s *Service) Query(ctx context.Context, q SubscriptionQuery) (*androidpublisher.Order, *SubscriptionResult, error)
func (s *Service) Refund(ctx context.Context, packageName, subscriptionID, purchaseToken string) error

// Deprecated
func (s *Service) VerifySubscriptions(ctx context.Context, packageName, subscriptionID, purchaseToken string) (bool, error)
```

### orders.Service

```go
func (s *Service) Get(ctx context.Context, packageName, orderID string) (*androidpublisher.Order, error)
```

### inappproducts.Service

```go
type ListOption func(*androidpublisher.InappproductsListCall)

func (s *Service) List(ctx context.Context, packageName string, opts ...ListOption) (*androidpublisher.InappproductsListResponse, error)
func (s *Service) Get(ctx context.Context, packageName, sku string) (*androidpublisher.InAppProduct, error)
func (s *Service) Insert(ctx context.Context, packageName string, product *androidpublisher.InAppProduct) (*androidpublisher.InAppProduct, error)
func (s *Service) Update(ctx context.Context, packageName, sku string, product *androidpublisher.InAppProduct) (*androidpublisher.InAppProduct, error)
func (s *Service) Delete(ctx context.Context, packageName, sku string) error
func (s *Service) BatchGet(ctx context.Context, packageName string, skus []string) (*androidpublisher.InappproductsBatchGetResponse, error)
func (s *Service) BatchUpdate(ctx context.Context, packageName string, req *androidpublisher.InappproductsBatchUpdateRequest) (*androidpublisher.InappproductsBatchUpdateResponse, error)
```

### voidedpurchases.Service

```go
type ListOption func(*androidpublisher.VoidedpurchasesListCall)

func WithStartTime(t time.Time) ListOption
func WithEndTime(t time.Time) ListOption
func WithMaxResults(n int64) ListOption
func WithPageToken(token string) ListOption
func WithType(purchaseType int64) ListOption

func (s *Service) List(ctx context.Context, packageName string, opts ...ListOption) (*androidpublisher.VoidedPurchasesListResponse, error)
```

---

## Verify() Routing Logic

```
Input: VerifyRequest{PackageName, ProductID, SubscriptionID, PurchaseToken, OrderID, Type}

OrderID only (no Type, no Token):
  → orders.Get(packageName, orderID)
  → LineItems[0].ProductType == "TYPE_IN_APP_PRODUCT"  → purchases.Query(OrderID)
  → LineItems[0].ProductType == "TYPE_SUBSCRIPTION"    → subscriptions.Query(OrderID)
  → unknown type → ErrRouteUnknown

Type=product + PurchaseToken:
  → purchases.Query(PurchaseToken + ProductID)

Type=subscription + PurchaseToken:
  → subscriptions.Query(PurchaseToken + SubscriptionID)

Type="" + PurchaseToken + ProductID:
  → purchases.Query(token)

Type="" + PurchaseToken + SubscriptionID:
  → subscriptions.Query(token)

No distinguishing fields → ErrRouteUnknown
```

---

## Error Handling

### Consolidated errors.go

```go
var (
    ErrRouteUnknown                = errors.New("publisher: cannot determine verification type")
    ErrMissingPackageName          = errors.New("publisher: package name is required")
    ErrMissingPurchaseToken        = errors.New("publisher: purchase token is required")
    ErrMissingProductID            = errors.New("publisher: product ID is required")
    ErrMissingSubscriptionID       = errors.New("publisher: subscription ID is required")
    ErrMissingOrderID              = errors.New("publisher: order ID is required")
    ErrMixedOrderProductInput      = errors.New("publisher: order ID and product ID are mutually exclusive")
    ErrMixedOrderSubscriptionInput = errors.New("publisher: order ID and subscription ID are mutually exclusive")
    // ErrNotFound removed — Breaking Change, documented in CHANGELOG
)
```

### RTDN Listener

`StartSubscriptionMonitor` signature changes to accept `errCh chan<- error` instead of calling `log.Fatalf`. Callers decide whether to restart, log, or exit.

---

## Testing

### Unit Tests (per sub-package)

Each sub-package has `service_test.go` using `httptest.Server` with a `newTest<Resource>Service()` helper. Coverage targets:
- New sub-packages: ≥ 80%
- `publisher.go` (constructor paths): ≥ 70%

Every test file covers:
- Happy path (HTTP 200)
- Input validation (no network calls, sentinel errors)
- API error propagation (HTTP 4xx/5xx)

Constructor error paths (`NewClientWithTokenSource`, `NewClientWithKey`) get explicit tests for the swallowed-error bug fix.

### Integration Tests

```go
//go:build integration

// Reads: GOOGLE_APPLICATION_CREDENTIALS, TEST_PACKAGE_NAME env vars
// At least one List/Get smoke test per sub-service
// Run with: go test -tags=integration ./android/publisher/...
```

---

## Breaking Changes (CHANGELOG)

| Change | Type | Migration |
|---|---|---|
| `publisher.Service` → `publisher.Client` | Rename | Replace all usages |
| `ErrNotFound` removed | Deletion | Remove callers |
| `NewClient(ctx, cfg)` signature | New param | Add `ctx` |
| `StartSubscriptionMonitor` signature | New param | Add `errCh` |
| Sub-package import paths | New | `publisher/purchases`, etc. |

---

## Implementation Order

1. Fix Critical bugs in `androidpublisher.go`
2. Fix Important bugs (context, comments, errors, tests)
3. Create `orders/` sub-package (needed by Verify routing)
4. Create `purchases/` sub-package (Acknowledge, Consume)
5. Create `subscriptions/` sub-package (v2 default)
6. Create `inappproducts/` sub-package (full CRUD + batch)
7. Create `voidedpurchases/` sub-package
8. Refactor top-level `publisher.go` → `publisher.Client` aggregator
9. Add integration test scaffold
10. Update README + CHANGELOG
