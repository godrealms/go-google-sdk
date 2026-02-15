# Publisher Unified Verify Query Task 2 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Complete Task 2 by adding subscription order/token query tests and mixed-input validation for purchase/subscription queries.

**Architecture:** Keep query methods on `publisher.Service` and return `(order, nil)` for order lookups or `(nil, purchase)` for token lookups. Add explicit mixed-input validation to both query methods and expand tests to cover subscription order/token paths and mixed-input errors.

**Tech Stack:** Go, `google.golang.org/api/androidpublisher/v3`, Go testing, `httptest`.

---

### Task 1: Add failing tests for mixed-input validation

**Files:**
- Modify: `android/publisher/androidpublisher_verify_test.go`

**Step 1: Write the failing tests**

```go
func TestQueryPurchaseRejectsMixedInputs(t *testing.T) {
	t.Parallel()

	service, closeServer := newTestPublisherService(t, "/unused", http.MethodGet, http.StatusOK, `{}`)
	defer closeServer()

	_, _, err := service.QueryPurchase(context.Background(), PurchaseQuery{
		PackageName:   "com.example.app",
		OrderID:       "order-123",
		ProductID:     "product-123",
		PurchaseToken: "token-123",
	})
	if err == nil {
		t.Fatalf("expected error for mixed order and token inputs")
	}
}

func TestQuerySubscriptionRejectsMixedInputs(t *testing.T) {
	t.Parallel()

	service, closeServer := newTestPublisherService(t, "/unused", http.MethodGet, http.StatusOK, `{}`)
	defer closeServer()

	_, _, err := service.QuerySubscription(context.Background(), SubscriptionQuery{
		PackageName:    "com.example.app",
		OrderID:        "order-123",
		SubscriptionID: "sub-123",
		PurchaseToken:  "token-123",
	})
	if err == nil {
		t.Fatalf("expected error for mixed order and token inputs")
	}
}
```

**Step 2: Run tests to verify failure**

Run: `go test ./android/publisher -run TestQueryPurchaseRejectsMixedInputs -v`

Expected: FAIL with missing mixed-input validation.

---

### Task 2: Add failing tests for subscription order/token query paths

**Files:**
- Modify: `android/publisher/androidpublisher_verify_test.go`

**Step 1: Write the failing tests**

```go
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
```

**Step 2: Run tests to verify failure**

Run: `go test ./android/publisher -run TestQuerySubscriptionByOrderIDUsesOrdersEndpoint -v`

Expected: FAIL if subscription queries are missing or incorrect.

---

### Task 3: Implement mixed-input validation in query methods

**Files:**
- Modify: `android/publisher/androidpublisher.go`

**Step 1: Add minimal validation logic**

```go
if q.OrderID != "" && (q.ProductID != "" || q.PurchaseToken != "") {
	return nil, nil, errors.New("orderID cannot be combined with productID or purchaseToken")
}
```

and for subscriptions:

```go
if q.OrderID != "" && (q.SubscriptionID != "" || q.PurchaseToken != "") {
	return nil, nil, errors.New("orderID cannot be combined with subscriptionID or purchaseToken")
}
```

**Step 2: Run tests to verify mixed-input tests pass**

Run: `go test ./android/publisher -run TestQueryPurchaseRejectsMixedInputs -v`

Expected: PASS

---

### Task 4: Run package tests

**Files:**
- Test: `android/publisher/androidpublisher_verify_test.go`

**Step 1: Run package tests**

Run: `go test ./android/publisher -v`

Expected: PASS

---

### Task 5: Commit changes

**Files:**
- `android/publisher/androidpublisher.go`
- `android/publisher/androidpublisher_verify_test.go`

**Step 1: Commit**

```bash
git add android/publisher/androidpublisher.go android/publisher/androidpublisher_verify_test.go
git commit -m "feat(publisher): validate mixed inputs and cover subscription queries"
```
