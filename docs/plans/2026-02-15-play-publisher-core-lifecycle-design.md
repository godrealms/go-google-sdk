# Play Publisher Core Lifecycle Design

Date: 2026-02-15
Owner: sdk
Status: Draft

## Goal

Add core Google Play Publisher lifecycle APIs that cover common operational flows while keeping the surface area minimal and consistent with existing refund/verify methods.

## Scope

- Acknowledge one-time purchases
- Consume one-time purchases
- Cancel subscriptions
- Revoke subscriptions
- List voided purchases

Out of scope:

- Subscriptions v2 endpoints
- Large response model abstractions beyond the upstream client types

## API Design

New methods on the Publisher service:

- `AcknowledgePurchase(ctx, packageName, productId, purchaseToken string) error`
- `ConsumePurchase(ctx, packageName, productId, purchaseToken string) error`
- `CancelSubscription(ctx, packageName, subscriptionId, purchaseToken string) error`
- `RevokeSubscription(ctx, packageName, subscriptionId, purchaseToken string) error`
- `ListVoidedPurchases(ctx, packageName string, opts *VoidedPurchaseOptions) (*androidpublisher.VoidedPurchasesListResponse, error)`

New options struct for list query parameters:

```go
type VoidedPurchaseOptions struct {
    StartTimeMillis int64
    EndTimeMillis   int64
    Token           string
    MaxResults      int64
    Type            int64
}
```

## Behavior

- Validate receiver and required arguments before calling the API.
- Use `.Context(ctx).Do()` for all calls.
- Wrap errors with context matching existing refund helpers.
- For `ListVoidedPurchases`, only set optional query params when non-zero or non-empty.

## Testing

- Add unit tests mirroring existing refund tests.
- Validate argument errors for empty/invalid inputs.
- Verify request method/path for each endpoint.
- Cover successful and failure responses for each API.

## Compatibility

- Keep signatures consistent with existing naming patterns.
- Avoid breaking changes to existing methods.
- Upstream response types remain unchanged.

## Rollout

- Update README API reference to include new methods.
- Add changelog entry when implementation is completed.
