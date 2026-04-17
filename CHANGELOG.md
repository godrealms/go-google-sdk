# Changelog / 变更日志

## v0.0.4 — 2026-04-17

### Breaking Changes

- `publisher.Service` renamed to `publisher.Client`
- `NewService` / `NewServiceWithTokenSource` / `NewServiceWithKey` replaced by `NewClient` / `NewClientWithTokenSource` / `NewClientWithKey`
- `ErrNotFound` removed from `publisher` package
- `NewClient` now requires `ctx context.Context` as first argument
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

## v0.0.3

- Added order-level and token-level purchase/subscription query: `QueryPurchase`, `QuerySubscription`
- Enhanced mixed-input validation (order ID + token combinations) and test coverage

## v0.0.2

- 中文：新增 Android Publisher 退款能力：`RefundPurchase` 与 `RefundSubscription`，并补充完整的参数校验、成功/失败及请求校验测试；更新 `README` API 文档。
- English: Added Android Publisher refund support with `RefundPurchase` and `RefundSubscription`, including input validation, success/failure, and request-path/method tests, and updated `README` API docs.

## v0.0.1

- 中文：新增 RTDN、购买验证、秘钥与支付相关能力，见对应发布说明。
- English: Added RTDN handling and expanded in-app purchase/keys/payment capabilities (see release notes).
