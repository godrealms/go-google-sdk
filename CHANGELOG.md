# Changelog / 变更日志

## v0.0.7 — 2026-04-17

### Breaking Changes

- `payment` module rewritten to match Google Pay's Payment Method Token specification. Tokens produced against the old SDK will not decrypt.
  - `EncryptedToken` wire format: `signature` is a top-level field; `signedMessage` is a JSON-encoded string; new `IntermediateSigningKey` block for the ECv2 signing chain.
  - Signature data construction uses `toLengthValue` (4-byte little-endian length prefix) over `"Google" || merchant:<id> || <protocol> || signedMessage`.
  - Key derivation switched to HKDF-SHA256 (`golang.org/x/crypto/hkdf`, `info="Google"`, 64-byte output).
  - Symmetric decryption switched from CBC+PKCS7 to AES-256-CTR with a zero IV.
  - Root keys JSON parser honours `keyExpiration` (ms since epoch) and drops expired keys.
  - `CardDetails.ExpirationMonth` / `ExpirationYear` changed from `string` to `int`.

### New Features

- `Client.DecryptToken` — preferred alias for `DecryptPaymentToken`
- `payment.Sandbox` / `payment.Production` — short environment aliases
- `KeyManager.AllRootKeys` / `KeyManager.RootKeysForProtocol` — protocol-aware root-key snapshots for ECv2 verification
- Client cache now re-validates `ExpiresAt` on hits, so a long `CacheTTL` can no longer return a stale token
- `DecryptToken` requires a non-empty `messageExpiration`; `IntermediateSignedKey.keyExpiration` must be present

## v0.0.6 — 2026-04-17

### New Features

- New `reviews` sub-package — user reviews (`Get` / `List` / `Reply`)
- New `access/users` and `access/grants` sub-packages — Play Console user and permission management
- New `externaltransactions` sub-package — external transactions (`Create` / `Get` / `Refund`)
- New `applications` sub-package — `DataSafety`, `DeviceTierConfigs` CRUD, cross-track `ListTrackReleases`
- New `apprecovery` sub-package — `AddTargeting` / `Cancel` / `Create` / `Deploy` / `List`
- New `generatedapks`, `systemapks`, `internalappsharing` distribution sub-packages (Download / Upload / CRUD)
- New `edits` sub-package — full `edits` lifecycle (`Commit` / `Delete` / `Get` / `Insert` / `Validate`) plus every nested resource (`apks`, `bundles`, `countryAvailability`, `deobfuscationFiles`, `details`, `expansionFiles`, `images`, `listings`, `testers`, `tracks`)
- `subscriptions.CancelV2` and `subscriptions.DeferV2`
- Top-level `Client` wired with the new sub-service fields

## v0.0.5 — 2026-04-17

### New Features

- `purchases.GetV2` — product purchase lookup via the `productsv2` endpoint (token-only; no productID in path)
- `subscriptions.Acknowledge` / `Cancel` / `Defer` / `Revoke` — full lifecycle management for v1 subscription purchases
- `subscriptions.RevokeV2` — revoke via the `subscriptionsv2` endpoint
- `orders.Refund` gains a `revoke bool` parameter; `orders.BatchGet` for multi-order retrieval
- `inappproducts.BatchDelete` for bulk catalog deletion
- New `monetization/onetimeproducts` sub-package — full CRUD for one-time products plus `purchaseOptions` and `purchaseOptions.offers` sub-resources (Activate/Cancel/Deactivate/List/Batch*)
- New `monetization/subscriptions` sub-package — full Subscription CRUD (Create/Get/List/Patch/Delete/Archive), `basePlans` (Activate/Deactivate/Delete/MigratePrices/Batch*), `basePlans.offers` (full CRUD + Activate/Deactivate/Batch*), and `ConvertRegionPrices` pricing endpoint
- `Client.OneTimeProducts` and `Client.MonetizationSubscriptions` wired into the top-level aggregator

### Dependencies

- Upgraded `google.golang.org/api` from v0.243.0 to v0.276.0 (Go toolchain bumped to 1.25.0 as required)

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
