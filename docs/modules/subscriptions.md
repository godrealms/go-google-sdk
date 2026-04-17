# subscriptions — 订阅购买查询与生命周期管理

封装 `purchases.subscriptions`（v1）与 `purchases.subscriptionsv2`（v2）资源，覆盖订阅的查询、确认、取消、延期、撤销与退款。

- 所需 Scope: `https://www.googleapis.com/auth/androidpublisher`
- Go 包路径: `github.com/godrealms/go-google-sdk/android/publisher/subscriptions`

## 快速示例

```go
result, err := client.Subscriptions.Query(ctx, subscriptions.SubscriptionQuery{
    PackageName:    "com.example.app",
    SubscriptionID: "monthly_pro",
    PurchaseToken:  token,
})
if err != nil {
    log.Fatal(err)
}
// 默认走 v2
log.Printf("state=%s", result.V2.SubscriptionState)
```

## Query

订阅查询，默认使用 v2；`UseV1: true` 回退到 v1。

```go
func (s *Service) Query(ctx context.Context, q SubscriptionQuery) (*SubscriptionResult, error)
```

`SubscriptionResult` 根据调用分支填充 `V1` 或 `V2`：

| 分支 | REST 端点 | 返回字段 |
|---|---|---|
| 默认 v2 | `GET /androidpublisher/v3/applications/{packageName}/purchases/subscriptionsv2/tokens/{token}` | `V2 *SubscriptionPurchaseV2` |
| `UseV1=true` | `GET /androidpublisher/v3/applications/{packageName}/purchases/subscriptions/{subscriptionId}/tokens/{token}` | `V1 *SubscriptionPurchase` |

```go
// v1 路径
v1Res, err := client.Subscriptions.Query(ctx, subscriptions.SubscriptionQuery{
    PackageName:    "com.example.app",
    SubscriptionID: "monthly_pro",
    PurchaseToken:  token,
    UseV1:          true,
})
```

> v2 不需要 `SubscriptionID`，v1 必填。

## Acknowledge

确认订阅购买。

```go
func (s *Service) Acknowledge(ctx context.Context, packageName, subscriptionID, purchaseToken string) error
```

REST: `POST /androidpublisher/v3/applications/{packageName}/purchases/subscriptions/{subscriptionId}/tokens/{token}:acknowledge`

```go
_ = client.Subscriptions.Acknowledge(ctx, "com.example.app", "monthly_pro", token)
```

## Cancel

取消订阅（v1）。

```go
func (s *Service) Cancel(ctx context.Context, packageName, subscriptionID, purchaseToken string) error
```

REST: `POST /androidpublisher/v3/applications/{packageName}/purchases/subscriptions/{subscriptionId}/tokens/{token}:cancel`

## CancelV2

v2 取消，接受请求体（支持取消原因等字段）。

```go
func (s *Service) CancelV2(ctx context.Context, packageName, purchaseToken string, req *androidpublisher.CancelSubscriptionPurchaseRequest) (*androidpublisher.CancelSubscriptionPurchaseResponse, error)
```

REST: `POST /androidpublisher/v3/applications/{packageName}/purchases/subscriptionsv2/tokens/{token}:cancel`

```go
resp, err := client.Subscriptions.CancelV2(ctx, "com.example.app", token,
    &androidpublisher.CancelSubscriptionPurchaseRequest{/* ... */})
```

## Defer

推迟下一次续订（v1）。

```go
func (s *Service) Defer(ctx context.Context, packageName, subscriptionID, purchaseToken string, req *androidpublisher.SubscriptionPurchasesDeferRequest) (*androidpublisher.SubscriptionPurchasesDeferResponse, error)
```

REST: `POST /androidpublisher/v3/applications/{packageName}/purchases/subscriptions/{subscriptionId}/tokens/{token}:defer`

## DeferV2

v2 延期。

```go
func (s *Service) DeferV2(ctx context.Context, packageName, purchaseToken string, req *androidpublisher.DeferSubscriptionPurchaseRequest) (*androidpublisher.DeferSubscriptionPurchaseResponse, error)
```

REST: `POST /androidpublisher/v3/applications/{packageName}/purchases/subscriptionsv2/tokens/{token}:defer`

## Revoke

立即撤销订阅（v1，不等到期）。

```go
func (s *Service) Revoke(ctx context.Context, packageName, subscriptionID, purchaseToken string) error
```

REST: `POST /androidpublisher/v3/applications/{packageName}/purchases/subscriptions/{subscriptionId}/tokens/{token}:revoke`

## RevokeV2

v2 撤销，支持按比例退款等高级字段。

```go
func (s *Service) RevokeV2(ctx context.Context, packageName, purchaseToken string, req *androidpublisher.RevokeSubscriptionPurchaseRequest) error
```

REST: `POST /androidpublisher/v3/applications/{packageName}/purchases/subscriptionsv2/tokens/{token}:revoke`

## Refund

只退款但保留订阅（用户仍享有订阅权益至到期日）。

```go
func (s *Service) Refund(ctx context.Context, packageName, subscriptionID, purchaseToken string) error
```

REST: `POST /androidpublisher/v3/applications/{packageName}/purchases/subscriptions/{subscriptionId}/tokens/{token}:refund`

## 备注

- `VerifySubscriptions` 已弃用（对未确认的新订阅会误报为无效）。
- 新集成推荐全部使用 v2 接口。
