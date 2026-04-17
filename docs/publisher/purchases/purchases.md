# purchases — 一次性内购查询与生命周期管理

封装 `androidpublisher.Purchases.Products`（v1）与 `Purchases.Productsv2`（v2）REST 资源，用于查询、确认、消费和退款一次性内购。

- 官方资源: `purchases.products`, `purchases.productsv2`
- 所需 Scope: `https://www.googleapis.com/auth/androidpublisher`
- Go 包路径: `github.com/godrealms/go-google-sdk/android/publisher/purchases`

## 快速示例

```go
client, err := publisher.NewClient(ctx)
if err != nil {
    log.Fatal(err)
}

purchase, err := client.Purchases.Query(ctx, purchases.PurchaseQuery{
    PackageName:   "com.example.app",
    ProductID:     "sword_001",
    PurchaseToken: "purchase-token-from-google-play",
})
if err != nil {
    log.Fatal(err)
}
log.Printf("PurchaseState=%d OrderId=%s", purchase.PurchaseState, purchase.OrderId)
```

## Query

查询一次性内购详情（v1 接口）。

```go
func (s *Service) Query(ctx context.Context, q PurchaseQuery) (*androidpublisher.ProductPurchase, error)
```

参数 `PurchaseQuery` 必须同时提供 `PackageName`、`ProductID`、`PurchaseToken`。

```go
purchase, err := client.Purchases.Query(ctx, purchases.PurchaseQuery{
    PackageName:   "com.example.app",
    ProductID:     "gem_pack_100",
    PurchaseToken: token,
})
```

REST: `GET /androidpublisher/v3/applications/{packageName}/purchases/products/{productId}/tokens/{token}`

## GetV2

v2 接口仅需 token，无需 ProductID（Google 会从 token 解析商品）。返回 `ProductPurchaseV2`，字段更丰富。

```go
func (s *Service) GetV2(ctx context.Context, packageName, purchaseToken string) (*androidpublisher.ProductPurchaseV2, error)
```

```go
v2, err := client.Purchases.GetV2(ctx, "com.example.app", token)
```

REST: `GET /androidpublisher/v3/applications/{packageName}/purchases/productsv2/tokens/{token}`

## Acknowledge

确认一次性内购。Google 要求购买必须在 3 天内确认，否则会自动退款。

```go
func (s *Service) Acknowledge(ctx context.Context, packageName, productID, purchaseToken string) error
```

```go
if err := client.Purchases.Acknowledge(ctx, "com.example.app", "sword_001", token); err != nil {
    log.Fatal(err)
}
```

REST: `POST /androidpublisher/v3/applications/{packageName}/purchases/products/{productId}/tokens/{token}:acknowledge`

## Consume

将消耗型商品标记为已消耗，使玩家可以再次购买。

```go
func (s *Service) Consume(ctx context.Context, packageName, productID, purchaseToken string) error
```

```go
_ = client.Purchases.Consume(ctx, "com.example.app", "gem_pack_100", token)
```

REST: `POST /androidpublisher/v3/applications/{packageName}/purchases/products/{productId}/tokens/{token}:consume`

## Refund

退还一次性订单（底层走 Orders.Refund）。

```go
func (s *Service) Refund(ctx context.Context, packageName, orderID string) error
```

```go
_ = client.Purchases.Refund(ctx, "com.example.app", "GPA.1234-5678-9012-34567")
```

REST: `POST /androidpublisher/v3/applications/{packageName}/orders/{orderId}:refund`

## 备注

- `VerifyPurchase` 已弃用，请改用顶层 `client.Verify` 或本包 `Query`。
- v2 相比 v1 的优势：不依赖 ProductID，且返回的 `PurchaseStateContext` 结构可区分主账号 / 家庭共享等场景。
