# monetization/subscriptions — 订阅商品目录与 basePlans / offers

封装 `monetization.subscriptions` 资源：订阅商品 CRUD + Archive、`basePlans` 基础套餐、`basePlans.offers` 优惠，以及 `convertRegionPrices` 定价换算。

- Go 包路径（别名 `monetizationsubs`）: `github.com/godrealms/go-google-sdk/android/publisher/monetization/subscriptions`
- Scope: `https://www.googleapis.com/auth/androidpublisher`

> 注意：与 `client.Subscriptions`（查询已购买订阅）不同，这里管理的是开发者后台 SKU 目录。

结构：`client.MonetizationSubscriptions` → `.BasePlans` → `.Offers`。

## 快速示例

```go
sub, err := client.MonetizationSubscriptions.Get(ctx, "com.example.app", "monthly_pro")
```

## Get / List / Create / Patch / Delete / Archive

```go
func (s *Service) Get(ctx, packageName, productID) (*androidpublisher.Subscription, error)
func (s *Service) List(ctx, packageName, ListOptions{PageSize, PageToken, ShowArchived}) (*androidpublisher.ListSubscriptionsResponse, error)
func (s *Service) Create(ctx, packageName, productID, sub *androidpublisher.Subscription, CreateOptions{RegionsVersion}) (*androidpublisher.Subscription, error)
func (s *Service) Patch(ctx, packageName, productID, sub *androidpublisher.Subscription, PatchOptions{UpdateMask, AllowMissing, LatencyTolerance, RegionsVersion}) (*androidpublisher.Subscription, error)
func (s *Service) Delete(ctx, packageName, productID, DeleteOptions) error
func (s *Service) Archive(ctx, packageName, productID, req *androidpublisher.ArchiveSubscriptionRequest) (*androidpublisher.Subscription, error)
```

```go
newSub, err := client.MonetizationSubscriptions.Create(ctx, "com.example.app", "monthly_pro",
    &androidpublisher.Subscription{/* ... */},
    monetizationsubs.CreateOptions{RegionsVersion: "2022/02"})
```

REST:
- `GET /androidpublisher/v3/applications/{packageName}/subscriptions/{productId}`
- `GET /androidpublisher/v3/applications/{packageName}/subscriptions`
- `POST /androidpublisher/v3/applications/{packageName}/subscriptions`
- `PATCH /androidpublisher/v3/applications/{packageName}/subscriptions/{productId}`
- `DELETE /androidpublisher/v3/applications/{packageName}/subscriptions/{productId}`
- `POST /androidpublisher/v3/applications/{packageName}/subscriptions/{productId}:archive`

## BatchGet / BatchUpdate

```go
func (s *Service) BatchGet(ctx, packageName, productIDs []string) (*androidpublisher.BatchGetSubscriptionsResponse, error)
func (s *Service) BatchUpdate(ctx, packageName, req *androidpublisher.BatchUpdateSubscriptionsRequest) (*androidpublisher.BatchUpdateSubscriptionsResponse, error)
```

REST: `.../subscriptions:batchGet`, `.../subscriptions:batchUpdate`

## ConvertRegionPrices

根据基准价计算多地区本地化价格。

```go
func (s *Service) ConvertRegionPrices(ctx, packageName, req *androidpublisher.ConvertRegionPricesRequest) (*androidpublisher.ConvertRegionPricesResponse, error)
```

REST: `POST /androidpublisher/v3/applications/{packageName}/pricing:convertRegionPrices`

## BasePlans

子资源 `client.MonetizationSubscriptions.BasePlans`：

```go
func (b *BasePlansService) Activate(ctx, packageName, productID, basePlanID string, req *androidpublisher.ActivateBasePlanRequest) (*androidpublisher.Subscription, error)
func (b *BasePlansService) Deactivate(ctx, packageName, productID, basePlanID string, req *androidpublisher.DeactivateBasePlanRequest) (*androidpublisher.Subscription, error)
func (b *BasePlansService) Delete(ctx, packageName, productID, basePlanID string) error
func (b *BasePlansService) MigratePrices(ctx, packageName, productID, basePlanID string, req *androidpublisher.MigrateBasePlanPricesRequest) (*androidpublisher.MigrateBasePlanPricesResponse, error)
func (b *BasePlansService) BatchMigratePrices(ctx, packageName, productID string, req *androidpublisher.BatchMigrateBasePlanPricesRequest) (*androidpublisher.BatchMigrateBasePlanPricesResponse, error)
func (b *BasePlansService) BatchUpdateStates(ctx, packageName, productID string, req *androidpublisher.BatchUpdateBasePlanStatesRequest) (*androidpublisher.BatchUpdateBasePlanStatesResponse, error)
```

```go
_, err := client.MonetizationSubscriptions.BasePlans.Activate(ctx,
    "com.example.app", "monthly_pro", "monthly-basic", nil)
```

REST 根路径：`/androidpublisher/v3/applications/{packageName}/subscriptions/{productId}/basePlans/...`

## BasePlans.Offers

子资源 `client.MonetizationSubscriptions.BasePlans.Offers`：

```go
func (o *OffersService) Get(ctx, packageName, productID, basePlanID, offerID) (*androidpublisher.SubscriptionOffer, error)
func (o *OffersService) List(ctx, packageName, productID, basePlanID, ListOptions) (*androidpublisher.ListSubscriptionOffersResponse, error)
func (o *OffersService) Create(ctx, packageName, productID, basePlanID, offer, CreateOptions) (*androidpublisher.SubscriptionOffer, error)
func (o *OffersService) Patch(ctx, packageName, productID, basePlanID, offerID, offer, PatchOptions) (*androidpublisher.SubscriptionOffer, error)
func (o *OffersService) Delete(ctx, packageName, productID, basePlanID, offerID) error
func (o *OffersService) Activate(ctx, packageName, productID, basePlanID, offerID, req) (*androidpublisher.SubscriptionOffer, error)
func (o *OffersService) Deactivate(ctx, packageName, productID, basePlanID, offerID, req) (*androidpublisher.SubscriptionOffer, error)
func (o *OffersService) BatchGet / BatchUpdate / BatchUpdateStates(ctx, packageName, productID, basePlanID, req) (..., error)
```

REST 根路径：`/androidpublisher/v3/applications/{packageName}/subscriptions/{productId}/basePlans/{basePlanId}/offers/...`
