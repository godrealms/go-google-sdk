# monetization/onetimeproducts — 一次性商品（新版）目录管理

封装 `monetization.onetimeproducts` 资源，覆盖一次性商品 CRUD、`purchaseOptions`、`purchaseOptions.offers` 三层嵌套资源的全量方法。

- Go 包路径: `github.com/godrealms/go-google-sdk/android/publisher/monetization/onetimeproducts`
- Scope: `https://www.googleapis.com/auth/androidpublisher`

结构：`client.OneTimeProducts` → `.PurchaseOptions` → `.Offers`。

## 快速示例

```go
product, err := client.OneTimeProducts.Get(ctx, "com.example.app", "gem_pack_100")
```

## Get / List / Patch / Delete

```go
func (s *Service) Get(ctx context.Context, packageName, productID string) (*androidpublisher.OneTimeProduct, error)
func (s *Service) List(ctx context.Context, packageName string, opts ListOptions) (*androidpublisher.ListOneTimeProductsResponse, error)
func (s *Service) Patch(ctx context.Context, packageName, productID string, product *androidpublisher.OneTimeProduct, opts PatchOptions) (*androidpublisher.OneTimeProduct, error)
func (s *Service) Delete(ctx context.Context, packageName, productID string, opts DeleteOptions) error
```

`ListOptions{PageSize, PageToken}`；`PatchOptions{UpdateMask, AllowMissing, LatencyTolerance, RegionsVersion}`；`DeleteOptions{LatencyTolerance}`。

```go
list, err := client.OneTimeProducts.List(ctx, "com.example.app",
    onetimeproducts.ListOptions{PageSize: 50})

_, err = client.OneTimeProducts.Patch(ctx, "com.example.app", "gem_pack_100",
    &androidpublisher.OneTimeProduct{/* ... */},
    onetimeproducts.PatchOptions{UpdateMask: "title,listings", AllowMissing: true})
```

REST:
- `GET /androidpublisher/v3/applications/{packageName}/onetimeproducts/{productId}`
- `GET /androidpublisher/v3/applications/{packageName}/onetimeproducts`
- `PATCH /androidpublisher/v3/applications/{packageName}/onetimeproducts/{productId}`
- `DELETE /androidpublisher/v3/applications/{packageName}/onetimeproducts/{productId}`

## BatchGet / BatchUpdate / BatchDelete

```go
func (s *Service) BatchGet(ctx context.Context, packageName string, productIDs []string) (*androidpublisher.BatchGetOneTimeProductsResponse, error)
func (s *Service) BatchUpdate(ctx context.Context, packageName string, req *androidpublisher.BatchUpdateOneTimeProductsRequest) (*androidpublisher.BatchUpdateOneTimeProductsResponse, error)
func (s *Service) BatchDelete(ctx context.Context, packageName string, req *androidpublisher.BatchDeleteOneTimeProductsRequest) error
```

REST:
- `GET .../onetimeproducts:batchGet`
- `POST .../onetimeproducts:batchUpdate`
- `POST .../onetimeproducts:batchDelete`

## PurchaseOptions

子资源 `client.OneTimeProducts.PurchaseOptions`：

```go
func (p *PurchaseOptionsService) BatchDelete(ctx context.Context, packageName, productID string, req *androidpublisher.BatchDeletePurchaseOptionsRequest) error
func (p *PurchaseOptionsService) BatchUpdateStates(ctx context.Context, packageName, productID string, req *androidpublisher.BatchUpdatePurchaseOptionStatesRequest) (*androidpublisher.BatchUpdatePurchaseOptionStatesResponse, error)
```

REST:
- `POST .../onetimeproducts/{productId}/purchaseOptions:batchDelete`
- `POST .../onetimeproducts/{productId}/purchaseOptions:batchUpdateStates`

## PurchaseOptions.Offers

子资源 `client.OneTimeProducts.PurchaseOptions.Offers`，涵盖激活、取消、下架、列出与批量操作：

```go
func (o *OffersService) Activate(ctx, packageName, productID, purchaseOptionID, offerID string, req *androidpublisher.ActivateOneTimeProductOfferRequest) (*androidpublisher.OneTimeProductOffer, error)
func (o *OffersService) Cancel(ctx, packageName, productID, purchaseOptionID, offerID string, req *androidpublisher.CancelOneTimeProductOfferRequest) (*androidpublisher.OneTimeProductOffer, error)
func (o *OffersService) Deactivate(ctx, packageName, productID, purchaseOptionID, offerID string, req *androidpublisher.DeactivateOneTimeProductOfferRequest) (*androidpublisher.OneTimeProductOffer, error)
func (o *OffersService) List(ctx, packageName, productID, purchaseOptionID string, opts ListOptions) (*androidpublisher.ListOneTimeProductOffersResponse, error)
func (o *OffersService) BatchGet(ctx, packageName, productID, purchaseOptionID string, req *androidpublisher.BatchGetOneTimeProductOffersRequest) (*androidpublisher.BatchGetOneTimeProductOffersResponse, error)
func (o *OffersService) BatchUpdate(ctx, packageName, productID, purchaseOptionID string, req *androidpublisher.BatchUpdateOneTimeProductOffersRequest) (*androidpublisher.BatchUpdateOneTimeProductOffersResponse, error)
func (o *OffersService) BatchDelete(ctx, packageName, productID, purchaseOptionID string, req *androidpublisher.BatchDeleteOneTimeProductOffersRequest) error
func (o *OffersService) BatchUpdateStates(ctx, packageName, productID, purchaseOptionID string, req *androidpublisher.BatchUpdateOneTimeProductOfferStatesRequest) (*androidpublisher.BatchUpdateOneTimeProductOfferStatesResponse, error)
```

```go
offer, err := client.OneTimeProducts.PurchaseOptions.Offers.Activate(ctx,
    "com.example.app", "gem_pack_100", "option_id", "offer_id", nil)
```

REST 根路径：`/androidpublisher/v3/applications/{packageName}/onetimeproducts/{productId}/purchaseOptions/{purchaseOptionId}/offers/...`
