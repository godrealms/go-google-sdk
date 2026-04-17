# inappproducts — 应用内商品（旧版 SKU）目录管理

封装 `androidpublisher.Inappproducts` 资源：管理应用内商品（旧版 SKU，包含消耗型与非消耗型内购）。

- Go 包路径: `github.com/godrealms/go-google-sdk/android/publisher/inappproducts`
- Scope: `https://www.googleapis.com/auth/androidpublisher`

> 新版开发建议优先使用 [`monetization-onetimeproducts`](./monetization-onetimeproducts.md) 子包。

## 快速示例

```go
resp, err := client.InAppProducts.List(ctx, "com.example.app",
    inappproducts.WithMaxResults(100))
for _, p := range resp.Inappproduct {
    fmt.Println(p.Sku, p.Status)
}
```

## List

列出商品。可选 `WithMaxResults(n)`、`WithToken(t)` 进行分页。

```go
func (s *Service) List(ctx context.Context, packageName string, opts ...ListOption) (*androidpublisher.InappproductsListResponse, error)
```

REST: `GET /androidpublisher/v3/applications/{packageName}/inappproducts`

## Get

```go
func (s *Service) Get(ctx context.Context, packageName, sku string) (*androidpublisher.InAppProduct, error)
```

REST: `GET /androidpublisher/v3/applications/{packageName}/inappproducts/{sku}`

## Insert

```go
func (s *Service) Insert(ctx context.Context, packageName string, product *androidpublisher.InAppProduct) (*androidpublisher.InAppProduct, error)
```

```go
created, err := client.InAppProducts.Insert(ctx, "com.example.app", &androidpublisher.InAppProduct{
    Sku:         "gem_pack_100",
    PurchaseType: "managedUser",
    Status:       "active",
    DefaultLanguage: "en-US",
})
```

REST: `POST /androidpublisher/v3/applications/{packageName}/inappproducts`

## Update

全量替换一个 SKU。

```go
func (s *Service) Update(ctx context.Context, packageName, sku string, product *androidpublisher.InAppProduct) (*androidpublisher.InAppProduct, error)
```

REST: `PUT /androidpublisher/v3/applications/{packageName}/inappproducts/{sku}`

## Delete

```go
func (s *Service) Delete(ctx context.Context, packageName, sku string) error
```

REST: `DELETE /androidpublisher/v3/applications/{packageName}/inappproducts/{sku}`

## BatchGet / BatchUpdate / BatchDelete

批量操作：

```go
func (s *Service) BatchGet(ctx context.Context, packageName string, skus []string) (*androidpublisher.InappproductsBatchGetResponse, error)
func (s *Service) BatchUpdate(ctx context.Context, packageName string, req *androidpublisher.InappproductsBatchUpdateRequest) (*androidpublisher.InappproductsBatchUpdateResponse, error)
func (s *Service) BatchDelete(ctx context.Context, packageName string, req *androidpublisher.InappproductsBatchDeleteRequest) error
```

```go
resp, err := client.InAppProducts.BatchGet(ctx, "com.example.app",
    []string{"sku_a", "sku_b"})
```

REST:
- `GET /androidpublisher/v3/applications/{packageName}/inappproducts:batchGet`
- `POST /androidpublisher/v3/applications/{packageName}/inappproducts:batchUpdate`
- `POST /androidpublisher/v3/applications/{packageName}/inappproducts:batchDelete`
