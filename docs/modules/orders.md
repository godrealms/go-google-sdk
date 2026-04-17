# orders — 订单查询与退款

封装 `androidpublisher.Orders` 资源：按订单 ID 查询详情、批量查询、以及发起退款 / 撤销。

- Go 包路径: `github.com/godrealms/go-google-sdk/android/publisher/orders`
- Scope: `https://www.googleapis.com/auth/androidpublisher`

## 快速示例

```go
order, err := client.Orders.Get(ctx, "com.example.app", "GPA.1234-5678-9012-34567")
if err != nil {
    log.Fatal(err)
}
log.Printf("state=%s lineItems=%d", order.State, len(order.LineItems))
```

## Get

按订单 ID 获取订单。

```go
func (s *Service) Get(ctx context.Context, packageName, orderID string) (*androidpublisher.Order, error)
```

REST: `GET /androidpublisher/v3/applications/{packageName}/orders/{orderId}`

## Refund

退款。传 `revoke=true` 既退款又撤销（立刻回收商品 / 订阅）；`false` 仅退款。

```go
func (s *Service) Refund(ctx context.Context, packageName, orderID string, revoke bool) error
```

```go
// 仅退款
_ = client.Orders.Refund(ctx, "com.example.app", orderID, false)
// 退款并撤销订阅
_ = client.Orders.Refund(ctx, "com.example.app", orderID, true)
```

REST: `POST /androidpublisher/v3/applications/{packageName}/orders/{orderId}:refund?revoke={bool}`

## BatchGet

一次最多 1000 个订单 ID 批量查询。

```go
func (s *Service) BatchGet(ctx context.Context, packageName string, orderIDs []string) (*androidpublisher.BatchGetOrdersResponse, error)
```

```go
resp, err := client.Orders.BatchGet(ctx, "com.example.app",
    []string{"GPA.aaaa", "GPA.bbbb", "GPA.cccc"})
```

REST: `GET /androidpublisher/v3/applications/{packageName}/orders:batchGet?orderIds=...`
