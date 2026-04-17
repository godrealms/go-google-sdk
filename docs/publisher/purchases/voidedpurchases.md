# voidedpurchases — 已撤销购买查询

封装 `purchases.voidedpurchases` 资源，用于列出被撤销 / 退款的购买，常用于欺诈检测与对账。

- Go 包路径: `github.com/godrealms/go-google-sdk/android/publisher/voidedpurchases`
- Scope: `https://www.googleapis.com/auth/androidpublisher`

## 快速示例

```go
resp, err := client.VoidedPurchases.List(ctx, "com.example.app",
    voidedpurchases.WithMaxResults(100),
    voidedpurchases.WithStartTime(time.Now().Add(-24*time.Hour)),
)
for _, v := range resp.VoidedPurchases {
    fmt.Println(v.OrderId, v.VoidedTimeMillis)
}
```

## List

```go
func (s *Service) List(ctx context.Context, packageName string, opts ...ListOption) (*androidpublisher.VoidedPurchasesListResponse, error)
```

支持的选项：

| 选项 | 作用 |
|---|---|
| `WithStartTime(t time.Time)` | 起始时间（毫秒） |
| `WithEndTime(t time.Time)`   | 结束时间（毫秒） |
| `WithMaxResults(n int64)`    | 单页数量 |
| `WithPageToken(token string)` | 分页游标 |
| `WithType(purchaseType int64)` | 1=一次性内购, 2=订阅 |

REST: `GET /androidpublisher/v3/applications/{packageName}/purchases/voidedpurchases`
