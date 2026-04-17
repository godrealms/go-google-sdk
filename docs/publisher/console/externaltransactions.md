# externaltransactions — 外部交易（替代 / 用户选择计费）

封装 `androidpublisher.Externaltransactions` 资源：用于替代结算 (Alternative Billing) 和用户选择结算 (User Choice Billing) 场景下上报与对账。

- Go 包路径: `github.com/godrealms/go-google-sdk/android/publisher/externaltransactions`
- Scope: `https://www.googleapis.com/auth/androidpublisher`
- 资源名格式：
  - `parent`: `applications/{packageName}`
  - `name`: `applications/{packageName}/externalTransactions/{externalTransactionId}`

## 快速示例

```go
txn, err := client.ExternalTransactions.Create(ctx,
    "applications/com.example.app",
    &androidpublisher.ExternalTransaction{/* TransactionProgramCode, UserTaxAddress, ... */},
    externaltransactions.CreateOptions{ExternalTransactionID: "txn-2026-0001"},
)
```

## Create

```go
func (s *Service) Create(ctx context.Context, parent string, txn *androidpublisher.ExternalTransaction, opts CreateOptions) (*androidpublisher.ExternalTransaction, error)
```

`CreateOptions{ExternalTransactionID}` 允许调用方指定幂等键。

REST: `POST /androidpublisher/v3/{parent=applications/*}/externalTransactions`

## Get

```go
func (s *Service) Get(ctx context.Context, name string) (*androidpublisher.ExternalTransaction, error)
```

REST: `GET /androidpublisher/v3/{name=applications/*/externalTransactions/*}`

## Refund

```go
func (s *Service) Refund(ctx context.Context, name string, req *androidpublisher.RefundExternalTransactionRequest) (*androidpublisher.ExternalTransaction, error)
```

REST: `POST /androidpublisher/v3/{name=applications/*/externalTransactions/*}:refund`

```go
_, err := client.ExternalTransactions.Refund(ctx,
    "applications/com.example.app/externalTransactions/txn-2026-0001",
    &androidpublisher.RefundExternalTransactionRequest{/* PartialRefund / FullRefund */})
```
