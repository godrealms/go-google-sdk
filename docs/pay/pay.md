# pay — Google Pay Token 解密与密钥管理

`payment` 包提供 Google Pay 支付网关所需的 Token 解密、签名校验、密钥缓存与健康检查。

- Go 包路径: `github.com/godrealms/go-google-sdk/payment`
- 支持协议: ECv1 / ECv2

## 快速示例

```go
import "github.com/godrealms/go-google-sdk/payment"

cfg := &payment.Config{
    Environment:    payment.EnvironmentProduction,
    MerchantID:     "merchant.example",
    MerchantName:   "Example Inc.",
    PrivateKeyPath: "/path/to/merchant-private-key.pem",
}
client, err := payment.NewClient(cfg)
if err != nil {
    log.Fatal(err)
}
defer client.Close()

token, err := client.DecryptPaymentToken(ctx, encryptedToken)
if err != nil {
    log.Fatal(err)
}
log.Printf("card last4=%s network=%s", token.GetCardLast4(), token.GetCardBrand())
```

## NewClient

```go
func NewClient(config *Config) (*Client, error)
```

`Config` 关键字段：

| 字段 | 说明 |
|---|---|
| `Environment` | `EnvironmentSandbox` 或 `EnvironmentProduction` |
| `MerchantID` / `MerchantName` | 商户信息 |
| `PrivateKeyPath` / `PrivateKeyData` | 商户私钥（二选一） |
| `Timeout` / `MaxRetries` | 网络调用参数 |
| `CacheEnabled` / `CacheTTL` | 是否缓存已解密 Token |
| `LogLevel` / `EnableDebugLog` | 日志 |

`DefaultConfig()` 给出合理默认（sandbox + 5 分钟缓存）。

## DecryptPaymentToken

```go
func (c *Client) DecryptPaymentToken(ctx context.Context, encryptedToken string) (*PaymentToken, error)
```

解密从前端收到的 Google Pay Token。结果缓存键基于 token 的 SHA-256。

```go
token, err := client.DecryptPaymentToken(ctx, raw)
if err != nil {
    return err
}
card := token.PaymentMethodDetails
fmt.Println(card.PAN, card.ExpirationMonth, card.ExpirationYear)
if token.IsExpired() {
    return errors.New("token expired")
}
```

## ValidatePaymentToken

```go
func (c *Client) ValidatePaymentToken(ctx context.Context, token *PaymentToken) error
```

校验有效期 + 签名。

## GetPaymentMethodInfo

返回脱敏的支付方式信息（类型、描述、网络、卡详情）。

```go
func (c *Client) GetPaymentMethodInfo(ctx context.Context, token *PaymentToken) (*PaymentMethodInfo, error)
```

## Health

检查 KeyManager 与 TokenHandler 可用性。

```go
func (c *Client) Health(ctx context.Context) error
```

## Close

释放密钥管理器、缓存等资源。

```go
func (c *Client) Close() error
```

## PaymentToken 辅助方法

```go
(pt *PaymentToken) IsExpired() bool
(pt *PaymentToken) GetCardLast4() string
(pt *PaymentToken) GetCardBrand() string
```

## KeyManager

通过 `KeyManager` 访问 Google 根公钥：

```go
func (km *KeyManager) GetRootKey(keyID string) (*ecdsa.PublicKey, error)
func (km *KeyManager) RefreshRootKeys(ctx context.Context) error
func (km *KeyManager) Health(ctx context.Context) error
func (km *KeyManager) Close() error
```

`RefreshRootKeys` 通常由 SDK 内部调度，正常使用不需要手动调用。
