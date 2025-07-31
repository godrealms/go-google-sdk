# Go Google SDK

[![Go Report Card](https://goreportcard.com/badge/github.com/godrealms/go-google-sdk)](https://goreportcard.com/report/github.com/godrealms/go-google-sdk)
[![GoDoc](https://godoc.org/github.com/godrealms/go-google-sdk?status.svg)](https://godoc.org/github.com/godrealms/go-google-sdk)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

一个功能完整的 Go 语言 Google 服务 SDK，提供 Google Play Developer API 和 Google Pay 支付处理的完整解决方案。

## 特性

- 🚀 **Google Play Developer API** - 应用内购买验证、订阅管理
- 💳 **Google Pay 支付处理** - Token 解密、签名验证、密钥管理
- 🔔 **实时开发者通知** - Google Cloud Pub/Sub RTDN 监听
- 🔐 **多种认证方式** - 服务账户、OAuth2、默认凭据
- 🛡️ **安全加密** - ECDSA 签名验证、AES-GCM 解密
- 📊 **智能缓存** - 密钥缓存、Token 缓存机制
- 🔧 **灵活配置** - 环境切换、超时控制、日志管理

## 支持的服务

### Google Play Developer API

- ✅ 应用内购买验证
- ✅ 订阅管理和验证
- ✅ 实时开发者通知处理
- ✅ 购买确认和撤销

### Google Pay 支付处理

- ✅ 加密 Token 解密
- ✅ ECDSA 签名验证
- ✅ 密钥自动管理和刷新
- ✅ 支持 ECv1 和 ECv2 协议
- ✅ 卡片信息提取
- ✅ 3DS 认证信息处理

## 安装

```bash
go get github.com/godrealms/go-google-sdk
```

## 依赖项

```go
require (
golang.org/x/oauth2 v0.15.0
google.golang.org/api v0.153.0
cloud.google.com/go/pubsub v1.33.0
)
```

## 快速开始

### 1. Google Play Developer API

#### 初始化服务

```go
package main

import (
	"context"
	"log"

	"github.com/godrealms/go-google-sdk/publisher"
)

func main() {
	ctx := context.Background()

	// 使用服务账户密钥文件
	service, err := publisher.NewServiceWithKey(ctx, "/path/to/service-account.json")
	if err != nil {
		log.Fatal(err)
	}

	// 验证购买
	purchase, err := service.VerifyPurchase("com.example.app", "premium_upgrade", "purchase-token")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Purchase State: %d", purchase.PurchaseState)
}
```

#### 验证订阅

```go
func verifySubscription(service *publisher.Service) {
subscription, err := service.VerifySubscriptions(
"com.example.app",
"premium_monthly",
"subscription-token",
)
if err != nil {
log.Printf("验证订阅失败: %v", err)
return
}

log.Printf("自动续订: %v", subscription.AutoRenewing)
log.Printf("到期时间: %d", subscription.ExpiryTimeMillis)
}
```

### 2. Google Pay 支付处理

#### 初始化 Google Pay 客户端

```go
package main

import (
	"log"

	"github.com/godrealms/go-google-sdk/payment"
)

func main() {
	config := &payment.Config{
		Environment:    payment.Production, // 或 payment.Sandbox
		MerchantID:     "your-merchant-id",
		MerchantName:   "Your Merchant Name",
		PrivateKeyPath: "/path/to/private-key.pem",

		// 可选配置
		Timeout:        30 * time.Second,
		LogLevel:       "info",
		EnableDebugLog: false,
		CacheConfig: &payment.CacheConfig{
			TTL:        1 * time.Hour,
			MaxEntries: 1000,
		},
	}

	client, err := payment.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	// 现在可以使用客户端解密 Google Pay Token
}
```

#### 解密 Google Pay Token

```go
func processGooglePayToken(client *payment.Client, encryptedToken string) {
ctx := context.Background()

// 解密Token
paymentToken, err := client.DecryptToken(ctx, encryptedToken)
if err != nil {
log.Printf("解密Token失败: %v", err)
return
}

// 访问卡片信息
cardDetails := paymentToken.PaymentMethodDetails
log.Printf("卡号: %s", cardDetails.PAN)
log.Printf("过期月份: %s", cardDetails.ExpirationMonth)
log.Printf("过期年份: %s", cardDetails.ExpirationYear)
log.Printf("卡片网络: %s", paymentToken.PaymentNetwork)

// 3DS 认证信息
if paymentToken.Cryptogram != "" {
log.Printf("3DS Cryptogram: %s", paymentToken.Cryptogram)
log.Printf("ECI Indicator: %s", paymentToken.EciIndicator)
}

// 检查Token是否过期
if time.Now().After(paymentToken.ExpiresAt) {
log.Println("Token已过期")
return
}

log.Println("Token解密成功，可以进行支付处理")
}
```

## 配置详解

### Google Play Publisher 配置

```go
// 基础配置
type Config struct {
ProjectID      string `json:",omitempty"` // GCP 项目ID
SubscriptionID string `json:",omitempty"` // Pub/Sub 订阅ID
JsonKey        string `json:",omitempty"` // 服务账户密钥文件路径
}

// OAuth2 配置
type OAuth2 struct {
Type                    string `json:"type"`
ProjectId               string `json:"project_id"`
PrivateKeyId            string `json:"private_key_id"`
PrivateKey              string `json:"private_key"`
ClientEmail             string `json:"client_email"`
ClientId                string `json:"client_id"`
AuthUri                 string `json:"auth_uri"`
TokenUri                string `json:"token_uri"`
AuthProviderX509CertUrl string `json:"auth_provider_x509_cert_url"`
ClientX509CertUrl       string `json:"client_x509_cert_url"`
}
```

### Google Pay 配置

```go
type Config struct {
// 环境配置
Environment Environment `json:"environment"` // Production 或 Sandbox

// 商户配置
MerchantID   string `json:"merchant_id"`
MerchantName string `json:"merchant_name"`

// 密钥配置
PrivateKeyPath string `json:"private_key_path"` // 私钥文件路径
PrivateKeyData []byte `json:"private_key_data"` // 或直接提供密钥数据

// 网络配置
Timeout           time.Duration `json:"timeout"`
MaxRetries        int          `json:"max_retries"`
RetryDelay        time.Duration `json:"retry_delay"`

// 缓存配置
CacheConfig *CacheConfig `json:"cache_config"`

// 日志配置
LogLevel       string `json:"log_level"`
EnableDebugLog bool   `json:"enable_debug_log"`
}

type CacheConfig struct {
TTL        time.Duration `json:"ttl"`
MaxEntries int          `json:"max_entries"`
}

// 环境类型
type Environment string

const (
Sandbox    Environment = "sandbox"
Production Environment = "production"
)
```

## 数据结构

### Google Pay Token 结构

```go
// 加密Token结构
type EncryptedToken struct {
ProtocolVersion string        `json:"protocolVersion"` // "ECv1" 或 "ECv2"
Signature       string        `json:"signature"`
SignedMessage   SignedMessage `json:"signedMessage"`
}

// 解密后的支付Token
type PaymentToken struct {
MessageID                string      `json:"messageId"`
MessageExpiration        string      `json:"messageExpiration"`
PaymentMethod            string      `json:"paymentMethod"`
PaymentMethodType        string      `json:"paymentMethodType"`
PaymentMethodDescription string      `json:"paymentMethodDescription"`
PaymentNetwork           string      `json:"paymentNetwork"`
PaymentMethodDetails     CardDetails `json:"paymentMethodDetails"`

// 3DS 认证信息
AuthenticationMethod string `json:"authenticationMethod,omitempty"`
CryptogramType       string `json:"cryptogramType,omitempty"`
Cryptogram           string `json:"cryptogram,omitempty"`
EciIndicator         string `json:"eciIndicator,omitempty"`
}

// 卡片详情
type CardDetails struct {
PAN             string `json:"pan"`
ExpirationMonth string `json:"expirationMonth"`
ExpirationYear  string `json:"expirationYear"`
CVV             string `json:"cvv,omitempty"`
}
```

### Google Play 通知结构

```go
type Notification struct {
Version                    string                      `json:"version"`
PackageName                string                      `json:"packageName"`
EventTimeMillis            int64                       `json:"eventTimeMillis"`
OneTimeProductNotification *OneTimeProductNotification `json:"oneTimeProductNotification,omitempty"`
SubscriptionNotification   *SubscriptionNotification   `json:"subscriptionNotification,omitempty"`
VoidedPurchaseNotification *VoidedPurchaseNotification `json:"voidedPurchaseNotification,omitempty"`
TestNotification           *TestNotification           `json:"testNotification,omitempty"`
}
```

## 高级功能

### 1. 密钥自动管理

```go
// KeyManager 自动管理 Google 根密钥
type KeyManager struct {
config     *Config
logger     logs.Logger
privateKey *ecdsa.PrivateKey
rootKeys   map[string]*ecdsa.PublicKey
lastUpdate time.Time
}

// 密钥会自动刷新，无需手动管理
func (km *KeyManager) RefreshRootKeys(ctx context.Context) error {
// 自动从 Google 获取最新的根密钥
}
```

### 2. 智能缓存机制

```go
// 配置缓存
config := &payment.Config{
CacheConfig: &payment.CacheConfig{
TTL:        2 * time.Hour, // 缓存2小时
MaxEntries: 5000, // 最大5000个条目
},
}

// Token 和密钥会自动缓存，提高性能
```

### 3. 错误处理和重试

```go
func handlePaymentWithRetry(client *payment.Client, token string) (*payment.PaymentToken, error) {
var paymentToken *payment.PaymentToken
var err error

for i := 0; i < 3; i++ {
paymentToken, err = client.DecryptToken(context.Background(), token)
if err == nil {
return paymentToken, nil
}

// 检查是否为可重试错误
if !isRetryableError(err) {
break
}

time.Sleep(time.Duration(i+1) * time.Second)
}

return nil, err
}
```

## 实时开发者通知 (RTDN)

### 设置通知监听

```go
func setupRTDNListener() {
config := &publisher.Config{
ProjectID:      "your-gcp-project-id",
SubscriptionID: "your-pubsub-subscription-id",
JsonKey:        "/path/to/service-account.json",
}

// 启动监听器
go publisher.StartSubscriptionMonitor(config)
}

// 处理不同类型的通知
func handleNotification(notification *publisher.Notification) {
switch {
case notification.SubscriptionNotification != nil:
handleSubscriptionNotification(notification.SubscriptionNotification)
case notification.OneTimeProductNotification != nil:
handlePurchaseNotification(notification.OneTimeProductNotification)
}
}
```

## 完整示例

### Google Pay 支付处理服务

```go
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/godrealms/go-google-sdk/payment"
)

type PaymentRequest struct {
	EncryptedToken string `json:"encrypted_token"`
	OrderID        string `json:"order_id"`
	Amount         int64  `json:"amount"`
}

type PaymentResponse struct {
	Success   bool   `json:"success"`
	OrderID   string `json:"order_id"`
	CardLast4 string `json:"card_last4,omitempty"`
	Network   string `json:"network,omitempty"`
	Message   string `json:"message,omitempty"`
}

func main() {
	// 初始化 Google Pay 客户端
	config := &payment.Config{
		Environment:    payment.Production,
		MerchantID:     "your-merchant-id",
		MerchantName:   "Your Store",
		PrivateKeyPath: "private-key.pem",
		Timeout:        30 * time.Second,
		LogLevel:       "info",
	}

	client, err := payment.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/process-payment", func(w http.ResponseWriter, r *http.Request) {
		var req PaymentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		// 解密 Google Pay Token
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		paymentToken, err := client.DecryptToken(ctx, req.EncryptedToken)
		if err != nil {
			resp := PaymentResponse{
				Success: false,
				OrderID: req.OrderID,
				Message: "Token decryption failed: " + err.Error(),
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		// 提取卡片信息
		cardDetails := paymentToken.PaymentMethodDetails
		cardLast4 := ""
		if len(cardDetails.PAN) >= 4 {
			cardLast4 = cardDetails.PAN[len(cardDetails.PAN)-4:]
		}

		// 这里可以调用支付处理器进行实际支付
		success := processPayment(paymentToken, req.Amount, req.OrderID)

		resp := PaymentResponse{
			Success:   success,
			OrderID:   req.OrderID,
			CardLast4: cardLast4,
			Network:   paymentToken.PaymentNetwork,
		}

		if success {
			resp.Message = "Payment processed successfully"
		} else {
			resp.Message = "Payment processing failed"
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	log.Println("Payment service started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func processPayment(token *payment.PaymentToken, amount int64, orderID string) bool {
	// 实现实际的支付处理逻辑
	// 这里可以调用您的支付处理器 API
	log.Printf("Processing payment for order %s, amount %d", orderID, amount)
	log.Printf("Card network: %s", token.PaymentNetwork)

	// 模拟支付处理
	return true
}
```

## API 参考

### Google Play Publisher

| 方法                    | 参数                                         | 返回值                                             | 描述        |
|-----------------------|--------------------------------------------|-------------------------------------------------|-----------|
| `VerifyPurchase`      | packageName, productId, purchaseToken      | `*androidpublisher.ProductPurchase, error`      | 验证一次性产品购买 |
| `VerifySubscriptions` | packageName, subscriptionId, purchaseToken | `*androidpublisher.SubscriptionPurchase, error` | 验证订阅购买    |

### Google Pay Client

| 方法             | 参数                  | 返回值                    | 描述                  |
|----------------|---------------------|------------------------|---------------------|
| `NewClient`    | config              | `*Client, error`       | 创建新的 Google Pay 客户端 |
| `DecryptToken` | ctx, encryptedToken | `*PaymentToken, error` | 解密 Google Pay Token |

### Key Manager

| 方法                | 参数    | 返回值                       | 描述            |
|-------------------|-------|---------------------------|---------------|
| `GetRootKey`      | keyID | `*ecdsa.PublicKey, error` | 获取指定的根密钥      |
| `RefreshRootKeys` | ctx   | `error`                   | 刷新 Google 根密钥 |

## 最佳实践

### 1. 环境配置

```bash
# 生产环境
export GOOGLE_PAY_ENVIRONMENT=production
export GOOGLE_PAY_MERCHANT_ID=your-merchant-id
export GOOGLE_PAY_PRIVATE_KEY=/path/to/production-key.pem

# 测试环境
export GOOGLE_PAY_ENVIRONMENT=sandbox
export GOOGLE_PAY_MERCHANT_ID=your-test-merchant-id
export GOOGLE_PAY_PRIVATE_KEY=/path/to/test-key.pem
```

### 2. 安全考虑

```go
// 1. 私钥安全存储
config := &payment.Config{
PrivateKeyData: loadFromSecureStorage(), // 从安全存储加载
// 避免硬编码私钥路径
}

// 2. Token 过期检查
if time.Now().After(paymentToken.ExpiresAt) {
return errors.New("payment token expired")
}

// 3. 签名验证
// SDK 自动进行签名验证，确保 Token 来源可信
```

### 3. 性能优化

```go
// 1. 连接池复用
var (
paymentClient *payment.Client
once         sync.Once
)

func GetPaymentClient() *payment.Client {
once.Do(func () {
config := loadConfig()
var err error
paymentClient, err = payment.NewClient(config)
if err != nil {
log.Fatal(err)
}
})
return paymentClient
}

// 2. 并发处理
func processMultipleTokens(client *payment.Client, tokens []string) {
var wg sync.WaitGroup
results := make(chan *payment.PaymentToken, len(tokens))

for _, token := range tokens {
wg.Add(1)
go func (t string) {
defer wg.Done()
result, err := client.DecryptToken(context.Background(), t)
if err == nil {
results <- result
}
}(token)
}

go func () {
wg.Wait()
close(results)
}()

for result := range results {
// 处理结果
processPaymentToken(result)
}
}
```

## 测试

### 单元测试

```bash
go test ./...
```

### 集成测试

```bash
go test -tags=integration ./...
```

### 基准测试

```bash
go test -bench=. ./...
```

## 贡献指南

1. Fork 项目
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

## 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 更新日志

### v0.0.0

- ✅ 新增 Google Pay 支付处理功能
- ✅ ECDSA 签名验证
- ✅ 智能密钥管理
- ✅ 缓存机制优化

### v0.0.0

- ✅ Google Play Developer API 基础功能
- ✅ 购买和订阅验证
- ✅ 实时开发者通知支持

## 支持与反馈

- 🐛 [报告问题](https://github.com/godrealms/go-google-sdk/issues)
- 💡 [功能请求](https://github.com/godrealms/go-google-sdk/discussions)
- 📧 邮箱: support@godrealms.cn

## 相关资源

- [Google Play Developer API 文档](https://developers.google.com/android-publisher)
- [Google Pay API 文档](https://developers.google.com/pay/api)
- [Google Cloud Pub/Sub 文档](https://cloud.google.com/pubsub/docs)
- [实时开发者通知指南](https://developer.android.com/google/play/billing/rtdn-reference)