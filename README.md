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
ctx := context.Background()

// 使用服务账户密钥文件
service, err := publisher.NewServiceWithKey(ctx, "/path/to/service-account.json")
if err != nil {
log.Fatal(err)
}

// 验证订阅
subscription, err := service.VerifySubscriptions("com.example.app", "subscriptionId", "purchase-token")
if err != nil {
log.Fatal(err)
}

log.Printf("Subscriptions State: %d", subscription.PaymentState)
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

## API 参考

### Google Play Publisher

| 方法                | 参数                                             | 返回值                                             | 描述        |
|-------------------|------------------------------------------------|-------------------------------------------------|-----------|
| `VerifyPurchase`  | packageName, productId, purchaseToken          | `*androidpublisher.ProductPurchase, error`      | 验证一次性产品购买 |
| `VerifySubscriptions` | packageName, subscriptionId, purchaseToken | `*androidpublisher.SubscriptionPurchase, error` | 验证订阅购买    |
| `QueryPurchase`   | ctx, packageName, productId, purchaseToken or orderId | `*androidpublisher.Order, *androidpublisher.ProductPurchase, error` | 查询一次性购买 |
| `QuerySubscription` | ctx, packageName, subscriptionId, purchaseToken or orderId | `*androidpublisher.Order, *androidpublisher.SubscriptionPurchase, error` | 查询订阅 |
| `Verify`          | ctx, request                                   | `*VerifyResult, error`                           | 统一校验入口 |
| `RefundPurchase`  | ctx, packageName, orderId                      | `error`                                          | 退款一次性订单    |
| `RefundSubscription` | ctx, packageName, subscriptionId, purchaseToken | `error`                                     | 退款订阅         |

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

## 贡献指南

1. Fork 项目
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

## 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 更新日志

### v0.0.2（2026-02-15 16:55:22 +08:00 / `c77efc0`）

#### 变更要点

- ✅ 新增 Android Publisher 退款接口：`RefundPurchase`（订单级）与 `RefundSubscription`（订阅）
- ✅ 新增退款能力测试：参数校验、成功/失败分支、请求路径与方法校验
- ✅ 更新 `README` 中 Google Play Publisher API 说明

#### 版本元信息

- 📌 发布提交：`c77efc027108b627afe15b253048c8ee928e7cb6`
- 📦 提交范围：`9b72808..c77efc0`
- 🧪 验证：`GOFLAGS=-mod=mod go test ./android/publisher -run TestServiceRefund -v`、`GOFLAGS=-mod=mod go test ./...`
- 🔗 PR：[#3](https://github.com/godrealms/go-google-sdk/pull/3)
- 🚀 发布说明：[`v0.0.2`](https://github.com/godrealms/go-google-sdk/releases/tag/v0.0.2)

### v0.0.1（2026-02-15 16:15:35 +08:00 / `9b72808`）

#### 变更要点

- ✅ 支持 Android Publisher 模块的可观测性与可靠性增强
- ✅ 支持使用 JSON 密钥初始化 Pub/Sub 客户端
- ✅ 重构订阅监控与 RTDN 校验流程，提高稳定性
- ✅ 完善支付模块测试覆盖，补齐 token 流程异常分支

#### 版本元信息

- 📌 发布提交：`9b72808b34b557bd1927e7b4a6615eb02505c47b`
- 📦 提交范围：`9b72808..afe7f49`
- 🚀 发布说明：[`v0.0.1`](https://github.com/godrealms/go-google-sdk/releases/tag/v0.0.1)

### v0.0.0

- ✅ Google Play Developer API 基础功能
- ✅ 购买和订阅验证
- ✅ 实时开发者通知支持
- ✅ 新增 Google Pay 支付处理功能
- ✅ ECDSA 签名验证
- ✅ 智能密钥管理
- ✅ 缓存机制优化

## 支持与反馈

- 🐛 [报告问题](https://github.com/godrealms/go-google-sdk/issues)
- 💡 [功能请求](https://github.com/godrealms/go-google-sdk/discussions)
- 📧 邮箱: support@godrealms.cn

## 相关资源

- [Google Play Developer API 文档](https://developers.google.com/android-publisher)
- [Google Pay API 文档](https://developers.google.com/pay/api)
- [Google Cloud Pub/Sub 文档](https://cloud.google.com/pubsub/docs)
- [实时开发者通知指南](https://developer.android.com/google/play/billing/rtdn-reference)
