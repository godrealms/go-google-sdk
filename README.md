# Go Google SDK

[![Go Report Card](https://goreportcard.com/badge/github.com/godrealms/go-google-sdk)](https://goreportcard.com/report/github.com/godrealms/go-google-sdk)
[![GoDoc](https://godoc.org/github.com/godrealms/go-google-sdk?status.svg)](https://godoc.org/github.com/godrealms/go-google-sdk)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

一个易于使用的 Go 语言 Google API SDK，提供对 Google Play Developer API、Google Cloud API 等服务的简化访问。

## 特性

- 🚀 简化的 API 调用接口
- 🔐 支持多种认证方式（服务账户、OAuth2）
- 📱 Google Play Developer API 完整支持
- ☁️ Google Cloud 服务集成
- 🛡️ 内置错误处理和重试机制
- 📊 详细的日志记录
- 🔧 灵活的配置选项

## 支持的服务

### Google Play Developer API

- 应用内购买验证
- 订阅管理
- 应用发布管理
- 评论和评分管理

### Google Cloud Services

- Google Cloud Storage
- Google Cloud Pub/Sub
- Google Cloud Functions
- 其他 Google Cloud 服务

## 安装

```bash
go get github.com/godrealms/go-google-sdk
```

## 快速开始

### 1. 配置认证

#### 使用服务账户密钥文件

```go
package main

import (
	"context"
	"log"

	"github.com/godrealms/go-google-sdk/android/publisher"
	"google.golang.org/api/option"
)

func main() {
	ctx := context.Background()

	// 使用服务账户密钥文件
	client, err := publisher.NewClient(ctx, option.WithCredentialsFile("path/to/service-account.json"))
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
```

#### 使用环境变量

```bash
export GOOGLE_APPLICATION_CREDENTIALS="path/to/service-account.json"
```

```go
// 使用默认凭据
client, err := publisher.NewClient(ctx)
if err != nil {
log.Fatal(err)
}
```

### 2. Google Play Developer API 使用示例

#### 验证应用内购买

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/godrealms/go-google-sdk/android/publisher"
)

func main() {
	ctx := context.Background()
	client, err := publisher.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// 验证应用内购买
	purchase, err := client.VerifyPurchase(ctx, &publisher.VerifyPurchaseRequest{
		PackageName:   "com.example.app",
		ProductID:     "premium_upgrade",
		PurchaseToken: "purchase_token_here",
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Purchase State: %d\n", purchase.PurchaseState)
	fmt.Printf("Purchase Time: %d\n", purchase.PurchaseTimeMillis)
}
```

#### 验证订阅

```go
// 验证订阅购买
subscription, err := client.VerifySubscription(ctx, &publisher.VerifySubscriptionRequest{
PackageName:      "com.example.app",
SubscriptionID:   "premium_monthly",
PurchaseToken:    "subscription_token_here",
})
if err != nil {
log.Fatal(err)
}

fmt.Printf("Auto Renewing: %v\n", subscription.AutoRenewing)
fmt.Printf("Expiry Time: %d\n", subscription.ExpiryTimeMillis)
fmt.Printf("Payment State: %d\n", *subscription.PaymentState)
```

#### 确认购买

```go
// 确认购买
err = client.AcknowledgePurchase(ctx, &publisher.AcknowledgePurchaseRequest{
PackageName:   "com.example.app",
ProductID:     "premium_upgrade",
PurchaseToken: "purchase_token_here",
})
if err != nil {
log.Fatal(err)
}
```

### 3. 配置选项

```go
config := &publisher.Config{
// API 超时设置
Timeout: 30 * time.Second,

// 重试配置
RetryConfig: &publisher.RetryConfig{
MaxRetries: 3,
BackoffDelay: time.Second,
},

// 日志配置
Logger: log.New(os.Stdout, "[GoogleSDK] ", log.LstdFlags),

// 自定义 HTTP 客户端
HTTPClient: &http.Client{
Timeout: 30 * time.Second,
},
}

client, err := publisher.NewClientWithConfig(ctx, config)
```

## API 参考

### Publisher Client

#### 购买验证方法

| 方法                                  | 描述      |
|-------------------------------------|---------|
| `VerifyPurchase(ctx, req)`          | 验证应用内购买 |
| `VerifySubscription(ctx, req)`      | 验证订阅购买  |
| `AcknowledgePurchase(ctx, req)`     | 确认购买    |
| `AcknowledgeSubscription(ctx, req)` | 确认订阅    |

#### 订阅管理方法

| 方法                             | 描述   |
|--------------------------------|------|
| `CancelSubscription(ctx, req)` | 取消订阅 |
| `DeferSubscription(ctx, req)`  | 延期订阅 |
| `RefundSubscription(ctx, req)` | 退款订阅 |
| `RevokeSubscription(ctx, req)` | 撤销订阅 |

### 数据结构

#### SubscriptionPurchase

```go
type SubscriptionPurchase struct {
AcknowledgementState        int64  `json:"acknowledgementState,omitempty"`
AutoRenewing               bool   `json:"autoRenewing,omitempty"`
CancelReason               int64  `json:"cancelReason,omitempty"`
CountryCode                string `json:"countryCode,omitempty"`
ExpiryTimeMillis           int64  `json:"expiryTimeMillis,omitempty,string"`
PaymentState               *int64 `json:"paymentState,omitempty"`
PriceAmountMicros          int64  `json:"priceAmountMicros,omitempty,string"`
PriceCurrencyCode          string `json:"priceCurrencyCode,omitempty"`
StartTimeMillis            int64  `json:"startTimeMillis,omitempty,string"`
UserCancellationTimeMillis int64  `json:"userCancellationTimeMillis,omitempty,string"`
// ... 其他字段
}
```

## 错误处理

SDK 提供了详细的错误类型和处理机制：

```go
purchase, err := client.VerifyPurchase(ctx, req)
if err != nil {
switch e := err.(type) {
case *publisher.APIError:
fmt.Printf("API Error: %s (Code: %d)\n", e.Message, e.Code)
case *publisher.AuthError:
fmt.Printf("Authentication Error: %s\n", e.Message)
case *publisher.NetworkError:
fmt.Printf("Network Error: %s\n", e.Message)
default:
fmt.Printf("Unknown Error: %s\n", err.Error())
}
return
}
```

## 最佳实践

### 1. 连接池管理

```go
// 使用单例模式管理客户端
var (
publisherClient *publisher.Client
once           sync.Once
)

func GetPublisherClient() *publisher.Client {
once.Do(func () {
ctx := context.Background()
var err error
publisherClient, err = publisher.NewClient(ctx)
if err != nil {
log.Fatal(err)
}
})
return publisherClient
}
```

### 2. 错误重试

```go
func verifyPurchaseWithRetry(client *publisher.Client, req *publisher.VerifyPurchaseRequest) (*publisher.Purchase, error) {
var purchase *publisher.Purchase
var err error

for i := 0; i < 3; i++ {
purchase, err = client.VerifyPurchase(context.Background(), req)
if err == nil {
return purchase, nil
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

### 3. 超时控制

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

purchase, err := client.VerifyPurchase(ctx, req)
```

## 测试

运行测试：

```bash
go test ./...
```

运行基准测试：

```bash
go test -bench=. ./...
```

## 贡献

欢迎贡献代码！请遵循以下步骤：

1. Fork 项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开 Pull Request

## 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 更新日志

### v1.2.0 (2024-01-15)

- 添加订阅管理功能
- 改进错误处理机制
- 优化性能和内存使用

### v1.1.0 (2023-12-01)

- 添加 Google Cloud 服务支持
- 改进文档和示例
- 修复已知问题

### v1.0.0 (2023-11-01)

- 初始版本发布
- 支持 Google Play Developer API
- 基础认证和购买验证功能

## 支持

- 📧 Email: support@godrealms.com
- 🐛 Issues: [GitHub Issues](https://github.com/godrealms/go-google-sdk/issues)
- 📖 文档: [Wiki](https://github.com/godrealms/go-google-sdk/wiki)

## 相关项目

- [Google Cloud Go SDK](https://github.com/googleapis/google-cloud-go) - 官方 Google Cloud SDK
- [Google API Go Client](https://github.com/googleapis/google-api-go-client) - 官方 Google API 客户端
