# Go Google SDK

[![Go Report Card](https://goreportcard.com/badge/github.com/godrealms/go-google-sdk)](https://goreportcard.com/report/github.com/godrealms/go-google-sdk)
[![GoDoc](https://godoc.org/github.com/godrealms/go-google-sdk?status.svg)](https://godoc.org/github.com/godrealms/go-google-sdk)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

一个功能完整的 Go 语言 Google 服务 SDK，全量覆盖 **Google Play Developer Publisher API v3** 的 137 个 REST 方法，并提供 Google Pay Token 解密与 Pub/Sub 实时开发者通知（RTDN）监听。

## 目录

- [特性](#特性)
- [支持的服务](#支持的服务)
- [安装](#安装)
- [依赖项](#依赖项)
- [认证方式](#认证方式)
- [快速开始](#快速开始)
- [Publisher 子模块一览](#publisher-子模块一览)
- [错误处理](#错误处理)
- [实时开发者通知 (RTDN)](#实时开发者通知-rtdn)
- [API 参考](#api-参考)
- [最佳实践](#最佳实践)
- [贡献指南](#贡献指南)
- [许可证](#许可证)
- [更新日志](#更新日志)

## 特性

- 🚀 **Publisher API 全量覆盖** — 137 个 REST 方法零遗漏，拆分为 18 个职责清晰的子包
- 💳 **Google Pay 支付处理** — ECv1/ECv2 Token 解密、ECDSA 签名验证、根密钥自动刷新
- 🔔 **实时开发者通知 (RTDN)** — Google Cloud Pub/Sub 订阅监听与消息路由
- 🔐 **多种认证方式** — Application Default Credentials、OAuth2 授权码、API Key、服务账户
- 🎯 **统一购买验证** — `client.Verify()` 基于 ProductID / SubscriptionID / OrderID 自动路由
- 🧩 **Options 模式** — 所有可选查询参数通过 `XxxOptions` struct 传递，向后兼容
- 🛡️ **哨兵错误** — 每个子包导出 `ErrMissingXxx` 等命名错误，便于 `errors.Is` 判断
- 📦 **资源名与 packageName 双模式** — 同时支持 `developers/{id}/users/{email}` 与 `com.example.app` 两类路径模板

## 支持的服务

### Google Play Developer Publisher API（v3）

| 分类 | 覆盖范围 |
|---|---|
| 购买与订阅验证 | `purchases` / `subscriptions` / `voidedpurchases` / `orders` |
| 商品目录 | `inappproducts` / `monetization.onetimeproducts` / `monetization.subscriptions` |
| 用户评论 | `reviews`（Get / List / Reply） |
| 用户权限 | `users` / `grants`（Play Console 用户与应用授权） |
| 外部交易 | `externaltransactions`（替代计费 / 用户选择计费） |
| 应用元数据 | `applications`（数据安全、设备层级配置、版本轨道） |
| 应用恢复 | `apprecovery`（AddTargeting / Cancel / Create / Deploy / List） |
| 构建分发 | `generatedapks` / `systemapks` / `internalappsharing` |
| 发布编辑 | `edits`（APK/Bundle、listings、tracks、testers、images 等完整生命周期） |

### Google Pay 支付处理

- ✅ 加密 Token 解密（ECv1 / ECv2）
- ✅ ECDSA 签名验证
- ✅ Google 根密钥自动管理与定期刷新
- ✅ 卡片信息提取（PAN / 过期时间 / 卡网络）
- ✅ 3DS 认证信息处理（Cryptogram / ECI Indicator）

## 安装

```bash
go get github.com/godrealms/go-google-sdk
```

要求：Go 1.25 或更高。

## 依赖项

```go
require (
    google.golang.org/api v0.276.0
    golang.org/x/oauth2 v0.25.0
    cloud.google.com/go/pubsub v1.45.1
)
```

## 认证方式

Publisher 客户端支持三种认证方式，按场景选择：

```go
import (
    "context"

    "golang.org/x/oauth2"
    "google.golang.org/api/option"

    "github.com/godrealms/go-google-sdk/android/publisher"
)

ctx := context.Background()

// 方式 1：Application Default Credentials（推荐：GCP 环境、工作负载身份联合）
client, err := publisher.NewClient(ctx)

// 方式 2：服务账户 JSON 密钥文件
client, err := publisher.NewClient(ctx,
    option.WithCredentialsFile("/path/to/service-account.json"))

// 方式 3：OAuth2 授权码交换（面向用户授权的工具）
oauthConfig := &oauth2.Config{ /* ClientID / ClientSecret / Scopes... */ }
client, err := publisher.NewClientWithTokenSource(ctx, oauthConfig, "authorization-code")

// 方式 4：API Key（仅适用于少数公开接口）
client, err := publisher.NewClientWithKey(ctx, "your-api-key")
```

所需 OAuth2 Scope：`https://www.googleapis.com/auth/androidpublisher`。

## 快速开始

### 1. Google Play Developer API

```go
import (
    "context"
    "log"

    "github.com/godrealms/go-google-sdk/android/publisher"
    "github.com/godrealms/go-google-sdk/android/publisher/subscriptions"
    "github.com/godrealms/go-google-sdk/android/publisher/voidedpurchases"
)

func main() {
    ctx := context.Background()

    // 初始化客户端（使用 Application Default Credentials）
    client, err := publisher.NewClient(ctx)
    if err != nil {
        log.Fatal(err)
    }
    // ... rest of examples

    // 统一验证购买（自动根据 ProductID / SubscriptionID / OrderID 路由）
    result, err := client.Verify(ctx, publisher.VerifyRequest{
        PackageName:   "com.example.app",
        ProductID:     "sword_001",
        PurchaseToken: "purchase-token-from-google-play",
    })

    // 确认一次性内购（需在 3 天内确认）
    err = client.Purchases.Acknowledge(ctx, "com.example.app", "sword_001", "purchase-token")

    // 查询订阅详情（默认使用 v2 API）
    _, subResult, err := client.Subscriptions.Query(ctx, subscriptions.SubscriptionQuery{
        PackageName:    "com.example.app",
        SubscriptionID: "monthly_pro",
        PurchaseToken:  "sub-token",
    })
    // subResult.V2 包含 SubscriptionPurchaseV2

    // 列出应用内产品目录
    resp, err := client.InAppProducts.List(ctx, "com.example.app")

    // 列出已撤销购买（用于欺诈检测）
    voidedResp, err := client.VoidedPurchases.List(ctx, "com.example.app",
        voidedpurchases.WithMaxResults(100))
}
```

### 2. 其他 Publisher 子模块速览

```go
// --- 用户评论：批量回复 1 星评价 ---
list, _ := client.Reviews.List(ctx, "com.example.app", reviews.ListOptions{MaxResults: 50})
for _, r := range list.Reviews {
    _, _ = client.Reviews.Reply(ctx, "com.example.app", r.ReviewId, "感谢反馈，我们已在最新版本修复此问题。")
}

// --- Play Console 用户管理 ---
_, _ = client.Users.Create(ctx, "developers/1234567890", &androidpublisher.User{
    Email:         "teammate@example.com",
    DeveloperAccountPermissions: []string{"CAN_VIEW_NON_FINANCIAL_DATA_GLOBAL"},
})

// --- 应用恢复：回滚线上崩溃版本 ---
action, _ := client.AppRecovery.Create(ctx, "com.example.app",
    &androidpublisher.CreateDraftAppRecoveryRequest{VersionCode: 42})
_, _ = client.AppRecovery.Deploy(ctx, "com.example.app", action.AppRecoveryId, nil)

// --- Edits 发布流程：插入 → 上传 AAB → 分配到 production → 提交 ---
edit, _ := client.Edits.Insert(ctx, "com.example.app", nil)
bundle, _ := client.Edits.BundlesUpload(ctx, "com.example.app", edit.Id,
    aabFile, edits.BundlesUploadOptions{})
_, _ = client.Edits.TracksUpdate(ctx, "com.example.app", edit.Id, "production", &androidpublisher.Track{
    Releases: []*androidpublisher.TrackRelease{{
        VersionCodes: []int64{bundle.VersionCode},
        Status:       "completed",
    }},
})
_, _ = client.Edits.Commit(ctx, "com.example.app", edit.Id, edits.CommitOptions{})

// --- 一次性商品目录：批量查询 ---
_, _ = client.OneTimeProducts.BatchGet(ctx, "com.example.app",
    &androidpublisher.BatchGetOneTimeProductsRequest{ProductIds: []string{"coin_100", "coin_500"}})

// --- 订阅定价：跨区域换算 ---
_, _ = client.MonetizationSubscriptions.ConvertRegionPrices(ctx, "com.example.app",
    &androidpublisher.ConvertRegionPricesRequest{Price: &androidpublisher.Money{
        CurrencyCode: "USD", Units: 9, Nanos: 990000000,
    }})
```

> 💡 每个子模块的完整用法、方法签名、REST 端点请见 [`docs/publisher/`](docs/publisher/README.md)。

## Publisher 子模块一览

| 子服务 | 职责 | 文档 |
|---|---|---|
| `client.Purchases` | 一次性内购确认 / 消费 / 查询 / 退款 | [purchases/purchases.md](docs/publisher/purchases/purchases.md) |
| `client.Subscriptions` | 订阅查询（v2/v1）与全生命周期管理 | [purchases/subscriptions.md](docs/publisher/purchases/subscriptions.md) |
| `client.Orders` | 订单详情、退款、批量查询 | [purchases/orders.md](docs/publisher/purchases/orders.md) |
| `client.InAppProducts` | 应用内商品（旧接口）CRUD + 批量 | [catalog/inappproducts.md](docs/publisher/catalog/inappproducts.md) |
| `client.VoidedPurchases` | 已撤销购买列表（欺诈 / 退款审计） | [purchases/voidedpurchases.md](docs/publisher/purchases/voidedpurchases.md) |
| `client.OneTimeProducts` | 一次性商品（新接口）+ purchaseOptions + offers | [catalog/monetization-onetimeproducts.md](docs/publisher/catalog/monetization-onetimeproducts.md) |
| `client.MonetizationSubscriptions` | 订阅商品（新接口）+ basePlans + offers + 区域定价 | [catalog/monetization-subscriptions.md](docs/publisher/catalog/monetization-subscriptions.md) |
| `client.Reviews` | 用户评论查询与回复 | [console/reviews.md](docs/publisher/console/reviews.md) |
| `client.Users` / `client.Grants` | Play Console 成员与应用授权 | [console/users-grants.md](docs/publisher/console/users-grants.md) |
| `client.ExternalTransactions` | 替代计费 / 用户选择计费交易 | [console/externaltransactions.md](docs/publisher/console/externaltransactions.md) |
| `client.Applications` | 数据安全、设备层级配置、跨轨道发布 | [publishing/applications.md](docs/publisher/publishing/applications.md) |
| `client.AppRecovery` | 应用恢复（回滚、定向、灰度部署） | [publishing/apprecovery.md](docs/publisher/publishing/apprecovery.md) |
| `client.GeneratedAPKs` / `client.SystemAPKs` | Play 生成的分发件与系统镜像变体 | [publishing/generatedapks-systemapks.md](docs/publisher/publishing/generatedapks-systemapks.md) |
| `client.InternalAppSharing` | 内部共享链接的 APK / AAB 上传 | [publishing/internalappsharing.md](docs/publisher/publishing/internalappsharing.md) |
| `client.Edits` | 完整的编辑会话生命周期（APK/Bundle/track/listing/...） | [publishing/edits.md](docs/publisher/publishing/edits.md) |

顶层还提供 `client.Verify(ctx, VerifyRequest)` 统一购买验证入口，以及 [RTDN 监听](docs/rtdn/rtdn.md) 与 [Google Pay Token 解密](docs/pay/pay.md)。

## 错误处理

所有子包均导出命名哨兵错误，推荐使用 `errors.Is` 判别：

```go
import (
    "errors"

    "github.com/godrealms/go-google-sdk/android/publisher/purchases"
)

_, err := client.Purchases.Query(ctx, "com.example.app", "", "token")
switch {
case errors.Is(err, purchases.ErrMissingProductID):
    // 请求缺少商品 ID，属于调用方参数错误
case errors.Is(err, purchases.ErrServiceNil):
    // 客户端未初始化
case err != nil:
    // Google API 返回的 *googleapi.Error 等业务错误
}
```

常见错误约定：

| 错误 | 触发场景 |
|---|---|
| `ErrServiceNil` | 子服务或其内部 `*androidpublisher.Service` 为 nil |
| `ErrMissingPackageName` | 未提供 `packageName` |
| `ErrMissingProductID` / `ErrMissingSubscriptionID` / `ErrMissingToken` | 相关路径参数缺失 |
| `ErrMissingOrderID` | 订单级接口缺 `orderId` |
| `ErrMissingMedia` / `ErrMissingVersion` / `ErrMissingVariantID` | 上传 / 版本相关接口参数缺失 |
| `ErrMissingRequest` / `ErrMissingBody` | 必填的请求体为空 |

Google API 层返回的 HTTP 错误仍为 `*googleapi.Error`，可进一步读取 `Code`、`Message`、`Errors[]` 等字段。

### 3. Google Pay 支付处理

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
errCh := make(chan error, 1)
go publisher.StartSubscriptionMonitor(ctx, config, errCh, func(ctx context.Context, msg *pubsub.Message) {
    // 处理通知
    msg.Ack()
})
// 在另一个 goroutine 中监听错误
go func() {
    if err := <-errCh; err != nil {
        log.Printf("RTDN 监听器错误: %v", err)
    }
}()
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

> 📖 每个子模块的完整使用示例见 [`docs/publisher/`](docs/publisher/README.md)。

### Google Play Publisher

| 子包 | 方法 |
|---|---|
| `client.Purchases` | `Acknowledge`, `Consume`, `Query`, `GetV2`, `Refund` |
| `client.Subscriptions` | `Query`（v2/v1）, `Acknowledge`, `Cancel`, `Defer`, `Revoke`, `RevokeV2`, `Refund` |
| `client.Orders` | `Get`, `Refund`, `BatchGet` |
| `client.InAppProducts` | `List`, `Get`, `Insert`, `Update`, `Delete`, `BatchGet`, `BatchUpdate`, `BatchDelete` |
| `client.VoidedPurchases` | `List` |
| `client.OneTimeProducts` | `Get`, `List`, `Patch`, `Delete`, `BatchGet`, `BatchUpdate`, `BatchDelete`, `PurchaseOptions.*`, `PurchaseOptions.Offers.*` |
| `client.MonetizationSubscriptions` | `Get`, `List`, `Create`, `Patch`, `Delete`, `Archive`, `BatchGet`, `BatchUpdate`, `ConvertRegionPrices`, `BasePlans.*`, `BasePlans.Offers.*` |
| `client.Reviews` | `Get`, `List`, `Reply` |
| `client.Users` | `Create`, `List`, `Patch`, `Delete` |
| `client.Grants` | `Create`, `Patch`, `Delete` |
| `client.ExternalTransactions` | `Create`, `Get`, `Refund` |
| `client.Applications` | `DataSafety`, `CreateDeviceTierConfig`, `GetDeviceTierConfig`, `ListDeviceTierConfigs`, `ListTrackReleases` |
| `client.AppRecovery` | `AddTargeting`, `Cancel`, `Create`, `Deploy`, `List` |
| `client.GeneratedAPKs` | `Download`, `List` |
| `client.SystemAPKs` | `Create`, `Get`, `List`, `Download` |
| `client.InternalAppSharing` | `UploadAPK`, `UploadBundle` |
| `client.Edits` | `Commit`, `Delete`, `Get`, `Insert`, `Validate`, `Apks.*`, `Bundles.*`, `CountryAvailability.*`, `DeobfuscationFiles.*`, `Details.*`, `ExpansionFiles.*`, `Images.*`, `Listings.*`, `Testers.*`, `Tracks.*` |
| `client`（顶层） | `Verify`（统一路由） |

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

本项目采用 [Apache License 2.0](LICENSE) 开源协议。

## 更新日志

### v0.0.6（2026-04-17）

#### 变更要点

- ✨ 新增 `reviews` 子包：用户评论 `Get` / `List` / `Reply`
- ✨ 新增 `users` 与 `grants` 子包：Play Console 用户与权限管理
- ✨ 新增 `externaltransactions` 子包：外部交易 `Create` / `Get` / `Refund`
- ✨ 新增 `applications` 子包：`DataSafety`、`DeviceTierConfigs` CRUD、跨轨道 `ListTrackReleases`
- ✨ 新增 `apprecovery` 子包：`AddTargeting` / `Cancel` / `Create` / `Deploy` / `List`
- ✨ 新增 `generatedapks`、`systemapks`、`internalappsharing` 三个分发子包（Download / Upload / CRUD）
- ✨ 新增 `edits` 子包：完整覆盖 `edits` 生命周期（`Commit` / `Delete` / `Get` / `Insert` / `Validate`）以及 `apks`、`bundles`、`countryAvailability`、`deobfuscationFiles`、`details`、`expansionFiles`、`images`、`listings`、`testers`、`tracks` 全部嵌套资源
- ➕ 补齐 `subscriptions.CancelV2` 与 `subscriptions.DeferV2`
- 🔌 顶层 `Client` 注入全部新子服务字段

### v0.0.5（2026-04-17）

#### 变更要点

- ✅ 新增 `purchases.GetV2`（productsv2 端点，仅按 token 查询）
- ✅ 补齐 `subscriptions.Acknowledge` / `Cancel` / `Defer` / `Revoke` / `RevokeV2` 全生命周期管理
- ✅ `orders.Refund` 新增 `revoke` 参数；新增 `orders.BatchGet`
- ✅ 新增 `inappproducts.BatchDelete` 批量删除
- ✨ 新增 `monetization/onetimeproducts` 子包：一次性商品 CRUD、`purchaseOptions`、`purchaseOptions.offers` 全量方法
- ✨ 新增 `monetization/subscriptions` 子包：订阅商品 CRUD + Archive、`basePlans`、`basePlans.offers`、`ConvertRegionPrices` 定价换算
- 🔌 `client.OneTimeProducts` 与 `client.MonetizationSubscriptions` 已纳入顶层 `Client`
- ⬆️ 升级 `google.golang.org/api` v0.243.0 → v0.276.0（Go 工具链升级到 1.25.0）

#### 版本元信息

- 🧪 验证：`go test ./...`

### v0.0.4（2026-04-17 / `0bacb4e0aeb3629e757404e1e58a780ec199c307`）

#### 变更要点

- ⚠️ **Breaking**: `publisher.Service` 重命名为 `publisher.Client`；构造函数 `NewService*` → `NewClient*`
- ⚠️ **Breaking**: `ErrNotFound` 已移除；`NewClient` 新增 `ctx` 参数；`StartSubscriptionMonitor` 新增 `ctx` + `errCh` 参数
- ✅ 新增 `purchases.Acknowledge`、`purchases.Consume`（确认/消费内购）
- ✅ 新增 `subscriptions.Query`（默认 v2，`UseV1: true` 可切换 v1）
- ✅ 新增 `inappproducts` 子包（完整 CRUD + BatchGet/BatchUpdate）
- ✅ 新增 `voidedpurchases` 子包（撤销购买列表）
- ✅ `Verify(OrderID-only)` 现在通过 Orders API 自动解析产品类型
- 🐛 修复 `NewClientWithTokenSource` 静默丢弃构造错误
- 🐛 修复 `StartSubscriptionMonitor` 调用 `log.Fatalf` 问题

#### 版本元信息

- 📌 发布提交：`0bacb4e0aeb3629e757404e1e58a780ec199c307`
- 📦 提交范围：`1e1cb1c..HEAD`
- 🧪 验证：`go test ./...`

### v0.0.3（2026-02-15 19:55:54 +08:00 / `ec50628`）

#### 变更要点

- ✅ 新增订单级/Token 级购买与订阅查询：`QueryPurchase`、`QuerySubscription`
- ✅ 增强混合输入校验（订单号与 token 组合）与测试覆盖
- ✅ 移除仓库内 `docs/` 目录

#### 版本元信息

- 📌 发布提交：`ec50628ecd5e15b9e29837b811d2c5a1387d5e5a`
- 📦 提交范围：`a0ca4e1..ec50628ecd5e15b9e29837b811d2c5a1387d5e5a`
- 🧪 验证：`go test ./...`
- 🔗 PR：[#2](https://github.com/WuJieOnce/go-google-sdk/pull/2)
- 🚀 发布说明：[`v0.0.3`](https://github.com/WuJieOnce/go-google-sdk/releases/tag/v0.0.3)

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
