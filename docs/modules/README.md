# 子模块使用指南

本目录按子包提供详细的使用说明与 Go 代码示例。入口是顶层 `publisher.Client`（见 [`android/publisher/publisher.go`](../../android/publisher/publisher.go)）暴露的各子服务字段。

## Google Play Publisher

| 文档 | 子服务 / 包 | 简介 |
|---|---|---|
| [purchases.md](./purchases.md) | `client.Purchases` | 一次性内购查询、确认、消费、退款（v1 + v2） |
| [subscriptions.md](./subscriptions.md) | `client.Subscriptions` | 订阅查询与生命周期（v2 默认 + v1 回退） |
| [orders.md](./orders.md) | `client.Orders` | 订单 Get / Refund / BatchGet |
| [inappproducts.md](./inappproducts.md) | `client.InAppProducts` | 旧版 SKU 目录 CRUD + 批量操作 |
| [voidedpurchases.md](./voidedpurchases.md) | `client.VoidedPurchases` | 已撤销购买列表（欺诈检测） |
| [monetization-onetimeproducts.md](./monetization-onetimeproducts.md) | `client.OneTimeProducts` | 新版一次性商品目录 + purchaseOptions/offers |
| [monetization-subscriptions.md](./monetization-subscriptions.md) | `client.MonetizationSubscriptions` | 订阅 SKU 目录 + basePlans/offers + 定价换算 |
| [reviews.md](./reviews.md) | `client.Reviews` | 评论列表 / 单条 / 回复 |
| [users-grants.md](./users-grants.md) | `client.Users`, `client.Grants` | Play Console 用户与应用级授权 |
| [externaltransactions.md](./externaltransactions.md) | `client.ExternalTransactions` | 替代 / 用户选择结算的外部交易 |
| [applications.md](./applications.md) | `client.Applications` | 数据安全、DeviceTier、跨轨道发布摘要 |
| [apprecovery.md](./apprecovery.md) | `client.AppRecovery` | 应用紧急恢复（回滚 / 定向修复） |
| [generatedapks-systemapks.md](./generatedapks-systemapks.md) | `client.GeneratedAPKs`, `client.SystemAPKs` | 生成 / 系统 APK 列表与下载 |
| [internalappsharing.md](./internalappsharing.md) | `client.InternalAppSharing` | 内部应用分享产物上传 |
| [edits.md](./edits.md) | `client.Edits` | Edit 事务全生命周期 + 所有嵌套资源 |

## 其它模块

| 文档 | 说明 |
|---|---|
| [pay.md](./pay.md) | Google Pay Token 解密 (`payment.Client`) |
| [rtdn.md](./rtdn.md) | RTDN 监听器 `publisher.StartSubscriptionMonitor` |

## 顶层统一入口

`client.Verify(ctx, VerifyRequest)` 会根据输入自动路由到 `Orders.Get` / `Purchases.Query` / `Subscriptions.Query`，详见 [`publisher.go`](../../android/publisher/publisher.go) 中的 GoDoc。
