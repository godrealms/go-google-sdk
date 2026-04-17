# Publisher 子模块使用指南

本目录按功能域划分：`purchases/` 负责交易与验证、`catalog/` 负责商品目录、`publishing/` 负责发布与分发、`console/` 负责 Play Console 运营。入口是顶层 `publisher.Client`（见 [`android/publisher/publisher.go`](../../android/publisher/publisher.go)）暴露的各子服务字段。

## 交易与验证 (`purchases/`)

| 文档 | 子服务 | 简介 |
|---|---|---|
| [purchases/purchases.md](./purchases/purchases.md) | `client.Purchases` | 一次性内购查询、确认、消费、退款（v1 + v2） |
| [purchases/subscriptions.md](./purchases/subscriptions.md) | `client.Subscriptions` | 订阅查询与生命周期（v2 默认 + v1 回退） |
| [purchases/orders.md](./purchases/orders.md) | `client.Orders` | 订单 Get / Refund / BatchGet |
| [purchases/voidedpurchases.md](./purchases/voidedpurchases.md) | `client.VoidedPurchases` | 已撤销购买列表（欺诈检测） |

## 商品目录 (`catalog/`)

| 文档 | 子服务 | 简介 |
|---|---|---|
| [catalog/inappproducts.md](./catalog/inappproducts.md) | `client.InAppProducts` | 旧版 SKU 目录 CRUD + 批量操作 |
| [catalog/monetization-onetimeproducts.md](./catalog/monetization-onetimeproducts.md) | `client.OneTimeProducts` | 新版一次性商品目录 + purchaseOptions/offers |
| [catalog/monetization-subscriptions.md](./catalog/monetization-subscriptions.md) | `client.MonetizationSubscriptions` | 订阅 SKU 目录 + basePlans/offers + 定价换算 |

## 发布与分发 (`publishing/`)

| 文档 | 子服务 | 简介 |
|---|---|---|
| [publishing/edits.md](./publishing/edits.md) | `client.Edits` | Edit 事务全生命周期 + 所有嵌套资源 |
| [publishing/applications.md](./publishing/applications.md) | `client.Applications` | 数据安全、DeviceTier、跨轨道发布摘要 |
| [publishing/apprecovery.md](./publishing/apprecovery.md) | `client.AppRecovery` | 应用紧急恢复（回滚 / 定向修复） |
| [publishing/generatedapks-systemapks.md](./publishing/generatedapks-systemapks.md) | `client.GeneratedAPKs`, `client.SystemAPKs` | 生成 / 系统 APK 列表与下载 |
| [publishing/internalappsharing.md](./publishing/internalappsharing.md) | `client.InternalAppSharing` | 内部应用分享产物上传 |

## Play Console 运营 (`console/`)

| 文档 | 子服务 | 简介 |
|---|---|---|
| [console/reviews.md](./console/reviews.md) | `client.Reviews` | 评论列表 / 单条 / 回复 |
| [console/users-grants.md](./console/users-grants.md) | `client.Users`, `client.Grants` | Play Console 用户与应用级授权 |
| [console/externaltransactions.md](./console/externaltransactions.md) | `client.ExternalTransactions` | 替代 / 用户选择结算的外部交易 |

## 其它顶层模块

- Google Pay Token 解密：[`docs/pay/pay.md`](../pay/pay.md)
- RTDN 实时通知监听：[`docs/rtdn/rtdn.md`](../rtdn/rtdn.md)

## 顶层统一入口

`client.Verify(ctx, VerifyRequest)` 会根据输入自动路由到 `Orders.Get` / `Purchases.Query` / `Subscriptions.Query`，详见 [`publisher.go`](../../android/publisher/publisher.go) 中的 GoDoc。
