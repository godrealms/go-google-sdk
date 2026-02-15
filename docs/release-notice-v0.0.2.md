# v0.0.2 发布公告 / Release Notes

## 中文

我们发布了 go-google-sdk v0.0.2，主要更新如下：

- 新增 `RefundPurchase(ctx, packageName, orderID)`：支持订单级退款（Android Publisher Orders API）。
- 新增 `RefundSubscription(ctx, packageName, subscriptionID, purchaseToken)`：支持订阅退款（Android Publisher Purchases.Subscriptions API）。
- 完善测试：新增退款功能的参数校验、成功/失败、请求方法与路径校验用例。
- 更新 `README.md` 中 Google Play Publisher API 列表。

### 安装 / 引用

```bash
go get github.com/godrealms/go-google-sdk@v0.0.2
```

## English

go-google-sdk `v0.0.2` is now available with the following updates:

- Added `RefundPurchase(ctx, packageName, orderID)`: support for order-level refunds via Android Publisher Orders API.
- Added `RefundSubscription(ctx, packageName, subscriptionID, purchaseToken)`: support for subscription refunds via Android Publisher Purchases.Subscriptions API.
- Expanded test coverage with input validation, success/failure, and request method/path assertions for refund flows.
- Updated `README.md` API reference for Google Play Publisher.

### Install

```bash
```
