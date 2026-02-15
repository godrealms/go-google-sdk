# Android Publisher Refund Interface Design

## 目标

在 `android/publisher` 模块新增 `退款接口`，覆盖两类业务：

- 一次性/订单级退款
- 订阅退款

要求：接口风格与现有 `publisher.Service` 保持一致，优先兼容 Google Android Publisher API 的能力边界，并具备可测试性。

## 约束与边界

- 当前依赖的 `google.golang.org/api/androidpublisher/v3` 版本（`v0.243.0`）提供：
  - `Purchases.Subscriptions.Refund`（可用于订阅退款）
  - `Orders.Refund`（可通过订单 ID 退款）
  - `Purchases.Products` 当前无 `Refund` 调用（仅 `Get/Acknowledge/Consume`），因此一次性商品退款优先使用订单级退款入口。
- `orders` 退款支持 `revoke` 标记，后续可按需透出该参数。

## 设计方案

### 方案 A（推荐）

新增两个明确入口，分别实现可观测、可测试的退款动作：

1. `RefundPurchase(ctx context.Context, packageName, orderID string) error`
2. `RefundSubscription(ctx context.Context, packageName, subscriptionID, purchaseToken string) error`

优势：

- API 清晰、易用，和现有服务方法命名风格一致。
- 与现有验证方法相同的签名和返回语义（返回 `error`）。
- 便于后续扩展可选参数（例如 `RefundPurchaseWithRevoke`）而不破坏现有方法。

### 方案 B

新增单一泛化方法：`Refund(ctx, kind RefundTarget, req RefundRequest) error`。

取舍：

- 接口统一，但需要额外枚举与分支逻辑，短期内语义不如方案 A 直观。
- 用户调用负担更重，易错字段组合。

### 方案 C

仅新增订阅退款（不加一次性/订单退款）。

取舍：

- 实现最短，但不满足“退款接口”完整预期，可能后续再补充接口导致 API 演进成本更高。

## 代码设计

- 文件：`android/publisher/androidpublisher.go`
- 在 `Service` 上新增两个方法。
- 通过生成客户端调用 `s.Androidpublisher.Orders.Refund` 与 `s.Androidpublisher.Purchases.Subscriptions.Refund`。
- 两类方法都调用 `Context(ctx)`，让调用方可控制超时与取消。
- 对返回错误做统一包装（`fmt.Errorf`）以区分失败动作：
  - `refund purchase failed` / `refund subscription failed`
- 保持零行为变更原则：不改现有验证/监听/鉴权路径。

## 测试设计（TDD）

1. 先补齐失败/成功路径测试（红）
   - `TestService_RefundPurchase_ReturnsErrorOnEmptyOrderID`
   - `TestService_RefundPurchase_SucceedsOn2xxResponse`
   - `TestService_RefundSubscription_ReturnsErrorOnEmptyPackageName`
   - `TestService_RefundSubscription_SucceedsOn2xxResponse`

2. 使用 `httptest.NewServer` 搭建最小 HTTP 响应桩。

   - 用 `option.WithEndpoint(server.URL)` + `option.WithoutAuthentication()` 创建 `androidpublisher.Service`。
   - 模拟 200/4xx 响应分别验证成功和错误分支。

3. 覆盖 `revoke` 参数（可选）

   - 增加测试校验请求 URL/query：`/orders/{packageName}/:refund` 上 `revoke` 行为（默认 false，或通过未来扩展接口覆盖）。

4. 在实现后运行：

- `GOFLAGS=-mod=mod go test ./android/publisher`
- `GOFLAGS=-mod=mod go test ./...`

## 文档与发布

- 更新 `README.md` 的 API 表格，新增一项 `RefundPurchase` 与 `RefundSubscription`。
- 提交时附带变更说明到 `更新日志`。
