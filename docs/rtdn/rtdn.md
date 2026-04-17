# rtdn — Real-time Developer Notifications 监听器

`publisher.StartSubscriptionMonitor` 启动一个 Google Cloud Pub/Sub 客户端，订阅 Play Developer 配置的 RTDN Topic，把每条通知回调给调用方处理。

- Go 包路径: `github.com/godrealms/go-google-sdk/android/publisher`
- 底层依赖: `cloud.google.com/go/pubsub`

## Config

```go
type Config struct {
    ProjectID      string // GCP 项目 ID
    SubscriptionID string // Pub/Sub Subscription ID
    JsonKey        string // 服务账号 JSON 密钥内容或路径（见下）
}
```

当 `JsonKey` 非空时，SDK 会用它作为凭据 (`option.WithCredentialsJSON`) 初始化 Pub/Sub 客户端；否则使用 Application Default Credentials。

## StartSubscriptionMonitor

```go
func StartSubscriptionMonitor(
    ctx context.Context,
    config *Config,
    errCh chan<- error,
    fun func(ctx context.Context, msg *pubsub.Message),
)
```

阻塞直到 `ctx` 取消。任何初始化或接收错误会 push 到 `errCh`（若非 nil）。

## 快速示例

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

cfg := &publisher.Config{
    ProjectID:      "your-gcp-project",
    SubscriptionID: "play-rtdn-sub",
    JsonKey:        string(jsonKeyBytes),
}

errCh := make(chan error, 1)
go publisher.StartSubscriptionMonitor(ctx, cfg, errCh, func(ctx context.Context, msg *pubsub.Message) {
    decoded, err := base64.StdEncoding.DecodeString(string(msg.Data))
    if err != nil {
        msg.Nack()
        return
    }

    var n publisher.Notification
    if err := json.Unmarshal(decoded, &n); err != nil {
        msg.Nack()
        return
    }

    switch {
    case n.SubscriptionNotification != nil:
        _ = n.SubscriptionNotification.Process()
    case n.OneTimeProductNotification != nil:
        n.OneTimeProductNotification.Process()
    case n.VoidedPurchaseNotification != nil:
        // 处理作废事件
    case n.TestNotification != nil:
        _ = n.TestNotification.Process()
    }

    msg.Ack()
})

if err := <-errCh; err != nil {
    log.Printf("RTDN listener exited: %v", err)
}
```

## Notification 结构

```go
type Notification struct {
    Version                    string
    PackageName                string
    EventTimeMillis            int64
    OneTimeProductNotification *OneTimeProductNotification
    SubscriptionNotification   *SubscriptionNotification
    VoidedPurchaseNotification *VoidedPurchaseNotification
    TestNotification           *TestNotification
}
```

不同事件只会填充对应的指针，其余为 `nil`。常见 `SubscriptionNotification.NotificationType`：

- 1 RECOVERED / 2 RENEWED / 3 CANCELED / 4 PURCHASED
- 5 ON_HOLD / 6 IN_GRACE_PERIOD / 7 RESTARTED
- 12 REVOKED / 13 EXPIRED / 20 PENDING_PURCHASE_CANCELED

## 可靠性建议

- 处理函数务必在业务完成后再调用 `msg.Ack()`，失败走 `msg.Nack()`。
- 将 `StartSubscriptionMonitor` 放在单独 goroutine，并监听 `errCh` 用于告警 / 重启。
- 不要在回调里做长时间阻塞操作，推到工作队列处理。
