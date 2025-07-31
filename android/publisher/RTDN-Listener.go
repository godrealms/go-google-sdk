package publisher

import (
	"cloud.google.com/go/pubsub"
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
)

type Notification struct {
	Version                    string                      `json:"version"`
	PackageName                string                      `json:"packageName"`
	EventTimeMillis            int64                       `json:"eventTimeMillis"`
	OneTimeProductNotification *OneTimeProductNotification `json:"oneTimeProductNotification,omitempty"`
	SubscriptionNotification   *SubscriptionNotification   `json:"subscriptionNotification,omitempty"`
	VoidedPurchaseNotification *VoidedPurchaseNotification `json:"voidedPurchaseNotification,omitempty"`
	TestNotification           *TestNotification           `json:"testNotification,omitempty"`
}

type OneTimeProductNotification struct {
	Version          string `json:"version"`          // 此通知的版本。最初，此值为“1.0”。此版本与其他版本字段不同。
	NotificationType int    `json:"notificationType"` // 通知的类型。它可以具有以下值：
	PurchaseToken    string `json:"purchaseToken"`    // 购买时向用户设备提供的令牌。
	Sku              string `json:"sku"`              // 购买的一次性商品的商品 ID（例如“sword_001”）。
}

func (n *OneTimeProductNotification) Process() {

}

type SubscriptionNotification struct {
	Version          string `json:"version"`          // 此通知的版本。最初，此值为“1.0”。此版本与其他版本字段不同。
	NotificationType int    `json:"notificationType"` // 订阅的 notificationType 可以具有以下值：
	// (1) SUBSCRIPTION_RECOVERED - 从账号保留状态恢复了订阅。
	// (2) SUBSCRIPTION_RENEWED - 续订了处于活动状态的订阅。
	// (3) SUBSCRIPTION_CANCELED - 自愿或非自愿地取消了订阅。如果是自愿取消，在用户取消时发送。
	// (4) SUBSCRIPTION_PURCHASED - 购买了新的订阅。
	// (5) SUBSCRIPTION_ON_HOLD - 订阅已进入账号保留状态（如果已启用）。
	// (6) SUBSCRIPTION_IN_GRACE_PERIOD - 订阅已进入宽限期（如果已启用）。
	// (7) SUBSCRIPTION_RESTARTED - 用户已通过 Play > 账号 > 订阅恢复了订阅。订阅已取消，但在用户恢复时尚未到期。如需了解详情，请参阅恢复。
	// (8) SUBSCRIPTION_PRICE_CHANGE_CONFIRMED - 用户已成功确认订阅价格变动。
	// (9) SUBSCRIPTION_DEFERRED - 订阅的续订时间点已延期。
	// (10) SUBSCRIPTION_PAUSED - 订阅已暂停。
	// (11) SUBSCRIPTION_PAUSE_SCHEDULE_CHANGED - 订阅暂停计划已更改。
	// (12) SUBSCRIPTION_REVOKED - 用户在到期时间之前已撤消订阅。
	// (13) SUBSCRIPTION_EXPIRED - 订阅已到期。
	// (20) SUBSCRIPTION_PENDING_PURCHASE_CANCELED - 待处理的交易 项订阅已取消。
	PurchaseToken  string `json:"purchaseToken"`  // 购买订阅时向用户设备提供的令牌。
	SubscriptionId string `json:"subscriptionId"` // 所购买订阅的商品 ID（例如“monthly001”）。
}

func (n *SubscriptionNotification) Process(packName string) error {
	return nil
}

type VoidedPurchaseNotification struct {
	PurchaseToken string `json:"purchaseToken"` // 与作废的购买交易关联的令牌。当有新的购买交易发生时，系统会向开发者提供此信息。
	OrderId       string `json:"orderId"`       // 与作废的交易关联的唯一订单 ID。对于一次性购买，此字段代表了为这笔购买交易生成的唯一订单 ID。对于自动续订型订阅，系统会为每笔续订交易生成一个新的订单 ID。
	ProductType   int    `json:"productType"`   // 作废的购买交易的 productType 可以具有以下值：
	RefundType    int    `json:"refundType"`    // 作废的购买交易的 refundType 可以具有以下值：
}

type TestNotification struct {
	Version string `json:"version"` // 此通知的版本。最初，此值为“1.0”。此版本与其他版本字段不同。
}

func (n *TestNotification) Process() error {
	return nil
}

// StartSubscriptionMonitor 启动订阅监控器 Set your Google Cloud project ID and subscription ID
func StartSubscriptionMonitor(config *Config) {
	if config == nil {
		return
	}
	// 设置 GOOGLE_APPLICATION_CREDENTIALS 环境变量，指向服务账号 JSON 文件
	// export GOOGLE_APPLICATION_CREDENTIALS="/path/to/your-service-account-key.json"
	ctx := context.Background()
	client, err := pubsub.NewClient(ctx, config.ProjectID) // Initialize Pub/Sub client
	if err != nil {
		return
	}
	defer client.Close()

	// Get the subscription
	sub := client.Subscription(config.SubscriptionID)

	// Start receiving messages
	err = sub.Receive(ctx, func(ctx context.Context, msg *pubsub.Message) {
		// Decode the Base64 encoded message
		decodedData, errs := base64.StdEncoding.DecodeString(string(msg.Data))
		if errs != nil {
			msg.Nack() // Negative acknowledgment
			return
		}

		// Parse the JSON message
		var notification Notification
		if err = json.Unmarshal(decodedData, &notification); err != nil {
			msg.Nack() // 否定确认
			return
		}

		if notification.OneTimeProductNotification != nil { // 一次性购买处理
			notification.OneTimeProductNotification.Process()
		}
		if notification.SubscriptionNotification != nil { // 订阅通知处理
			err = notification.SubscriptionNotification.Process(notification.PackageName)
			if err != nil {
				msg.Nack() // 否定确认
				return
			}
		}
		if notification.VoidedPurchaseNotification != nil { // 无效购买通知处理
			notification.TestNotification.Process()
		}
		if notification.TestNotification != nil { // 测试通知处理\
			notification.TestNotification.Process()
		}

		msg.Ack() // 确认消息
	})
	if err != nil {
		log.Fatalf("Failed to receive messages: %v", err)
	}
}
