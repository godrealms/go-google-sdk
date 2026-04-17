package publisher

type Config struct {
	ProjectID      string `json:",omitempty"` // 项目ID
	SubscriptionID string `json:",omitempty"` // 订阅ID
	JsonKey        string `json:",omitempty"` // JsonKey路径地址
}
