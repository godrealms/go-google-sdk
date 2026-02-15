package publisher

type VerifyType string

const (
	VerifyTypeProduct      VerifyType = "product"
	VerifyTypeSubscription VerifyType = "subscription"
)

type VerifyRequest struct {
	PackageName    string
	ProductID      string
	SubscriptionID string
	PurchaseToken  string
	OrderID        string
	Type           VerifyType
}

type VerifyResult struct {
	Type VerifyType
	Raw  any
}
