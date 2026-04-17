package subscriptions

import (
	"errors"

	"google.golang.org/api/androidpublisher/v3"
)

var ErrMixedOrderSubscriptionInput = errors.New("subscriptions: orderID and subscriptionID are mutually exclusive")

type SubscriptionQuery struct {
	PackageName    string
	SubscriptionID string
	PurchaseToken  string
	OrderID        string
	UseV1          bool // true → use v1 Purchases.Subscriptions API instead of v2
}

type SubscriptionResult struct {
	V1 *androidpublisher.SubscriptionPurchase   // non-nil when UseV1=true
	V2 *androidpublisher.SubscriptionPurchaseV2 // non-nil by default
}
