package subscriptions

import (
	"errors"

	"google.golang.org/api/androidpublisher/v3"
)

var (
	ErrServiceNil              = errors.New("subscriptions: service is nil")
	ErrMissingPackageName      = errors.New("subscriptions: packageName is required")
	ErrMissingSubscriptionID   = errors.New("subscriptions: subscriptionID is required")
	ErrMissingPurchaseToken    = errors.New("subscriptions: purchaseToken is required")
)

type SubscriptionQuery struct {
	PackageName    string
	SubscriptionID string
	PurchaseToken  string
	UseV1          bool // true → use v1 Purchases.Subscriptions API instead of v2
}

type SubscriptionResult struct {
	V1 *androidpublisher.SubscriptionPurchase   // non-nil when UseV1=true
	V2 *androidpublisher.SubscriptionPurchaseV2 // non-nil by default
}
