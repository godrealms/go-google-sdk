package publisher

import "errors"

var (
	ErrRouteUnknown                = errors.New("publisher: cannot determine verification type")
	ErrMissingPackageName          = errors.New("publisher: package name is required")
	ErrMissingPurchaseToken        = errors.New("publisher: purchase token is required")
	ErrMissingProductID            = errors.New("publisher: product ID is required")
	ErrMissingSubscriptionID       = errors.New("publisher: subscription ID is required")
	ErrMissingOrderID              = errors.New("publisher: order ID is required")
	ErrMixedOrderProductInput      = errors.New("publisher: order ID and product ID are mutually exclusive")
	ErrMixedOrderSubscriptionInput = errors.New("publisher: order ID and subscription ID are mutually exclusive")
)
