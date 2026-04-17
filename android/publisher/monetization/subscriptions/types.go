// Package subscriptions wraps the Google Play Publisher
// monetization.subscriptions API (Subscription CRUD + basePlans +
// basePlans.offers) and the monetization.convertRegionPrices pricing endpoint.
package subscriptions

import "errors"

var (
	ErrServiceNil         = errors.New("monetization/subscriptions: service is nil")
	ErrMissingPackageName = errors.New("monetization/subscriptions: packageName is required")
	ErrMissingProductID   = errors.New("monetization/subscriptions: productID is required")
	ErrMissingBasePlanID  = errors.New("monetization/subscriptions: basePlanID is required")
	ErrMissingOfferID     = errors.New("monetization/subscriptions: offerID is required")
	ErrMissingRequest     = errors.New("monetization/subscriptions: request body is required")
	ErrMissingSubscription = errors.New("monetization/subscriptions: subscription body is required")
	ErrMissingOffer       = errors.New("monetization/subscriptions: offer body is required")
)

type ListOptions struct {
	PageSize     int64
	PageToken    string
	ShowArchived bool
}

type CreateOptions struct {
	RegionsVersion string
}

type PatchOptions struct {
	UpdateMask       string
	AllowMissing     bool
	LatencyTolerance string
	RegionsVersion   string
}

type DeleteOptions struct {
	LatencyTolerance string
}
