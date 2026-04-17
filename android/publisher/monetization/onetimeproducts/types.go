// Package onetimeproducts wraps the Google Play Publisher
// monetization.onetimeproducts API surface (OneTimeProduct CRUD +
// purchaseOptions + purchaseOptions.offers).
package onetimeproducts

import "errors"

var (
	ErrServiceNil             = errors.New("onetimeproducts: service is nil")
	ErrMissingPackageName     = errors.New("onetimeproducts: packageName is required")
	ErrMissingProductID       = errors.New("onetimeproducts: productID is required")
	ErrMissingPurchaseOptionID = errors.New("onetimeproducts: purchaseOptionID is required")
	ErrMissingOfferID         = errors.New("onetimeproducts: offerID is required")
	ErrMissingRequest         = errors.New("onetimeproducts: request body is required")
	ErrMissingProduct         = errors.New("onetimeproducts: product body is required")
)

// ListOptions holds optional parameters for paginated listing.
type ListOptions struct {
	PageSize  int64
	PageToken string
}

// PatchOptions holds optional parameters for OneTimeProduct.Patch.
type PatchOptions struct {
	UpdateMask       string
	AllowMissing     bool
	LatencyTolerance string
	RegionsVersion   string
}

// DeleteOptions holds optional parameters for OneTimeProduct.Delete.
type DeleteOptions struct {
	LatencyTolerance string
}
