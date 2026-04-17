package inappproducts

import (
	"errors"

	"google.golang.org/api/androidpublisher/v3"
)

var (
	ErrServiceNil         = errors.New("inappproducts: service is nil")
	ErrMissingPackageName = errors.New("inappproducts: packageName is required")
	ErrMissingSKU         = errors.New("inappproducts: sku is required")
	ErrMissingRequest     = errors.New("inappproducts: request is required")
)

// ListOption configures an inappproducts list call.
type ListOption func(*androidpublisher.InappproductsListCall)

// WithMaxResults limits the number of results returned.
func WithMaxResults(n int64) ListOption {
	return func(c *androidpublisher.InappproductsListCall) {
		c.MaxResults(n)
	}
}

// WithToken sets the pagination token for the next page.
func WithToken(token string) ListOption {
	return func(c *androidpublisher.InappproductsListCall) {
		c.Token(token)
	}
}
