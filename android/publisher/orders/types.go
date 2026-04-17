package orders

import "errors"

var (
	ErrServiceNil         = errors.New("orders: service is nil")
	ErrMissingPackageName = errors.New("orders: packageName is required")
	ErrMissingOrderID     = errors.New("orders: orderID is required")
)
