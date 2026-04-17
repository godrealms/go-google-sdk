package purchases

import "errors"

var (
	ErrServiceNil           = errors.New("purchases: service is nil")
	ErrMissingPackageName   = errors.New("purchases: packageName is required")
	ErrMissingProductID     = errors.New("purchases: productID is required")
	ErrMissingPurchaseToken = errors.New("purchases: purchaseToken is required")
	ErrMissingOrderID       = errors.New("purchases: orderID is required")
)

type PurchaseQuery struct {
	PackageName   string
	ProductID     string
	PurchaseToken string
}
