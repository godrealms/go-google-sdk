package purchases

import "errors"

var ErrMixedOrderProductInput = errors.New("purchases: orderID and productID are mutually exclusive")

type PurchaseQuery struct {
	PackageName   string
	ProductID     string
	PurchaseToken string
	OrderID       string
}
