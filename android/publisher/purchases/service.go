package purchases

import (
	"context"
	"fmt"

	"google.golang.org/api/androidpublisher/v3"
)

type Service struct {
	raw *androidpublisher.Service
}

func New(raw *androidpublisher.Service) *Service {
	return &Service{raw: raw}
}

func (s *Service) Acknowledge(ctx context.Context, packageName, productID, purchaseToken string) error {
	if s == nil || s.raw == nil {
		return ErrServiceNil
	}
	if packageName == "" {
		return ErrMissingPackageName
	}
	if productID == "" {
		return ErrMissingProductID
	}
	if purchaseToken == "" {
		return ErrMissingPurchaseToken
	}
	return s.raw.Purchases.Products.Acknowledge(packageName, productID, purchaseToken,
		&androidpublisher.ProductPurchasesAcknowledgeRequest{}).Context(ctx).Do()
}

func (s *Service) Consume(ctx context.Context, packageName, productID, purchaseToken string) error {
	if s == nil || s.raw == nil {
		return ErrServiceNil
	}
	if packageName == "" {
		return ErrMissingPackageName
	}
	if productID == "" {
		return ErrMissingProductID
	}
	if purchaseToken == "" {
		return ErrMissingPurchaseToken
	}
	return s.raw.Purchases.Products.Consume(packageName, productID, purchaseToken).Context(ctx).Do()
}

func (s *Service) Query(ctx context.Context, q PurchaseQuery) (*androidpublisher.ProductPurchase, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if q.PackageName == "" {
		return nil, ErrMissingPackageName
	}
	if q.ProductID == "" {
		return nil, ErrMissingProductID
	}
	if q.PurchaseToken == "" {
		return nil, ErrMissingPurchaseToken
	}
	return s.raw.Purchases.Products.Get(q.PackageName, q.ProductID, q.PurchaseToken).Context(ctx).Do()
}

// GetV2 retrieves a product purchase via the v2 endpoint. The v2 API does not
// require productID in the path — only packageName and purchaseToken.
func (s *Service) GetV2(ctx context.Context, packageName, purchaseToken string) (*androidpublisher.ProductPurchaseV2, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if purchaseToken == "" {
		return nil, ErrMissingPurchaseToken
	}
	return s.raw.Purchases.Productsv2.Getproductpurchasev2(packageName, purchaseToken).Context(ctx).Do()
}

func (s *Service) Refund(ctx context.Context, packageName, orderID string) error {
	if s == nil || s.raw == nil {
		return ErrServiceNil
	}
	if packageName == "" {
		return ErrMissingPackageName
	}
	if orderID == "" {
		return ErrMissingOrderID
	}
	if err := s.raw.Orders.Refund(packageName, orderID).Context(ctx).Do(); err != nil {
		return fmt.Errorf("purchases: refund failed: %w", err)
	}
	return nil
}

// Deprecated: Use the parent Client.Verify instead. The validity check in this
// method is simplistic and does not reflect the full purchase lifecycle.
func (s *Service) VerifyPurchase(ctx context.Context, packageName, productID, purchaseToken string) (*androidpublisher.ProductPurchase, error) {
	purchase, err := s.raw.Purchases.Products.Get(packageName, productID, purchaseToken).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	if purchase.PurchaseState == 0 { // 0 = purchased, 1 = canceled
		return purchase, nil
	}
	return purchase, fmt.Errorf("purchases: purchase not valid")
}
