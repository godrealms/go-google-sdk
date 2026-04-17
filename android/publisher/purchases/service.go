package purchases

import (
	"context"
	"errors"
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
		return errors.New("purchases: service is nil")
	}
	if packageName == "" {
		return errors.New("purchases: packageName is required")
	}
	if productID == "" {
		return errors.New("purchases: productID is required")
	}
	if purchaseToken == "" {
		return errors.New("purchases: purchaseToken is required")
	}
	return s.raw.Purchases.Products.Acknowledge(packageName, productID, purchaseToken,
		&androidpublisher.ProductPurchasesAcknowledgeRequest{}).Context(ctx).Do()
}

func (s *Service) Consume(ctx context.Context, packageName, productID, purchaseToken string) error {
	if s == nil || s.raw == nil {
		return errors.New("purchases: service is nil")
	}
	if packageName == "" {
		return errors.New("purchases: packageName is required")
	}
	if productID == "" {
		return errors.New("purchases: productID is required")
	}
	if purchaseToken == "" {
		return errors.New("purchases: purchaseToken is required")
	}
	return s.raw.Purchases.Products.Consume(packageName, productID, purchaseToken).Context(ctx).Do()
}

func (s *Service) Query(ctx context.Context, q PurchaseQuery) (*androidpublisher.Order, *androidpublisher.ProductPurchase, error) {
	if s == nil || s.raw == nil {
		return nil, nil, errors.New("purchases: service is nil")
	}
	if q.PackageName == "" {
		return nil, nil, errors.New("purchases: packageName is required")
	}
	if q.OrderID != "" && (q.ProductID != "" || q.PurchaseToken != "") {
		return nil, nil, ErrMixedOrderProductInput
	}
	if q.OrderID != "" {
		order, err := s.raw.Orders.Get(q.PackageName, q.OrderID).Context(ctx).Do()
		if err != nil {
			return nil, nil, err
		}
		return order, nil, nil
	}
	if q.ProductID == "" || q.PurchaseToken == "" {
		return nil, nil, errors.New("purchases: productID and purchaseToken are required")
	}
	purchase, err := s.raw.Purchases.Products.Get(q.PackageName, q.ProductID, q.PurchaseToken).Context(ctx).Do()
	if err != nil {
		return nil, nil, err
	}
	return nil, purchase, nil
}

func (s *Service) Refund(ctx context.Context, packageName, orderID string) error {
	if s == nil || s.raw == nil {
		return errors.New("purchases: service is nil")
	}
	if packageName == "" {
		return errors.New("purchases: packageName is required")
	}
	if orderID == "" {
		return errors.New("purchases: orderID is required")
	}
	if err := s.raw.Orders.Refund(packageName, orderID).Context(ctx).Do(); err != nil {
		return fmt.Errorf("purchases: refund failed: %w", err)
	}
	return nil
}

// Deprecated: Use the parent Client.Verify instead.
func (s *Service) VerifyPurchase(ctx context.Context, packageName, productID, purchaseToken string) (*androidpublisher.ProductPurchase, error) {
	purchase, err := s.raw.Purchases.Products.Get(packageName, productID, purchaseToken).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	if purchase.PurchaseState == 0 { // PurchaseState: 0 = purchased, 1 = canceled
		return purchase, nil
	}
	return purchase, fmt.Errorf("purchases: purchase not valid")
}
