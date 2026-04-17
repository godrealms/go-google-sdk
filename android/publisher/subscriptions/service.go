package subscriptions

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

func (s *Service) Query(ctx context.Context, q SubscriptionQuery) (*androidpublisher.Order, *SubscriptionResult, error) {
	if s == nil || s.raw == nil {
		return nil, nil, errors.New("subscriptions: service is nil")
	}
	if q.PackageName == "" {
		return nil, nil, errors.New("subscriptions: packageName is required")
	}
	if q.OrderID != "" && (q.SubscriptionID != "" || q.PurchaseToken != "") {
		return nil, nil, ErrMixedOrderSubscriptionInput
	}
	if q.OrderID != "" {
		order, err := s.raw.Orders.Get(q.PackageName, q.OrderID).Context(ctx).Do()
		if err != nil {
			return nil, nil, err
		}
		return order, nil, nil
	}
	if q.SubscriptionID == "" || q.PurchaseToken == "" {
		return nil, nil, errors.New("subscriptions: subscriptionID and purchaseToken are required")
	}
	if q.UseV1 {
		purchase, err := s.raw.Purchases.Subscriptions.Get(q.PackageName, q.SubscriptionID, q.PurchaseToken).Context(ctx).Do()
		if err != nil {
			return nil, nil, err
		}
		return nil, &SubscriptionResult{V1: purchase}, nil
	}
	purchase, err := s.raw.Purchases.Subscriptionsv2.Get(q.PackageName, q.PurchaseToken).Context(ctx).Do()
	if err != nil {
		return nil, nil, err
	}
	return nil, &SubscriptionResult{V2: purchase}, nil
}

func (s *Service) Refund(ctx context.Context, packageName, subscriptionID, purchaseToken string) error {
	if s == nil || s.raw == nil {
		return errors.New("subscriptions: service is nil")
	}
	if packageName == "" {
		return errors.New("subscriptions: packageName is required")
	}
	if subscriptionID == "" {
		return errors.New("subscriptions: subscriptionID is required")
	}
	if purchaseToken == "" {
		return errors.New("subscriptions: purchaseToken is required")
	}
	if err := s.raw.Purchases.Subscriptions.Refund(packageName, subscriptionID, purchaseToken).Context(ctx).Do(); err != nil {
		return fmt.Errorf("subscriptions: refund failed: %w", err)
	}
	return nil
}

// Deprecated: Use the parent Client.Verify instead.
func (s *Service) VerifySubscriptions(ctx context.Context, packageName, subscriptionID, purchaseToken string) (*androidpublisher.SubscriptionPurchase, error) {
	purchase, err := s.raw.Purchases.Subscriptions.Get(packageName, subscriptionID, purchaseToken).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	if purchase.AcknowledgementState == 1 && purchase.PaymentState != nil { // AcknowledgementState: 0 = not acknowledged, 1 = acknowledged
		return purchase, nil
	}
	return purchase, fmt.Errorf("subscriptions: purchase not valid")
}
