package subscriptions

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

func (s *Service) Query(ctx context.Context, q SubscriptionQuery) (*SubscriptionResult, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if q.PackageName == "" {
		return nil, ErrMissingPackageName
	}
	if q.PurchaseToken == "" {
		return nil, ErrMissingPurchaseToken
	}
	if q.UseV1 {
		if q.SubscriptionID == "" {
			return nil, ErrMissingSubscriptionID
		}
		purchase, err := s.raw.Purchases.Subscriptions.Get(q.PackageName, q.SubscriptionID, q.PurchaseToken).Context(ctx).Do()
		if err != nil {
			return nil, err
		}
		return &SubscriptionResult{V1: purchase}, nil
	}
	purchase, err := s.raw.Purchases.Subscriptionsv2.Get(q.PackageName, q.PurchaseToken).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	return &SubscriptionResult{V2: purchase}, nil
}

func (s *Service) Refund(ctx context.Context, packageName, subscriptionID, purchaseToken string) error {
	if s == nil || s.raw == nil {
		return ErrServiceNil
	}
	if packageName == "" {
		return ErrMissingPackageName
	}
	if subscriptionID == "" {
		return ErrMissingSubscriptionID
	}
	if purchaseToken == "" {
		return ErrMissingPurchaseToken
	}
	if err := s.raw.Purchases.Subscriptions.Refund(packageName, subscriptionID, purchaseToken).Context(ctx).Do(); err != nil {
		return fmt.Errorf("subscriptions: refund failed: %w", err)
	}
	return nil
}

// Deprecated: Use the parent Client.Verify instead. The validity check in this
// method is incorrect — an unacknowledged-but-valid new subscription will be
// reported as invalid.
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
