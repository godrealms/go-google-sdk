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

func (s *Service) Acknowledge(ctx context.Context, packageName, subscriptionID, purchaseToken string) error {
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
	if err := s.raw.Purchases.Subscriptions.Acknowledge(packageName, subscriptionID, purchaseToken, &androidpublisher.SubscriptionPurchasesAcknowledgeRequest{}).Context(ctx).Do(); err != nil {
		return fmt.Errorf("subscriptions: acknowledge failed: %w", err)
	}
	return nil
}

func (s *Service) Cancel(ctx context.Context, packageName, subscriptionID, purchaseToken string) error {
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
	if err := s.raw.Purchases.Subscriptions.Cancel(packageName, subscriptionID, purchaseToken).Context(ctx).Do(); err != nil {
		return fmt.Errorf("subscriptions: cancel failed: %w", err)
	}
	return nil
}

func (s *Service) Defer(ctx context.Context, packageName, subscriptionID, purchaseToken string, req *androidpublisher.SubscriptionPurchasesDeferRequest) (*androidpublisher.SubscriptionPurchasesDeferResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if subscriptionID == "" {
		return nil, ErrMissingSubscriptionID
	}
	if purchaseToken == "" {
		return nil, ErrMissingPurchaseToken
	}
	if req == nil {
		req = &androidpublisher.SubscriptionPurchasesDeferRequest{}
	}
	resp, err := s.raw.Purchases.Subscriptions.Defer(packageName, subscriptionID, purchaseToken, req).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("subscriptions: defer failed: %w", err)
	}
	return resp, nil
}

func (s *Service) Revoke(ctx context.Context, packageName, subscriptionID, purchaseToken string) error {
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
	if err := s.raw.Purchases.Subscriptions.Revoke(packageName, subscriptionID, purchaseToken).Context(ctx).Do(); err != nil {
		return fmt.Errorf("subscriptions: revoke failed: %w", err)
	}
	return nil
}

func (s *Service) CancelV2(ctx context.Context, packageName, purchaseToken string, req *androidpublisher.CancelSubscriptionPurchaseRequest) (*androidpublisher.CancelSubscriptionPurchaseResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if purchaseToken == "" {
		return nil, ErrMissingPurchaseToken
	}
	if req == nil {
		req = &androidpublisher.CancelSubscriptionPurchaseRequest{}
	}
	resp, err := s.raw.Purchases.Subscriptionsv2.Cancel(packageName, purchaseToken, req).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("subscriptions: cancel v2 failed: %w", err)
	}
	return resp, nil
}

func (s *Service) DeferV2(ctx context.Context, packageName, purchaseToken string, req *androidpublisher.DeferSubscriptionPurchaseRequest) (*androidpublisher.DeferSubscriptionPurchaseResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if purchaseToken == "" {
		return nil, ErrMissingPurchaseToken
	}
	if req == nil {
		req = &androidpublisher.DeferSubscriptionPurchaseRequest{}
	}
	resp, err := s.raw.Purchases.Subscriptionsv2.Defer(packageName, purchaseToken, req).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("subscriptions: defer v2 failed: %w", err)
	}
	return resp, nil
}

func (s *Service) RevokeV2(ctx context.Context, packageName, purchaseToken string, req *androidpublisher.RevokeSubscriptionPurchaseRequest) error {
	if s == nil || s.raw == nil {
		return ErrServiceNil
	}
	if packageName == "" {
		return ErrMissingPackageName
	}
	if purchaseToken == "" {
		return ErrMissingPurchaseToken
	}
	if req == nil {
		req = &androidpublisher.RevokeSubscriptionPurchaseRequest{}
	}
	if _, err := s.raw.Purchases.Subscriptionsv2.Revoke(packageName, purchaseToken, req).Context(ctx).Do(); err != nil {
		return fmt.Errorf("subscriptions: revoke v2 failed: %w", err)
	}
	return nil
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
