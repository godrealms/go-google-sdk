package publisher

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/oauth2"
	"google.golang.org/api/androidpublisher/v3"
	"google.golang.org/api/option"
)

type Service struct {
	Androidpublisher *androidpublisher.Service
}

func (s *Service) VerifyPurchase(packageName, productId, purchaseToken string) (*androidpublisher.ProductPurchase, error) {
	if s == nil {
		return nil, errors.New("service is nil")
	}
	if s.Androidpublisher == nil {
		return nil, errors.New("androidpublisher service is nil")
	}
	if s.Androidpublisher.Purchases == nil || s.Androidpublisher.Purchases.Products == nil {
		return nil, errors.New("products service is unavailable")
	}

	// 验证购买
	purchase, err := s.Androidpublisher.Purchases.Products.Get(packageName, productId, purchaseToken).Do()
	if err != nil {
		return nil, err
	}

	// 检查购买状态
	if purchase.PurchaseState == 0 { // 0 = purchased, 1 = canceled
		return purchase, nil
	}

	return purchase, fmt.Errorf("purchase not valid")
}

func (s *Service) VerifySubscriptions(packageName, subscriptionId, purchaseToken string) (*androidpublisher.SubscriptionPurchase, error) {
	if s == nil {
		return nil, errors.New("service is nil")
	}
	if s.Androidpublisher == nil {
		return nil, errors.New("androidpublisher service is unavailable")
	}
	if s.Androidpublisher.Purchases == nil || s.Androidpublisher.Purchases.Subscriptions == nil {
		return nil, errors.New("subscriptions service is unavailable")
	}

	// 验证购买
	purchase, err := s.Androidpublisher.Purchases.Subscriptions.Get(packageName, subscriptionId, purchaseToken).Do()
	if err != nil {
		return nil, err
	}

	// 检查购买状态
	if purchase.AcknowledgementState == 1 && purchase.PaymentState != nil { // 0 = purchased, 1 = canceled
		return purchase, nil
	}

	return purchase, fmt.Errorf("purchase not valid")
}

func NewServiceWithTokenSource(ctx context.Context, config *oauth2.Config, code string, opts ...oauth2.AuthCodeOption) (*Service, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if config == nil {
		return nil, errors.New("config is nil")
	}
	token, err := config.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, err
	}
	androidpublisherService, err := androidpublisher.NewService(ctx, option.WithTokenSource(config.TokenSource(ctx, token)))

	service := &Service{
		Androidpublisher: androidpublisherService,
	}

	return service, nil
}

func NewServiceWithKey(ctx context.Context, APIKey string) (*Service, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if APIKey == "" {
		return nil, errors.New("api key is required")
	}

	// 使用服务账号密钥初始化客户端
	androidpublisherService, err := androidpublisher.NewService(ctx, option.WithAPIKey(APIKey))
	if err != nil {
		return nil, err
	}

	service := &Service{
		Androidpublisher: androidpublisherService,
	}

	return service, nil
}

func NewService(ctx context.Context, opts ...option.ClientOption) (*Service, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	// 使用服务账号密钥初始化客户端
	androidpublisherService, err := androidpublisher.NewService(ctx, opts...)
	if err != nil {
		return nil, err
	}

	service := &Service{
		Androidpublisher: androidpublisherService,
	}

	return service, nil
}
