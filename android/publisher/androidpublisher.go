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

type PurchaseQuery struct {
	PackageName   string
	ProductID     string
	PurchaseToken string
	OrderID       string
}

type SubscriptionQuery struct {
	PackageName    string
	SubscriptionID string
	PurchaseToken  string
	OrderID        string
}

func (s *Service) QueryPurchase(ctx context.Context, q PurchaseQuery) (*androidpublisher.Order, *androidpublisher.ProductPurchase, error) {
	if s == nil || s.Androidpublisher == nil {
		return nil, nil, errors.New("service is nil")
	}
	if q.PackageName == "" {
		return nil, nil, errors.New("packageName is required")
	}
	if q.OrderID != "" {
		order, err := s.Androidpublisher.Orders.Get(q.PackageName, q.OrderID).Context(ctx).Do()
		if err != nil {
			return nil, nil, err
		}
		return order, nil, nil
	}
	if q.ProductID == "" || q.PurchaseToken == "" {
		return nil, nil, errors.New("productID and purchaseToken are required")
	}
	purchase, err := s.Androidpublisher.Purchases.Products.Get(q.PackageName, q.ProductID, q.PurchaseToken).Context(ctx).Do()
	if err != nil {
		return nil, nil, err
	}
	return nil, purchase, nil
}

func (s *Service) QuerySubscription(ctx context.Context, q SubscriptionQuery) (*androidpublisher.Order, *androidpublisher.SubscriptionPurchase, error) {
	if s == nil || s.Androidpublisher == nil {
		return nil, nil, errors.New("service is nil")
	}
	if q.PackageName == "" {
		return nil, nil, errors.New("packageName is required")
	}
	if q.OrderID != "" {
		order, err := s.Androidpublisher.Orders.Get(q.PackageName, q.OrderID).Context(ctx).Do()
		if err != nil {
			return nil, nil, err
		}
		return order, nil, nil
	}
	if q.SubscriptionID == "" || q.PurchaseToken == "" {
		return nil, nil, errors.New("subscriptionID and purchaseToken are required")
	}
	purchase, err := s.Androidpublisher.Purchases.Subscriptions.Get(q.PackageName, q.SubscriptionID, q.PurchaseToken).Context(ctx).Do()
	if err != nil {
		return nil, nil, err
	}
	return nil, purchase, nil
}

func (s *Service) Verify(ctx context.Context, req VerifyRequest) (*VerifyResult, error) {
	if s == nil || s.Androidpublisher == nil {
		return nil, errors.New("service is nil")
	}
	if req.PackageName == "" {
		return nil, errors.New("packageName is required")
	}

	resolved := req.Type
	if resolved == "" {
		switch {
		case req.SubscriptionID != "":
			resolved = VerifyTypeSubscription
		case req.ProductID != "":
			resolved = VerifyTypeProduct
		case req.OrderID != "":
			return nil, ErrRouteUnknown
		default:
			return nil, ErrRouteUnknown
		}
	}

	switch resolved {
	case VerifyTypeSubscription:
		order, purchase, err := s.QuerySubscription(ctx, SubscriptionQuery{
			PackageName:    req.PackageName,
			SubscriptionID: req.SubscriptionID,
			PurchaseToken:  req.PurchaseToken,
			OrderID:        req.OrderID,
		})
		if err != nil {
			return nil, err
		}
		if order != nil {
			return &VerifyResult{Type: VerifyTypeSubscription, Raw: order}, nil
		}
		return &VerifyResult{Type: VerifyTypeSubscription, Raw: purchase}, nil
	case VerifyTypeProduct:
		order, purchase, err := s.QueryPurchase(ctx, PurchaseQuery{
			PackageName:   req.PackageName,
			ProductID:     req.ProductID,
			PurchaseToken: req.PurchaseToken,
			OrderID:       req.OrderID,
		})
		if err != nil {
			return nil, err
		}
		if order != nil {
			return &VerifyResult{Type: VerifyTypeProduct, Raw: order}, nil
		}
		return &VerifyResult{Type: VerifyTypeProduct, Raw: purchase}, nil
	default:
		return nil, ErrRouteUnknown
	}
}

func (s *Service) VerifyPurchase(packageName, productId, purchaseToken string) (*androidpublisher.ProductPurchase, error) {
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

// RefundPurchase 退款一次性购买订单。
//
// 注意：当前 Android Publisher V3 客户端提供订单级退款接口，参数为 orderId。
func (s *Service) RefundPurchase(ctx context.Context, packageName, orderID string) error {
	if s == nil {
		return errors.New("service is nil")
	}
	if s.Androidpublisher == nil {
		return errors.New("android publisher service is nil")
	}
	if packageName == "" {
		return errors.New("packageName is required")
	}
	if orderID == "" {
		return errors.New("orderID is required")
	}

	if err := s.Androidpublisher.Orders.Refund(packageName, orderID).Context(ctx).Do(); err != nil {
		return fmt.Errorf("refund purchase failed: %w", err)
	}

	return nil
}

// RefundSubscription 退款订阅。
func (s *Service) RefundSubscription(ctx context.Context, packageName, subscriptionID, purchaseToken string) error {
	if s == nil {
		return errors.New("service is nil")
	}
	if s.Androidpublisher == nil {
		return errors.New("android publisher service is nil")
	}
	if packageName == "" {
		return errors.New("packageName is required")
	}
	if subscriptionID == "" {
		return errors.New("subscriptionID is required")
	}
	if purchaseToken == "" {
		return errors.New("purchaseToken is required")
	}

	if err := s.Androidpublisher.Purchases.Subscriptions.Refund(packageName, subscriptionID, purchaseToken).Context(ctx).Do(); err != nil {
		return fmt.Errorf("refund subscription failed: %w", err)
	}

	return nil
}

func NewServiceWithTokenSource(ctx context.Context, config *oauth2.Config, code string, opts ...oauth2.AuthCodeOption) (*Service, error) {
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
