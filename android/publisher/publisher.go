package publisher

import (
	"context"
	"errors"

	"golang.org/x/oauth2"
	"google.golang.org/api/androidpublisher/v3"
	"google.golang.org/api/option"

	"github.com/godrealms/go-google-sdk/android/publisher/inappproducts"
	"github.com/godrealms/go-google-sdk/android/publisher/orders"
	"github.com/godrealms/go-google-sdk/android/publisher/purchases"
	"github.com/godrealms/go-google-sdk/android/publisher/subscriptions"
	"github.com/godrealms/go-google-sdk/android/publisher/voidedpurchases"
)

// Client is the top-level Google Play Publisher client.
// Use its sub-service fields for resource-specific operations.
type Client struct {
	Purchases       *purchases.Service
	Subscriptions   *subscriptions.Service
	Orders          *orders.Service
	InAppProducts   *inappproducts.Service
	VoidedPurchases *voidedpurchases.Service
	raw             *androidpublisher.Service
}

func newClient(raw *androidpublisher.Service) *Client {
	return &Client{
		Purchases:       purchases.New(raw),
		Subscriptions:   subscriptions.New(raw),
		Orders:          orders.New(raw),
		InAppProducts:   inappproducts.New(raw),
		VoidedPurchases: voidedpurchases.New(raw),
		raw:             raw,
	}
}

// NewClient creates a Client using Application Default Credentials or the provided options.
func NewClient(ctx context.Context, opts ...option.ClientOption) (*Client, error) {
	raw, err := androidpublisher.NewService(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return newClient(raw), nil
}

// NewClientWithTokenSource creates a Client from an OAuth2 authorization code exchange.
func NewClientWithTokenSource(ctx context.Context, config *oauth2.Config, code string, opts ...oauth2.AuthCodeOption) (*Client, error) {
	if config == nil {
		return nil, errors.New("publisher: config is nil")
	}
	token, err := config.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, err
	}
	raw, err := androidpublisher.NewService(ctx, option.WithTokenSource(config.TokenSource(ctx, token)))
	if err != nil {
		return nil, err
	}
	return newClient(raw), nil
}

// NewClientWithKey creates a Client authenticated with an API key.
func NewClientWithKey(ctx context.Context, apiKey string) (*Client, error) {
	raw, err := androidpublisher.NewService(ctx, option.WithAPIKey(apiKey))
	if err != nil {
		return nil, err
	}
	return newClient(raw), nil
}

// Verify routes a purchase verification request to the appropriate sub-service.
// When only OrderID is provided (no Type, no PurchaseToken), Verify calls the Orders
// API to inspect LineItems and auto-resolves the product type.
func (c *Client) Verify(ctx context.Context, req VerifyRequest) (*VerifyResult, error) {
	if c == nil || c.raw == nil {
		return nil, errors.New("publisher: client is nil")
	}
	if req.PackageName == "" {
		return nil, ErrMissingPackageName
	}

	resolved := req.Type
	if resolved == "" {
		switch {
		case req.SubscriptionID != "":
			resolved = VerifyTypeSubscription
		case req.ProductID != "":
			resolved = VerifyTypeProduct
		case req.OrderID != "":
			// Auto-resolve by fetching the order and inspecting its line items.
			order, err := c.Orders.Get(ctx, req.PackageName, req.OrderID)
			if err != nil {
				return nil, err
			}
			if len(order.LineItems) == 0 {
				return nil, ErrRouteUnknown
			}
			item := order.LineItems[0]
			switch {
			case item.SubscriptionDetails != nil:
				return &VerifyResult{Type: VerifyTypeSubscription, Raw: order}, nil
			case item.OneTimePurchaseDetails != nil || item.PaidAppDetails != nil:
				return &VerifyResult{Type: VerifyTypeProduct, Raw: order}, nil
			default:
				return nil, ErrRouteUnknown
			}
		default:
			return nil, ErrRouteUnknown
		}
	}

	switch resolved {
	case VerifyTypeProduct:
		order, purchase, err := c.Purchases.Query(ctx, purchases.PurchaseQuery{
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

	case VerifyTypeSubscription:
		order, result, err := c.Subscriptions.Query(ctx, subscriptions.SubscriptionQuery{
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
		return &VerifyResult{Type: VerifyTypeSubscription, Raw: result}, nil

	default:
		return nil, ErrRouteUnknown
	}
}
