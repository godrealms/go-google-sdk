// Package publisher provides a Google Play Developer Publisher API client
// organized as a Client aggregator over resource-specific sub-services
// (purchases, subscriptions, orders, inappproducts, voidedpurchases).
// The top-level Client owns the Verify() routing logic including OrderID
// auto-resolution via the Orders API.
package publisher

import (
	"context"
	"errors"

	"golang.org/x/oauth2"
	"google.golang.org/api/androidpublisher/v3"
	"google.golang.org/api/option"

	"github.com/godrealms/go-google-sdk/android/publisher/inappproducts"
	monetizationsubs "github.com/godrealms/go-google-sdk/android/publisher/monetization/subscriptions"
	"github.com/godrealms/go-google-sdk/android/publisher/monetization/onetimeproducts"
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
	// OneTimeProducts wraps the monetization.onetimeproducts catalog surface.
	OneTimeProducts *onetimeproducts.Service
	// MonetizationSubscriptions wraps the monetization.subscriptions catalog
	// surface (Subscription CRUD + basePlans + offers + convertRegionPrices).
	// Distinct from Subscriptions, which handles purchased-subscription lookups.
	MonetizationSubscriptions *monetizationsubs.Service
	raw                       *androidpublisher.Service
}

func newClient(raw *androidpublisher.Service) *Client {
	return &Client{
		Purchases:                 purchases.New(raw),
		Subscriptions:             subscriptions.New(raw),
		Orders:                    orders.New(raw),
		InAppProducts:             inappproducts.New(raw),
		VoidedPurchases:           voidedpurchases.New(raw),
		OneTimeProducts:           onetimeproducts.New(raw),
		MonetizationSubscriptions: monetizationsubs.New(raw),
		raw:                       raw,
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
//
// Routing rules:
//   - OrderID provided: calls Orders.Get. If Type is also set, returns the order
//     tagged with that type. If Type is empty, inspects LineItems[0] to auto-resolve.
//   - PurchaseToken + ProductID (or Type=product): delegates to Purchases.Query.
//   - PurchaseToken + SubscriptionID (or Type=subscription): delegates to Subscriptions.Query.
//   - Otherwise: returns ErrRouteUnknown.
func (c *Client) Verify(ctx context.Context, req VerifyRequest) (*VerifyResult, error) {
	if c == nil || c.raw == nil {
		return nil, errors.New("publisher: client is nil")
	}
	if req.PackageName == "" {
		return nil, ErrMissingPackageName
	}

	if req.OrderID != "" {
		order, err := c.Orders.Get(ctx, req.PackageName, req.OrderID)
		if err != nil {
			return nil, err
		}
		resolved := req.Type
		if resolved == "" {
			if len(order.LineItems) == 0 {
				return nil, ErrRouteUnknown
			}
			item := order.LineItems[0]
			switch {
			case item.SubscriptionDetails != nil:
				resolved = VerifyTypeSubscription
			case item.OneTimePurchaseDetails != nil || item.PaidAppDetails != nil:
				resolved = VerifyTypeProduct
			default:
				return nil, ErrRouteUnknown
			}
		}
		return &VerifyResult{Type: resolved, Raw: order}, nil
	}

	resolved := req.Type
	if resolved == "" {
		switch {
		case req.SubscriptionID != "":
			resolved = VerifyTypeSubscription
		case req.ProductID != "":
			resolved = VerifyTypeProduct
		default:
			return nil, ErrRouteUnknown
		}
	}

	switch resolved {
	case VerifyTypeProduct:
		purchase, err := c.Purchases.Query(ctx, purchases.PurchaseQuery{
			PackageName:   req.PackageName,
			ProductID:     req.ProductID,
			PurchaseToken: req.PurchaseToken,
		})
		if err != nil {
			return nil, err
		}
		return &VerifyResult{Type: VerifyTypeProduct, Raw: purchase}, nil

	case VerifyTypeSubscription:
		result, err := c.Subscriptions.Query(ctx, subscriptions.SubscriptionQuery{
			PackageName:    req.PackageName,
			SubscriptionID: req.SubscriptionID,
			PurchaseToken:  req.PurchaseToken,
		})
		if err != nil {
			return nil, err
		}
		return &VerifyResult{Type: VerifyTypeSubscription, Raw: result}, nil

	default:
		return nil, ErrRouteUnknown
	}
}
