package orders

import (
	"context"
	"errors"

	"google.golang.org/api/androidpublisher/v3"
)

type Service struct {
	raw *androidpublisher.Service
}

func New(raw *androidpublisher.Service) *Service {
	return &Service{raw: raw}
}

func (s *Service) Get(ctx context.Context, packageName, orderID string) (*androidpublisher.Order, error) {
	if s == nil || s.raw == nil {
		return nil, errors.New("orders: service is nil")
	}
	if packageName == "" {
		return nil, errors.New("orders: packageName is required")
	}
	if orderID == "" {
		return nil, errors.New("orders: orderID is required")
	}
	return s.raw.Orders.Get(packageName, orderID).Context(ctx).Do()
}
