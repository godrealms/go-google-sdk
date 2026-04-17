package orders

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

func (s *Service) Get(ctx context.Context, packageName, orderID string) (*androidpublisher.Order, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if orderID == "" {
		return nil, ErrMissingOrderID
	}
	return s.raw.Orders.Get(packageName, orderID).Context(ctx).Do()
}

func (s *Service) Refund(ctx context.Context, packageName, orderID string, revoke bool) error {
	if s == nil || s.raw == nil {
		return ErrServiceNil
	}
	if packageName == "" {
		return ErrMissingPackageName
	}
	if orderID == "" {
		return ErrMissingOrderID
	}
	if err := s.raw.Orders.Refund(packageName, orderID).Revoke(revoke).Context(ctx).Do(); err != nil {
		return fmt.Errorf("orders: refund failed: %w", err)
	}
	return nil
}

func (s *Service) BatchGet(ctx context.Context, packageName string, orderIDs []string) (*androidpublisher.BatchGetOrdersResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if len(orderIDs) == 0 {
		return nil, ErrMissingOrderID
	}
	return s.raw.Orders.Batchget(packageName).OrderIds(orderIDs...).Context(ctx).Do()
}
