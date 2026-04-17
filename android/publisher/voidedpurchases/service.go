package voidedpurchases

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

func (s *Service) List(ctx context.Context, packageName string, opts ...ListOption) (*androidpublisher.VoidedPurchasesListResponse, error) {
	if s == nil || s.raw == nil {
		return nil, errors.New("voidedpurchases: service is nil")
	}
	if packageName == "" {
		return nil, errors.New("voidedpurchases: packageName is required")
	}
	call := s.raw.Purchases.Voidedpurchases.List(packageName).Context(ctx)
	for _, o := range opts {
		o(call)
	}
	return call.Do()
}
