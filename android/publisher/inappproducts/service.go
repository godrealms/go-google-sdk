package inappproducts

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

func (s *Service) List(ctx context.Context, packageName string, opts ...ListOption) (*androidpublisher.InappproductsListResponse, error) {
	if s == nil || s.raw == nil {
		return nil, errors.New("inappproducts: service is nil")
	}
	if packageName == "" {
		return nil, errors.New("inappproducts: packageName is required")
	}
	call := s.raw.Inappproducts.List(packageName).Context(ctx)
	for _, o := range opts {
		o(call)
	}
	return call.Do()
}

func (s *Service) Get(ctx context.Context, packageName, sku string) (*androidpublisher.InAppProduct, error) {
	if s == nil || s.raw == nil {
		return nil, errors.New("inappproducts: service is nil")
	}
	if packageName == "" {
		return nil, errors.New("inappproducts: packageName is required")
	}
	if sku == "" {
		return nil, errors.New("inappproducts: sku is required")
	}
	return s.raw.Inappproducts.Get(packageName, sku).Context(ctx).Do()
}

func (s *Service) Insert(ctx context.Context, packageName string, product *androidpublisher.InAppProduct) (*androidpublisher.InAppProduct, error) {
	if s == nil || s.raw == nil {
		return nil, errors.New("inappproducts: service is nil")
	}
	if packageName == "" {
		return nil, errors.New("inappproducts: packageName is required")
	}
	return s.raw.Inappproducts.Insert(packageName, product).Context(ctx).Do()
}

func (s *Service) Update(ctx context.Context, packageName, sku string, product *androidpublisher.InAppProduct) (*androidpublisher.InAppProduct, error) {
	if s == nil || s.raw == nil {
		return nil, errors.New("inappproducts: service is nil")
	}
	if packageName == "" {
		return nil, errors.New("inappproducts: packageName is required")
	}
	if sku == "" {
		return nil, errors.New("inappproducts: sku is required")
	}
	return s.raw.Inappproducts.Update(packageName, sku, product).Context(ctx).Do()
}

func (s *Service) Delete(ctx context.Context, packageName, sku string) error {
	if s == nil || s.raw == nil {
		return errors.New("inappproducts: service is nil")
	}
	if packageName == "" {
		return errors.New("inappproducts: packageName is required")
	}
	if sku == "" {
		return errors.New("inappproducts: sku is required")
	}
	return s.raw.Inappproducts.Delete(packageName, sku).Context(ctx).Do()
}

func (s *Service) BatchGet(ctx context.Context, packageName string, skus []string) (*androidpublisher.InappproductsBatchGetResponse, error) {
	if s == nil || s.raw == nil {
		return nil, errors.New("inappproducts: service is nil")
	}
	if packageName == "" {
		return nil, errors.New("inappproducts: packageName is required")
	}
	return s.raw.Inappproducts.BatchGet(packageName).Sku(skus...).Context(ctx).Do()
}

func (s *Service) BatchUpdate(ctx context.Context, packageName string, req *androidpublisher.InappproductsBatchUpdateRequest) (*androidpublisher.InappproductsBatchUpdateResponse, error) {
	if s == nil || s.raw == nil {
		return nil, errors.New("inappproducts: service is nil")
	}
	if packageName == "" {
		return nil, errors.New("inappproducts: packageName is required")
	}
	return s.raw.Inappproducts.BatchUpdate(packageName, req).Context(ctx).Do()
}
