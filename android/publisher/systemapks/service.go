// Package systemapks wraps the Google Play Publisher system APK variants API.
package systemapks

import (
	"context"
	"errors"
	"io"
	"net/http"

	"google.golang.org/api/androidpublisher/v3"
)

var (
	ErrServiceNil         = errors.New("systemapks: service is nil")
	ErrMissingPackageName = errors.New("systemapks: package name is required")
	ErrMissingVersion     = errors.New("systemapks: version code is required")
	ErrMissingVariantID   = errors.New("systemapks: variant id is required")
	ErrMissingVariant     = errors.New("systemapks: variant body is required")
)

type Service struct {
	raw *androidpublisher.Service
}

func New(raw *androidpublisher.Service) *Service { return &Service{raw: raw} }

func (s *Service) Create(ctx context.Context, packageName string, versionCode int64, variant *androidpublisher.Variant) (*androidpublisher.Variant, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if versionCode == 0 {
		return nil, ErrMissingVersion
	}
	if variant == nil {
		return nil, ErrMissingVariant
	}
	return s.raw.Systemapks.Variants.Create(packageName, versionCode, variant).Context(ctx).Do()
}

func (s *Service) Get(ctx context.Context, packageName string, versionCode, variantID int64) (*androidpublisher.Variant, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if versionCode == 0 {
		return nil, ErrMissingVersion
	}
	if variantID == 0 {
		return nil, ErrMissingVariantID
	}
	return s.raw.Systemapks.Variants.Get(packageName, versionCode, variantID).Context(ctx).Do()
}

func (s *Service) List(ctx context.Context, packageName string, versionCode int64) (*androidpublisher.SystemApksListResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if versionCode == 0 {
		return nil, ErrMissingVersion
	}
	return s.raw.Systemapks.Variants.List(packageName, versionCode).Context(ctx).Do()
}

// Download returns the raw response body; caller must close.
func (s *Service) Download(ctx context.Context, packageName string, versionCode, variantID int64) (io.ReadCloser, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if versionCode == 0 {
		return nil, ErrMissingVersion
	}
	if variantID == 0 {
		return nil, ErrMissingVariantID
	}
	resp, err := s.raw.Systemapks.Variants.Download(packageName, versionCode, variantID).Context(ctx).Download()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		resp.Body.Close()
		return nil, errors.New("systemapks: download failed with status " + resp.Status)
	}
	return resp.Body, nil
}
