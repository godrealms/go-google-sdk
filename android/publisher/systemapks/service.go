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
	// ErrServiceNil is returned when the receiver Service is nil or its raw client is unset.
	ErrServiceNil = errors.New("systemapks: service is nil")
	// ErrMissingPackageName is returned when the package name is empty.
	ErrMissingPackageName = errors.New("systemapks: package name is required")
	// ErrMissingVersion is returned when the version code is zero.
	ErrMissingVersion = errors.New("systemapks: version code is required")
	// ErrMissingVariantID is returned when the variant id is zero.
	ErrMissingVariantID = errors.New("systemapks: variant id is required")
	// ErrMissingVariant is returned when the variant body is nil.
	ErrMissingVariant = errors.New("systemapks: variant body is required")
)

// Service wraps the Google Play Publisher Systemapks resource (preloaded /
// system image APK variants).
type Service struct {
	raw *androidpublisher.Service
}

// New constructs a systemapks Service from an already-configured raw client.
func New(raw *androidpublisher.Service) *Service { return &Service{raw: raw} }

// Create wraps androidpublisher.Systemapks.Variants.Create, requesting a new system-image variant.
// POST /androidpublisher/v3/applications/{packageName}/systemApks/{versionCode}/variants
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

// Get wraps androidpublisher.Systemapks.Variants.Get.
// GET /androidpublisher/v3/applications/{packageName}/systemApks/{versionCode}/variants/{variantId}
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

// List wraps androidpublisher.Systemapks.Variants.List.
// GET /androidpublisher/v3/applications/{packageName}/systemApks/{versionCode}/variants
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

// Download wraps androidpublisher.Systemapks.Variants.Download, returning the raw
// response body for the generated system APK. The caller must close it.
// GET /androidpublisher/v3/applications/{packageName}/systemApks/{versionCode}/variants/{variantId}:download
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
