package edits

import (
	"context"
	"io"

	"google.golang.org/api/androidpublisher/v3"
)

// BundlesList lists all uploaded app bundles for the current edit.
func (s *Service) BundlesList(ctx context.Context, packageName, editID string) (*androidpublisher.BundlesListResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if editID == "" {
		return nil, ErrMissingEditID
	}
	return s.raw.Edits.Bundles.List(packageName, editID).Context(ctx).Do()
}

// BundlesUploadOptions holds optional parameters for bundle uploads.
type BundlesUploadOptions struct {
	AckBundleInstallationWarning bool
	DeviceTierConfigID           string
}

// BundlesUpload uploads an app bundle to the current edit.
func (s *Service) BundlesUpload(ctx context.Context, packageName, editID string, media io.Reader, opts BundlesUploadOptions) (*androidpublisher.Bundle, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if editID == "" {
		return nil, ErrMissingEditID
	}
	if media == nil {
		return nil, ErrMissingMedia
	}
	call := s.raw.Edits.Bundles.Upload(packageName, editID).Media(media).Context(ctx)
	if opts.AckBundleInstallationWarning {
		call = call.AckBundleInstallationWarning(true)
	}
	if opts.DeviceTierConfigID != "" {
		call = call.DeviceTierConfigId(opts.DeviceTierConfigID)
	}
	return call.Do()
}
