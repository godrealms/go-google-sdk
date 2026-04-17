// Package internalappsharing wraps the Google Play Publisher internal app
// sharing artifacts API (APK and bundle uploads).
package internalappsharing

import (
	"context"
	"errors"
	"io"

	"google.golang.org/api/androidpublisher/v3"
)

var (
	// ErrServiceNil is returned when the receiver Service is nil or its raw client is unset.
	ErrServiceNil = errors.New("internalappsharing: service is nil")
	// ErrMissingPackageName is returned when the package name is empty.
	ErrMissingPackageName = errors.New("internalappsharing: package name is required")
	// ErrMissingMedia is returned when the media reader is nil.
	ErrMissingMedia = errors.New("internalappsharing: media reader is required")
)

// Service wraps the Google Play Publisher Internalappsharingartifacts resource.
type Service struct {
	raw *androidpublisher.Service
}

// New constructs an internalappsharing Service from an already-configured raw client.
func New(raw *androidpublisher.Service) *Service { return &Service{raw: raw} }

// UploadAPK wraps androidpublisher.Internalappsharingartifacts.Uploadapk.
// POST /androidpublisher/v3/applications/internalappsharing/{packageName}/artifacts/apk
func (s *Service) UploadAPK(ctx context.Context, packageName string, media io.Reader) (*androidpublisher.InternalAppSharingArtifact, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if media == nil {
		return nil, ErrMissingMedia
	}
	return s.raw.Internalappsharingartifacts.Uploadapk(packageName).Media(media).Context(ctx).Do()
}

// UploadBundle wraps androidpublisher.Internalappsharingartifacts.Uploadbundle, uploading an AAB as an internal-app-sharing artifact.
// POST /androidpublisher/v3/applications/internalappsharing/{packageName}/artifacts/bundle
func (s *Service) UploadBundle(ctx context.Context, packageName string, media io.Reader) (*androidpublisher.InternalAppSharingArtifact, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if media == nil {
		return nil, ErrMissingMedia
	}
	return s.raw.Internalappsharingartifacts.Uploadbundle(packageName).Media(media).Context(ctx).Do()
}
