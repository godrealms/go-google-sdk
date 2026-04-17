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
	ErrServiceNil         = errors.New("internalappsharing: service is nil")
	ErrMissingPackageName = errors.New("internalappsharing: package name is required")
	ErrMissingMedia       = errors.New("internalappsharing: media reader is required")
)

type Service struct {
	raw *androidpublisher.Service
}

func New(raw *androidpublisher.Service) *Service { return &Service{raw: raw} }

// UploadAPK uploads an APK as an internal-app-sharing artifact.
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

// UploadBundle uploads an Android App Bundle as an internal-app-sharing artifact.
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
