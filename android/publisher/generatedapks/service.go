// Package generatedapks wraps the Google Play Publisher generated APKs API.
package generatedapks

import (
	"context"
	"errors"
	"io"
	"net/http"

	"google.golang.org/api/androidpublisher/v3"
)

var (
	ErrServiceNil         = errors.New("generatedapks: service is nil")
	ErrMissingPackageName = errors.New("generatedapks: package name is required")
	ErrMissingVersion     = errors.New("generatedapks: version code is required")
	ErrMissingDownloadID  = errors.New("generatedapks: download id is required")
)

type Service struct {
	raw *androidpublisher.Service
}

func New(raw *androidpublisher.Service) *Service { return &Service{raw: raw} }

// Download returns the raw HTTP response body for the requested generated APK
// download. The caller is responsible for closing the body.
func (s *Service) Download(ctx context.Context, packageName string, versionCode int64, downloadID string) (io.ReadCloser, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if versionCode == 0 {
		return nil, ErrMissingVersion
	}
	if downloadID == "" {
		return nil, ErrMissingDownloadID
	}
	resp, err := s.raw.Generatedapks.Download(packageName, versionCode, downloadID).Context(ctx).Download()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		resp.Body.Close()
		return nil, errors.New("generatedapks: download failed with status " + resp.Status)
	}
	return resp.Body, nil
}

// List lists the generated APKs produced by Play for the given version.
func (s *Service) List(ctx context.Context, packageName string, versionCode int64) (*androidpublisher.GeneratedApksListResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if versionCode == 0 {
		return nil, ErrMissingVersion
	}
	return s.raw.Generatedapks.List(packageName, versionCode).Context(ctx).Do()
}
