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
	// ErrServiceNil is returned when the receiver Service is nil or its raw client is unset.
	ErrServiceNil = errors.New("generatedapks: service is nil")
	// ErrMissingPackageName is returned when the package name is empty.
	ErrMissingPackageName = errors.New("generatedapks: package name is required")
	// ErrMissingVersion is returned when the version code is zero.
	ErrMissingVersion = errors.New("generatedapks: version code is required")
	// ErrMissingDownloadID is returned when the download id is empty.
	ErrMissingDownloadID = errors.New("generatedapks: download id is required")
)

// Service wraps the Google Play Publisher Generatedapks resource, exposing the
// Play-generated split APKs produced from an uploaded App Bundle.
type Service struct {
	raw *androidpublisher.Service
}

// New constructs a generatedapks Service from an already-configured raw client.
func New(raw *androidpublisher.Service) *Service { return &Service{raw: raw} }

// Download wraps androidpublisher.Generatedapks.Download, returning the raw HTTP
// response body for the requested generated APK. The caller is responsible for
// closing the body.
// GET /androidpublisher/v3/applications/{packageName}/generatedApks/{versionCode}/downloads/{downloadId}:download
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

// List wraps androidpublisher.Generatedapks.List, returning the Play-generated APK variants for the version.
// GET /androidpublisher/v3/applications/{packageName}/generatedApks/{versionCode}
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
