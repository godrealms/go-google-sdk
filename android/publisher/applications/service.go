// Package applications wraps the Google Play Publisher applications API
// (data safety, device tier configs, and cross-track release listing).
package applications

import (
	"context"
	"errors"

	"google.golang.org/api/androidpublisher/v3"
)

var (
	ErrServiceNil         = errors.New("applications: service is nil")
	ErrMissingPackageName = errors.New("applications: package name is required")
	ErrMissingParent      = errors.New("applications: parent resource name is required")
	ErrMissingRequest     = errors.New("applications: request body is required")
	ErrMissingConfig      = errors.New("applications: device tier config is required")
	ErrMissingID          = errors.New("applications: device tier config id is required")
)

type Service struct {
	raw *androidpublisher.Service
}

func New(raw *androidpublisher.Service) *Service { return &Service{raw: raw} }

// DataSafety updates the data safety labels for the given app.
func (s *Service) DataSafety(ctx context.Context, packageName string, req *androidpublisher.SafetyLabelsUpdateRequest) (*androidpublisher.SafetyLabelsUpdateResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if req == nil {
		return nil, ErrMissingRequest
	}
	return s.raw.Applications.DataSafety(packageName, req).Context(ctx).Do()
}

// CreateDeviceTierConfigOptions holds optional parameters for creating a
// device tier config.
type CreateDeviceTierConfigOptions struct {
	AllowUnknownDevices bool
}

// CreateDeviceTierConfig creates a new device tier config for the app.
func (s *Service) CreateDeviceTierConfig(ctx context.Context, packageName string, cfg *androidpublisher.DeviceTierConfig, opts CreateDeviceTierConfigOptions) (*androidpublisher.DeviceTierConfig, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if cfg == nil {
		return nil, ErrMissingConfig
	}
	call := s.raw.Applications.DeviceTierConfigs.Create(packageName, cfg).Context(ctx)
	if opts.AllowUnknownDevices {
		call = call.AllowUnknownDevices(true)
	}
	return call.Do()
}

// GetDeviceTierConfig fetches a specific device tier config.
func (s *Service) GetDeviceTierConfig(ctx context.Context, packageName string, deviceTierConfigID int64) (*androidpublisher.DeviceTierConfig, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if deviceTierConfigID == 0 {
		return nil, ErrMissingID
	}
	return s.raw.Applications.DeviceTierConfigs.Get(packageName, deviceTierConfigID).Context(ctx).Do()
}

// ListDeviceTierConfigsOptions holds optional pagination parameters.
type ListDeviceTierConfigsOptions struct {
	PageSize  int64
	PageToken string
}

// ListDeviceTierConfigs lists device tier configs.
func (s *Service) ListDeviceTierConfigs(ctx context.Context, packageName string, opts ListDeviceTierConfigsOptions) (*androidpublisher.ListDeviceTierConfigsResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	call := s.raw.Applications.DeviceTierConfigs.List(packageName).Context(ctx)
	if opts.PageSize > 0 {
		call = call.PageSize(opts.PageSize)
	}
	if opts.PageToken != "" {
		call = call.PageToken(opts.PageToken)
	}
	return call.Do()
}

// ListTrackReleases lists releases for a given track parent
// (format: applications/{packageName}/tracks/{trackId}).
func (s *Service) ListTrackReleases(ctx context.Context, parent string) (*androidpublisher.ListReleaseSummariesResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if parent == "" {
		return nil, ErrMissingParent
	}
	return s.raw.Applications.Tracks.Releases.List(parent).Context(ctx).Do()
}
