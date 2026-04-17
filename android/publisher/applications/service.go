// Package applications wraps the Google Play Publisher applications API
// (data safety, device tier configs, and cross-track release listing).
package applications

import (
	"context"
	"errors"

	"google.golang.org/api/androidpublisher/v3"
)

var (
	// ErrServiceNil is returned when the receiver Service is nil or its raw client is unset.
	ErrServiceNil = errors.New("applications: service is nil")
	// ErrMissingPackageName is returned when the package name is empty.
	ErrMissingPackageName = errors.New("applications: package name is required")
	// ErrMissingParent is returned when the parent resource name is empty.
	ErrMissingParent = errors.New("applications: parent resource name is required")
	// ErrMissingRequest is returned when the request body is nil.
	ErrMissingRequest = errors.New("applications: request body is required")
	// ErrMissingConfig is returned when the device tier config body is nil.
	ErrMissingConfig = errors.New("applications: device tier config is required")
	// ErrMissingID is returned when the device tier config id is zero.
	ErrMissingID = errors.New("applications: device tier config id is required")
)

// Service wraps the Google Play Publisher Applications resource (data safety,
// device tier configs, and cross-track release listing).
type Service struct {
	raw *androidpublisher.Service
}

// New constructs an applications Service from an already-configured raw client.
func New(raw *androidpublisher.Service) *Service { return &Service{raw: raw} }

// DataSafety wraps androidpublisher.Applications.DataSafety, updating data safety labels for the given app.
// POST /androidpublisher/v3/applications/{packageName}/dataSafety
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

// CreateDeviceTierConfig wraps androidpublisher.Applications.DeviceTierConfigs.Create.
// POST /androidpublisher/v3/applications/{packageName}/deviceTierConfigs
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

// GetDeviceTierConfig wraps androidpublisher.Applications.DeviceTierConfigs.Get.
// GET /androidpublisher/v3/applications/{packageName}/deviceTierConfigs/{deviceTierConfigId}
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

// ListDeviceTierConfigs wraps androidpublisher.Applications.DeviceTierConfigs.List.
// GET /androidpublisher/v3/applications/{packageName}/deviceTierConfigs
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

// ListTrackReleases wraps androidpublisher.Applications.Tracks.Releases.List.
// Parent format: applications/{packageName}/tracks/{trackId}.
// GET /androidpublisher/v3/{parent=applications/*/tracks/*}/releases
func (s *Service) ListTrackReleases(ctx context.Context, parent string) (*androidpublisher.ListReleaseSummariesResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if parent == "" {
		return nil, ErrMissingParent
	}
	return s.raw.Applications.Tracks.Releases.List(parent).Context(ctx).Do()
}
