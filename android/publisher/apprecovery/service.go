// Package apprecovery wraps the Google Play Publisher app recovery API.
// App recovery actions are keyed by (packageName, appRecoveryId).
package apprecovery

import (
	"context"
	"errors"

	"google.golang.org/api/androidpublisher/v3"
)

var (
	// ErrServiceNil is returned when the receiver Service is nil or its raw client is unset.
	ErrServiceNil = errors.New("apprecovery: service is nil")
	// ErrMissingPackageName is returned when the package name is empty.
	ErrMissingPackageName = errors.New("apprecovery: package name is required")
	// ErrMissingID is returned when the app recovery id is zero.
	ErrMissingID = errors.New("apprecovery: app recovery id is required")
	// ErrMissingRequest is returned when the request body is nil.
	ErrMissingRequest = errors.New("apprecovery: request body is required")
)

// Service wraps the Google Play Publisher Apprecovery resource, which drives
// targeted rollback and recovery of a published APK/bundle.
type Service struct {
	raw *androidpublisher.Service
}

// New constructs an apprecovery Service from an already-configured raw client.
func New(raw *androidpublisher.Service) *Service { return &Service{raw: raw} }

// AddTargeting wraps androidpublisher.Apprecovery.AddTargeting, extending the set of devices covered.
// POST /androidpublisher/v3/applications/{packageName}/appRecoveries/{appRecoveryId}:addTargeting
func (s *Service) AddTargeting(ctx context.Context, packageName string, appRecoveryID int64, req *androidpublisher.AddTargetingRequest) (*androidpublisher.AddTargetingResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if appRecoveryID == 0 {
		return nil, ErrMissingID
	}
	if req == nil {
		req = &androidpublisher.AddTargetingRequest{}
	}
	return s.raw.Apprecovery.AddTargeting(packageName, appRecoveryID, req).Context(ctx).Do()
}

// Cancel wraps androidpublisher.Apprecovery.Cancel, halting an in-progress recovery action.
// POST /androidpublisher/v3/applications/{packageName}/appRecoveries/{appRecoveryId}:cancel
func (s *Service) Cancel(ctx context.Context, packageName string, appRecoveryID int64, req *androidpublisher.CancelAppRecoveryRequest) (*androidpublisher.CancelAppRecoveryResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if appRecoveryID == 0 {
		return nil, ErrMissingID
	}
	if req == nil {
		req = &androidpublisher.CancelAppRecoveryRequest{}
	}
	return s.raw.Apprecovery.Cancel(packageName, appRecoveryID, req).Context(ctx).Do()
}

// Create wraps androidpublisher.Apprecovery.Create, creating a draft recovery action.
// POST /androidpublisher/v3/applications/{packageName}/appRecoveries
func (s *Service) Create(ctx context.Context, packageName string, req *androidpublisher.CreateDraftAppRecoveryRequest) (*androidpublisher.AppRecoveryAction, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if req == nil {
		return nil, ErrMissingRequest
	}
	return s.raw.Apprecovery.Create(packageName, req).Context(ctx).Do()
}

// Deploy wraps androidpublisher.Apprecovery.Deploy, promoting a draft to rollout.
// POST /androidpublisher/v3/applications/{packageName}/appRecoveries/{appRecoveryId}:deploy
func (s *Service) Deploy(ctx context.Context, packageName string, appRecoveryID int64, req *androidpublisher.DeployAppRecoveryRequest) (*androidpublisher.DeployAppRecoveryResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if appRecoveryID == 0 {
		return nil, ErrMissingID
	}
	if req == nil {
		req = &androidpublisher.DeployAppRecoveryRequest{}
	}
	return s.raw.Apprecovery.Deploy(packageName, appRecoveryID, req).Context(ctx).Do()
}

// ListOptions holds optional query parameters.
type ListOptions struct {
	VersionCode int64
}

// List wraps androidpublisher.Apprecovery.List.
// GET /androidpublisher/v3/applications/{packageName}/appRecoveries
func (s *Service) List(ctx context.Context, packageName string, opts ListOptions) (*androidpublisher.ListAppRecoveriesResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	call := s.raw.Apprecovery.List(packageName).Context(ctx)
	if opts.VersionCode > 0 {
		call = call.VersionCode(opts.VersionCode)
	}
	return call.Do()
}
