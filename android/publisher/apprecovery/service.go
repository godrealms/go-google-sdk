// Package apprecovery wraps the Google Play Publisher app recovery API.
// App recovery actions are keyed by (packageName, appRecoveryId).
package apprecovery

import (
	"context"
	"errors"

	"google.golang.org/api/androidpublisher/v3"
)

var (
	ErrServiceNil         = errors.New("apprecovery: service is nil")
	ErrMissingPackageName = errors.New("apprecovery: package name is required")
	ErrMissingID          = errors.New("apprecovery: app recovery id is required")
	ErrMissingRequest     = errors.New("apprecovery: request body is required")
)

type Service struct {
	raw *androidpublisher.Service
}

func New(raw *androidpublisher.Service) *Service { return &Service{raw: raw} }

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
