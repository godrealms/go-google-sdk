// Package grants wraps the Google Play Publisher grants API (per-app
// permissions for Developer Console users). "parent" uses user resource-name
// format "developers/{developerId}/users/{email}" and "name" uses grant
// resource-name format ".../grants/{packageName}".
package grants

import (
	"context"
	"errors"

	"google.golang.org/api/androidpublisher/v3"
)

var (
	ErrServiceNil    = errors.New("grants: service is nil")
	ErrMissingParent = errors.New("grants: parent resource name is required")
	ErrMissingName   = errors.New("grants: grant resource name is required")
	ErrMissingGrant  = errors.New("grants: grant body is required")
)

type Service struct {
	raw *androidpublisher.Service
}

func New(raw *androidpublisher.Service) *Service { return &Service{raw: raw} }

func (s *Service) Create(ctx context.Context, parent string, grant *androidpublisher.Grant) (*androidpublisher.Grant, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if parent == "" {
		return nil, ErrMissingParent
	}
	if grant == nil {
		return nil, ErrMissingGrant
	}
	return s.raw.Grants.Create(parent, grant).Context(ctx).Do()
}

func (s *Service) Patch(ctx context.Context, name, updateMask string, grant *androidpublisher.Grant) (*androidpublisher.Grant, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if name == "" {
		return nil, ErrMissingName
	}
	if grant == nil {
		return nil, ErrMissingGrant
	}
	call := s.raw.Grants.Patch(name, grant).Context(ctx)
	if updateMask != "" {
		call = call.UpdateMask(updateMask)
	}
	return call.Do()
}

func (s *Service) Delete(ctx context.Context, name string) error {
	if s == nil || s.raw == nil {
		return ErrServiceNil
	}
	if name == "" {
		return ErrMissingName
	}
	return s.raw.Grants.Delete(name).Context(ctx).Do()
}
