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
	// ErrServiceNil is returned when the receiver Service is nil or its raw client is unset.
	ErrServiceNil = errors.New("grants: service is nil")
	// ErrMissingParent is returned when the parent resource name is empty.
	ErrMissingParent = errors.New("grants: parent resource name is required")
	// ErrMissingName is returned when the grant resource name is empty.
	ErrMissingName = errors.New("grants: grant resource name is required")
	// ErrMissingGrant is returned when the grant body is nil.
	ErrMissingGrant = errors.New("grants: grant body is required")
)

// Service wraps the Google Play Publisher Grants resource (per-app permission
// grants for Developer Console users).
type Service struct {
	raw *androidpublisher.Service
}

// New constructs a grants Service from an already-configured raw client.
func New(raw *androidpublisher.Service) *Service { return &Service{raw: raw} }

// Create wraps androidpublisher.Grants.Create, issuing a new app-level grant.
// POST /androidpublisher/v3/{parent=developers/*/users/*}/grants
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

// Patch wraps androidpublisher.Grants.Patch, updating the permissions on an existing grant.
// PATCH /androidpublisher/v3/{name=developers/*/users/*/grants/*}
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

// Delete wraps androidpublisher.Grants.Delete, revoking an app-level grant.
// DELETE /androidpublisher/v3/{name=developers/*/users/*/grants/*}
func (s *Service) Delete(ctx context.Context, name string) error {
	if s == nil || s.raw == nil {
		return ErrServiceNil
	}
	if name == "" {
		return ErrMissingName
	}
	return s.raw.Grants.Delete(name).Context(ctx).Do()
}
