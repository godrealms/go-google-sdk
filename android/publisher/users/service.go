// Package users wraps the Google Play Publisher users API (Developer
// Console user account management). "parent" and "name" use resource-name
// format, e.g. "developers/{developerId}" and
// "developers/{developerId}/users/{email}".
package users

import (
	"context"
	"errors"

	"google.golang.org/api/androidpublisher/v3"
)

var (
	// ErrServiceNil is returned when the receiver Service is nil or its raw client is unset.
	ErrServiceNil = errors.New("users: service is nil")
	// ErrMissingParent is returned when the parent resource name is empty.
	ErrMissingParent = errors.New("users: parent resource name is required")
	// ErrMissingName is returned when the user resource name is empty.
	ErrMissingName = errors.New("users: user resource name is required")
	// ErrMissingUser is returned when the user body is nil.
	ErrMissingUser = errors.New("users: user body is required")
)

// Service wraps the Google Play Publisher Users resource (Developer Console
// user account management).
type Service struct {
	raw *androidpublisher.Service
}

// New constructs a users Service from an already-configured raw client.
func New(raw *androidpublisher.Service) *Service { return &Service{raw: raw} }

// ListOptions holds optional paginated-list query parameters.
type ListOptions struct {
	PageSize  int64
	PageToken string
}

// Create wraps androidpublisher.Users.Create, granting a new user in the Play console.
// POST /androidpublisher/v3/{parent=developers/*}/users
func (s *Service) Create(ctx context.Context, parent string, user *androidpublisher.User) (*androidpublisher.User, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if parent == "" {
		return nil, ErrMissingParent
	}
	if user == nil {
		return nil, ErrMissingUser
	}
	return s.raw.Users.Create(parent, user).Context(ctx).Do()
}

// List wraps androidpublisher.Users.List.
// GET /androidpublisher/v3/{parent=developers/*}/users
func (s *Service) List(ctx context.Context, parent string, opts ListOptions) (*androidpublisher.ListUsersResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if parent == "" {
		return nil, ErrMissingParent
	}
	call := s.raw.Users.List(parent).Context(ctx)
	if opts.PageSize > 0 {
		call = call.PageSize(opts.PageSize)
	}
	if opts.PageToken != "" {
		call = call.PageToken(opts.PageToken)
	}
	return call.Do()
}

// Patch wraps androidpublisher.Users.Patch, partially updating a user's roles/access.
// PATCH /androidpublisher/v3/{name=developers/*/users/*}
func (s *Service) Patch(ctx context.Context, name, updateMask string, user *androidpublisher.User) (*androidpublisher.User, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if name == "" {
		return nil, ErrMissingName
	}
	if user == nil {
		return nil, ErrMissingUser
	}
	call := s.raw.Users.Patch(name, user).Context(ctx)
	if updateMask != "" {
		call = call.UpdateMask(updateMask)
	}
	return call.Do()
}

// Delete wraps androidpublisher.Users.Delete, revoking console access for the user.
// DELETE /androidpublisher/v3/{name=developers/*/users/*}
func (s *Service) Delete(ctx context.Context, name string) error {
	if s == nil || s.raw == nil {
		return ErrServiceNil
	}
	if name == "" {
		return ErrMissingName
	}
	return s.raw.Users.Delete(name).Context(ctx).Do()
}
