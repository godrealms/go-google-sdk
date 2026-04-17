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
	ErrServiceNil     = errors.New("users: service is nil")
	ErrMissingParent  = errors.New("users: parent resource name is required")
	ErrMissingName    = errors.New("users: user resource name is required")
	ErrMissingUser    = errors.New("users: user body is required")
)

type Service struct {
	raw *androidpublisher.Service
}

func New(raw *androidpublisher.Service) *Service { return &Service{raw: raw} }

// ListOptions holds optional paginated-list query parameters.
type ListOptions struct {
	PageSize  int64
	PageToken string
}

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

func (s *Service) Delete(ctx context.Context, name string) error {
	if s == nil || s.raw == nil {
		return ErrServiceNil
	}
	if name == "" {
		return ErrMissingName
	}
	return s.raw.Users.Delete(name).Context(ctx).Do()
}
