// Package edits wraps the Google Play Publisher edits API, covering the
// edit-lifecycle (insert/get/commit/validate/delete) and all nested
// resources (APKs, bundles, listings, images, tracks, testers, etc.).
package edits

import (
	"context"
	"errors"

	"google.golang.org/api/androidpublisher/v3"
)

var (
	ErrServiceNil         = errors.New("edits: service is nil")
	ErrMissingPackageName = errors.New("edits: package name is required")
	ErrMissingEditID      = errors.New("edits: edit id is required")
	ErrMissingTrack       = errors.New("edits: track is required")
	ErrMissingLanguage    = errors.New("edits: language is required")
	ErrMissingImageType   = errors.New("edits: image type is required")
	ErrMissingImageID     = errors.New("edits: image id is required")
	ErrMissingVersion     = errors.New("edits: apk version code is required")
	ErrMissingFileType    = errors.New("edits: file type is required")
	ErrMissingMedia       = errors.New("edits: media is required")
	ErrMissingRequest     = errors.New("edits: request body is required")
	ErrMissingDetails     = errors.New("edits: app details body is required")
	ErrMissingListing     = errors.New("edits: listing body is required")
	ErrMissingTesters     = errors.New("edits: testers body is required")
	ErrMissingTrackBody   = errors.New("edits: track body is required")
	ErrMissingTrackConfig = errors.New("edits: track config body is required")
	ErrMissingExpansion   = errors.New("edits: expansion file body is required")
)

// Service wraps the Edits resource of the Android Publisher API.
type Service struct {
	raw *androidpublisher.Service
}

// New constructs an edits Service from an already-configured raw service.
func New(raw *androidpublisher.Service) *Service { return &Service{raw: raw} }

// CommitOptions holds optional parameters for committing an edit.
type CommitOptions struct {
	ChangesNotSentForReview bool
}

// Commit commits the specified edit, optionally marking changes as not sent
// for review.
func (s *Service) Commit(ctx context.Context, packageName, editID string, opts CommitOptions) (*androidpublisher.AppEdit, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if editID == "" {
		return nil, ErrMissingEditID
	}
	call := s.raw.Edits.Commit(packageName, editID).Context(ctx)
	if opts.ChangesNotSentForReview {
		call = call.ChangesNotSentForReview(true)
	}
	return call.Do()
}

// Delete discards the specified edit.
func (s *Service) Delete(ctx context.Context, packageName, editID string) error {
	if s == nil || s.raw == nil {
		return ErrServiceNil
	}
	if packageName == "" {
		return ErrMissingPackageName
	}
	if editID == "" {
		return ErrMissingEditID
	}
	return s.raw.Edits.Delete(packageName, editID).Context(ctx).Do()
}

// Get fetches the specified edit.
func (s *Service) Get(ctx context.Context, packageName, editID string) (*androidpublisher.AppEdit, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if editID == "" {
		return nil, ErrMissingEditID
	}
	return s.raw.Edits.Get(packageName, editID).Context(ctx).Do()
}

// Insert creates a new edit. If edit is nil an empty body is sent.
func (s *Service) Insert(ctx context.Context, packageName string, edit *androidpublisher.AppEdit) (*androidpublisher.AppEdit, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if edit == nil {
		edit = &androidpublisher.AppEdit{}
	}
	return s.raw.Edits.Insert(packageName, edit).Context(ctx).Do()
}

// Validate validates the specified edit.
func (s *Service) Validate(ctx context.Context, packageName, editID string) (*androidpublisher.AppEdit, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if editID == "" {
		return nil, ErrMissingEditID
	}
	return s.raw.Edits.Validate(packageName, editID).Context(ctx).Do()
}
