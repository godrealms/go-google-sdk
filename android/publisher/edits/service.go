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
	// ErrServiceNil is returned when the receiver Service is nil or its raw client is unset.
	ErrServiceNil = errors.New("edits: service is nil")
	// ErrMissingPackageName is returned when the package name is empty.
	ErrMissingPackageName = errors.New("edits: package name is required")
	// ErrMissingEditID is returned when the edit id is empty.
	ErrMissingEditID = errors.New("edits: edit id is required")
	// ErrMissingTrack is returned when the track identifier is empty.
	ErrMissingTrack = errors.New("edits: track is required")
	// ErrMissingLanguage is returned when the BCP-47 language tag is empty.
	ErrMissingLanguage = errors.New("edits: language is required")
	// ErrMissingImageType is returned when the image type is empty.
	ErrMissingImageType = errors.New("edits: image type is required")
	// ErrMissingImageID is returned when the image id is empty.
	ErrMissingImageID = errors.New("edits: image id is required")
	// ErrMissingVersion is returned when the APK version code is zero.
	ErrMissingVersion = errors.New("edits: apk version code is required")
	// ErrMissingFileType is returned when the expansion or deobfuscation file type is empty.
	ErrMissingFileType = errors.New("edits: file type is required")
	// ErrMissingMedia is returned when the upload media reader is nil.
	ErrMissingMedia = errors.New("edits: media is required")
	// ErrMissingRequest is returned when the request body is nil.
	ErrMissingRequest = errors.New("edits: request body is required")
	// ErrMissingDetails is returned when the app-details body is nil.
	ErrMissingDetails = errors.New("edits: app details body is required")
	// ErrMissingListing is returned when the listing body is nil.
	ErrMissingListing = errors.New("edits: listing body is required")
	// ErrMissingTesters is returned when the testers body is nil.
	ErrMissingTesters = errors.New("edits: testers body is required")
	// ErrMissingTrackBody is returned when the track body is nil.
	ErrMissingTrackBody = errors.New("edits: track body is required")
	// ErrMissingTrackConfig is returned when the track-create config is nil.
	ErrMissingTrackConfig = errors.New("edits: track config body is required")
	// ErrMissingExpansion is returned when the expansion-file body is nil.
	ErrMissingExpansion = errors.New("edits: expansion file body is required")
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

// Commit wraps androidpublisher.Edits.Commit, sealing the edit and optionally
// flagging changes as not sent for review.
// POST /androidpublisher/v3/applications/{packageName}/edits/{editId}:commit
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

// Delete wraps androidpublisher.Edits.Delete, discarding the specified edit.
// DELETE /androidpublisher/v3/applications/{packageName}/edits/{editId}
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

// Get wraps androidpublisher.Edits.Get.
// GET /androidpublisher/v3/applications/{packageName}/edits/{editId}
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

// Insert wraps androidpublisher.Edits.Insert, creating a new edit transaction.
// If edit is nil an empty body is sent.
// POST /androidpublisher/v3/applications/{packageName}/edits
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

// Validate wraps androidpublisher.Edits.Validate, running server-side validation without committing.
// POST /androidpublisher/v3/applications/{packageName}/edits/{editId}:validate
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
