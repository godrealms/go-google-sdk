package edits

import (
	"context"

	"google.golang.org/api/androidpublisher/v3"
)

// DetailsGet fetches the app details for the current edit.
func (s *Service) DetailsGet(ctx context.Context, packageName, editID string) (*androidpublisher.AppDetails, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if editID == "" {
		return nil, ErrMissingEditID
	}
	return s.raw.Edits.Details.Get(packageName, editID).Context(ctx).Do()
}

// DetailsPatch partially updates the app details.
func (s *Service) DetailsPatch(ctx context.Context, packageName, editID string, details *androidpublisher.AppDetails) (*androidpublisher.AppDetails, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if editID == "" {
		return nil, ErrMissingEditID
	}
	if details == nil {
		return nil, ErrMissingDetails
	}
	return s.raw.Edits.Details.Patch(packageName, editID, details).Context(ctx).Do()
}

// DetailsUpdate fully updates the app details.
func (s *Service) DetailsUpdate(ctx context.Context, packageName, editID string, details *androidpublisher.AppDetails) (*androidpublisher.AppDetails, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if editID == "" {
		return nil, ErrMissingEditID
	}
	if details == nil {
		return nil, ErrMissingDetails
	}
	return s.raw.Edits.Details.Update(packageName, editID, details).Context(ctx).Do()
}
