package edits

import (
	"context"

	"google.golang.org/api/androidpublisher/v3"
)

// ListingsDelete deletes the listing for a specific language.
func (s *Service) ListingsDelete(ctx context.Context, packageName, editID, language string) error {
	if s == nil || s.raw == nil {
		return ErrServiceNil
	}
	if packageName == "" {
		return ErrMissingPackageName
	}
	if editID == "" {
		return ErrMissingEditID
	}
	if language == "" {
		return ErrMissingLanguage
	}
	return s.raw.Edits.Listings.Delete(packageName, editID, language).Context(ctx).Do()
}

// ListingsDeleteAll deletes all listings for the current edit.
func (s *Service) ListingsDeleteAll(ctx context.Context, packageName, editID string) error {
	if s == nil || s.raw == nil {
		return ErrServiceNil
	}
	if packageName == "" {
		return ErrMissingPackageName
	}
	if editID == "" {
		return ErrMissingEditID
	}
	return s.raw.Edits.Listings.Deleteall(packageName, editID).Context(ctx).Do()
}

// ListingsGet fetches the listing for a specific language.
func (s *Service) ListingsGet(ctx context.Context, packageName, editID, language string) (*androidpublisher.Listing, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if editID == "" {
		return nil, ErrMissingEditID
	}
	if language == "" {
		return nil, ErrMissingLanguage
	}
	return s.raw.Edits.Listings.Get(packageName, editID, language).Context(ctx).Do()
}

// ListingsList lists all localized listings for the current edit.
func (s *Service) ListingsList(ctx context.Context, packageName, editID string) (*androidpublisher.ListingsListResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if editID == "" {
		return nil, ErrMissingEditID
	}
	return s.raw.Edits.Listings.List(packageName, editID).Context(ctx).Do()
}

// ListingsPatch partially updates a listing for a specific language.
func (s *Service) ListingsPatch(ctx context.Context, packageName, editID, language string, listing *androidpublisher.Listing) (*androidpublisher.Listing, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if editID == "" {
		return nil, ErrMissingEditID
	}
	if language == "" {
		return nil, ErrMissingLanguage
	}
	if listing == nil {
		return nil, ErrMissingListing
	}
	return s.raw.Edits.Listings.Patch(packageName, editID, language, listing).Context(ctx).Do()
}

// ListingsUpdate fully updates a listing for a specific language.
func (s *Service) ListingsUpdate(ctx context.Context, packageName, editID, language string, listing *androidpublisher.Listing) (*androidpublisher.Listing, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if editID == "" {
		return nil, ErrMissingEditID
	}
	if language == "" {
		return nil, ErrMissingLanguage
	}
	if listing == nil {
		return nil, ErrMissingListing
	}
	return s.raw.Edits.Listings.Update(packageName, editID, language, listing).Context(ctx).Do()
}
