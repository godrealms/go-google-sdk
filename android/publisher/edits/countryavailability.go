package edits

import (
	"context"

	"google.golang.org/api/androidpublisher/v3"
)

// CountryAvailabilityGet fetches country availability for a track.
func (s *Service) CountryAvailabilityGet(ctx context.Context, packageName, editID, track string) (*androidpublisher.TrackCountryAvailability, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if editID == "" {
		return nil, ErrMissingEditID
	}
	if track == "" {
		return nil, ErrMissingTrack
	}
	return s.raw.Edits.Countryavailability.Get(packageName, editID, track).Context(ctx).Do()
}
