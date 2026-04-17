package edits

import (
	"context"

	"google.golang.org/api/androidpublisher/v3"
)

// TracksCreate creates a new track.
func (s *Service) TracksCreate(ctx context.Context, packageName, editID string, cfg *androidpublisher.TrackConfig) (*androidpublisher.Track, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if editID == "" {
		return nil, ErrMissingEditID
	}
	if cfg == nil {
		return nil, ErrMissingTrackConfig
	}
	return s.raw.Edits.Tracks.Create(packageName, editID, cfg).Context(ctx).Do()
}

// TracksGet fetches a single track.
func (s *Service) TracksGet(ctx context.Context, packageName, editID, track string) (*androidpublisher.Track, error) {
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
	return s.raw.Edits.Tracks.Get(packageName, editID, track).Context(ctx).Do()
}

// TracksList lists all tracks for the current edit.
func (s *Service) TracksList(ctx context.Context, packageName, editID string) (*androidpublisher.TracksListResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if editID == "" {
		return nil, ErrMissingEditID
	}
	return s.raw.Edits.Tracks.List(packageName, editID).Context(ctx).Do()
}

// TracksPatch partially updates a track.
func (s *Service) TracksPatch(ctx context.Context, packageName, editID, track string, body *androidpublisher.Track) (*androidpublisher.Track, error) {
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
	if body == nil {
		return nil, ErrMissingTrackBody
	}
	return s.raw.Edits.Tracks.Patch(packageName, editID, track, body).Context(ctx).Do()
}

// TracksUpdate fully updates a track.
func (s *Service) TracksUpdate(ctx context.Context, packageName, editID, track string, body *androidpublisher.Track) (*androidpublisher.Track, error) {
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
	if body == nil {
		return nil, ErrMissingTrackBody
	}
	return s.raw.Edits.Tracks.Update(packageName, editID, track, body).Context(ctx).Do()
}
