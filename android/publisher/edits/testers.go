package edits

import (
	"context"

	"google.golang.org/api/androidpublisher/v3"
)

// TestersGet wraps androidpublisher.Edits.Testers.Get.
// GET /androidpublisher/v3/applications/{packageName}/edits/{editId}/testers/{track}
func (s *Service) TestersGet(ctx context.Context, packageName, editID, track string) (*androidpublisher.Testers, error) {
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
	return s.raw.Edits.Testers.Get(packageName, editID, track).Context(ctx).Do()
}

// TestersPatch wraps androidpublisher.Edits.Testers.Patch (partial update).
// PATCH /androidpublisher/v3/applications/{packageName}/edits/{editId}/testers/{track}
func (s *Service) TestersPatch(ctx context.Context, packageName, editID, track string, testers *androidpublisher.Testers) (*androidpublisher.Testers, error) {
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
	if testers == nil {
		return nil, ErrMissingTesters
	}
	return s.raw.Edits.Testers.Patch(packageName, editID, track, testers).Context(ctx).Do()
}

// TestersUpdate wraps androidpublisher.Edits.Testers.Update (full replacement).
// PUT /androidpublisher/v3/applications/{packageName}/edits/{editId}/testers/{track}
func (s *Service) TestersUpdate(ctx context.Context, packageName, editID, track string, testers *androidpublisher.Testers) (*androidpublisher.Testers, error) {
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
	if testers == nil {
		return nil, ErrMissingTesters
	}
	return s.raw.Edits.Testers.Update(packageName, editID, track, testers).Context(ctx).Do()
}
