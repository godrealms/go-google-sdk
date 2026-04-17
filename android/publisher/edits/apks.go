package edits

import (
	"context"
	"io"

	"google.golang.org/api/androidpublisher/v3"
)

// ApksAddExternallyHosted wraps androidpublisher.Edits.Apks.Addexternallyhosted
// (enterprise-only externally hosted APK registration).
// POST /androidpublisher/v3/applications/{packageName}/edits/{editId}/apks/externallyHosted
func (s *Service) ApksAddExternallyHosted(ctx context.Context, packageName, editID string, req *androidpublisher.ApksAddExternallyHostedRequest) (*androidpublisher.ApksAddExternallyHostedResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if editID == "" {
		return nil, ErrMissingEditID
	}
	if req == nil {
		return nil, ErrMissingRequest
	}
	return s.raw.Edits.Apks.Addexternallyhosted(packageName, editID, req).Context(ctx).Do()
}

// ApksList wraps androidpublisher.Edits.Apks.List.
// GET /androidpublisher/v3/applications/{packageName}/edits/{editId}/apks
func (s *Service) ApksList(ctx context.Context, packageName, editID string) (*androidpublisher.ApksListResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if editID == "" {
		return nil, ErrMissingEditID
	}
	return s.raw.Edits.Apks.List(packageName, editID).Context(ctx).Do()
}

// ApksUpload wraps androidpublisher.Edits.Apks.Upload, streaming an APK into the current edit.
// POST /upload/androidpublisher/v3/applications/{packageName}/edits/{editId}/apks
func (s *Service) ApksUpload(ctx context.Context, packageName, editID string, media io.Reader) (*androidpublisher.Apk, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if editID == "" {
		return nil, ErrMissingEditID
	}
	if media == nil {
		return nil, ErrMissingMedia
	}
	return s.raw.Edits.Apks.Upload(packageName, editID).Media(media).Context(ctx).Do()
}
