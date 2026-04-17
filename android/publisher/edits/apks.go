package edits

import (
	"context"
	"io"

	"google.golang.org/api/androidpublisher/v3"
)

// ApksAddExternallyHosted registers an externally hosted APK (enterprise only).
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

// ApksList lists all uploaded APKs for the current edit.
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

// ApksUpload uploads an APK to the current edit.
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
