package edits

import (
	"context"
	"io"

	"google.golang.org/api/androidpublisher/v3"
)

// ImagesDelete wraps androidpublisher.Edits.Images.Delete.
// DELETE /androidpublisher/v3/applications/{packageName}/edits/{editId}/listings/{language}/{imageType}/{imageId}
func (s *Service) ImagesDelete(ctx context.Context, packageName, editID, language, imageType, imageID string) error {
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
	if imageType == "" {
		return ErrMissingImageType
	}
	if imageID == "" {
		return ErrMissingImageID
	}
	return s.raw.Edits.Images.Delete(packageName, editID, language, imageType, imageID).Context(ctx).Do()
}

// ImagesDeleteAll wraps androidpublisher.Edits.Images.Deleteall.
// DELETE /androidpublisher/v3/applications/{packageName}/edits/{editId}/listings/{language}/{imageType}
func (s *Service) ImagesDeleteAll(ctx context.Context, packageName, editID, language, imageType string) (*androidpublisher.ImagesDeleteAllResponse, error) {
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
	if imageType == "" {
		return nil, ErrMissingImageType
	}
	return s.raw.Edits.Images.Deleteall(packageName, editID, language, imageType).Context(ctx).Do()
}

// ImagesList wraps androidpublisher.Edits.Images.List.
// GET /androidpublisher/v3/applications/{packageName}/edits/{editId}/listings/{language}/{imageType}
func (s *Service) ImagesList(ctx context.Context, packageName, editID, language, imageType string) (*androidpublisher.ImagesListResponse, error) {
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
	if imageType == "" {
		return nil, ErrMissingImageType
	}
	return s.raw.Edits.Images.List(packageName, editID, language, imageType).Context(ctx).Do()
}

// ImagesUpload wraps androidpublisher.Edits.Images.Upload.
// POST /upload/androidpublisher/v3/applications/{packageName}/edits/{editId}/listings/{language}/{imageType}
func (s *Service) ImagesUpload(ctx context.Context, packageName, editID, language, imageType string, media io.Reader) (*androidpublisher.ImagesUploadResponse, error) {
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
	if imageType == "" {
		return nil, ErrMissingImageType
	}
	if media == nil {
		return nil, ErrMissingMedia
	}
	return s.raw.Edits.Images.Upload(packageName, editID, language, imageType).Media(media).Context(ctx).Do()
}
