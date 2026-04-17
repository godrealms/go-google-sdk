package edits

import (
	"context"
	"io"

	"google.golang.org/api/androidpublisher/v3"
)

// ImagesDelete deletes a single image.
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

// ImagesDeleteAll deletes all images of a given type for a language.
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

// ImagesList lists images of a given type for a language.
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

// ImagesUpload uploads an image of a given type for a language.
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
