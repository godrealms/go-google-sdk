package edits

import (
	"context"
	"io"

	"google.golang.org/api/androidpublisher/v3"
)

func (s *Service) validateExpansionArgs(packageName, editID string, apkVersionCode int64, expansionFileType string) error {
	if s == nil || s.raw == nil {
		return ErrServiceNil
	}
	if packageName == "" {
		return ErrMissingPackageName
	}
	if editID == "" {
		return ErrMissingEditID
	}
	if apkVersionCode == 0 {
		return ErrMissingVersion
	}
	if expansionFileType == "" {
		return ErrMissingFileType
	}
	return nil
}

// ExpansionFilesGet fetches the expansion file configuration for an APK.
func (s *Service) ExpansionFilesGet(ctx context.Context, packageName, editID string, apkVersionCode int64, expansionFileType string) (*androidpublisher.ExpansionFile, error) {
	if err := s.validateExpansionArgs(packageName, editID, apkVersionCode, expansionFileType); err != nil {
		return nil, err
	}
	return s.raw.Edits.Expansionfiles.Get(packageName, editID, apkVersionCode, expansionFileType).Context(ctx).Do()
}

// ExpansionFilesPatch partially updates an expansion file configuration.
func (s *Service) ExpansionFilesPatch(ctx context.Context, packageName, editID string, apkVersionCode int64, expansionFileType string, file *androidpublisher.ExpansionFile) (*androidpublisher.ExpansionFile, error) {
	if err := s.validateExpansionArgs(packageName, editID, apkVersionCode, expansionFileType); err != nil {
		return nil, err
	}
	if file == nil {
		return nil, ErrMissingExpansion
	}
	return s.raw.Edits.Expansionfiles.Patch(packageName, editID, apkVersionCode, expansionFileType, file).Context(ctx).Do()
}

// ExpansionFilesUpdate fully updates an expansion file configuration.
func (s *Service) ExpansionFilesUpdate(ctx context.Context, packageName, editID string, apkVersionCode int64, expansionFileType string, file *androidpublisher.ExpansionFile) (*androidpublisher.ExpansionFile, error) {
	if err := s.validateExpansionArgs(packageName, editID, apkVersionCode, expansionFileType); err != nil {
		return nil, err
	}
	if file == nil {
		return nil, ErrMissingExpansion
	}
	return s.raw.Edits.Expansionfiles.Update(packageName, editID, apkVersionCode, expansionFileType, file).Context(ctx).Do()
}

// ExpansionFilesUpload uploads an expansion file for an APK version.
func (s *Service) ExpansionFilesUpload(ctx context.Context, packageName, editID string, apkVersionCode int64, expansionFileType string, media io.Reader) (*androidpublisher.ExpansionFilesUploadResponse, error) {
	if err := s.validateExpansionArgs(packageName, editID, apkVersionCode, expansionFileType); err != nil {
		return nil, err
	}
	if media == nil {
		return nil, ErrMissingMedia
	}
	return s.raw.Edits.Expansionfiles.Upload(packageName, editID, apkVersionCode, expansionFileType).Media(media).Context(ctx).Do()
}
