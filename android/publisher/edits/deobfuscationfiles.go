package edits

import (
	"context"
	"io"

	"google.golang.org/api/androidpublisher/v3"
)

// DeobfuscationFilesUpload uploads a deobfuscation (or symbols) file for a
// given APK version.
func (s *Service) DeobfuscationFilesUpload(ctx context.Context, packageName, editID string, apkVersionCode int64, deobfuscationFileType string, media io.Reader) (*androidpublisher.DeobfuscationFilesUploadResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if editID == "" {
		return nil, ErrMissingEditID
	}
	if apkVersionCode == 0 {
		return nil, ErrMissingVersion
	}
	if deobfuscationFileType == "" {
		return nil, ErrMissingFileType
	}
	if media == nil {
		return nil, ErrMissingMedia
	}
	return s.raw.Edits.Deobfuscationfiles.Upload(packageName, editID, apkVersionCode, deobfuscationFileType).Media(media).Context(ctx).Do()
}
