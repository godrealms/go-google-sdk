// Package reviews wraps the Google Play Publisher reviews API (user reviews
// of the app, with reply support).
package reviews

import (
	"context"
	"errors"

	"google.golang.org/api/androidpublisher/v3"
)

var (
	// ErrServiceNil is returned when the receiver Service is nil or its raw client is unset.
	ErrServiceNil = errors.New("reviews: service is nil")
	// ErrMissingPackageName is returned when the packageName argument is empty.
	ErrMissingPackageName = errors.New("reviews: packageName is required")
	// ErrMissingReviewID is returned when the reviewID argument is empty.
	ErrMissingReviewID = errors.New("reviews: reviewID is required")
	// ErrMissingReply is returned when the reply text is empty.
	ErrMissingReply = errors.New("reviews: reply text is required")
)

// Service wraps the Google Play Publisher Reviews resource.
type Service struct {
	raw *androidpublisher.Service
}

// New constructs a reviews Service from an already-configured raw client.
func New(raw *androidpublisher.Service) *Service { return &Service{raw: raw} }

// ListOptions holds optional query parameters for List.
type ListOptions struct {
	MaxResults          int64
	StartIndex          int64
	Token               string
	TranslationLanguage string
}

// Get wraps androidpublisher.Reviews.Get.
// GET /androidpublisher/v3/applications/{packageName}/reviews/{reviewId}
func (s *Service) Get(ctx context.Context, packageName, reviewID, translationLanguage string) (*androidpublisher.Review, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if reviewID == "" {
		return nil, ErrMissingReviewID
	}
	call := s.raw.Reviews.Get(packageName, reviewID).Context(ctx)
	if translationLanguage != "" {
		call = call.TranslationLanguage(translationLanguage)
	}
	return call.Do()
}

// List wraps androidpublisher.Reviews.List.
// GET /androidpublisher/v3/applications/{packageName}/reviews
func (s *Service) List(ctx context.Context, packageName string, opts ListOptions) (*androidpublisher.ReviewsListResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	call := s.raw.Reviews.List(packageName).Context(ctx)
	if opts.MaxResults > 0 {
		call = call.MaxResults(opts.MaxResults)
	}
	if opts.StartIndex > 0 {
		call = call.StartIndex(opts.StartIndex)
	}
	if opts.Token != "" {
		call = call.Token(opts.Token)
	}
	if opts.TranslationLanguage != "" {
		call = call.TranslationLanguage(opts.TranslationLanguage)
	}
	return call.Do()
}

// Reply wraps androidpublisher.Reviews.Reply, posting a developer reply to a user review.
// POST /androidpublisher/v3/applications/{packageName}/reviews/{reviewId}:reply
func (s *Service) Reply(ctx context.Context, packageName, reviewID, replyText string) (*androidpublisher.ReviewsReplyResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if reviewID == "" {
		return nil, ErrMissingReviewID
	}
	if replyText == "" {
		return nil, ErrMissingReply
	}
	return s.raw.Reviews.Reply(packageName, reviewID, &androidpublisher.ReviewsReplyRequest{
		ReplyText: replyText,
	}).Context(ctx).Do()
}
