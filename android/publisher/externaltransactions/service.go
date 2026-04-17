// Package externaltransactions wraps the Google Play Publisher external
// transactions API. "parent" uses "applications/{packageName}" and "name"
// uses "applications/{packageName}/externalTransactions/{externalTransactionId}".
package externaltransactions

import (
	"context"
	"errors"

	"google.golang.org/api/androidpublisher/v3"
)

var (
	ErrServiceNil       = errors.New("externaltransactions: service is nil")
	ErrMissingParent    = errors.New("externaltransactions: parent resource name is required")
	ErrMissingName      = errors.New("externaltransactions: external transaction name is required")
	ErrMissingTxn       = errors.New("externaltransactions: external transaction body is required")
	ErrMissingRefundReq = errors.New("externaltransactions: refund request is required")
)

type Service struct {
	raw *androidpublisher.Service
}

func New(raw *androidpublisher.Service) *Service { return &Service{raw: raw} }

// CreateOptions holds optional query parameters for Create.
type CreateOptions struct {
	ExternalTransactionID string
}

func (s *Service) Create(ctx context.Context, parent string, txn *androidpublisher.ExternalTransaction, opts CreateOptions) (*androidpublisher.ExternalTransaction, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if parent == "" {
		return nil, ErrMissingParent
	}
	if txn == nil {
		return nil, ErrMissingTxn
	}
	call := s.raw.Externaltransactions.Createexternaltransaction(parent, txn).Context(ctx)
	if opts.ExternalTransactionID != "" {
		call = call.ExternalTransactionId(opts.ExternalTransactionID)
	}
	return call.Do()
}

func (s *Service) Get(ctx context.Context, name string) (*androidpublisher.ExternalTransaction, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if name == "" {
		return nil, ErrMissingName
	}
	return s.raw.Externaltransactions.Getexternaltransaction(name).Context(ctx).Do()
}

func (s *Service) Refund(ctx context.Context, name string, req *androidpublisher.RefundExternalTransactionRequest) (*androidpublisher.ExternalTransaction, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if name == "" {
		return nil, ErrMissingName
	}
	if req == nil {
		return nil, ErrMissingRefundReq
	}
	return s.raw.Externaltransactions.Refundexternaltransaction(name, req).Context(ctx).Do()
}
