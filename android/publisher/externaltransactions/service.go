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
	// ErrServiceNil is returned when the receiver Service is nil or its raw client is unset.
	ErrServiceNil = errors.New("externaltransactions: service is nil")
	// ErrMissingParent is returned when the parent resource name is empty.
	ErrMissingParent = errors.New("externaltransactions: parent resource name is required")
	// ErrMissingName is returned when the external transaction name is empty.
	ErrMissingName = errors.New("externaltransactions: external transaction name is required")
	// ErrMissingTxn is returned when the external transaction body is nil.
	ErrMissingTxn = errors.New("externaltransactions: external transaction body is required")
	// ErrMissingRefundReq is returned when the refund request body is nil.
	ErrMissingRefundReq = errors.New("externaltransactions: refund request is required")
)

// Service wraps the Google Play Publisher Externaltransactions resource
// (alternative billing / user-choice billing reconciliation).
type Service struct {
	raw *androidpublisher.Service
}

// New constructs an externaltransactions Service from an already-configured raw client.
func New(raw *androidpublisher.Service) *Service { return &Service{raw: raw} }

// CreateOptions holds optional query parameters for Create.
type CreateOptions struct {
	ExternalTransactionID string
}

// Create wraps androidpublisher.Externaltransactions.Createexternaltransaction, reporting a new external transaction.
// POST /androidpublisher/v3/{parent=applications/*}/externalTransactions
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

// Get wraps androidpublisher.Externaltransactions.Getexternaltransaction.
// GET /androidpublisher/v3/{name=applications/*/externalTransactions/*}
func (s *Service) Get(ctx context.Context, name string) (*androidpublisher.ExternalTransaction, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if name == "" {
		return nil, ErrMissingName
	}
	return s.raw.Externaltransactions.Getexternaltransaction(name).Context(ctx).Do()
}

// Refund wraps androidpublisher.Externaltransactions.Refundexternaltransaction.
// POST /androidpublisher/v3/{name=applications/*/externalTransactions/*}:refund
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
