package voidedpurchases

import (
	"time"

	"google.golang.org/api/androidpublisher/v3"
)

// ListOption configures a voidedpurchases list call.
type ListOption func(*androidpublisher.PurchasesVoidedpurchasesListCall)

func WithStartTime(t time.Time) ListOption {
	return func(c *androidpublisher.PurchasesVoidedpurchasesListCall) {
		c.StartTime(t.UnixMilli())
	}
}

func WithEndTime(t time.Time) ListOption {
	return func(c *androidpublisher.PurchasesVoidedpurchasesListCall) {
		c.EndTime(t.UnixMilli())
	}
}

func WithMaxResults(n int64) ListOption {
	return func(c *androidpublisher.PurchasesVoidedpurchasesListCall) {
		c.MaxResults(n)
	}
}

func WithPageToken(token string) ListOption {
	return func(c *androidpublisher.PurchasesVoidedpurchasesListCall) {
		c.Token(token)
	}
}

func WithType(purchaseType int64) ListOption {
	return func(c *androidpublisher.PurchasesVoidedpurchasesListCall) {
		c.Type(purchaseType)
	}
}
