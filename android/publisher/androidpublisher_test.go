package publisher

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"golang.org/x/oauth2"
	"google.golang.org/api/androidpublisher/v3"
	"google.golang.org/api/option"
)

func TestVerifyPurchaseReturnsErrorForNilService(t *testing.T) {
	t.Parallel()

	var s *Service
	if _, err := s.VerifyPurchase("pkg", "prod", "token"); err == nil {
		t.Fatalf("expected error for nil service")
	} else if err.Error() != "service is nil" {
		t.Fatalf("unexpected nil service error: %v", err)
	}
}

func TestVerifyPurchaseReturnsErrorForMissingServices(t *testing.T) {
	t.Parallel()

	s := &Service{Androidpublisher: &androidpublisher.Service{}}
	if _, err := s.VerifyPurchase("pkg", "prod", "token"); err == nil {
		t.Fatalf("expected error when purchases service is missing")
	} else if err.Error() != "products service is unavailable" {
		t.Fatalf("unexpected products service error: %v", err)
	}
}

func TestVerifySubscriptionsReturnsErrorForNilService(t *testing.T) {
	t.Parallel()

	var s *Service
	if _, err := s.VerifySubscriptions("pkg", "sub", "token"); err == nil {
		t.Fatalf("expected error for nil service")
	} else if err.Error() != "service is nil" {
		t.Fatalf("unexpected nil service error: %v", err)
	}
}

func TestVerifySubscriptionsReturnsErrorForMissingServices(t *testing.T) {
	t.Parallel()

	s := &Service{Androidpublisher: &androidpublisher.Service{}}
	if _, err := s.VerifySubscriptions("pkg", "sub", "token"); err == nil {
		t.Fatalf("expected error when subscriptions service is missing")
	} else if err.Error() != "subscriptions service is unavailable" {
		t.Fatalf("unexpected subscriptions service error: %v", err)
	}
}

func TestNewServiceWithTokenSourceRequiresConfig(t *testing.T) {
	t.Parallel()

	if _, err := NewServiceWithTokenSource(context.Background(), nil, "code"); err == nil {
		t.Fatalf("expected nil config error")
	} else if err.Error() != "config is nil" {
		t.Fatalf("unexpected config error: %v", err)
	}
}

func TestNewServiceWithKeyRejectsEmptyAPIKey(t *testing.T) {
	t.Parallel()

	if _, err := NewServiceWithKey(context.Background(), ""); err == nil {
		t.Fatalf("expected error for empty api key")
	} else if err.Error() != "api key is required" {
		t.Fatalf("unexpected api key error: %v", err)
	}
}

func TestNewServiceFallsBackNilContext(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("expected nil context fallback without panic, got %v", r)
		}
	}()

	_, _ = NewService(nil)
}

func TestNewServiceWithTokenSourceNilContextReturnsErrorForMissingTokenURL(t *testing.T) {
	t.Parallel()

	cfg := &oauth2.Config{}
	if _, err := NewServiceWithTokenSource(nil, cfg, "code"); err == nil {
		t.Fatalf("expected exchange error with zero oauth2 config")
	}
}

func TestNewServiceWithTokenSourceWorksWithNilContext(t *testing.T) {
	t.Parallel()

	var requests int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"nil-ctx-token","token_type":"Bearer"}`)
	}))
	t.Cleanup(func() { ts.Close() })

	cfg := &oauth2.Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Endpoint: oauth2.Endpoint{
			TokenURL: ts.URL,
		},
	}

	svc, err := NewServiceWithTokenSource(nil, cfg, "code")
	if err != nil {
		t.Fatalf("expected service creation to succeed with nil context, got: %v", err)
	}
	if svc == nil || svc.Androidpublisher == nil {
		t.Fatalf("expected service to be created")
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Fatalf("expected one token request, got %d", got)
	}
}

func TestNewServiceWithTokenSourceCallsTokenEndpoint(t *testing.T) {
	t.Parallel()

	var requests int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"bad code"}`))
	}))
	defer ts.Close()

	cfg := &oauth2.Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Endpoint: oauth2.Endpoint{
			TokenURL: ts.URL,
		},
	}

	_, err := NewServiceWithTokenSource(context.Background(), cfg, "invalid-code")
	if err == nil {
		t.Fatalf("expected token exchange error")
	}
	if got := atomic.LoadInt32(&requests); got < 1 {
		t.Fatalf("expected at least one token request, got %d", got)
	}
}

func TestNewServiceWithTokenSourceReturnsServiceAfterSuccessfulExchange(t *testing.T) {
	t.Parallel()

	var requests int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"test-token","token_type":"Bearer"}`))
	}))
	t.Cleanup(func() { ts.Close() })

	cfg := &oauth2.Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Endpoint: oauth2.Endpoint{
			TokenURL: ts.URL,
		},
	}

	svc, err := NewServiceWithTokenSource(context.Background(), cfg, "valid-code")
	if err != nil {
		t.Fatalf("expected successful service creation, got: %v", err)
	}
	if svc == nil || svc.Androidpublisher == nil {
		t.Fatalf("expected non-nil service")
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Fatalf("expected exactly one token request, got %d", got)
	}
}

func TestVerifyPurchaseReturnsPurchaseForPurchasedState(t *testing.T) {
	t.Parallel()

	var requestPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"purchaseState":0}`)
	}))
	t.Cleanup(func() { ts.Close() })

	api, err := androidpublisher.NewService(context.Background(),
		option.WithEndpoint(ts.URL),
		option.WithHTTPClient(ts.Client()),
	)
	if err != nil {
		t.Fatalf("failed to create test api service: %v", err)
	}

	svc := &Service{Androidpublisher: api}
	if _, err := svc.VerifyPurchase("pkg", "prod", "token"); err != nil {
		t.Fatalf("expected purchase to be valid, got %v", err)
	}
	if requestPath == "" {
		t.Fatalf("expected request path to be set")
	}
}

func TestVerifyPurchaseRejectsNonPurchasedState(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"purchaseState":1}`)
	}))
	t.Cleanup(func() { ts.Close() })

	api, err := androidpublisher.NewService(context.Background(), option.WithEndpoint(ts.URL), option.WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("failed to create test api service: %v", err)
	}

	svc := &Service{Androidpublisher: api}
	if _, err := svc.VerifyPurchase("pkg", "prod", "token"); err == nil {
		t.Fatalf("expected invalid purchase state error")
	} else if err.Error() != "purchase not valid" {
		t.Fatalf("unexpected invalid purchase state error: %v", err)
	}
}

func TestVerifyPurchaseReturnsErrorWhenApiCallFails(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":"internal"}`)
	}))
	t.Cleanup(func() { ts.Close() })

	api, err := androidpublisher.NewService(context.Background(), option.WithEndpoint(ts.URL), option.WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("failed to create test api service: %v", err)
	}

	svc := &Service{Androidpublisher: api}
	if _, err := svc.VerifyPurchase("pkg", "prod", "token"); err == nil {
		t.Fatalf("expected api error when purchase call fails")
	}
}

func TestVerifySubscriptionsReturnsSubscriptionForAcknowledgedPaidState(t *testing.T) {
	t.Parallel()

	paymentState := int64(1)
	payload, _ := json.Marshal(map[string]any{
		"acknowledgementState": 1,
		"paymentState":         paymentState,
	})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, string(payload))
	}))
	t.Cleanup(func() { ts.Close() })

	api, err := androidpublisher.NewService(context.Background(), option.WithEndpoint(ts.URL), option.WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("failed to create test api service: %v", err)
	}

	svc := &Service{Androidpublisher: api}
	if _, err := svc.VerifySubscriptions("pkg", "sub", "token"); err != nil {
		t.Fatalf("expected active subscription, got %v", err)
	}
}

func TestVerifySubscriptionsRejectsMissingPaymentState(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"acknowledgementState":1}`)
	}))
	t.Cleanup(func() { ts.Close() })

	api, err := androidpublisher.NewService(context.Background(), option.WithEndpoint(ts.URL), option.WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("failed to create test api service: %v", err)
	}

	svc := &Service{Androidpublisher: api}
	if _, err := svc.VerifySubscriptions("pkg", "sub", "token"); err == nil {
		t.Fatalf("expected payment state validation error")
	} else if err.Error() != "purchase not valid" {
		t.Fatalf("unexpected missing payment state error: %v", err)
	}
}

func TestVerifySubscriptionsRejectsUnacknowledgedPaidState(t *testing.T) {
	t.Parallel()

	paymentState := int64(1)
	payload, _ := json.Marshal(map[string]any{
		"acknowledgementState": 0,
		"paymentState":         paymentState,
	})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, string(payload))
	}))
	t.Cleanup(func() { ts.Close() })

	api, err := androidpublisher.NewService(context.Background(), option.WithEndpoint(ts.URL), option.WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("failed to create test api service: %v", err)
	}

	svc := &Service{Androidpublisher: api}
	if _, err := svc.VerifySubscriptions("pkg", "sub", "token"); err == nil {
		t.Fatalf("expected acknowledgement state validation error")
	} else if err.Error() != "purchase not valid" {
		t.Fatalf("unexpected unacknowledged paid error: %v", err)
	}
}

func TestVerifySubscriptionsReturnsErrorWhenApiCallFails(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":"internal"}`)
	}))
	t.Cleanup(func() { ts.Close() })

	api, err := androidpublisher.NewService(context.Background(), option.WithEndpoint(ts.URL), option.WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("failed to create test api service: %v", err)
	}

	svc := &Service{Androidpublisher: api}
	if _, err := svc.VerifySubscriptions("pkg", "sub", "token"); err == nil {
		t.Fatalf("expected api error when subscription call fails")
	}
}
