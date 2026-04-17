package subscriptions_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/api/androidpublisher/v3"
	"google.golang.org/api/option"

	msubs "github.com/godrealms/go-google-sdk/android/publisher/monetization/subscriptions"
)

func TestGetHitsExpectedPath(t *testing.T) {
	t.Parallel()
	const pkg, prod = "com.example.app", "sub-1"
	path := "/androidpublisher/v3/applications/" + pkg + "/subscriptions/" + prod
	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{"productId":"sub-1"}`)
	defer closeFunc()
	if _, err := svc.Get(context.Background(), pkg, prod); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListHitsExpectedPath(t *testing.T) {
	t.Parallel()
	const pkg = "com.example.app"
	path := "/androidpublisher/v3/applications/" + pkg + "/subscriptions"
	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.List(context.Background(), pkg, msubs.ListOptions{ShowArchived: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreateHitsExpectedPath(t *testing.T) {
	t.Parallel()
	const pkg, prod = "com.example.app", "sub-1"
	path := "/androidpublisher/v3/applications/" + pkg + "/subscriptions"
	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{"productId":"sub-1"}`)
	defer closeFunc()
	body := &androidpublisher.Subscription{PackageName: pkg}
	if _, err := svc.Create(context.Background(), pkg, prod, body, msubs.CreateOptions{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPatchHitsExpectedPath(t *testing.T) {
	t.Parallel()
	const pkg, prod = "com.example.app", "sub-1"
	path := "/androidpublisher/v3/applications/" + pkg + "/subscriptions/" + prod
	svc, closeFunc := newTestService(t, path, http.MethodPatch, http.StatusOK, `{}`)
	defer closeFunc()
	body := &androidpublisher.Subscription{PackageName: pkg}
	if _, err := svc.Patch(context.Background(), pkg, prod, body, msubs.PatchOptions{UpdateMask: "listings"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteHitsExpectedPath(t *testing.T) {
	t.Parallel()
	const pkg, prod = "com.example.app", "sub-1"
	path := "/androidpublisher/v3/applications/" + pkg + "/subscriptions/" + prod
	svc, closeFunc := newTestService(t, path, http.MethodDelete, http.StatusOK, ``)
	defer closeFunc()
	if err := svc.Delete(context.Background(), pkg, prod, msubs.DeleteOptions{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestArchiveHitsExpectedPath(t *testing.T) {
	t.Parallel()
	const pkg, prod = "com.example.app", "sub-1"
	path := "/androidpublisher/v3/applications/" + pkg + "/subscriptions/" + prod + ":archive"
	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.Archive(context.Background(), pkg, prod, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBatchGetHitsExpectedPath(t *testing.T) {
	t.Parallel()
	const pkg = "com.example.app"
	path := "/androidpublisher/v3/applications/" + pkg + "/subscriptions:batchGet"
	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.BatchGet(context.Background(), pkg, []string{"a", "b"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBatchUpdateHitsExpectedPath(t *testing.T) {
	t.Parallel()
	const pkg = "com.example.app"
	path := "/androidpublisher/v3/applications/" + pkg + "/subscriptions:batchUpdate"
	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.BatchUpdate(context.Background(), pkg, &androidpublisher.BatchUpdateSubscriptionsRequest{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConvertRegionPricesHitsExpectedPath(t *testing.T) {
	t.Parallel()
	const pkg = "com.example.app"
	path := "/androidpublisher/v3/applications/" + pkg + "/pricing:convertRegionPrices"
	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.ConvertRegionPrices(context.Background(), pkg, &androidpublisher.ConvertRegionPricesRequest{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBasePlansEndpoints(t *testing.T) {
	t.Parallel()
	const pkg, prod, bp = "com.example.app", "sub-1", "bp-1"
	base := "/androidpublisher/v3/applications/" + pkg + "/subscriptions/" + prod + "/basePlans"

	cases := []struct {
		name, method, path string
		call               func(*msubs.Service) error
	}{
		{"activate", http.MethodPost, base + "/" + bp + ":activate", func(s *msubs.Service) error {
			_, err := s.BasePlans.Activate(context.Background(), pkg, prod, bp, nil)
			return err
		}},
		{"deactivate", http.MethodPost, base + "/" + bp + ":deactivate", func(s *msubs.Service) error {
			_, err := s.BasePlans.Deactivate(context.Background(), pkg, prod, bp, nil)
			return err
		}},
		{"delete", http.MethodDelete, base + "/" + bp, func(s *msubs.Service) error {
			return s.BasePlans.Delete(context.Background(), pkg, prod, bp)
		}},
		{"migratePrices", http.MethodPost, base + "/" + bp + ":migratePrices", func(s *msubs.Service) error {
			_, err := s.BasePlans.MigratePrices(context.Background(), pkg, prod, bp, &androidpublisher.MigrateBasePlanPricesRequest{})
			return err
		}},
		{"batchMigratePrices", http.MethodPost, base + ":batchMigratePrices", func(s *msubs.Service) error {
			_, err := s.BasePlans.BatchMigratePrices(context.Background(), pkg, prod, &androidpublisher.BatchMigrateBasePlanPricesRequest{})
			return err
		}},
		{"batchUpdateStates", http.MethodPost, base + ":batchUpdateStates", func(s *msubs.Service) error {
			_, err := s.BasePlans.BatchUpdateStates(context.Background(), pkg, prod, &androidpublisher.BatchUpdateBasePlanStatesRequest{})
			return err
		}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc, closeFunc := newTestService(t, tc.path, tc.method, http.StatusOK, `{}`)
			defer closeFunc()
			if err := tc.call(svc); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestOffersEndpoints(t *testing.T) {
	t.Parallel()
	const pkg, prod, bp, off = "com.example.app", "sub-1", "bp-1", "off-1"
	base := "/androidpublisher/v3/applications/" + pkg + "/subscriptions/" + prod + "/basePlans/" + bp + "/offers"

	cases := []struct {
		name, method, path string
		call               func(*msubs.Service) error
	}{
		{"get", http.MethodGet, base + "/" + off, func(s *msubs.Service) error {
			_, err := s.BasePlans.Offers.Get(context.Background(), pkg, prod, bp, off)
			return err
		}},
		{"list", http.MethodGet, base, func(s *msubs.Service) error {
			_, err := s.BasePlans.Offers.List(context.Background(), pkg, prod, bp, msubs.ListOptions{})
			return err
		}},
		{"create", http.MethodPost, base, func(s *msubs.Service) error {
			_, err := s.BasePlans.Offers.Create(context.Background(), pkg, prod, bp, &androidpublisher.SubscriptionOffer{}, msubs.CreateOptions{})
			return err
		}},
		{"patch", http.MethodPatch, base + "/" + off, func(s *msubs.Service) error {
			_, err := s.BasePlans.Offers.Patch(context.Background(), pkg, prod, bp, off, &androidpublisher.SubscriptionOffer{}, msubs.PatchOptions{})
			return err
		}},
		{"delete", http.MethodDelete, base + "/" + off, func(s *msubs.Service) error {
			return s.BasePlans.Offers.Delete(context.Background(), pkg, prod, bp, off)
		}},
		{"activate", http.MethodPost, base + "/" + off + ":activate", func(s *msubs.Service) error {
			_, err := s.BasePlans.Offers.Activate(context.Background(), pkg, prod, bp, off, nil)
			return err
		}},
		{"deactivate", http.MethodPost, base + "/" + off + ":deactivate", func(s *msubs.Service) error {
			_, err := s.BasePlans.Offers.Deactivate(context.Background(), pkg, prod, bp, off, nil)
			return err
		}},
		{"batchGet", http.MethodPost, base + ":batchGet", func(s *msubs.Service) error {
			_, err := s.BasePlans.Offers.BatchGet(context.Background(), pkg, prod, bp, &androidpublisher.BatchGetSubscriptionOffersRequest{})
			return err
		}},
		{"batchUpdate", http.MethodPost, base + ":batchUpdate", func(s *msubs.Service) error {
			_, err := s.BasePlans.Offers.BatchUpdate(context.Background(), pkg, prod, bp, &androidpublisher.BatchUpdateSubscriptionOffersRequest{})
			return err
		}},
		{"batchUpdateStates", http.MethodPost, base + ":batchUpdateStates", func(s *msubs.Service) error {
			_, err := s.BasePlans.Offers.BatchUpdateStates(context.Background(), pkg, prod, bp, &androidpublisher.BatchUpdateSubscriptionOfferStatesRequest{})
			return err
		}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc, closeFunc := newTestService(t, tc.path, tc.method, http.StatusOK, `{}`)
			defer closeFunc()
			if err := tc.call(svc); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidationErrors(t *testing.T) {
	t.Parallel()
	svc, closeFunc := newTestService(t, "/unused", http.MethodGet, http.StatusOK, `{}`)
	defer closeFunc()

	if _, err := svc.Create(context.Background(), "", "p", &androidpublisher.Subscription{}, msubs.CreateOptions{}); err == nil {
		t.Fatalf("expected missing packageName")
	}
	if _, err := svc.Create(context.Background(), "pkg", "p", nil, msubs.CreateOptions{}); err == nil {
		t.Fatalf("expected missing subscription body")
	}
	if _, err := svc.BatchUpdate(context.Background(), "pkg", nil); err == nil {
		t.Fatalf("expected missing request")
	}
	if _, err := svc.BasePlans.Offers.Patch(context.Background(), "pkg", "p", "bp", "", &androidpublisher.SubscriptionOffer{}, msubs.PatchOptions{}); err == nil {
		t.Fatalf("expected missing offerID")
	}
}

func newTestService(t *testing.T, expectedPath, expectedMethod string, status int, body string) (*msubs.Service, func()) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != expectedMethod {
			t.Errorf("expected %s, got %s", expectedMethod, r.Method)
		}
		if r.URL.Path != expectedPath {
			t.Errorf("unexpected path: got %q, want %q", r.URL.Path, expectedPath)
		}
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	raw, err := androidpublisher.NewService(context.Background(),
		option.WithEndpoint(server.URL),
		option.WithoutAuthentication(),
	)
	if err != nil {
		t.Fatalf("create raw service: %v", err)
	}
	return msubs.New(raw), server.Close
}
