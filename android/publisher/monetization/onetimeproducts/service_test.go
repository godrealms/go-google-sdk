package onetimeproducts_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/api/androidpublisher/v3"
	"google.golang.org/api/option"

	"github.com/godrealms/go-google-sdk/android/publisher/monetization/onetimeproducts"
)

func TestGetHitsExpectedPath(t *testing.T) {
	t.Parallel()
	const pkg, prod = "com.example.app", "prod-1"
	path := "/androidpublisher/v3/applications/" + pkg + "/oneTimeProducts/" + prod
	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{"productId":"prod-1"}`)
	defer closeFunc()
	p, err := svc.Get(context.Background(), pkg, prod)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil || p.ProductId != prod {
		t.Fatalf("got %+v", p)
	}
}

func TestListHitsExpectedPath(t *testing.T) {
	t.Parallel()
	const pkg = "com.example.app"
	path := "/androidpublisher/v3/applications/" + pkg + "/oneTimeProducts"
	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.List(context.Background(), pkg, onetimeproducts.ListOptions{PageSize: 50}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteHitsExpectedPath(t *testing.T) {
	t.Parallel()
	const pkg, prod = "com.example.app", "prod-1"
	path := "/androidpublisher/v3/applications/" + pkg + "/oneTimeProducts/" + prod
	svc, closeFunc := newTestService(t, path, http.MethodDelete, http.StatusOK, ``)
	defer closeFunc()
	if err := svc.Delete(context.Background(), pkg, prod, onetimeproducts.DeleteOptions{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPatchHitsExpectedPath(t *testing.T) {
	t.Parallel()
	const pkg, prod = "com.example.app", "prod-1"
	// Generated client uses lowercase "onetimeproducts" for PATCH (vs camelCase elsewhere).
	path := "/androidpublisher/v3/applications/" + pkg + "/onetimeproducts/" + prod
	svc, closeFunc := newTestService(t, path, http.MethodPatch, http.StatusOK, `{"productId":"prod-1"}`)
	defer closeFunc()
	body := &androidpublisher.OneTimeProduct{ProductId: prod, PackageName: pkg}
	if _, err := svc.Patch(context.Background(), pkg, prod, body, onetimeproducts.PatchOptions{UpdateMask: "listings"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPatchRejectsNilBody(t *testing.T) {
	t.Parallel()
	svc, closeFunc := newTestService(t, "/unused", http.MethodPatch, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.Patch(context.Background(), "com.example", "prod", nil, onetimeproducts.PatchOptions{}); err == nil {
		t.Fatalf("expected error for nil product body")
	}
}

func TestBatchGetHitsExpectedPath(t *testing.T) {
	t.Parallel()
	const pkg = "com.example.app"
	path := "/androidpublisher/v3/applications/" + pkg + "/oneTimeProducts:batchGet"
	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.BatchGet(context.Background(), pkg, []string{"a", "b"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBatchUpdateHitsExpectedPath(t *testing.T) {
	t.Parallel()
	const pkg = "com.example.app"
	path := "/androidpublisher/v3/applications/" + pkg + "/oneTimeProducts:batchUpdate"
	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()
	req := &androidpublisher.BatchUpdateOneTimeProductsRequest{}
	if _, err := svc.BatchUpdate(context.Background(), pkg, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBatchDeleteHitsExpectedPath(t *testing.T) {
	t.Parallel()
	const pkg = "com.example.app"
	path := "/androidpublisher/v3/applications/" + pkg + "/oneTimeProducts:batchDelete"
	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, ``)
	defer closeFunc()
	req := &androidpublisher.BatchDeleteOneTimeProductsRequest{}
	if err := svc.BatchDelete(context.Background(), pkg, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPurchaseOptionsBatchDelete(t *testing.T) {
	t.Parallel()
	const pkg, prod = "com.example.app", "prod-1"
	path := "/androidpublisher/v3/applications/" + pkg + "/oneTimeProducts/" + prod + "/purchaseOptions:batchDelete"
	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, ``)
	defer closeFunc()
	if err := svc.PurchaseOptions.BatchDelete(context.Background(), pkg, prod, &androidpublisher.BatchDeletePurchaseOptionsRequest{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPurchaseOptionsBatchUpdateStates(t *testing.T) {
	t.Parallel()
	const pkg, prod = "com.example.app", "prod-1"
	path := "/androidpublisher/v3/applications/" + pkg + "/oneTimeProducts/" + prod + "/purchaseOptions:batchUpdateStates"
	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.PurchaseOptions.BatchUpdateStates(context.Background(), pkg, prod, &androidpublisher.BatchUpdatePurchaseOptionStatesRequest{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOffersActivate(t *testing.T) {
	t.Parallel()
	const pkg, prod, po, off = "com.example.app", "prod-1", "po-1", "off-1"
	path := "/androidpublisher/v3/applications/" + pkg + "/oneTimeProducts/" + prod + "/purchaseOptions/" + po + "/offers/" + off + ":activate"
	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.PurchaseOptions.Offers.Activate(context.Background(), pkg, prod, po, off, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOffersCancel(t *testing.T) {
	t.Parallel()
	const pkg, prod, po, off = "com.example.app", "prod-1", "po-1", "off-1"
	path := "/androidpublisher/v3/applications/" + pkg + "/oneTimeProducts/" + prod + "/purchaseOptions/" + po + "/offers/" + off + ":cancel"
	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.PurchaseOptions.Offers.Cancel(context.Background(), pkg, prod, po, off, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOffersDeactivate(t *testing.T) {
	t.Parallel()
	const pkg, prod, po, off = "com.example.app", "prod-1", "po-1", "off-1"
	path := "/androidpublisher/v3/applications/" + pkg + "/oneTimeProducts/" + prod + "/purchaseOptions/" + po + "/offers/" + off + ":deactivate"
	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.PurchaseOptions.Offers.Deactivate(context.Background(), pkg, prod, po, off, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOffersList(t *testing.T) {
	t.Parallel()
	const pkg, prod, po = "com.example.app", "prod-1", "po-1"
	path := "/androidpublisher/v3/applications/" + pkg + "/oneTimeProducts/" + prod + "/purchaseOptions/" + po + "/offers"
	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{}`)
	defer closeFunc()
	if _, err := svc.PurchaseOptions.Offers.List(context.Background(), pkg, prod, po, onetimeproducts.ListOptions{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOffersBatchEndpoints(t *testing.T) {
	t.Parallel()
	const pkg, prod, po = "com.example.app", "prod-1", "po-1"
	base := "/androidpublisher/v3/applications/" + pkg + "/oneTimeProducts/" + prod + "/purchaseOptions/" + po + "/offers"

	cases := []struct {
		name, path string
		call       func(*onetimeproducts.Service) error
	}{
		{"batchGet", base + ":batchGet", func(s *onetimeproducts.Service) error {
			_, err := s.PurchaseOptions.Offers.BatchGet(context.Background(), pkg, prod, po, &androidpublisher.BatchGetOneTimeProductOffersRequest{})
			return err
		}},
		{"batchUpdate", base + ":batchUpdate", func(s *onetimeproducts.Service) error {
			_, err := s.PurchaseOptions.Offers.BatchUpdate(context.Background(), pkg, prod, po, &androidpublisher.BatchUpdateOneTimeProductOffersRequest{})
			return err
		}},
		{"batchDelete", base + ":batchDelete", func(s *onetimeproducts.Service) error {
			return s.PurchaseOptions.Offers.BatchDelete(context.Background(), pkg, prod, po, &androidpublisher.BatchDeleteOneTimeProductOffersRequest{})
		}},
		{"batchUpdateStates", base + ":batchUpdateStates", func(s *onetimeproducts.Service) error {
			_, err := s.PurchaseOptions.Offers.BatchUpdateStates(context.Background(), pkg, prod, po, &androidpublisher.BatchUpdateOneTimeProductOfferStatesRequest{})
			return err
		}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc, closeFunc := newTestService(t, tc.path, http.MethodPost, http.StatusOK, `{}`)
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

	if _, err := svc.Get(context.Background(), "", "p"); err == nil {
		t.Fatalf("expected missing packageName")
	}
	if _, err := svc.Get(context.Background(), "pkg", ""); err == nil {
		t.Fatalf("expected missing productID")
	}
	if err := svc.BatchDelete(context.Background(), "pkg", nil); err == nil {
		t.Fatalf("expected missing request")
	}
	if _, err := svc.PurchaseOptions.Offers.Activate(context.Background(), "pkg", "p", "po", "", nil); err == nil {
		t.Fatalf("expected missing offerID")
	}
}

func newTestService(t *testing.T, expectedPath, expectedMethod string, status int, body string) (*onetimeproducts.Service, func()) {
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
	return onetimeproducts.New(raw), server.Close
}
