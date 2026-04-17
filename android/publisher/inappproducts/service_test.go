package inappproducts_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/api/androidpublisher/v3"
	"google.golang.org/api/option"

	"github.com/godrealms/go-google-sdk/android/publisher/inappproducts"
)

func TestListSucceeds(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	path := "/androidpublisher/v3/applications/" + pkg + "/inappproducts"

	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{"inappproduct":[]}`)
	defer closeFunc()

	resp, err := svc.List(context.Background(), pkg)
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if resp == nil {
		t.Fatalf("expected non-nil response")
	}
}

func TestGetSucceeds(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	const sku = "sword_001"
	path := "/androidpublisher/v3/applications/" + pkg + "/inappproducts/" + sku

	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{"sku":"`+sku+`"}`)
	defer closeFunc()

	product, err := svc.Get(context.Background(), pkg, sku)
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if product.Sku != sku {
		t.Fatalf("expected sku %q, got %q", sku, product.Sku)
	}
}

func TestInsertSucceeds(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	path := "/androidpublisher/v3/applications/" + pkg + "/inappproducts"

	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{"sku":"new_item"}`)
	defer closeFunc()

	product, err := svc.Insert(context.Background(), pkg, &androidpublisher.InAppProduct{Sku: "new_item"})
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if product == nil {
		t.Fatalf("expected non-nil product")
	}
}

func TestUpdateSucceeds(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	const sku = "sword_001"
	path := "/androidpublisher/v3/applications/" + pkg + "/inappproducts/" + sku

	svc, closeFunc := newTestService(t, path, http.MethodPut, http.StatusOK, `{"sku":"`+sku+`"}`)
	defer closeFunc()

	product, err := svc.Update(context.Background(), pkg, sku, &androidpublisher.InAppProduct{Sku: sku})
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if product == nil {
		t.Fatalf("expected non-nil product")
	}
}

func TestDeleteSucceeds(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	const sku = "sword_001"
	path := "/androidpublisher/v3/applications/" + pkg + "/inappproducts/" + sku

	svc, closeFunc := newTestService(t, path, http.MethodDelete, http.StatusOK, `{}`)
	defer closeFunc()

	if err := svc.Delete(context.Background(), pkg, sku); err != nil {
		t.Fatalf("expected success: %v", err)
	}
}

func TestBatchGetSucceeds(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	path := "/androidpublisher/v3/applications/" + pkg + "/inappproducts:batchGet"

	svc, closeFunc := newTestService(t, path, http.MethodGet, http.StatusOK, `{"inappproduct":[]}`)
	defer closeFunc()

	resp, err := svc.BatchGet(context.Background(), pkg, []string{"sku1", "sku2"})
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if resp == nil {
		t.Fatalf("expected non-nil response")
	}
}

func TestBatchUpdateSucceeds(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	path := "/androidpublisher/v3/applications/" + pkg + "/inappproducts:batchUpdate"

	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{"inappproducts":[]}`)
	defer closeFunc()

	req := &androidpublisher.InappproductsBatchUpdateRequest{}
	resp, err := svc.BatchUpdate(context.Background(), pkg, req)
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if resp == nil {
		t.Fatalf("expected non-nil response")
	}
}

func TestBatchDeleteSucceeds(t *testing.T) {
	t.Parallel()

	const pkg = "com.example.app"
	path := "/androidpublisher/v3/applications/" + pkg + "/inappproducts:batchDelete"

	svc, closeFunc := newTestService(t, path, http.MethodPost, http.StatusOK, `{}`)
	defer closeFunc()

	req := &androidpublisher.InappproductsBatchDeleteRequest{}
	if err := svc.BatchDelete(context.Background(), pkg, req); err != nil {
		t.Fatalf("expected success: %v", err)
	}
}

func TestRequiresPackageName(t *testing.T) {
	t.Parallel()

	svc, closeFunc := newTestService(t, "/unused", http.MethodGet, http.StatusOK, `{}`)
	defer closeFunc()

	if _, err := svc.List(context.Background(), ""); err == nil {
		t.Fatalf("expected error for missing packageName in List")
	}
	if _, err := svc.Get(context.Background(), "", "sku"); err == nil {
		t.Fatalf("expected error for missing packageName in Get")
	}
	if err := svc.Delete(context.Background(), "", "sku"); err == nil {
		t.Fatalf("expected error for missing packageName in Delete")
	}
}

func newTestService(t *testing.T, expectedPath, expectedMethod string, status int, body string) (*inappproducts.Service, func()) {
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

	return inappproducts.New(raw), server.Close
}
