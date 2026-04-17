package edits_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/api/androidpublisher/v3"
	"google.golang.org/api/option"

	"github.com/godrealms/go-google-sdk/android/publisher/edits"
)

const (
	pkg    = "com.example.app"
	editID = "edit-1"
	base   = "/androidpublisher/v3/applications/" + pkg + "/edits/" + editID
)

// Core lifecycle ------------------------------------------------------------

func TestCommit(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base+":commit", http.MethodPost, http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.Commit(context.Background(), pkg, editID, edits.CommitOptions{ChangesNotSentForReview: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDelete(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base, http.MethodDelete, http.StatusOK, ``)
	defer closeFn()
	if err := svc.Delete(context.Background(), pkg, editID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGet(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base, http.MethodGet, http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.Get(context.Background(), pkg, editID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInsert(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, "/androidpublisher/v3/applications/"+pkg+"/edits", http.MethodPost, http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.Insert(context.Background(), pkg, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base+":validate", http.MethodPost, http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.Validate(context.Background(), pkg, editID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// APKs ---------------------------------------------------------------------

func TestApksAddExternallyHosted(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base+"/apks/externallyHosted", http.MethodPost, http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.ApksAddExternallyHosted(context.Background(), pkg, editID, &androidpublisher.ApksAddExternallyHostedRequest{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestApksList(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base+"/apks", http.MethodGet, http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.ApksList(context.Background(), pkg, editID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestApksUpload(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestServicePrefix(t, "/upload/androidpublisher/v3/applications/"+pkg+"/edits/"+editID+"/apks", http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.ApksUpload(context.Background(), pkg, editID, bytes.NewReader([]byte("apk"))); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Bundles ------------------------------------------------------------------

func TestBundlesList(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base+"/bundles", http.MethodGet, http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.BundlesList(context.Background(), pkg, editID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBundlesUpload(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestServicePrefix(t, "/upload/androidpublisher/v3/applications/"+pkg+"/edits/"+editID+"/bundles", http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.BundlesUpload(context.Background(), pkg, editID, bytes.NewReader([]byte("aab")), edits.BundlesUploadOptions{AckBundleInstallationWarning: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Country availability -----------------------------------------------------

func TestCountryAvailabilityGet(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base+"/countryAvailability/production", http.MethodGet, http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.CountryAvailabilityGet(context.Background(), pkg, editID, "production"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Deobfuscation files ------------------------------------------------------

func TestDeobfuscationFilesUpload(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestServicePrefix(t, "/upload/androidpublisher/v3/applications/"+pkg+"/edits/"+editID+"/apks/42/deobfuscationFiles/proguard", http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.DeobfuscationFilesUpload(context.Background(), pkg, editID, 42, "proguard", bytes.NewReader([]byte("x"))); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Details ------------------------------------------------------------------

func TestDetailsGet(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base+"/details", http.MethodGet, http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.DetailsGet(context.Background(), pkg, editID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDetailsPatch(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base+"/details", http.MethodPatch, http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.DetailsPatch(context.Background(), pkg, editID, &androidpublisher.AppDetails{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDetailsUpdate(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base+"/details", http.MethodPut, http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.DetailsUpdate(context.Background(), pkg, editID, &androidpublisher.AppDetails{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Expansion files ----------------------------------------------------------

func TestExpansionFilesGet(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base+"/apks/42/expansionFiles/main", http.MethodGet, http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.ExpansionFilesGet(context.Background(), pkg, editID, 42, "main"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExpansionFilesPatch(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base+"/apks/42/expansionFiles/main", http.MethodPatch, http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.ExpansionFilesPatch(context.Background(), pkg, editID, 42, "main", &androidpublisher.ExpansionFile{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExpansionFilesUpdate(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base+"/apks/42/expansionFiles/main", http.MethodPut, http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.ExpansionFilesUpdate(context.Background(), pkg, editID, 42, "main", &androidpublisher.ExpansionFile{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExpansionFilesUpload(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestServicePrefix(t, "/upload/androidpublisher/v3/applications/"+pkg+"/edits/"+editID+"/apks/42/expansionFiles/main", http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.ExpansionFilesUpload(context.Background(), pkg, editID, 42, "main", bytes.NewReader([]byte("x"))); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Images -------------------------------------------------------------------

func TestImagesDelete(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base+"/listings/en-US/icon/img-1", http.MethodDelete, http.StatusOK, ``)
	defer closeFn()
	if err := svc.ImagesDelete(context.Background(), pkg, editID, "en-US", "icon", "img-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestImagesDeleteAll(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base+"/listings/en-US/icon", http.MethodDelete, http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.ImagesDeleteAll(context.Background(), pkg, editID, "en-US", "icon"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestImagesList(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base+"/listings/en-US/icon", http.MethodGet, http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.ImagesList(context.Background(), pkg, editID, "en-US", "icon"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestImagesUpload(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestServicePrefix(t, "/upload/androidpublisher/v3/applications/"+pkg+"/edits/"+editID+"/listings/en-US/icon", http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.ImagesUpload(context.Background(), pkg, editID, "en-US", "icon", bytes.NewReader([]byte("png"))); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Listings -----------------------------------------------------------------

func TestListingsDelete(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base+"/listings/en-US", http.MethodDelete, http.StatusOK, ``)
	defer closeFn()
	if err := svc.ListingsDelete(context.Background(), pkg, editID, "en-US"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListingsDeleteAll(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base+"/listings", http.MethodDelete, http.StatusOK, ``)
	defer closeFn()
	if err := svc.ListingsDeleteAll(context.Background(), pkg, editID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListingsGet(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base+"/listings/en-US", http.MethodGet, http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.ListingsGet(context.Background(), pkg, editID, "en-US"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListingsList(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base+"/listings", http.MethodGet, http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.ListingsList(context.Background(), pkg, editID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListingsPatch(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base+"/listings/en-US", http.MethodPatch, http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.ListingsPatch(context.Background(), pkg, editID, "en-US", &androidpublisher.Listing{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListingsUpdate(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base+"/listings/en-US", http.MethodPut, http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.ListingsUpdate(context.Background(), pkg, editID, "en-US", &androidpublisher.Listing{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Testers ------------------------------------------------------------------

func TestTestersGet(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base+"/testers/beta", http.MethodGet, http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.TestersGet(context.Background(), pkg, editID, "beta"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTestersPatch(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base+"/testers/beta", http.MethodPatch, http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.TestersPatch(context.Background(), pkg, editID, "beta", &androidpublisher.Testers{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTestersUpdate(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base+"/testers/beta", http.MethodPut, http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.TestersUpdate(context.Background(), pkg, editID, "beta", &androidpublisher.Testers{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Tracks -------------------------------------------------------------------

func TestTracksCreate(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base+"/tracks", http.MethodPost, http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.TracksCreate(context.Background(), pkg, editID, &androidpublisher.TrackConfig{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTracksGet(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base+"/tracks/beta", http.MethodGet, http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.TracksGet(context.Background(), pkg, editID, "beta"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTracksList(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base+"/tracks", http.MethodGet, http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.TracksList(context.Background(), pkg, editID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTracksPatch(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base+"/tracks/beta", http.MethodPatch, http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.TracksPatch(context.Background(), pkg, editID, "beta", &androidpublisher.Track{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTracksUpdate(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, base+"/tracks/beta", http.MethodPut, http.StatusOK, `{}`)
	defer closeFn()
	if _, err := svc.TracksUpdate(context.Background(), pkg, editID, "beta", &androidpublisher.Track{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Validation ---------------------------------------------------------------

func TestValidation(t *testing.T) {
	t.Parallel()
	svc, closeFn := newTestService(t, "/unused", http.MethodGet, http.StatusOK, `{}`)
	defer closeFn()
	ctx := context.Background()
	if _, err := svc.Get(ctx, "", editID); err == nil {
		t.Fatal("expected missing pkg")
	}
	if _, err := svc.Get(ctx, pkg, ""); err == nil {
		t.Fatal("expected missing edit id")
	}
	if _, err := svc.ApksAddExternallyHosted(ctx, pkg, editID, nil); err == nil {
		t.Fatal("expected missing request")
	}
	if _, err := svc.ApksUpload(ctx, pkg, editID, nil); err == nil {
		t.Fatal("expected missing media")
	}
	if _, err := svc.BundlesUpload(ctx, pkg, editID, nil, edits.BundlesUploadOptions{}); err == nil {
		t.Fatal("expected missing media")
	}
	if _, err := svc.CountryAvailabilityGet(ctx, pkg, editID, ""); err == nil {
		t.Fatal("expected missing track")
	}
	if _, err := svc.DeobfuscationFilesUpload(ctx, pkg, editID, 0, "proguard", bytes.NewReader(nil)); err == nil {
		t.Fatal("expected missing version")
	}
	if _, err := svc.DetailsPatch(ctx, pkg, editID, nil); err == nil {
		t.Fatal("expected missing details")
	}
	if _, err := svc.ExpansionFilesGet(ctx, pkg, editID, 0, "main"); err == nil {
		t.Fatal("expected missing version")
	}
	if err := svc.ImagesDelete(ctx, pkg, editID, "en-US", "icon", ""); err == nil {
		t.Fatal("expected missing image id")
	}
	if _, err := svc.ListingsPatch(ctx, pkg, editID, "en-US", nil); err == nil {
		t.Fatal("expected missing listing")
	}
	if _, err := svc.TestersPatch(ctx, pkg, editID, "beta", nil); err == nil {
		t.Fatal("expected missing testers")
	}
	if _, err := svc.TracksCreate(ctx, pkg, editID, nil); err == nil {
		t.Fatal("expected missing track config")
	}
	if _, err := svc.TracksPatch(ctx, pkg, editID, "beta", nil); err == nil {
		t.Fatal("expected missing track body")
	}
}

// ----------------------------------------------------------------------------

func newTestService(t *testing.T, expectedPath, expectedMethod string, status int, body string) (*edits.Service, func()) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != expectedMethod {
			t.Errorf("expected method %s, got %s", expectedMethod, r.Method)
		}
		if r.URL.Path != expectedPath {
			t.Errorf("unexpected path: got %q, want %q", r.URL.Path, expectedPath)
		}
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	return edits.New(newRawClient(t, server.URL)), server.Close
}

func newTestServicePrefix(t *testing.T, expectedPrefix string, status int, body string) (*edits.Service, func()) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, expectedPrefix) {
			t.Errorf("unexpected path: got %q, want prefix %q", r.URL.Path, expectedPrefix)
		}
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	return edits.New(newRawClient(t, server.URL)), server.Close
}

func newRawClient(t *testing.T, endpoint string) *androidpublisher.Service {
	t.Helper()
	raw, err := androidpublisher.NewService(context.Background(),
		option.WithEndpoint(endpoint),
		option.WithoutAuthentication(),
	)
	if err != nil {
		t.Fatalf("create raw service: %v", err)
	}
	return raw
}
