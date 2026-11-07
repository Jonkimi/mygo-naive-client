package updater

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Tests that CheckLatestGeodata queries the release API and parses the release metadata.
func TestCheckLatestGeodata(t *testing.T) {
	const mockTag = "202611062204"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"tag_name": "%s", "name": "Released on %s"}`, mockTag, mockTag)
	}))
	defer srv.Close()

	origAPI := LatestGeodataReleaseAPI
	LatestGeodataReleaseAPI = srv.URL
	defer func() { LatestGeodataReleaseAPI = origAPI }()

	rel, err := CheckLatestGeodata(context.Background(), HTTPClientOptions{})
	if err != nil {
		t.Fatalf("CheckLatestGeodata failed: %v", err)
	}
	if rel == nil || rel.TagName != mockTag {
		t.Fatalf("expected release tag %q, got %+v", mockTag, rel)
	}
}
