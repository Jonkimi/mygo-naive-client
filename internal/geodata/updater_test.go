package geodata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// Tests that UpdateGeoData downloads geoip.dat and geosite.dat, verifies SHA256 checksums,
// and saves the files into destDir atomically.
func TestUpdateGeoData_DownloadAndVerify(t *testing.T) {
	mockGeoIP := []byte("mock-geoip-protobuf-data")
	mockGeoSite := []byte("mock-geosite-protobuf-data")

	ipHash := sha256.Sum256(mockGeoIP)
	ipHashStr := hex.EncodeToString(ipHash[:])
	siteHash := sha256.Sum256(mockGeoSite)
	siteHashStr := hex.EncodeToString(siteHash[:])

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/geoip.dat":
			_, _ = w.Write(mockGeoIP)
		case "/geoip.dat.sha256sum":
			_, _ = fmt.Fprintf(w, "%s  geoip.dat\n", ipHashStr)
		case "/geosite.dat":
			_, _ = w.Write(mockGeoSite)
		case "/geosite.dat.sha256sum":
			_, _ = fmt.Fprintf(w, "%s  geosite.dat\n", siteHashStr)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	destDir := t.TempDir()
	opts := UpdateOptions{
		DestDir:       destDir,
		GeoIPURL:      ts.URL + "/geoip.dat",
		GeoIPSumURL:   ts.URL + "/geoip.dat.sha256sum",
		GeoSiteURL:    ts.URL + "/geosite.dat",
		GeoSiteSumURL: ts.URL + "/geosite.dat.sha256sum",
	}

	err := Update(context.Background(), opts, nil)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// Verify files exist in destDir
	dataIP, err := os.ReadFile(filepath.Join(destDir, "geoip.dat"))
	if err != nil || string(dataIP) != string(mockGeoIP) {
		t.Fatalf("geoip.dat mismatch or missing: %v", err)
	}
	dataSite, err := os.ReadFile(filepath.Join(destDir, "geosite.dat"))
	if err != nil || string(dataSite) != string(mockGeoSite) {
		t.Fatalf("geosite.dat mismatch or missing: %v", err)
	}
}
