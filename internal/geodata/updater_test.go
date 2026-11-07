package geodata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
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

	_, err := Update(context.Background(), opts, nil)
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

func TestUpdateGeoData_DownloadViaProxy(t *testing.T) {
	mockGeoIP := []byte("mock-geoip-protobuf-data")
	mockGeoSite := []byte("mock-geosite-protobuf-data")

	ipHash := sha256.Sum256(mockGeoIP)
	ipHashStr := hex.EncodeToString(ipHash[:])
	siteHash := sha256.Sum256(mockGeoSite)
	siteHashStr := hex.EncodeToString(siteHash[:])

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	defer origin.Close()

	var proxyHits int
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits++
		resp, err := http.Get(origin.URL + r.URL.RequestURI())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	defer proxy.Close()

	destDir := t.TempDir()
	opts := UpdateOptions{
		DestDir:       destDir,
		GeoIPURL:      "http://example.com/geoip.dat",
		GeoIPSumURL:   "http://example.com/geoip.dat.sha256sum",
		GeoSiteURL:    "http://example.com/geosite.dat",
		GeoSiteSumURL: "http://example.com/geosite.dat.sha256sum",
		ProxyURL:      proxy.URL,
	}

	_, err := Update(context.Background(), opts, nil)
	if err != nil {
		t.Fatalf("Update with proxy failed: %v", err)
	}
	if proxyHits == 0 {
		t.Fatalf("expected proxy to receive requests, got %d hits", proxyHits)
	}
}

// Tests that Update records release version to version.txt and can be read by DetectLocalVersion.
func TestUpdateGeoData_VersionRecording(t *testing.T) {
	mockGeoIP := []byte("mock-geoip-data")
	mockGeoSite := []byte("mock-geosite-data")

	ipHash := sha256.Sum256(mockGeoIP)
	ipHashStr := hex.EncodeToString(ipHash[:])
	siteHash := sha256.Sum256(mockGeoSite)
	siteHashStr := hex.EncodeToString(siteHash[:])

	const expectedTag = "202611062204"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/releases/latest/download/geoip.dat":
			http.Redirect(w, r, "/releases/download/"+expectedTag+"/geoip.dat", http.StatusFound)
		case "/releases/download/" + expectedTag + "/geoip.dat":
			_, _ = w.Write(mockGeoIP)
		case "/releases/latest/download/geoip.dat.sha256sum":
			_, _ = fmt.Fprintf(w, "%s  geoip.dat\n", ipHashStr)
		case "/releases/latest/download/geosite.dat":
			http.Redirect(w, r, "/releases/download/"+expectedTag+"/geosite.dat", http.StatusFound)
		case "/releases/download/" + expectedTag + "/geosite.dat":
			_, _ = w.Write(mockGeoSite)
		case "/releases/latest/download/geosite.dat.sha256sum":
			_, _ = fmt.Fprintf(w, "%s  geosite.dat\n", siteHashStr)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	destDir := t.TempDir()
	opts := UpdateOptions{
		DestDir:       destDir,
		GeoIPURL:      ts.URL + "/releases/latest/download/geoip.dat",
		GeoIPSumURL:   ts.URL + "/releases/latest/download/geoip.dat.sha256sum",
		GeoSiteURL:    ts.URL + "/releases/latest/download/geosite.dat",
		GeoSiteSumURL: ts.URL + "/releases/latest/download/geosite.dat.sha256sum",
	}

	ver, err := Update(context.Background(), opts, nil)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if ver != expectedTag {
		t.Fatalf("expected version %q from redirect URL, got %q", expectedTag, ver)
	}

	// Verify version.txt was written and DetectLocalVersion reads it
	if localVer := DetectLocalVersion(destDir); localVer != expectedTag {
		t.Fatalf("DetectLocalVersion expected %q, got %q", expectedTag, localVer)
	}
}
