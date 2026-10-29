package updater

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"naive-client/internal/config"
	"naive-client/internal/runner"
)

func TestMatchAssetAllPlatforms(t *testing.T) {
	rel := &Release{
		TagName: "v154.0.8037.49-5",
		Assets: []Asset{
			{Name: "naiveproxy-plugin-v154.0.8037.49-5-arm64-v8a.apk"},
			{Name: "naiveproxy-v154.0.8037.49-5-mac-arm64-arm64.tar.xz"},
			{Name: "naiveproxy-v154.0.8037.49-5-mac-x64-x64.tar.xz"},
			{Name: "naiveproxy-v154.0.8037.49-5-win-x64.zip"},
			{Name: "naiveproxy-v154.0.8037.49-5-win-arm64.zip"},
			{Name: "naiveproxy-v154.0.8037.49-5-linux-x64.tar.xz"},
			{Name: "naiveproxy-v154.0.8037.49-5-linux-arm64.tar.xz"},
		},
	}

	cases := []struct {
		goos, goarch string
		want         string
	}{
		{"darwin", "arm64", "naiveproxy-v154.0.8037.49-5-mac-arm64-arm64.tar.xz"},
		{"darwin", "amd64", "naiveproxy-v154.0.8037.49-5-mac-x64-x64.tar.xz"},
		{"windows", "amd64", "naiveproxy-v154.0.8037.49-5-win-x64.zip"},
		{"windows", "arm64", "naiveproxy-v154.0.8037.49-5-win-arm64.zip"},
		{"linux", "amd64", "naiveproxy-v154.0.8037.49-5-linux-x64.tar.xz"},
		{"linux", "arm64", "naiveproxy-v154.0.8037.49-5-linux-arm64.tar.xz"},
	}

	for _, tc := range cases {
		got, err := MatchAsset(rel, tc.goos, tc.goarch)
		if err != nil {
			t.Fatalf("MatchAsset(%s/%s) failed: %v", tc.goos, tc.goarch, err)
		}
		if got.Name != tc.want {
			t.Errorf("MatchAsset(%s/%s) = %q, want %q", tc.goos, tc.goarch, got.Name, tc.want)
		}
	}
}

func TestParseVersionAndNeedsUpdate(t *testing.T) {
	if got := ParseVersionOutput("naive 154.0.8037.49-5\n"); got != "v154.0.8037.49-5" {
		t.Errorf("ParseVersionOutput = %q, want v154.0.8037.49-5", got)
	}
	if NeedsUpdate("v154.0.8037.49-5", "v154.0.8037.49-5") {
		t.Error("NeedsUpdate returned true for identical versions")
	}
	if !NeedsUpdate("v153.0.0.1-1", "v154.0.8037.49-5") {
		t.Error("NeedsUpdate returned false for older version")
	}
	if !NeedsUpdate("", "v154.0.8037.49-5") {
		t.Error("NeedsUpdate returned false when local version is empty")
	}

	// Test NeedsUpdateWithTag: distinguishes multiple releases for the same base Chrome version
	if !NeedsUpdateWithTag("v133.0.6943.98-1", "v133.0.6943.98", "v133.0.6943.98-2") {
		t.Error("NeedsUpdateWithTag should detect update when release patch tag changes (-1 -> -2)")
	}
	if NeedsUpdateWithTag("v133.0.6943.98-2", "v133.0.6943.98", "v133.0.6943.98-2") {
		t.Error("NeedsUpdateWithTag should return false when release tag matches installed tag")
	}
	if !NeedsUpdateWithTag("", "v133.0.6943.98", "v133.0.6943.98-2") {
		t.Error("NeedsUpdateWithTag should fallback to local version when installed tag is empty")
	}
}

func TestFileSHA256(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "sample.bin")
	data := []byte("naive-proxy-core-test-digest")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		t.Fatal(err)
	}
	expected := "cb9e8c46ea48d8a7c29cb2d2c1840eef9ec9f7ef82fcfa1c6861214081c7e937"
	// Calculate actual sha256 of data
	h := sha256.Sum256(data)
	expected = hex.EncodeToString(h[:])

	got, err := FileSHA256(tmp)
	if err != nil {
		t.Fatalf("FileSHA256 failed: %v", err)
	}
	if got != expected {
		t.Errorf("FileSHA256 = %s, want %s", got, expected)
	}
}

func TestSeamlessUpdateHotSwap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell binary simulation on unix")
	}
	dir := t.TempDir()
	binPath := filepath.Join(dir, "naive.exe")

	// Create initial v1 script
	v1Script := "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo \"naive 153.0.0.1-1\"; exit 0; fi\ntrap 'exit 0' INT TERM\nwhile true; do sleep 0.1; done\n"
	if err := os.WriteFile(binPath, []byte(v1Script), 0o755); err != nil {
		t.Fatalf("write v1 failed: %v", err)
	}

	// Build a zip archive containing v2 script named naive.exe
	v2Script := "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo \"naive 154.0.8037.49-5\"; exit 0; fi\ntrap 'exit 0' INT TERM\nwhile true; do sleep 0.1; done\n"
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	fw, err := zw.Create("naiveproxy-v154.0.8037.49-5-win-x64/naive.exe")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte(v2Script)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zipBytes := zipBuf.Bytes()
	sum := sha256.Sum256(zipBytes)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipBytes)
	}))
	defer srv.Close()

	mgr := runner.NewManager(binPath, dir, nil)
	svc := config.DefaultService("s1", 19876)
	if err := mgr.Start(svc); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer mgr.StopAll()

	rel := &Release{
		TagName: "v154.0.8037.49-5",
		Assets: []Asset{
			{
				Name:               "naiveproxy-v154.0.8037.49-5-win-x64.zip",
				Size:               int64(len(zipBytes)),
				Digest:             digest,
				BrowserDownloadURL: srv.URL + "/naiveproxy-v154.0.8037.49-5-win-x64.zip",
			},
		},
	}

	err = SeamlessUpdateForPlatform(context.Background(), rel, "windows", "amd64", binPath, mgr, HTTPClientOptions{}, "", nil)
	if err != nil {
		t.Fatalf("SeamlessUpdate failed: %v", err)
	}
	_ = os.Chmod(binPath, 0o755)

	if got := DetectLocalVersion(binPath); got != "v154.0.8037.49-5" {
		t.Errorf("DetectLocalVersion after update = %q, want v154.0.8037.49-5", got)
	}
}
