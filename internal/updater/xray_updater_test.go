package updater

import (
	"archive/zip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestMatchXrayAssetAllPlatforms(t *testing.T) {
	rel := &Release{
		TagName: "v1.8.24",
		Assets: []Asset{
			{Name: "Xray-macos-arm64-v8a.zip"},
			{Name: "Xray-macos-arm64-v8a.zip.dgst"},
			{Name: "Xray-macos-64.zip"},
			{Name: "Xray-windows-64.zip"},
			{Name: "Xray-windows-arm64-v8a.zip"},
			{Name: "Xray-linux-64.zip"},
			{Name: "Xray-linux-arm64-v8a.zip"},
		},
	}

	cases := []struct {
		goos, goarch string
		want         string
	}{
		{"darwin", "arm64", "Xray-macos-arm64-v8a.zip"},
		{"darwin", "amd64", "Xray-macos-64.zip"},
		{"windows", "amd64", "Xray-windows-64.zip"},
		{"windows", "arm64", "Xray-windows-arm64-v8a.zip"},
		{"linux", "amd64", "Xray-linux-64.zip"},
		{"linux", "arm64", "Xray-linux-arm64-v8a.zip"},
	}

	for _, tc := range cases {
		got, err := MatchXrayAsset(rel, tc.goos, tc.goarch)
		if err != nil {
			t.Fatalf("MatchXrayAsset(%s/%s) failed: %v", tc.goos, tc.goarch, err)
		}
		if got.Name != tc.want {
			t.Errorf("MatchXrayAsset(%s/%s) = %q, want %q", tc.goos, tc.goarch, got.Name, tc.want)
		}
	}
}

func TestParseXrayVersionOutput(t *testing.T) {
	raw := `Xray 1.8.24 (Xray, Penetrates Everything.) Custom (go1.22.5 darwin/arm64)
A unified platform for anti-censorship.`
	got := ParseXrayVersionOutput(raw)
	if got != "v1.8.24" {
		t.Errorf("ParseXrayVersionOutput() = %q, want v1.8.24", got)
	}
}

func TestParseXrayDGST(t *testing.T) {
	raw := `MD5= 89d81d2a4413fcfc14170e7040ff98a1
SHA1= 8f0d8a7c29cb2d2c1840eef9ec9f7ef82fcfa1c6
SHA256= e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
SHA512= cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
`
	got := ParseXrayDGST(raw)
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Errorf("ParseXrayDGST() = %q, want %q", got, want)
	}
}

func TestExtractXrayZip(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "xray.zip")
	targetBin := filepath.Join(dir, "bin", XrayBinaryFilename(runtime.GOOS))

	// Create test zip archive with xray binary
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	binName := filepath.Base(targetBin)
	w, err := zw.Create(binName)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("#!/bin/sh\necho xray test\n")
	if _, err := w.Write(content); err != nil {
		t.Fatal(err)
	}
	_ = zw.Close()
	_ = f.Close()

	// Calculate SHA256 of the zip
	digest, err := FileSHA256(zipPath)
	if err != nil {
		t.Fatalf("FileSHA256 failed: %v", err)
	}
	if len(digest) != 64 {
		t.Errorf("expected 64 char hex digest, got %q", digest)
	}

	// Extract
	if err := ExtractXrayZip(zipPath, targetBin); err != nil {
		t.Fatalf("ExtractXrayZip failed: %v", err)
	}

	extracted, err := os.ReadFile(targetBin)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(extracted) != string(content) {
		t.Errorf("extracted content mismatch: got %q, want %q", string(extracted), string(content))
	}
}

