package geodata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"naive-client/internal/config"
	"naive-client/internal/updater"
)

const (
	DefaultGeoIPURL    = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
	DefaultGeoSiteURL  = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
)

type UpdateOptions struct {
	DestDir       string
	GeoIPURL      string
	GeoIPSumURL   string
	GeoSiteURL    string
	GeoSiteSumURL string
	GitHubMirror  string
	ProxyURL      string
	ProxyEP       *config.ListenEndpoint
	Tag           string
}

func applyMirror(rawURL, mirror string) string {
	mirror = strings.TrimSpace(mirror)
	if mirror == "" {
		return rawURL
	}
	mirror = strings.TrimRight(mirror, "/")
	return mirror + "/" + rawURL
}

func extractReleaseTag(rawURL string) string {
	const marker = "/releases/download/"
	idx := strings.Index(rawURL, marker)
	if idx == -1 {
		return ""
	}
	rem := rawURL[idx+len(marker):]
	slash := strings.IndexByte(rem, '/')
	if slash == -1 {
		return rem
	}
	return rem[:slash]
}

// DetectLocalVersion reads the locally recorded release version from DestDir/version.txt if present.
func DetectLocalVersion(destDir string) string {
	if b, err := os.ReadFile(filepath.Join(destDir, "version.txt")); err == nil {
		return strings.TrimSpace(string(b))
	}
	return ""
}

func Update(ctx context.Context, opts UpdateOptions, onProgress func(stage string, percent float64)) (string, error) {
	if opts.DestDir == "" {
		return "", errors.New("destDir is required")
	}
	if err := os.MkdirAll(opts.DestDir, 0o755); err != nil {
		return "", err
	}

	ipURL := opts.GeoIPURL
	if ipURL == "" {
		ipURL = applyMirror(DefaultGeoIPURL, opts.GitHubMirror)
	}
	ipSumURL := opts.GeoIPSumURL
	if ipSumURL == "" {
		ipSumURL = applyMirror(DefaultGeoIPURL+".sha256sum", opts.GitHubMirror)
	}

	siteURL := opts.GeoSiteURL
	if siteURL == "" {
		siteURL = applyMirror(DefaultGeoSiteURL, opts.GitHubMirror)
	}
	siteSumURL := opts.GeoSiteSumURL
	if siteSumURL == "" {
		siteSumURL = applyMirror(DefaultGeoSiteURL+".sha256sum", opts.GitHubMirror)
	}

	// Build HTTP client
	client := updater.NewHTTPClient(updater.HTTPClientOptions{
		ProxyURL:      opts.ProxyURL,
		LocalEndpoint: opts.ProxyEP,
		Timeout:       60 * time.Second,
	})

	// 1. Download & verify geoip.dat
	ipDest := filepath.Join(opts.DestDir, "geoip.dat")
	tag1, err := downloadAndVerify(ctx, client, ipURL, ipSumURL, ipDest, "下载 GeoIP 规则库", 0.0, 0.5, onProgress)
	if err != nil {
		return "", fmt.Errorf("geoip: %w", err)
	}

	// 2. Download & verify geosite.dat
	siteDest := filepath.Join(opts.DestDir, "geosite.dat")
	tag2, err := downloadAndVerify(ctx, client, siteURL, siteSumURL, siteDest, "下载 GeoSite 规则库", 0.5, 1.0, onProgress)
	if err != nil {
		return "", fmt.Errorf("geosite: %w", err)
	}

	finalTag := strings.TrimSpace(opts.Tag)
	if finalTag == "" {
		if tag1 != "" {
			finalTag = tag1
		} else if tag2 != "" {
			finalTag = tag2
		}
	}
	if finalTag != "" {
		_ = os.WriteFile(filepath.Join(opts.DestDir, "version.txt"), []byte(finalTag), 0o644)
	}

	return finalTag, nil
}

func downloadAndVerify(
	ctx context.Context,
	client *http.Client,
	dataURL string,
	sumURL string,
	destFile string,
	stageName string,
	pStart float64,
	pEnd float64,
	onProgress func(stage string, percent float64),
) (string, error) {
	if onProgress != nil {
		onProgress(stageName, pStart)
	}

	// Download expected checksum
	reqSum, err := http.NewRequestWithContext(ctx, http.MethodGet, sumURL, nil)
	if err != nil {
		return "", err
	}
	respSum, err := client.Do(reqSum)
	if err != nil {
		return "", err
	}
	defer respSum.Body.Close()
	if respSum.StatusCode != http.StatusOK {
		return "", fmt.Errorf("checksum HTTP %d", respSum.StatusCode)
	}
	sumBytes, err := io.ReadAll(respSum.Body)
	if err != nil {
		return "", err
	}
	expectedHash := strings.ToLower(strings.TrimSpace(strings.Fields(string(sumBytes))[0]))

	// Download data payload
	reqData, err := http.NewRequestWithContext(ctx, http.MethodGet, dataURL, nil)
	if err != nil {
		return "", err
	}
	respData, err := client.Do(reqData)
	if err != nil {
		return "", err
	}
	defer respData.Body.Close()
	if respData.StatusCode != http.StatusOK {
		return "", fmt.Errorf("data HTTP %d", respData.StatusCode)
	}

	var detectedTag string
	if respData.Request != nil && respData.Request.URL != nil {
		detectedTag = extractReleaseTag(respData.Request.URL.String())
	}

	tmpFile := destFile + ".tmp"
	f, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = f.Close()
		_ = os.Remove(tmpFile)
	}()

	hasher := sha256.New()
	writer := io.MultiWriter(f, hasher)

	totalBytes := respData.ContentLength
	var downloaded int64
	buf := make([]byte, 32*1024)
	for {
		n, readErr := respData.Body.Read(buf)
		if n > 0 {
			if _, wErr := writer.Write(buf[:n]); wErr != nil {
				return "", wErr
			}
			downloaded += int64(n)
			if onProgress != nil && totalBytes > 0 {
				ratio := float64(downloaded) / float64(totalBytes)
				onProgress(stageName, pStart+ratio*(pEnd-pStart))
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return "", readErr
		}
	}

	if err := f.Close(); err != nil {
		return "", err
	}

	actualHash := hex.EncodeToString(hasher.Sum(nil))
	if expectedHash != "" && actualHash != expectedHash {
		return "", fmt.Errorf("SHA256 mismatch: got %s, expected %s", actualHash, expectedHash)
	}

	if err := os.Rename(tmpFile, destFile); err != nil {
		return "", err
	}

	if onProgress != nil {
		onProgress(stageName, pEnd)
	}
	return detectedTag, nil
}
