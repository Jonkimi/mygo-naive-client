package updater

import (
	"archive/tar"
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"naive-client/internal/config"
	"naive-client/internal/runner"
)

// LatestReleaseAPI is the GitHub API endpoint for klzgrad/naiveproxy releases.
var LatestReleaseAPI = "https://api.github.com/repos/klzgrad/naiveproxy/releases/latest"

// Asset represents a downloadable release asset on GitHub.
type Asset struct {
	Name               string `json:"name"`
	Size               int64  `json:"size"`
	Digest             string `json:"digest"` // e.g. "sha256:8b330140..."
	BrowserDownloadURL string `json:"browser_download_url"`
}

// Release represents a GitHub release of klzgrad/naiveproxy.
type Release struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	HTMLURL     string    `json:"html_url"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []Asset   `json:"assets"`
}

// BinaryFilename returns the platform-specific executable name ("naive" or "naive.exe").
func BinaryFilename(goos string) string {
	if goos == "windows" {
		return "naive.exe"
	}
	return "naive"
}

// ExpectedAssetSuffix returns the suffix in klzgrad/naiveproxy release asset names
// for a given GOOS and GOARCH.
// Examples from https://github.com/klzgrad/naiveproxy/releases:
//   - darwin/arm64  -> "-mac-arm64-arm64.tar.xz"
//   - darwin/amd64  -> "-mac-x64-x64.tar.xz"
//   - windows/amd64 -> "-win-x64.zip"
//   - windows/arm64 -> "-win-arm64.zip"
//   - windows/386   -> "-win-x86.zip"
//   - linux/amd64   -> "-linux-x64.tar.xz"
//   - linux/arm64   -> "-linux-arm64.tar.xz"
//   - linux/386     -> "-linux-x86.tar.xz"
//   - linux/arm     -> "-linux-arm.tar.xz"
//   - linux/riscv64 -> "-linux-riscv64.tar.xz"
//   - linux/loong64 -> "-linux-loong64.tar.xz"
func ExpectedAssetSuffix(goos, goarch string) (string, error) {
	switch goos {
	case "darwin":
		switch goarch {
		case "arm64":
			return "-mac-arm64-arm64.tar.xz", nil
		case "amd64":
			return "-mac-x64-x64.tar.xz", nil
		}
	case "windows":
		switch goarch {
		case "amd64":
			return "-win-x64.zip", nil
		case "arm64":
			return "-win-arm64.zip", nil
		case "386":
			return "-win-x86.zip", nil
		}
	case "linux":
		switch goarch {
		case "amd64":
			return "-linux-x64.tar.xz", nil
		case "arm64":
			return "-linux-arm64.tar.xz", nil
		case "386":
			return "-linux-x86.tar.xz", nil
		case "arm":
			return "-linux-arm.tar.xz", nil
		case "riscv64":
			return "-linux-riscv64.tar.xz", nil
		case "loong64":
			return "-linux-loong64.tar.xz", nil
		}
	}
	return "", fmt.Errorf("不支持的操作系统或架构组合: %s/%s", goos, goarch)
}

// MatchAsset picks the asset for goos/goarch from a Release.
func MatchAsset(rel *Release, goos, goarch string) (Asset, error) {
	if rel == nil {
		return Asset{}, errors.New("release info is nil")
	}
	suffix, err := ExpectedAssetSuffix(goos, goarch)
	if err != nil {
		return Asset{}, err
	}
	for _, a := range rel.Assets {
		if strings.HasPrefix(a.Name, "naiveproxy-") &&
			!strings.HasPrefix(a.Name, "naiveproxy-plugin-") &&
			strings.HasSuffix(a.Name, suffix) {
			return a, nil
		}
	}
	return Asset{}, fmt.Errorf("在版本 %s 中未找到适配 %s/%s 的安装包 (*%s)", rel.TagName, goos, goarch, suffix)
}

// DetectLocalVersion runs `naive --version` and extracts the version string.
func DetectLocalVersion(binPath string) string {
	if binPath == "" {
		return ""
	}
	info, err := os.Stat(binPath)
	if err != nil || info.IsDir() {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	return ParseVersionOutput(string(out))
}

// ParseVersionOutput normalizes the output of `naive --version` (e.g. "naive 154.0.8037.49-5" -> "v154.0.8037.49-5").
func ParseVersionOutput(raw string) string {
	line := strings.TrimSpace(strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")[0])
	if line == "" {
		return ""
	}
	fields := strings.Fields(line)
	ver := fields[len(fields)-1]
	ver = strings.TrimPrefix(ver, "v")
	if ver == "" {
		return ""
	}
	return "v" + ver
}

// NeedsUpdate reports whether remoteTag is newer/different from localVer.
func NeedsUpdate(localVer, remoteTag string) bool {
	remote := normalizeTag(remoteTag)
	if remote == "" {
		return false
	}
	local := normalizeTag(localVer)
	if local == "" {
		return true
	}
	return local != remote
}

// NeedsUpdateWithTag compares the remote release tag with the installed tag or detected local version.
// When installedTag is non-empty, exact release tag comparison is prioritized, resolving issues
// where multiple GitHub releases exist for the same Chrome build (<chrome-version>[-<version>]).
// Otherwise, it falls back to comparing localVer.
func NeedsUpdateWithTag(installedTag, localVer, remoteTag string) bool {
	if strings.TrimSpace(installedTag) != "" {
		return normalizeTag(installedTag) != normalizeTag(remoteTag)
	}
	return NeedsUpdate(localVer, remoteTag)
}

// FileSHA256 calculates the lowercase hex-encoded SHA256 checksum of the specified file.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func normalizeTag(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "naive ")
	v = strings.TrimPrefix(v, "v")
	if v == "" {
		return ""
	}
	return "v" + v
}

// MirrorURL applies an optional GitHub download mirror prefix (e.g. "https://ghfast.top/")
// to a github.com download URL.
func MirrorURL(downloadURL, mirrorPrefix string) string {
	mirrorPrefix = strings.TrimSpace(mirrorPrefix)
	if mirrorPrefix == "" {
		return downloadURL
	}
	if !strings.HasSuffix(mirrorPrefix, "/") {
		mirrorPrefix += "/"
	}
	if strings.HasPrefix(downloadURL, "https://github.com/") {
		return mirrorPrefix + downloadURL
	}
	return downloadURL
}

// HTTPClientOptions configures how GitHub API and asset downloads connect.
type HTTPClientOptions struct {
	ProxyURL      string                 // explicit HTTP/SOCKS5 proxy URL in settings
	LocalEndpoint *config.ListenEndpoint // optional running local naive service to tunnel through
	Timeout       time.Duration
}

// NewHTTPClient builds an *http.Client honoring proxy settings or active local service.
func NewHTTPClient(opts HTTPClientOptions) *http.Client {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if proxyRaw := strings.TrimSpace(opts.ProxyURL); proxyRaw != "" {
		if ep, err := config.ParseListenURI(proxyRaw); err == nil {
			if tr, err := runner.ProxyTransport(ep); err == nil {
				return &http.Client{Transport: tr, Timeout: timeout}
			}
		}
		if u, err := url.Parse(proxyRaw); err == nil && u.Scheme != "" {
			return &http.Client{
				Transport: &http.Transport{Proxy: http.ProxyURL(u)},
				Timeout:   timeout,
			}
		}
	}
	if opts.LocalEndpoint != nil {
		if tr, err := runner.ProxyTransport(*opts.LocalEndpoint); err == nil {
			return &http.Client{Transport: tr, Timeout: timeout}
		}
	}
	return &http.Client{Timeout: timeout}
}

// CheckLatest fetches the latest release metadata from GitHub Releases API.
func CheckLatest(ctx context.Context, opts HTTPClientOptions) (*Release, error) {
	client := NewHTTPClient(opts)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, LatestReleaseAPI, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "naive-client-mygo/0.1")

	resp, err := client.Do(req)
	if err != nil && opts.LocalEndpoint != nil && opts.ProxyURL == "" {
		// Fall back to direct connection if the local tunnel failed.
		direct := &http.Client{Timeout: 15 * time.Second}
		resp, err = direct.Do(req)
	}
	if err != nil {
		return nil, fmt.Errorf("检查更新请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("GitHub API 返回 HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("解析版本信息失败: %w", err)
	}
	if rel.TagName == "" {
		return nil, errors.New("未获取到有效的 Release Tag")
	}
	return &rel, nil
}

// ProgressFunc receives download and installation progress updates (0.0 to 1.0) and a status phase label.
type ProgressFunc func(progress float64, stage string)

// SeamlessUpdate downloads the release asset for the current platform, verifies its SHA256 digest,
// extracts the new `naive` binary, gracefully stops all currently running services in mgr,
// atomically swaps the binary at targetBinPath, and restarts all previously running services.
func SeamlessUpdate(
	ctx context.Context,
	rel *Release,
	targetBinPath string,
	mgr *runner.Manager,
	opts HTTPClientOptions,
	mirrorPrefix string,
	onProgress ProgressFunc,
) error {
	return SeamlessUpdateForPlatform(ctx, rel, runtime.GOOS, runtime.GOARCH, targetBinPath, mgr, opts, mirrorPrefix, onProgress)
}

// SeamlessUpdateForPlatform is the platform-parameterized implementation of SeamlessUpdate.
func SeamlessUpdateForPlatform(
	ctx context.Context,
	rel *Release,
	goos, goarch string,
	targetBinPath string,
	mgr *runner.Manager,
	opts HTTPClientOptions,
	mirrorPrefix string,
	onProgress ProgressFunc,
) error {
	if onProgress == nil {
		onProgress = func(float64, string) {}
	}
	asset, err := MatchAsset(rel, goos, goarch)
	if err != nil {
		return err
	}

	binDir := filepath.Dir(targetBinPath)
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return fmt.Errorf("创建核心目录失败: %w", err)
	}

	tmpArchive, err := os.CreateTemp(binDir, "naive-download-*"+filepath.Ext(asset.Name))
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	tmpArchivePath := tmpArchive.Name()
	defer func() {
		_ = tmpArchive.Close()
		_ = os.Remove(tmpArchivePath)
	}()

	downloadURL := MirrorURL(asset.BrowserDownloadURL, mirrorPrefix)
	onProgress(0.02, "正在连接下载服务器…")

	opts.Timeout = 10 * time.Minute
	client := NewHTTPClient(opts)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "naive-client-mygo/0.1")

	resp, err := client.Do(req)
	if err != nil && opts.LocalEndpoint != nil && opts.ProxyURL == "" {
		// Fallback to direct download if local proxy failed
		direct := &http.Client{Timeout: 10 * time.Minute}
		resp, err = direct.Do(req)
	}
	if err != nil {
		return fmt.Errorf("下载失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载服务器返回 HTTP %d", resp.StatusCode)
	}

	totalSize := asset.Size
	if resp.ContentLength > 0 {
		totalSize = resp.ContentLength
	}

	hasher := sha256.New()
	var downloaded int64
	buf := make([]byte, 32*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, wErr := tmpArchive.Write(buf[:n]); wErr != nil {
				return fmt.Errorf("写入下载文件失败: %w", wErr)
			}
			_, _ = hasher.Write(buf[:n])
			downloaded += int64(n)
			if totalSize > 0 {
				ratio := float64(downloaded) / float64(totalSize)
				onProgress(min(0.80, 0.05+ratio*0.75), fmt.Sprintf("正在下载 %s (%.1f%%)…", rel.TagName, ratio*100))
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("读取下载流失败: %w", readErr)
		}
	}
	if err := tmpArchive.Close(); err != nil {
		return err
	}

	// Verify SHA256 digest if provided by GitHub Release Asset
	if expectedHex := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(asset.Digest)), "sha256:"); expectedHex != "" && len(expectedHex) == 64 {
		actualHex := hex.EncodeToString(hasher.Sum(nil))
		if actualHex != expectedHex {
			return fmt.Errorf("SHA256 校验失败: 期望 %s，实际 %s", expectedHex[:12], actualHex[:12])
		}
	}

	onProgress(0.84, "正在解压核心文件…")
	stagingBinPath := targetBinPath + ".new"
	_ = os.Remove(stagingBinPath)
	defer func() {
		_ = os.Remove(stagingBinPath)
	}()

	binName := BinaryFilename(goos)
	if err := ExtractBinary(tmpArchivePath, asset.Name, binName, stagingBinPath); err != nil {
		return fmt.Errorf("解压核心失败: %w", err)
	}
	if err := os.Chmod(stagingBinPath, 0o755); err != nil && goos != "windows" {
		return fmt.Errorf("设置可执行权限失败: %w", err)
	}
	clearQuarantine(stagingBinPath)

	// Seamless swap:
	// 1. Stop all currently running services and remember them
	onProgress(0.92, "正在平滑切换运行中的服务…")
	var running []config.Service
	if mgr != nil {
		running = mgr.StopAll()
	}

	// 2. Atomically replace targetBinPath
	oldBackup := targetBinPath + ".old"
	_ = os.Remove(oldBackup)
	if _, err := os.Stat(targetBinPath); err == nil {
		// Rename existing binary to .old in case Windows holds a brief handle
		_ = os.Rename(targetBinPath, oldBackup)
	}
	if err := os.Rename(stagingBinPath, targetBinPath); err != nil {
		// Restore backup if rename failed
		if _, statErr := os.Stat(oldBackup); statErr == nil {
			_ = os.Rename(oldBackup, targetBinPath)
		}
		return fmt.Errorf("替换核心二进制失败: %w", err)
	}
	_ = os.Remove(oldBackup)

	// 3. Restart all previously running services with the new binary
	if mgr != nil {
		mgr.SetBinaryPath(targetBinPath)
		for _, svc := range running {
			_ = mgr.Start(svc)
		}
	}

	onProgress(1.0, "更新完成")
	return nil
}

// ExtractBinary extracts the `naive` or `naive.exe` executable from an archive (.zip or .tar.xz)
// into destPath.
func ExtractBinary(archivePath, assetName, targetExeName, destPath string) error {
	lower := strings.ToLower(assetName)
	switch {
	case strings.HasSuffix(lower, ".zip"):
		return extractFromZip(archivePath, targetExeName, destPath)
	case strings.HasSuffix(lower, ".tar.xz") || strings.HasSuffix(lower, ".txz"):
		return extractFromTarXz(archivePath, targetExeName, destPath)
	default:
		return fmt.Errorf("不支持的归档格式: %s", assetName)
	}
}

func extractFromZip(archivePath, targetExeName, destPath string) error {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer zr.Close()

	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if filepath.Base(f.Name) == targetExeName {
			rc, err := f.Open()
			if err != nil {
				return err
			}
			defer rc.Close()
			return writeStreamToFile(rc, destPath)
		}
	}
	return fmt.Errorf("在压缩包中未找到 %s", targetExeName)
}

func extractFromTarXz(archivePath, targetExeName, destPath string) error {
	// First try pure-Go XZ + tar extraction so no external tools are required on any OS.
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	xzr, err := NewXZReader(f)
	if err == nil {
		tr := tar.NewReader(xzr)
		for {
			hdr, tErr := tr.Next()
			if tErr == io.EOF {
				break
			}
			if tErr != nil {
				err = tErr
				break
			}
			if hdr.Typeflag == tar.TypeReg && filepath.Base(hdr.Name) == targetExeName {
				return writeStreamToFile(tr, destPath)
			}
		}
	}

	// Fallback to system `tar -xJf` if available
	tmpDir, mkErr := os.MkdirTemp(filepath.Dir(destPath), "naive-untar-*")
	if mkErr != nil {
		return fmt.Errorf("解压 tar.xz 失败: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cmd := exec.Command("tar", "-xJf", archivePath, "-C", tmpDir)
	if out, cmdErr := cmd.CombinedOutput(); cmdErr != nil {
		return fmt.Errorf("解压 tar.xz 失败: %v (%s)", err, strings.TrimSpace(string(out)))
	}

	var found string
	_ = filepath.WalkDir(tmpDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr == nil && !d.IsDir() && d.Name() == targetExeName {
			found = path
			return io.EOF
		}
		return nil
	})
	if found == "" {
		return fmt.Errorf("在归档中未找到可执行文件 %s", targetExeName)
	}
	in, openErr := os.Open(found)
	if openErr != nil {
		return openErr
	}
	defer in.Close()
	return writeStreamToFile(in, destPath)
}

func writeStreamToFile(r io.Reader, destPath string) error {
	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, r)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func clearQuarantine(path string) {
	if runtime.GOOS == "darwin" {
		_ = exec.Command("xattr", "-d", "com.apple.quarantine", path).Run()
	}
}

// AtomicFlag is a small helper for tracking whether an update is in progress.
type AtomicFlag struct {
	v atomic.Bool
}
