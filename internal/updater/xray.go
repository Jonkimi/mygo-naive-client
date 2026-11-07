package updater

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"naive-client/internal/config"
	"naive-client/internal/runner"
)

// LatestXrayReleaseAPI is the GitHub API endpoint for XTLS/Xray-core releases.
var LatestXrayReleaseAPI = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"

// XrayBinaryFilename returns the platform-specific executable name ("xray" or "xray.exe").
func XrayBinaryFilename(goos string) string {
	if goos == "windows" {
		return "xray.exe"
	}
	return "xray"
}

// ExpectedXrayAssetSuffix returns the suffix for XTLS/Xray-core release asset names.
func ExpectedXrayAssetSuffix(goos, goarch string) (string, error) {
	switch goos {
	case "darwin":
		switch goarch {
		case "arm64":
			return "macos-arm64-v8a.zip", nil
		case "amd64":
			return "macos-64.zip", nil
		}
	case "windows":
		switch goarch {
		case "amd64":
			return "windows-64.zip", nil
		case "arm64":
			return "windows-arm64-v8a.zip", nil
		case "386":
			return "windows-32.zip", nil
		}
	case "linux":
		switch goarch {
		case "amd64":
			return "linux-64.zip", nil
		case "arm64":
			return "linux-arm64-v8a.zip", nil
		case "386":
			return "linux-32.zip", nil
		case "arm":
			return "linux-arm32-v7a.zip", nil
		}
	}
	return "", fmt.Errorf("不支持的操作系统或架构组合: %s/%s", goos, goarch)
}

// MatchXrayAsset picks the asset for goos/goarch from a Release.
func MatchXrayAsset(rel *Release, goos, goarch string) (Asset, error) {
	if rel == nil {
		return Asset{}, errors.New("release info is nil")
	}
	suffix, err := ExpectedXrayAssetSuffix(goos, goarch)
	if err != nil {
		return Asset{}, err
	}
	for _, a := range rel.Assets {
		if strings.HasPrefix(a.Name, "Xray-") &&
			!strings.HasSuffix(a.Name, ".dgst") &&
			strings.HasSuffix(a.Name, suffix) {
			return a, nil
		}
	}
	return Asset{}, fmt.Errorf("在版本 %s 中未找到适配 %s/%s 的安装包 (*%s)", rel.TagName, goos, goarch, suffix)
}

// ParseXrayVersionOutput extracts normalized version string (e.g. "v1.8.24") from `xray version`.
func ParseXrayVersionOutput(raw string) string {
	line := strings.TrimSpace(strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")[0])
	if line == "" {
		return ""
	}
	fields := strings.Fields(line)
	if len(fields) >= 2 && strings.EqualFold(fields[0], "xray") {
		ver := strings.TrimPrefix(fields[1], "v")
		if ver != "" {
			return "v" + ver
		}
	}
	return ""
}

// ParseXrayDGST parses a .dgst file content and returns the SHA256 hex string.
func ParseXrayDGST(raw string) string {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(line), "SHA256=") || strings.HasPrefix(strings.ToUpper(line), "SHA256 =") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return strings.ToLower(strings.TrimSpace(parts[1]))
			}
		}
	}
	return ""
}

// DetectLocalXrayVersion runs `xray version` and extracts version.
func DetectLocalXrayVersion(binPath string) string {
	if binPath == "" {
		return ""
	}
	info, err := os.Stat(binPath)
	if err != nil || info.IsDir() {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, "version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	return ParseXrayVersionOutput(string(out))
}

// ExtractXrayZip extracts `xray` or `xray.exe` from zip into targetPath atomically.
func ExtractXrayZip(zipPath, targetBinPath string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("无法打开 zip 文件: %w", err)
	}
	defer r.Close()

	binName := strings.TrimSuffix(filepath.Base(targetBinPath), ".new")
	var targetFile *zip.File
	for _, f := range r.File {
		if filepath.Base(f.Name) == binName {
			targetFile = f
			break
		}
	}
	if targetFile == nil {
		return fmt.Errorf("在压缩包中未找到核心二进制 %q", binName)
	}

	rc, err := targetFile.Open()
	if err != nil {
		return fmt.Errorf("无法读取压缩包内二进制: %w", err)
	}
	defer rc.Close()

	if err := os.MkdirAll(filepath.Dir(targetBinPath), 0o755); err != nil {
		return err
	}

	tmpTarget := targetBinPath + ".tmp"
	_ = os.Remove(tmpTarget)
	out, err := os.OpenFile(tmpTarget, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("无法创建临时二进制文件: %w", err)
	}

	if _, err := io.Copy(out, rc); err != nil {
		out.Close()
		_ = os.Remove(tmpTarget)
		return fmt.Errorf("写入临时二进制文件失败: %w", err)
	}
	out.Close()

	_ = os.Remove(targetBinPath)
	if err := os.Rename(tmpTarget, targetBinPath); err != nil {
		_ = os.Remove(tmpTarget)
		return fmt.Errorf("重命名替换二进制文件失败: %w", err)
	}
	return nil
}

// CheckLatestXray fetches the latest release metadata for XTLS/Xray-core.
func CheckLatestXray(ctx context.Context, opts HTTPClientOptions) (*Release, error) {
	return CheckLatestFromURL(ctx, LatestXrayReleaseAPI, opts)
}

// SeamlessUpdateXray downloads the xray release asset for the current platform,
// extracts the binary, updates the manager, and restarts any affected services.
func SeamlessUpdateXray(
	ctx context.Context,
	rel *Release,
	targetBinPath string,
	mgr *runner.Manager,
	opts HTTPClientOptions,
	mirrorPrefix string,
	onProgress ProgressFunc,
) error {
	return SeamlessUpdateXrayForPlatform(ctx, rel, runtime.GOOS, runtime.GOARCH, targetBinPath, mgr, opts, mirrorPrefix, onProgress)
}

// SeamlessUpdateXrayForPlatform is the platform-parameterized implementation of SeamlessUpdateXray.
func SeamlessUpdateXrayForPlatform(
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
	asset, err := MatchXrayAsset(rel, goos, goarch)
	if err != nil {
		return err
	}

	binDir := filepath.Dir(targetBinPath)
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return fmt.Errorf("创建核心目录失败: %w", err)
	}

	tmpArchive, err := os.CreateTemp(binDir, "xray-download-*"+filepath.Ext(asset.Name))
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

	onProgress(0.84, "正在解压核心文件…")
	stagingBinPath := targetBinPath + ".new"
	_ = os.Remove(stagingBinPath)
	defer func() {
		_ = os.Remove(stagingBinPath)
	}()

	if err := ExtractXrayZip(tmpArchivePath, stagingBinPath); err != nil {
		return fmt.Errorf("解压核心失败: %w", err)
	}
	if err := os.Chmod(stagingBinPath, 0o755); err != nil && goos != "windows" {
		return fmt.Errorf("设置可执行权限失败: %w", err)
	}
	clearQuarantine(stagingBinPath)

	onProgress(0.92, "正在平滑切换运行中的服务…")
	var running []config.Service
	if mgr != nil {
		running = mgr.StopAll()
	}

	oldBackup := targetBinPath + ".old"
	_ = os.Remove(oldBackup)
	if _, err := os.Stat(targetBinPath); err == nil {
		_ = os.Rename(targetBinPath, oldBackup)
	}
	if err := os.Rename(stagingBinPath, targetBinPath); err != nil {
		if _, statErr := os.Stat(oldBackup); statErr == nil {
			_ = os.Rename(oldBackup, targetBinPath)
		}
		return fmt.Errorf("替换核心二进制失败: %w", err)
	}
	_ = os.Remove(oldBackup)

	if mgr != nil {
		mgr.SetXrayBinaryPath(targetBinPath)
		for _, svc := range running {
			_ = mgr.Start(svc)
		}
	}

	onProgress(1.0, "更新完成")
	return nil
}
