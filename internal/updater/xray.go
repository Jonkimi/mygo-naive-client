package updater

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
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

	binName := filepath.Base(targetBinPath)
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
