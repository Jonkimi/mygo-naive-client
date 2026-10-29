package app

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"

	"naive-client/internal/config"
	"naive-client/internal/runner"
	"naive-client/internal/updater"
)

func newTestApp(t *testing.T, initialServices []config.Service) (*app, *ui.Tester, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell mock script test runs on unix")
	}

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "bin", "naive")
	_ = os.MkdirAll(filepath.Dir(binPath), 0o755)

	script := `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "naive 143.0.7499.109-2"
  exit 0
fi
echo "naive started with $1"
trap 'exit 0' TERM INT
while true; do
  sleep 1
done
`
	if err := os.WriteFile(binPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write mock naive: %v", err)
	}

	a := newApp(tmpDir)
	a.headless = true
	a.state.AutoCheckUpdate = false
	a.state.Services = initialServices
	a.saveState()
	a.initSubsystems()

	t.Cleanup(func() {
		if a.mgr != nil {
			_ = a.mgr.StopAll()
		}
	})

	tt := ui.NewTester(a.view, 900, 660)
	tt.Frame()
	return a, tt, binPath
}

func freeLocalPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func TestMainPanel_MultiServiceStartStopAndExportV2rayN(t *testing.T) {
	p1 := freeLocalPort(t)
	p2 := freeLocalPort(t)

	svcs := []config.Service{
		{
			ID:      "svc-1",
			Name:    "HK-Primary",
			Listens: []string{fmt.Sprintf("socks://127.0.0.1:%d", p1)},
			Proxies: []string{"https://alice:secret@hk.example.com:443"},
		},
		{
			ID:      "svc-2",
			Name:    "JP-Backup",
			Listens: []string{fmt.Sprintf("socks://0.0.0.0:%d", p2)},
			Proxies: []string{"quic://bob:secret@jp.example.com:443"},
		},
	}

	a, tt, _ := newTestApp(t, svcs)

	// Verify initial state shows both services stopped and core version detected
	if _, ok := tt.Find("本地核心 v143.0.7499.109-2"); !ok {
		t.Fatalf("expected detected local version badge on main panel")
	}

	// Click "全部启动" to start both services concurrently
	if err := tt.Click("全部启动"); err != nil {
		t.Fatalf("click 全部启动: %v", err)
	}
	tt.Frame()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a.mgr.StatusOf("svc-1").State == runner.StateRunning &&
			a.mgr.StatusOf("svc-2").State == runner.StateRunning {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	tt.Frame()

	if _, ok := tt.Find("2 个运行中"); !ok {
		t.Fatalf("expected toolbar badge '2 个运行中' after starting both services")
	}

	// Click "复制本地链接" on the first card and verify clipboard format socks://address:port#alias
	if err := tt.Click("复制本地链接"); err != nil {
		t.Fatalf("click 复制本地链接: %v", err)
	}
	tt.Frame()

	wantURI := fmt.Sprintf("socks://127.0.0.1:%d#HK-Primary", p1)
	if a.clipboardMem != wantURI {
		t.Fatalf("clipboard URI = %q, want %q", a.clipboardMem, wantURI)
	}
	if !tt.HasText("已复制本地链接") {
		t.Fatalf("expected toast '已复制本地链接' after copy, got texts: %q", tt.Texts())
	}

	// Click "复制 Naive 链接" on the first card and verify clipboard format and toast
	if err := tt.Click("复制 Naive 链接"); err != nil {
		t.Fatalf("click 复制 Naive 链接: %v", err)
	}
	tt.Frame()

	wantNaiveURI := "naive+https://alice:secret@hk.example.com:443#HK-Primary"
	if a.clipboardMem != wantNaiveURI {
		t.Fatalf("clipboard Naive URI = %q, want %q", a.clipboardMem, wantNaiveURI)
	}
	if !tt.HasText("已复制 Naive 分享链接") {
		t.Fatalf("expected toast '已复制 Naive 分享链接' after copy, got texts: %q", tt.Texts())
	}

	// Click "全部停止" and verify both transition back to stopped
	if err := tt.Click("全部停止"); err != nil {
		t.Fatalf("click 全部停止: %v", err)
	}
	tt.Frame()

	if a.isServiceActive("svc-1") || a.isServiceActive("svc-2") {
		t.Fatalf("expected all services stopped after clicking 全部停止")
	}
	if _, ok := tt.Find("全部已停止"); !ok {
		t.Fatalf("expected toolbar badge '全部已停止'")
	}
}

func TestServiceCard_CopyTooltips(t *testing.T) {
	// 1. Service with configured proxy shows local link and naive share link tooltips
	svcs := []config.Service{
		{
			ID:      "svc-proxy",
			Name:    "US-Proxy",
			Listens: []string{"socks://127.0.0.1:1088"},
			Proxies: []string{"https://user:pass@proxy.example.com:443"},
		},
	}
	_, tt, _ := newTestApp(t, svcs)

	// Hover over "复制本地链接"
	r, ok := tt.Find("复制本地链接")
	if !ok {
		t.Fatalf("could not find '复制本地链接' button")
	}
	tt.Move(r.X+r.W/2, r.Y+r.H/2)
	tt.Advance(time.Second)
	wantLocalTip := "socks://127.0.0.1:1088#US-Proxy"
	if !tt.HasText(wantLocalTip) {
		t.Fatalf("expected tooltip %q, got texts: %q", wantLocalTip, tt.Texts())
	}

	// Move away and hover over "复制 Naive 链接"
	tt.Move(0, 0)
	tt.Advance(time.Second)

	r, ok = tt.Find("复制 Naive 链接")
	if !ok {
		t.Fatalf("could not find '复制 Naive 链接' button")
	}
	tt.Move(r.X+r.W/2, r.Y+r.H/2)
	tt.Advance(time.Second)
	wantNaiveTip := "naive+https://user:pass@proxy.example.com:443#US-Proxy"
	if !tt.HasText(wantNaiveTip) {
		t.Fatalf("expected tooltip %q, got texts: %q", wantNaiveTip, tt.Texts())
	}

	// 2. Service without configured proxy displays fallback tooltip
	noProxySvcs := []config.Service{
		{
			ID:      "svc-direct",
			Name:    "Direct-Only",
			Listens: []string{"socks://127.0.0.1:1089"},
		},
	}
	_, tt2, _ := newTestApp(t, noProxySvcs)
	r2, ok := tt2.Find("复制 Naive 链接")
	if !ok {
		t.Fatalf("could not find '复制 Naive 链接' button on unconfigured service")
	}
	tt2.Move(r2.X+r2.W/2, r2.Y+r2.H/2)
	tt2.Advance(time.Second)
	if !tt2.HasText("未配置可导出的远端节点") {
		t.Fatalf("expected tooltip '未配置可导出的远端节点', got texts: %q", tt2.Texts())
	}
}

func TestImportDialog_FromNaiveShareLink(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)

	a.clipboardMem = "https://alice:pass@hk.example.com#HK-Direct\nnaive+https://user1:pass1@1.2.3.4:443?security=tls&sni=sni.example.com&insecure-concurrency=3#US-West"

	if err := tt.Click("剪贴板导入"); err != nil {
		t.Fatalf("click 剪贴板导入: %v", err)
	}
	tt.Frame()

	if err := tt.Click("解析并导入"); err != nil {
		t.Fatalf("click 解析并导入: %v", err)
	}
	tt.Frame()

	if len(a.state.Services) != 2 {
		t.Fatalf("expected 2 imported services, got %d", len(a.state.Services))
	}
	if a.state.Services[0].Name != "HK-Direct" || a.state.Services[0].PrimaryProxy() != "https://alice:pass@hk.example.com" {
		t.Fatalf("unexpected first imported service: %+v", a.state.Services[0])
	}
	imported := a.state.Services[1]
	if imported.Name != "US-West" || imported.InsecureConcurrency != 3 {
		t.Fatalf("unexpected second imported service: %+v", imported)
	}
	if imported.PrimaryProxy() != "https://user1:pass1@sni.example.com:443" {
		t.Fatalf("expected sni used as node address, got %q", imported.PrimaryProxy())
	}
	if _, ok := tt.Find("US-West"); !ok {
		t.Fatalf("expected imported service card 'US-West' rendered on main panel")
	}

	// While service is stopped, clicking "延迟测速" or "下载测速" should be disabled (no probe/speed test started)
	_ = tt.Click("延迟测速")
	_ = tt.Click("下载测速")
	tt.Frame()
	st := a.mgr.StatusOf(imported.ID)
	if st.Probing || st.SpeedTesting {
		t.Fatalf("expected latency and download speed tests disabled while service is stopped")
	}
}

func TestSeamlessUpdateFromMainPanel(t *testing.T) {
	p1 := freeLocalPort(t)
	svcs := []config.Service{
		{
			ID:      "svc-hot",
			Name:    "SG-Node",
			Listens: []string{fmt.Sprintf("socks://127.0.0.1:%d", p1)},
			Proxies: []string{"https://u:p@sg.example.com"},
		},
	}
	a, tt, _ := newTestApp(t, svcs)

	// Start the service before updating
	if err := a.mgr.Start(svcs[0]); err != nil {
		t.Fatalf("start service: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a.mgr.StatusOf("svc-hot").State == runner.StateRunning {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	oldPID := a.mgr.StatusOf("svc-hot").PID

	suffix, err := updater.ExpectedAssetSuffix(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Skipf("unsupported test platform: %v", err)
	}
	assetName := "naiveproxy-v154.0.8037.49-5" + suffix

	newScript := []byte(`#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "naive 154.0.8037.49-5"
  exit 0
fi
trap 'exit 0' TERM INT
while true; do
  sleep 1
done
`)
	binName := updater.BinaryFilename(runtime.GOOS)
	archiveBytes := buildTestReleaseArchive(t, assetName, "naiveproxy-v154.0.8037.49-5/"+binName, newScript)
	sum := sha256.Sum256(archiveBytes)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/latest" {
			rel := updater.Release{
				TagName: "v154.0.8037.49-5",
				Assets: []updater.Asset{
					{
						Name:               assetName,
						Size:               int64(len(archiveBytes)),
						Digest:             digest,
						BrowserDownloadURL: srv.URL + "/download/" + assetName,
					},
				},
			}
			_ = json.NewEncoder(rw).Encode(rel)
			return
		}
		_, _ = rw.Write(archiveBytes)
	}))
	defer srv.Close()

	oldAPI := updater.LatestReleaseAPI
	updater.LatestReleaseAPI = srv.URL + "/latest"
	t.Cleanup(func() {
		updater.LatestReleaseAPI = oldAPI
	})

	a.latestRelease = &updater.Release{
		TagName: "v154.0.8037.49-5",
		Assets: []updater.Asset{
			{
				Name:               assetName,
				Size:               int64(len(archiveBytes)),
				Digest:             digest,
				BrowserDownloadURL: srv.URL + "/download/" + assetName,
			},
		},
	}
	a.hasUpdate = true
	tt.Frame()

	// Verify update button is shown and click it
	if err := tt.Click("无感更新至 v154.0.8037.49-5"); err != nil {
		t.Fatalf("click seamless update button: %v", err)
	}

	// Wait for background seamless update to finish and service to restart
	deadline = time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if !a.updatingCore && a.localVersion == "v154.0.8037.49-5" {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	tt.Frame()

	if a.localVersion != "v154.0.8037.49-5" {
		t.Fatalf("localVersion after update = %q, want v154.0.8037.49-5 (err=%s)", a.localVersion, a.updateError)
	}

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a.mgr.StatusOf("svc-hot").State == runner.StateRunning {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	newPID := a.mgr.StatusOf("svc-hot").PID
	if newPID == 0 || newPID == oldPID {
		t.Fatalf("expected service restarted with new PID after hot-swap (old=%d, new=%d)", oldPID, newPID)
	}
	if a.state.InstalledNaiveTag != "v154.0.8037.49-5" {
		t.Fatalf("expected state.InstalledNaiveTag = %q, got %q", "v154.0.8037.49-5", a.state.InstalledNaiveTag)
	}
	if a.state.InstalledNaiveSHA256 == "" {
		t.Fatalf("expected state.InstalledNaiveSHA256 to be populated")
	}
}

func TestIdleFrameBudget(t *testing.T) {
	_, tt, _ := newTestApp(t, []config.Service{
		{
			ID:      "svc-idle",
			Name:    "Idle-Service",
			Listens: []string{"socks://127.0.0.1:1080"},
			Proxies: []string{"https://u:p@example.com"},
		},
	})
	tt.Advance(500 * time.Millisecond)
	tt.Frame()
	if tt.FramePending() {
		t.Fatalf("idle main panel should not continuously request animation frames")
	}
}

// Regression test: DialogBase's panel defaults to horizontal box unless .Column() is set,
// and ui.Scroll inside the dialog requires .Grow(1) with a bounded dialog height so the
// header, scrollable body sections, and footer buttons stack vertically without overlapping.
func TestSettingsDialog_LayoutAndSave(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)

	if err := tt.Click("设置"); err != nil {
		t.Fatalf("click 设置: %v", err)
	}
	tt.Frame()

	hdr, ok := tt.Find("全局偏好设置")
	if !ok {
		t.Fatalf("expected settings dialog header '全局偏好设置'")
	}
	sec1, ok := tt.Find("外观与系统集成")
	if !ok {
		t.Fatalf("expected section 1 '外观与系统集成'")
	}
	secClient, ok := tt.Find("NaiveClient 客户端更新")
	if !ok {
		t.Fatalf("expected section 'NaiveClient 客户端更新'")
	}
	sec2, ok := tt.Find("NaiveProxy 核心与无感更新")
	if !ok {
		t.Fatalf("expected section 2 'NaiveProxy 核心与无感更新'")
	}
	saveBtn, ok := tt.Find("保存设置")
	if !ok {
		t.Fatalf("expected footer button '保存设置'")
	}

	if !(hdr.Y < sec1.Y && sec1.Y < secClient.Y && secClient.Y < sec2.Y && sec2.Y < saveBtn.Y) {
		t.Fatalf("expected vertical stacking in settings dialog: hdr.Y=%v, sec1.Y=%v, secClient.Y=%v, sec2.Y=%v, saveBtn.Y=%v",
			hdr.Y, sec1.Y, secClient.Y, sec2.Y, saveBtn.Y)
	}

	if err := tt.Click("深色"); err != nil {
		t.Fatalf("click 深色 theme option: %v", err)
	}
	tt.Frame()

	if err := tt.Click("保存设置"); err != nil {
		t.Fatalf("click 保存设置: %v", err)
	}
	tt.Frame()

	if a.settingsDlg.open {
		t.Fatalf("expected settings dialog closed after clicking 保存设置")
	}
	if a.state.Appearance != appearanceDark {
		t.Fatalf("expected state.Appearance = %q, got %q", appearanceDark, a.state.Appearance)
	}
}

func buildTestReleaseArchive(t *testing.T, assetName, entryName string, payload []byte) []byte {
	t.Helper()
	if strings.HasSuffix(assetName, ".zip") {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		w, err := zw.Create(entryName)
		if err != nil {
			t.Fatalf("zip create: %v", err)
		}
		_, _ = w.Write(payload)
		_ = zw.Close()
		return buf.Bytes()
	}

	// Build a tar archive and wrap it in a valid uncompressed LZMA2 XZ stream
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	if err := tw.WriteHeader(&tar.Header{
		Name: entryName,
		Mode: 0o755,
		Size: int64(len(payload)),
	}); err != nil {
		t.Fatalf("tar header: %v", err)
	}
	_, _ = tw.Write(payload)
	_ = tw.Close()
	return wrapUncompressedXZ(tarBuf.Bytes())
}

func wrapUncompressedXZ(data []byte) []byte {
	var out bytes.Buffer
	// Stream header: magic + flags(0x00, 0x01 = CRC32) + CRC32(flags)
	out.Write([]byte{0xFD, '7', 'z', 'X', 'Z', 0x00})
	flags := []byte{0x00, 0x01}
	out.Write(flags)
	_ = binary.Write(&out, binary.LittleEndian, crc32.ChecksumIEEE(flags))

	// Block header: size=2 ((2+1)*4 = 12 bytes total: 8 bytes body + 4 bytes CRC32)
	blkHdr := []byte{0x02, 0x00, 0x21, 0x01, 0x00, 0x00, 0x00, 0x00}
	out.Write(blkHdr)
	_ = binary.Write(&out, binary.LittleEndian, crc32.ChecksumIEEE(blkHdr))

	// LZMA2 uncompressed chunk(s)
	var lzma2 bytes.Buffer
	lzma2.WriteByte(0x01) // uncompressed reset dict
	sizeMinus1 := len(data) - 1
	lzma2.WriteByte(byte(sizeMinus1 >> 8))
	lzma2.WriteByte(byte(sizeMinus1))
	lzma2.Write(data)
	lzma2.WriteByte(0x00) // end of LZMA2 stream

	unpaddedSize := lzma2.Len() + 4 // +4 for CRC32 check
	out.Write(lzma2.Bytes())
	for out.Len()%4 != 0 {
		out.WriteByte(0x00)
	}
	// Block Check (CRC32 of uncompressed data)
	_ = binary.Write(&out, binary.LittleEndian, crc32.ChecksumIEEE(data))

	// Index: indicator(0x00) + numRecords(1) + unpaddedSize + uncompressedSize + padding + CRC32
	var idx bytes.Buffer
	idx.WriteByte(0x00)
	writeXZVarint(&idx, 1)
	writeXZVarint(&idx, uint64(unpaddedSize))
	writeXZVarint(&idx, uint64(len(data)))
	for idx.Len()%4 != 0 {
		idx.WriteByte(0x00)
	}
	idxCRC := crc32.ChecksumIEEE(idx.Bytes())
	out.Write(idx.Bytes())
	_ = binary.Write(&out, binary.LittleEndian, idxCRC)

	// Stream footer: CRC32(backwardSize + flags) + backwardSize(uint32) + flags(2) + 'Y','Z'
	backwardWords := uint32((idx.Len()+4)/4 - 1)
	var footerBody bytes.Buffer
	_ = binary.Write(&footerBody, binary.LittleEndian, backwardWords)
	footerBody.Write(flags)
	_ = binary.Write(&out, binary.LittleEndian, crc32.ChecksumIEEE(footerBody.Bytes()))
	out.Write(footerBody.Bytes())
	out.Write([]byte{'Y', 'Z'})
	return out.Bytes()
}

func writeXZVarint(b *bytes.Buffer, v uint64) {
	for v >= 0x80 {
		b.WriteByte(byte(v&0x7F) | 0x80)
		v >>= 7
	}
	b.WriteByte(byte(v))
}

func TestAutoCoreUpdateSilentHotSwap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skip on windows due to mock shell script")
	}

	p := freeLocalPort(t)
	svc := config.Service{
		ID:      "svc-auto",
		Name:    "Auto-Service",
		Listens: []string{fmt.Sprintf("socks://127.0.0.1:%d", p)},
		Proxies: []string{"https://alice:pass@proxy.example.com:443"},
	}

	a, tt, binPath := newTestApp(t, []config.Service{svc})
	a.state.InstalledNaiveTag = "v154.0.8037.49-1"
	a.state.AutoUpdateCore = true
	a.syncBinaryPathAndVersion()

	// Initial version display should match installed release tag
	if a.localVersion != "v154.0.8037.49-1" {
		t.Fatalf("expected initial localVersion = %q, got %q", "v154.0.8037.49-1", a.localVersion)
	}

	if err := a.mgr.Start(svc); err != nil {
		t.Fatalf("start initial service: %v", err)
	}

	// Prepare mock release server for v154.0.8037.49-2
	newScript := "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo \"naive 154.0.8037.49-2\"; exit 0; fi\ntrap 'exit 0' INT TERM\nwhile true; do sleep 0.1; done\n"
	assetSuffix, err := updater.ExpectedAssetSuffix(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatalf("asset suffix: %v", err)
	}
	assetName := "naiveproxy-v154.0.8037.49-2" + assetSuffix
	archiveBytes := buildTestReleaseArchive(t, assetName, updater.BinaryFilename(runtime.GOOS), []byte(newScript))
	sum := sha256.Sum256(archiveBytes)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest":
			rel := updater.Release{
				TagName: "v154.0.8037.49-2",
				Name:    "v154.0.8037.49-2",
				Assets: []updater.Asset{
					{
						Name:               assetName,
						Size:               int64(len(archiveBytes)),
						Digest:             digest,
						BrowserDownloadURL: srv.URL + "/download/" + assetName,
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(rel)
		case "/download/" + assetName:
			_, _ = w.Write(archiveBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	oldAPI := updater.LatestReleaseAPI
	updater.LatestReleaseAPI = srv.URL + "/latest"
	t.Cleanup(func() {
		updater.LatestReleaseAPI = oldAPI
	})

	// Trigger automatic background update check
	a.triggerCheckUpdate(false)

	// Wait for automatic seamless update hot-swap to complete in the background
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !a.updatingCore && a.localVersion == "v154.0.8037.49-2" {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	tt.Frame()

	if a.localVersion != "v154.0.8037.49-2" {
		t.Fatalf("localVersion after auto update = %q, want v154.0.8037.49-2 (err=%s)", a.localVersion, a.updateError)
	}
	if a.state.InstalledNaiveTag != "v154.0.8037.49-2" {
		t.Fatalf("expected state.InstalledNaiveTag = %q, got %q", "v154.0.8037.49-2", a.state.InstalledNaiveTag)
	}
	if a.state.InstalledNaiveSHA256 == "" {
		t.Fatalf("expected state.InstalledNaiveSHA256 to be populated")
	}

	// Verify binary was actually updated on disk
	binSum, err := updater.FileSHA256(binPath)
	if err != nil {
		t.Fatalf("FileSHA256 error: %v", err)
	}
	if binSum != a.state.InstalledNaiveSHA256 {
		t.Fatalf("persisted SHA256 %s does not match binary on disk %s", a.state.InstalledNaiveSHA256, binSum)
	}
}

func TestMainPanel_BatchSpeedTest(t *testing.T) {
	p1 := freeLocalPort(t)
	p2 := freeLocalPort(t)

	svcs := []config.Service{
		{
			ID:      "svc-1",
			Name:    "Server-1",
			Listens: []string{fmt.Sprintf("socks://127.0.0.1:%d", p1)},
			Proxies: []string{"https://alice:secret@s1.example.com:443"},
		},
		{
			ID:      "svc-2",
			Name:    "Server-2",
			Listens: []string{fmt.Sprintf("socks://127.0.0.1:%d", p2)},
			Proxies: []string{"https://bob:secret@s2.example.com:443"},
		},
	}

	a, tt, _ := newTestApp(t, svcs)

	// 1. Initially both services stopped: clicking 一键测速 should not trigger testing
	if err := tt.Click("一键测速"); err == nil {
		if a.batchTesting {
			t.Fatal("expected batchTesting to not start when no services are running")
		}
	}

	// 2. Start all services
	if err := tt.Click("全部启动"); err != nil {
		t.Fatalf("click 全部启动: %v", err)
	}
	tt.Frame()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a.mgr.StatusOf("svc-1").State == runner.StateRunning &&
			a.mgr.StatusOf("svc-2").State == runner.StateRunning {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	tt.Frame()

	if _, ok := tt.Find("2 个运行中"); !ok {
		t.Fatalf("expected toolbar badge '2 个运行中'")
	}

	// 3. Now listen on p1 to hold proxy connections and test cancellation
	slowLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p1))
	if err != nil {
		t.Fatalf("listen slow port: %v", err)
	}
	defer slowLn.Close()

	go func() {
		for {
			conn, err := slowLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 128)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	// Click "一键测速" while running, then cancel it
	if err := tt.Click("一键测速"); err != nil {
		t.Fatalf("click 一键测速: %v", err)
	}
	tt.Frame()

	if !a.batchTesting {
		t.Fatal("expected batchTesting to be true after clicking 一键测速")
	}
	if a.batchStage != "测延迟中..." {
		t.Fatalf("expected batchStage '测延迟中...', got %q", a.batchStage)
	}

	// Click again to cancel
	if err := tt.Click("测延迟中..."); err != nil {
		t.Fatalf("click cancel batch test: %v", err)
	}
	tt.Frame()

	if a.batchTesting {
		t.Fatal("expected batchTesting to be false after cancellation")
	}
	if !tt.HasText("已取消测速") {
		t.Fatalf("expected toast '已取消测速', got texts: %q", tt.Texts())
	}

	// 4. Run batch test to completion (close slow listener so requests fail quickly)
	_ = slowLn.Close()
	a.triggerBatchTest()
	tt.Frame()

	testDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(testDeadline) {
		if !a.batchTesting {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	tt.Frame()

	if a.batchTesting {
		t.Fatal("expected batchTesting to complete")
	}

	foundSummary := false
	for _, txt := range tt.Texts() {
		if strings.Contains(txt, "一键测速完成") {
			foundSummary = true
			break
		}
	}
	if !foundSummary {
		t.Fatalf("expected toast containing '一键测速完成', got texts: %q", tt.Texts())
	}
}
