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
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"

	"naive-client/internal/config"
	"naive-client/internal/routing"
	"naive-client/internal/runner"
	"naive-client/internal/updater"
	"naive-client/locales"
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
	a.state.Language = locales.LangZhHans
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
	if a.localVersion != "v143.0.7499.109-2" {
		t.Fatalf("expected detected local version v143.0.7499.109-2, got %q", a.localVersion)
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

func TestSeamlessUpdateFromSettings(t *testing.T) {
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
	// Navigate to Settings where core management & seamless update are housed
	if err := tt.Click(a.catalog().NavSettings()); err != nil {
		t.Fatalf("click settings: %v", err)
	}
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

// Clicking '设置' on the sidebar navigates directly to the settings workbench page where preferences can be adjusted.
func TestSettingsPage_SidebarNavigationAndTheme(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)

	if err := tt.Click("设置"); err != nil {
		t.Fatalf("click 设置: %v", err)
	}
	tt.Frame()

	if a.activeTab != TabSettings {
		t.Fatalf("expected activeTab = TabSettings, got %v", a.activeTab)
	}

	if _, ok := tt.Find("全局偏好设置"); !ok {
		t.Fatalf("expected settings workbench header '全局偏好设置'")
	}
	if _, ok := tt.Find("外观与系统集成"); !ok {
		t.Fatalf("expected section '外观与系统集成'")
	}
	if _, ok := tt.Find("NaiveProxy 核心与无感更新"); !ok {
		t.Fatalf("expected section 'NaiveProxy 核心与无感更新'")
	}
	if _, ok := tt.Find(a.catalog().DownloadChannelTitle()); !ok {
		t.Fatalf("expected section %q", a.catalog().DownloadChannelTitle())
	}

	if err := tt.Click("深色"); err != nil {
		t.Fatalf("click 深色 theme option: %v", err)
	}
	tt.Frame()

	if a.state.Appearance != appearanceDark {
		t.Fatalf("expected state.Appearance = %q, got %q", appearanceDark, a.state.Appearance)
	}
}

// Navigating to the settings workbench page via Cmd+5 allows hot-switching language and appearance.
func TestSettingsPage_WorkbenchNavigationAndI18n(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)

	// Switch to Settings tab
	tt.Key(ui.Cmd, ui.Key5)
	tt.Frame()

	if a.activeTab != TabSettings {
		t.Fatalf("expected activeTab = TabSettings, got %v", a.activeTab)
	}

	// Switch back to Nodes via Cmd+1
	tt.Key(ui.Cmd, ui.Key1)
	tt.Frame()
	if a.activeTab != TabNodes {
		t.Fatalf("expected activeTab = TabNodes, got %v", a.activeTab)
	}

	// Test industry-standard Cmd+, shortcut to navigate to Settings
	tt.Key(ui.Cmd, ui.KeyComma)
	tt.Frame()
	if a.activeTab != TabSettings {
		t.Fatalf("expected activeTab = TabSettings after Cmd+Comma, got %v", a.activeTab)
	}

	// Switch to English on settings workbench page
	if err := tt.Click("English"); err != nil {
		t.Fatalf("click English: %v", err)
	}
	tt.Frame()

	if a.state.Language != locales.LangEn {
		t.Fatalf("expected state.Language = LangEn, got %v", a.state.Language)
	}

	// Switch back to Nodes tab via Cmd+1
	tt.Key(ui.Cmd, ui.Key1)
	tt.Frame()

	if a.activeTab != TabNodes {
		t.Fatalf("expected activeTab = TabNodes, got %v", a.activeTab)
	}

	// In English, toolbar button must show English "New Service"
	if _, ok := tt.Find("New Service"); !ok {
		t.Fatalf("expected English 'New Service' on nodes toolbar after switching language")
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

func TestWorkbenchSidebarNavigationAndLogDrawer(t *testing.T) {
	svcs := []config.Service{
		{
			ID:      "svc-1",
			Name:    "HK-01",
			Listens: []string{"socks://127.0.0.1:1080"},
			Proxies: []string{"https://alice:secret@hk.example.com:443"},
		},
	}
	a, tt, _ := newTestApp(t, svcs)

	// 1. Initial tab is TabNodes
	if a.activeTab != TabNodes {
		t.Fatalf("expected initial tab TabNodes, got %v", a.activeTab)
	}

	// 2. Click Settings sidebar item
	if err := tt.Click("设置"); err != nil {
		t.Fatalf("click 设置 failed: %v", err)
	}
	tt.Frame()
	if a.activeTab != TabSettings {
		t.Fatalf("expected activeTab TabSettings, got %v", a.activeTab)
	}

	// Switch back to Nodes via click
	if err := tt.Click("节点"); err != nil {
		t.Fatalf("click 节点 failed: %v", err)
	}
	tt.Frame()
	if a.activeTab != TabNodes {
		t.Fatalf("expected activeTab TabNodes, got %v", a.activeTab)
	}

	// 3. Open Log Drawer
	if err := tt.Click("日志"); err != nil {
		t.Fatalf("click 日志 failed: %v", err)
	}
	tt.Frame()
	if a.activeLogDrawerID != "svc-1" {
		t.Fatalf("expected activeLogDrawerID to be 'svc-1', got %q", a.activeLogDrawerID)
	}

	// 4. Press Esc to close Log Drawer
	tt.Key(0, ui.KeyEscape)
	tt.Frame()
	if a.activeLogDrawerID != "" {
		t.Fatalf("expected activeLogDrawerID to be empty after Esc, got %q", a.activeLogDrawerID)
	}

	// 5. Language switching: set language to English and verify catalog changes
	a.state.Language = "en"
	a.saveState()
	tt.Frame()
	if a.catalog().Code() != "en" {
		t.Fatalf("expected catalog code 'en', got %q", a.catalog().Code())
	}
	if !tt.HasText("Nodes") {
		t.Fatalf("expected English text 'Nodes' on screen, got texts: %v", tt.Texts())
	}
}

// TestSidebarCollapseToggle verifies collapsing and expanding the sidebar via toggle button and Cmd+B.
func TestSidebarCollapseToggle(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)
	tt.Frame()

	if a.state.SidebarCollapsed {
		t.Fatalf("expected sidebar to be expanded initially")
	}

	// 1. Click collapse button to collapse sidebar
	if err := tt.Click(a.catalog().SidebarCollapse()); err != nil {
		t.Fatalf("click collapse sidebar: %v", err)
	}
	tt.Frame()

	if !a.state.SidebarCollapsed {
		t.Fatalf("expected sidebar to be collapsed after clicking toggle button")
	}

	// 2. In collapsed state, clicking a nav item (Settings tooltip) switches tab
	if err := tt.Click(a.catalog().NavSettings()); err != nil {
		t.Fatalf("click nav item in collapsed sidebar: %v", err)
	}
	tt.Frame()
	if a.activeTab != TabSettings {
		t.Fatalf("expected activeTab = TabSettings, got %v", a.activeTab)
	}

	// 3. Press Cmd+B shortcut to expand sidebar back
	tt.Key(ui.Cmd, ui.KeyB)
	tt.Frame()

	if a.state.SidebarCollapsed {
		t.Fatalf("expected sidebar to be expanded after Cmd+B shortcut")
	}

	// 4. Press Cmd+B shortcut again to collapse sidebar
	tt.Key(ui.Cmd, ui.KeyB)
	tt.Frame()

	if !a.state.SidebarCollapsed {
		t.Fatalf("expected sidebar to be collapsed after second Cmd+B shortcut")
	}

	// 5. Click expand button in collapsed sidebar to expand back
	if err := tt.Click(a.catalog().SidebarExpand()); err != nil {
		t.Fatalf("click expand sidebar: %v", err)
	}
	tt.Frame()

	if a.state.SidebarCollapsed {
		t.Fatalf("expected sidebar to be expanded after clicking expand button")
	}
}

// TestTopBarAndCompactCardUX verifies dynamic port reflection, upcoming mode feedback, core status navigation, and compact route rendering.
func TestTopBarAndCompactCardUX(t *testing.T) {
	svcs := []config.Service{
		{
			ID:      "svc-single",
			Name:    "naive-bwg",
			Listens: []string{"socks://127.0.0.1:1080"},
			Proxies: []string{"https://d_user:secret@codex.sfchenlab.com:443"},
		},
	}
	a, tt, _ := newTestApp(t, svcs)

	// 1. Top bar reflects the service's actual port (:1080) instead of a hardcoded :10808
	if !tt.HasText("仅端口 :1080") {
		t.Fatalf("expected top bar to reflect actual port '仅端口 :1080', got texts: %v", tt.Texts())
	}

	// 2. Single-service toolbar omits redundant '全部启动'/'全部停止' buttons
	if _, ok := tt.Find(a.catalog().ActionStartAll()); ok {
		t.Fatalf("expected '全部启动' to be hidden when only 1 service exists")
	}

	// 3. Card displays compact remote host without inline credentials
	if !tt.HasText("https://codex.sfchenlab.com:443") {
		t.Fatalf("expected compact remote endpoint 'https://codex.sfchenlab.com:443' on card, got: %v", tt.Texts())
	}

	// 4. Clicking an upcoming mode pill (TUN) shows a feedback toast
	if err := tt.Click(a.catalog().ModeTun()); err != nil {
		t.Fatalf("click ModeTun: %v", err)
	}
	tt.Frame()
	if !tt.HasText(a.catalog().ModeComingSoonTip()) {
		t.Fatalf("expected coming soon toast after clicking ModeTun, got: %v", tt.Texts())
	}

	// 5. Clicking the top bar core version badge navigates directly to Settings
	if err := tt.Click(a.catalog().CoreLocal() + a.localVersion); err != nil {
		t.Fatalf("click top bar core status: %v", err)
	}
	tt.Frame()
	if a.activeTab != TabSettings {
		t.Fatalf("expected clicking core status to switch to TabSettings, got %v", a.activeTab)
	}

	// 6. Switch back to Nodes and verify disabled test button tooltip & click toast guidance
	tt.Key(ui.Cmd, ui.Key1)
	tt.Frame()

	// Hover over stopped latency probe button
	r, ok := tt.Find("延迟测速")
	if !ok {
		t.Fatalf("could not find '延迟测速'")
	}
	tt.Move(r.X+r.W/2, r.Y+r.H/2)
	tt.Advance(time.Second)
	if !tt.HasText(a.catalog().TestRequiresRunning()) {
		t.Fatalf("expected tooltip %q when hovering stopped probe button, got texts: %v", a.catalog().TestRequiresRunning(), tt.Texts())
	}

	// Clicking stopped latency probe button shows toast guidance without starting test
	if err := tt.Click("延迟测速"); err != nil {
		t.Fatalf("click 延迟测速: %v", err)
	}
	tt.Frame()
	if !tt.HasText(a.catalog().TestRequiresRunning()) {
		t.Fatalf("expected toast %q after clicking stopped probe button, got texts: %v", a.catalog().TestRequiresRunning(), tt.Texts())
	}
	if a.mgr.StatusOf("svc-single").Probing {
		t.Fatalf("expected no probe started on stopped service")
	}
}

// Tests that the top control bar allows switching traffic takeover modes between PortOnly and SystemProxy.
func TestTopBar_TrafficModeSwitching(t *testing.T) {
	port := freeLocalPort(t)
	svc := config.Service{
		ID:        "svc-1",
		Name:      "Node 1",
		Kind:      config.KindManagedNaive,
		Listens:   []string{fmt.Sprintf("socks://127.0.0.1:%d", port)},
		Proxies:   []string{"https://user:pass@example.com"},
		EnableLog: true,
	}

	a, tt, _ := newTestApp(t, []config.Service{svc})
	gwPort := freeLocalPort(t)
	a.state.GatewayPort = gwPort
	a.state.GatewayEnabled = true
	if err := a.startGateway(); err != nil {
		t.Fatalf("startGateway: %v", err)
	}
	defer a.stopGateway()

	tt.Frame()

	// Initial mode should be "port"
	if a.state.TrafficMode != "port" {
		t.Fatalf("expected initial traffic mode 'port', got %q", a.state.TrafficMode)
	}

	// Click "系统代理" mode pill
	if err := tt.Click(a.catalog().ModeSysProxy()); err != nil {
		t.Fatalf("click ModeSysProxy: %v", err)
	}
	tt.Frame()

	if a.state.TrafficMode != "sysproxy" {
		t.Fatalf("expected trafficMode 'sysproxy' after click, got %q", a.state.TrafficMode)
	}
	if a.sysproxy == nil || !a.sysproxy.IsActive() {
		t.Fatalf("expected sysproxy active after clicking ModeSysProxy")
	}

	// Click port mode pill to switch back
	portLabel := a.primaryGatewayPortLabel()
	if err := tt.Click(portLabel); err != nil {
		t.Fatalf("click port label %q: %v", portLabel, err)
	}
	tt.Frame()

	if a.state.TrafficMode != "port" {
		t.Fatalf("expected trafficMode 'port' after click, got %q", a.state.TrafficMode)
	}
	if a.sysproxy != nil && a.sysproxy.IsActive() {
		t.Fatalf("expected sysproxy deactivated after clicking port pill")
	}
}

// Tests that requests entering the Unified Gateway are dispatched through the running node pool
// and recorded by the passive quality telemetry engine.
func TestGateway_EndToEndProxyAndTelemetry(t *testing.T) {
	// 1. Mock remote destination echo server
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo server listen: %v", err)
	}
	defer echoLn.Close()

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	echoAddr := echoLn.Addr().String()

	// 2. Mock upstream proxy server that accepts SOCKS5 CONNECT
	mockProxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mock proxy listen: %v", err)
	}
	defer mockProxyLn.Close()

	go func() {
		for {
			conn, err := mockProxyLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// SOCKS5 handshake greeting
				buf := make([]byte, 256)
				if _, err := io.ReadAtLeast(c, buf, 3); err != nil {
					return
				}
				_, _ = c.Write([]byte{0x05, 0x00}) // NO_AUTH

				// SOCKS5 request
				reqBuf := make([]byte, 256)
				n, err := io.ReadAtLeast(c, reqBuf, 7)
				if err != nil || n < 7 {
					return
				}
				// Dial actual echo server
				targetConn, err := net.Dial("tcp", echoAddr)
				if err != nil {
					_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				defer targetConn.Close()
				_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

				// Bidirectional copy
				done := make(chan struct{}, 2)
				go func() {
					io.Copy(targetConn, c)
					done <- struct{}{}
				}()
				go func() {
					io.Copy(c, targetConn)
					done <- struct{}{}
				}()
				<-done
			}(conn)
		}
	}()

	mockProxyHost, mockProxyPortStr, _ := net.SplitHostPort(mockProxyLn.Addr().String())
	mockProxyPort, _ := strconv.Atoi(mockProxyPortStr)

	// 3. Configure ExternalProxy node pointing to mockProxyLn
	svc := config.Service{
		ID:          "svc-ext",
		Name:        "Fast Node",
		Kind:        config.KindExternalProxy,
		ExternalURI: fmt.Sprintf("socks5://%s:%d", mockProxyHost, mockProxyPort),
		Tags:        []string{"US", "AI"},
	}

	a, _, _ := newTestApp(t, []config.Service{svc})
	gwPort := freeLocalPort(t)
	a.state.GatewayPort = gwPort
	a.state.GatewayEnabled = true
	if err := a.startGateway(); err != nil {
		t.Fatalf("startGateway: %v", err)
	}
	defer a.stopGateway()

	// Start the service in the manager so it is StateRunning
	if err := a.mgr.Start(svc); err != nil {
		t.Fatalf("start service: %v", err)
	}

	// 4. Client connects to Gateway using SOCKS5 to reach "openai.com:443"
	clientConn, err := net.DialTimeout("tcp", a.gateway.Addr(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer clientConn.Close()

	// SOCKS5 greeting
	if _, err := clientConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("client write greeting: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, resp); err != nil || resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("client read greeting resp: %v, err: %v", resp, err)
	}

	// SOCKS5 connect to domain "openai.com:443"
	domain := "openai.com"
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
	req = append(req, []byte(domain)...)
	req = append(req, 0x01, 0xbb) // port 443
	if _, err := clientConn.Write(req); err != nil {
		t.Fatalf("client write connect req: %v", err)
	}
	connResp := make([]byte, 10)
	if _, err := io.ReadFull(clientConn, connResp); err != nil || connResp[0] != 0x05 || connResp[1] != 0x00 {
		t.Fatalf("client connect resp failed: %v, err: %v", connResp, err)
	}

	// Echo payload check
	msg := []byte("ping-gateway-telemetry")
	if _, err := clientConn.Write(msg); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	echoBuf := make([]byte, len(msg))
	if _, err := io.ReadFull(clientConn, echoBuf); err != nil || string(echoBuf) != string(msg) {
		t.Fatalf("echo mismatch: got %q, expected %q (err=%v)", echoBuf, msg, err)
	}

	// 5. Verify telemetry recorded dial through "svc-ext" with domain affinity
	sc := a.tracker.GetScore("svc-ext")
	if sc.EWMA == 0 {
		t.Fatalf("expected telemetry EWMA recorded for svc-ext, got 0")
	}
	best, ok := a.tracker.SelectBest([]string{"svc-ext"}, "api.openai.com")
	if !ok || best != "svc-ext" {
		t.Fatalf("expected affinity locked to svc-ext, got %v (ok=%v)", best, ok)
	}
}

// Tests that incoming requests are dispatched according to routing rules (BLOCK, PROXY_TAG, PROXY_POOL).
func TestGateway_RoutingRulesDispatching(t *testing.T) {
	// Mock upstream echo/socks server
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxyLn listen: %v", err)
	}
	defer proxyLn.Close()

	go func() {
		for {
			conn, err := proxyLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 256)
				if _, err := io.ReadAtLeast(c, buf, 3); err != nil {
					return
				}
				_, _ = c.Write([]byte{0x05, 0x00}) // NO_AUTH
				reqBuf := make([]byte, 256)
				if _, err := io.ReadAtLeast(c, reqBuf, 7); err != nil {
					return
				}
				_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				io.Copy(c, c)
			}(conn)
		}
	}()

	proxyHost, proxyPortStr, _ := net.SplitHostPort(proxyLn.Addr().String())
	proxyPort, _ := strconv.Atoi(proxyPortStr)

	// Node 1: AI tag
	svcA := config.Service{
		ID:          "node-ai",
		Name:        "US AI Node",
		Kind:        config.KindExternalProxy,
		ExternalURI: fmt.Sprintf("socks5://%s:%d", proxyHost, proxyPort),
		Tags:        []string{"AI", "US"},
	}
	// Node 2: General tag
	svcB := config.Service{
		ID:          "node-general",
		Name:        "HK General Node",
		Kind:        config.KindExternalProxy,
		ExternalURI: fmt.Sprintf("socks5://%s:%d", proxyHost, proxyPort),
		Tags:        []string{"HK"},
	}

	a, _, _ := newTestApp(t, []config.Service{svcA, svcB})
	gwPort := freeLocalPort(t)
	a.state.GatewayPort = gwPort
	a.state.GatewayEnabled = true
	_ = a.mgr.Start(svcA)
	_ = a.mgr.Start(svcB)

	if err := a.startGateway(); err != nil {
		t.Fatalf("startGateway: %v", err)
	}
	defer a.stopGateway()

	// 1. Target "chatgpt.com:443" should match AI preset rule -> routed to "node-ai"
	c1, err := net.DialTimeout("tcp", a.gateway.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer c1.Close()
	_, _ = c1.Write([]byte{0x05, 0x01, 0x00})
	rBuf := make([]byte, 2)
	_, _ = io.ReadFull(c1, rBuf)

	targetDomain := "chatgpt.com"
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(targetDomain))}
	req = append(req, []byte(targetDomain)...)
	req = append(req, 0x01, 0xbb)
	_, _ = c1.Write(req)
	resp1 := make([]byte, 10)
	_, err = io.ReadFull(c1, resp1)
	if err != nil || resp1[1] != 0x00 {
		t.Fatalf("expected connect success for chatgpt.com, got %v (err=%v)", resp1, err)
	}
	// Verify telemetry recorded on "node-ai"
	if a.tracker.GetScore("node-ai").EWMA == 0 {
		t.Fatalf("expected telemetry recorded on node-ai for chatgpt.com")
	}

	// 2. Target "doubleclick.net:443" should match Ad Blocker -> BLOCK (reply error)
	c2, err := net.DialTimeout("tcp", a.gateway.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer c2.Close()
	_, _ = c2.Write([]byte{0x05, 0x01, 0x00})
	_, _ = io.ReadFull(c2, rBuf)

	blockDomain := "pagead2.doubleclick.net"
	req2 := []byte{0x05, 0x01, 0x00, 0x03, byte(len(blockDomain))}
	req2 = append(req2, []byte(blockDomain)...)
	req2 = append(req2, 0x01, 0xbb)
	_, _ = c2.Write(req2)
	resp2 := make([]byte, 10)
	_, err = io.ReadFull(c2, resp2)
	// Code 0x05 (Connection refused) or error expected
	if err == nil && resp2[1] == 0x00 {
		t.Fatalf("expected connection to doubleclick.net to be blocked, but succeeded")
	}
}

// Tests that pressing Cmd+2 switches to TabRouting and toggling rules updates router state.
func TestRoutingWorkbench_NavigationAndToggle(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)

	// 1. Initial tab should be TabNodes
	if a.activeTab != TabNodes {
		t.Fatalf("expected initial tab TabNodes, got %v", a.activeTab)
	}

	// 2. Press Cmd+2 to switch to TabRouting
	tt.Key(ui.Cmd, ui.Key2)
	tt.Frame()

	if a.activeTab != TabRouting {
		t.Fatalf("expected activeTab TabRouting after Cmd+2, got %v", a.activeTab)
	}

	// 3. Verify Routing Page elements are present
	if !tt.HasText(a.catalog().RoutingTitle()) {
		t.Fatalf("expected routing title %q, got: %v", a.catalog().RoutingTitle(), tt.Texts())
	}
	if !tt.HasText("广告拦截 (Ad Blocker)") {
		t.Fatalf("expected preset rule '广告拦截 (Ad Blocker)' on page, got: %v", tt.Texts())
	}

	// 4. Verify initial rule enabled state
	if !a.state.RoutingRules[0].Enabled {
		t.Fatalf("expected rule 0 enabled initially")
	}

	// 5. Toggle first rule (toggle-rule-preset-block-ads)
	r, ok := tt.Find("toggle-rule-preset-block-ads")
	if !ok {
		t.Fatalf("expected switch toggle for 'toggle-rule-preset-block-ads'")
	}
	tt.ClickAt(r.X+r.W/2, r.Y+r.H/2)
	tt.Frame()

	if a.state.RoutingRules[0].Enabled {
		t.Fatalf("expected rule 0 disabled after toggle click")
	}

	// Verify router updated and matches fallback instead of BLOCK
	act, _ := a.router.Match("pagead2.doubleclick.net:443")
	if act.Type == routing.ActionBlock {
		t.Fatalf("expected doubleclick.net not blocked after disabling rule")
	}
}

// Tests full CRUD configuration of routing rules: creating, editing, deleting, and resetting presets.
func TestRoutingWorkbench_RuleConfigurationCRUD(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)

	// Switch to Routing tab
	tt.Key(ui.Cmd, ui.Key2)
	tt.Frame()

	initialCount := len(a.state.RoutingRules)

	// 1. Create a new custom rule
	if err := tt.Click(a.catalog().NewRule()); err != nil {
		t.Fatalf("click NewRule button: %v", err)
	}
	tt.Frame()

	if !a.ruleEditor.open {
		t.Fatalf("expected ruleEditor to be open")
	}

	a.ruleEditor.name = "My Custom Work Rule"
	a.ruleEditor.domainsInput = "custom-corp.net\ngit.custom-corp.net"
	a.ruleEditor.actionIndex = 2 // DIRECT
	a.saveRuleEditor()
	tt.Frame()

	if a.ruleEditor.open {
		t.Fatalf("expected ruleEditor closed after save")
	}
	if len(a.state.RoutingRules) != initialCount+1 {
		t.Fatalf("expected rules count %d, got %d", initialCount+1, len(a.state.RoutingRules))
	}

	// Verify custom rule matches DIRECT
	act1, ruleName1 := a.router.Match("api.custom-corp.net:443")
	if act1.Type != routing.ActionDirect || ruleName1 != "My Custom Work Rule" {
		t.Fatalf("expected ActionDirect from 'My Custom Work Rule', got %+v (%s)", act1, ruleName1)
	}

	// 2. Edit the custom rule
	lastRule := a.state.RoutingRules[len(a.state.RoutingRules)-1]
	a.openEditRuleDialog(lastRule)
	tt.Frame()

	a.ruleEditor.domainsInput = "new-corp.com"
	a.saveRuleEditor()
	tt.Frame()

	act2, ruleName2 := a.router.Match("service.new-corp.com:80")
	if act2.Type != routing.ActionDirect || ruleName2 != "My Custom Work Rule" {
		t.Fatalf("expected ActionDirect for new-corp.com, got %+v (%s)", act2, ruleName2)
	}

	// 3. Delete the custom rule
	a.deleteRule(lastRule.ID)
	tt.Frame()

	if len(a.state.RoutingRules) != initialCount {
		t.Fatalf("expected rules count back to %d, got %d", initialCount, len(a.state.RoutingRules))
	}

	// 4. Reset presets
	a.resetRoutingPresets()
	tt.Frame()
	if len(a.state.RoutingRules) != len(routing.DefaultPresets()) {
		t.Fatalf("expected default presets count %d, got %d", len(routing.DefaultPresets()), len(a.state.RoutingRules))
	}
}

// Tests that when a PROXY_TAG rule is hit and its nodes are stopped, the gateway automatically
// launches the matching service on-demand (decision 5 in ADR-0002).
func TestGateway_OnDemandTagPoolAutoStart(t *testing.T) {
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxyLn listen: %v", err)
	}
	defer proxyLn.Close()

	go func() {
		for {
			conn, err := proxyLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 256)
				if _, err := io.ReadAtLeast(c, buf, 3); err != nil {
					return
				}
				_, _ = c.Write([]byte{0x05, 0x00}) // NO_AUTH
				reqBuf := make([]byte, 256)
				if _, err := io.ReadAtLeast(c, reqBuf, 7); err != nil {
					return
				}
				_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				io.Copy(c, c)
			}(conn)
		}
	}()

	proxyHost, proxyPortStr, _ := net.SplitHostPort(proxyLn.Addr().String())
	proxyPort, _ := strconv.Atoi(proxyPortStr)

	// Node with "AI" tag, intentionally NOT started
	svcA := config.Service{
		ID:          "dormant-ai-node",
		Name:        "Dormant AI Node",
		Kind:        config.KindExternalProxy,
		ExternalURI: fmt.Sprintf("socks5://%s:%d", proxyHost, proxyPort),
		Tags:        []string{"AI"},
	}

	a, _, _ := newTestApp(t, []config.Service{svcA})
	gwPort := freeLocalPort(t)
	a.state.GatewayPort = gwPort
	a.state.GatewayEnabled = true
	// Notice: svcA is NOT started!
	if a.mgr.StatusOf("dormant-ai-node").State == runner.StateRunning {
		t.Fatalf("dormant node should not be running initially")
	}

	if err := a.startGateway(); err != nil {
		t.Fatalf("startGateway: %v", err)
	}
	defer a.stopGateway()

	// Dial "chatgpt.com:443" through gateway, which matches AI preset -> PROXY_TAG("AI")
	conn, err := net.DialTimeout("tcp", a.gateway.Addr(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer conn.Close()

	_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
	rBuf := make([]byte, 2)
	_, _ = io.ReadFull(conn, rBuf)

	targetDomain := "chatgpt.com"
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(targetDomain))}
	req = append(req, []byte(targetDomain)...)
	req = append(req, 0x01, 0xbb)
	_, _ = conn.Write(req)

	resp := make([]byte, 10)
	_, err = io.ReadFull(conn, resp)
	if err != nil || resp[1] != 0x00 {
		t.Fatalf("expected connect success through on-demand started node, got %v (err=%v)", resp, err)
	}

	// Verify that the dormant service was automatically started by the gateway!
	if a.mgr.StatusOf("dormant-ai-node").State != runner.StateRunning {
		t.Fatalf("expected dormant-ai-node to be automatically started into StateRunning, got %v", a.mgr.StatusOf("dormant-ai-node").State)
	}
}

// Tests GeoData status badge and update trigger in Settings and Routing tab.
func TestGeoData_SettingsAndRoutingWorkbench(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)

	// Check initial geodata state (missing)
	if a.hasGeoData() {
		t.Fatalf("expected geodata not present initially")
	}

	// Navigate to settings and check status badge
	if err := tt.Click(a.catalog().NavSettings()); err != nil {
		t.Fatalf("click settings: %v", err)
	}
	tt.Frame()
	if !tt.HasText(a.catalog().GeodataStatusMissing()) {
		t.Fatalf("expected missing geodata badge in settings")
	}

	// Navigate to Routing
	tt.Key(ui.Cmd, ui.Key2)
	tt.Frame()

	// Verify Update GeoData button and missing banner are rendered
	if !tt.HasText(a.catalog().UpdateGeoData()) {
		t.Fatalf("expected UpdateGeoData button in routing workbench")
	}
	if !tt.HasText(a.catalog().RoutingGeodataBanner()) {
		t.Fatalf("expected RoutingGeodataBanner when database missing")
	}
	if !tt.HasText("geosite:category-ads-all (待规则库)") {
		t.Fatalf("expected '待规则库' warning tag for presets without geodata, got texts: %v", tt.Texts())
	}

	// Create a rule with GeoSite and GeoIP using quick-pick suggestions
	a.openCreateRuleDialog()
	tt.Frame()

	// Switch to GeoData tab in rule editor
	if err := tt.Click(a.catalog().RuleTabGeoData()); err != nil {
		t.Fatalf("click RuleTabGeoData: %v", err)
	}
	tt.Frame()

	// Since geodata is missing initially, verify download guidance banner is shown
	if !tt.HasText(a.catalog().GeodataDownloadGuide()) {
		t.Fatalf("expected GeodataDownloadGuide when database missing, got texts: %v", tt.Texts())
	}

	// Verify tag input cannot be modified when geodata is missing
	a.ruleEditor.geosites = []string{"cn"}
	a.ruleEditor.geositeQuery = "apple,"
	tt.Frame()
	// Should not have parsed "apple," into tags because input is disabled
	if len(a.ruleEditor.geosites) != 1 || a.ruleEditor.geosites[0] != "cn" {
		t.Fatalf("expected tags unmodified while disabled, got %v", a.ruleEditor.geosites)
	}
	// Delete button must NOT be present when disabled
	if _, ok := tt.Find("del-tag-cn"); ok {
		t.Fatalf("expected delete button not to exist when tag input is disabled")
	}
	// Reset ruleEditor state before proceeding
	a.ruleEditor.geosites = nil
	a.ruleEditor.geositeQuery = ""
	tt.Frame()

	// Now simulate ruleset loaded with real parsed tags from files
	a.geoSiteTags = []string{"category-ai-!cn", "cn", "apple", "openai"}
	a.geoIPTags = []string{"cn", "private"}
	tt.Frame()

	// Verify suggestion chips are displayed
	if !tt.HasText("+ category-ai-!cn") || !tt.HasText("+ cn") {
		t.Fatalf("expected '+ category-ai-!cn' and '+ cn' suggestion chips, got texts: %v", tt.Texts())
	}
	if err := tt.Click("+ cn"); err != nil {
		t.Fatalf("click '+ cn': %v", err)
	}
	tt.Frame()
	if len(a.ruleEditor.geosites) != 1 || a.ruleEditor.geosites[0] != "cn" {
		t.Fatalf("expected geosites ['cn'], got %v", a.ruleEditor.geosites)
	}

	// Click '×' button on 'cn' pill to verify tag removal
	if err := tt.Click("del-tag-cn"); err != nil {
		t.Fatalf("click 'del-tag-cn': %v", err)
	}
	tt.Frame()
	if len(a.ruleEditor.geosites) != 0 {
		t.Fatalf("expected geosites to be empty after clicking '×', got %v", a.ruleEditor.geosites)
	}

	// Re-add 'cn' via quick-pick chip
	if err := tt.Click("+ cn"); err != nil {
		t.Fatalf("re-click '+ cn': %v", err)
	}
	tt.Frame()

	a.ruleEditor.name = "China Traffic"
	addTag(&a.ruleEditor.geoips, "cn")
	a.ruleEditor.actionIndex = 2 // DIRECT
	a.saveRuleEditor()
	tt.Frame()

	// Verify rule was added with geosite/geoip
	createdRule := a.state.RoutingRules[len(a.state.RoutingRules)-1]
	if len(createdRule.GeoSite) != 1 || createdRule.GeoSite[0] != "cn" {
		t.Fatalf("expected geosite:cn in created rule, got %v", createdRule.GeoSite)
	}
	if len(createdRule.GeoIP) != 1 || createdRule.GeoIP[0] != "cn" {
		t.Fatalf("expected geoip:cn in created rule, got %v", createdRule.GeoIP)
	}
	if !tt.HasText("geosite:cn") || !tt.HasText("geoip:cn") {
		t.Fatalf("expected geosite:cn and geoip:cn pills on the workbench")
	}
}
