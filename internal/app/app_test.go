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
	"naive-client/internal/tunhelper"
	"naive-client/internal/updater"
	"naive-client/locales"

	"github.com/sagernet/sing-tun"
)

type mockTunDev struct {
	name string
	done chan struct{}
}

func (m *mockTunDev) Read(p []byte) (int, error) {
	<-m.done
	return 0, io.EOF
}

func (m *mockTunDev) Write(p []byte) (int, error) {
	return len(p), nil
}

func (m *mockTunDev) Name() (string, error) {
	return m.name, nil
}

func (m *mockTunDev) Start() error {
	return nil
}

func (m *mockTunDev) Close() error {
	select {
	case <-m.done:
	default:
		close(m.done)
	}
	return nil
}

func (m *mockTunDev) UpdateRouteOptions(options tun.Options) error {
	return nil
}

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

	rPipe, wPipe, pipeErr := os.Pipe()
	if pipeErr == nil {
		t.Cleanup(func() {
			_ = rPipe.Close()
			_ = wPipe.Close()
		})
		a.mockTunDevice = func() (*tunhelper.ReceivedDevice, error) {
			return &tunhelper.ReceivedDevice{
				FD:   int(wPipe.Fd()),
				Name: "utunTest",
			}, nil
		}
		a.mockTunCreator = func(options tun.Options) (tun.Tun, error) {
			name := options.Name
			if name == "" {
				name = "utunTest"
			}
			return &mockTunDev{name: name, done: make(chan struct{})}, nil
		}
	}

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

	// Click "复制配置链接" on the first card and verify clipboard format and toast
	if err := tt.Click("复制配置链接"); err != nil {
		t.Fatalf("click 复制配置链接: %v", err)
	}
	tt.Frame()

	wantNaiveURI := "naive+https://alice:secret@hk.example.com:443#HK-Primary"
	if a.clipboardMem != wantNaiveURI {
		t.Fatalf("clipboard Naive URI = %q, want %q", a.clipboardMem, wantNaiveURI)
	}
	if !tt.HasText("已复制配置链接") {
		t.Fatalf("expected toast '已复制配置链接' after copy, got texts: %q", tt.Texts())
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

	// Move away and hover over "复制配置链接"
	tt.Move(0, 0)
	tt.Advance(time.Second)

	r, ok = tt.Find("复制配置链接")
	if !ok {
		t.Fatalf("could not find '复制配置链接' button")
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
	r2, ok := tt2.Find("复制配置链接")
	if !ok {
		t.Fatalf("could not find '复制配置链接' button on unconfigured service")
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
	if _, ok := tt.Find(a.catalog().TriCoreSectionTitle()); !ok {
		t.Fatalf("expected section %q", a.catalog().TriCoreSectionTitle())
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

// Toggling auto start in settings updates application memory state without slow IPC on every frame.
func TestSettingsPage_AutoStartToggle(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)

	tt.Key(ui.Cmd, ui.KeyComma)
	tt.Frame()

	if a.openAtLogin {
		t.Fatalf("expected initial openAtLogin = false")
	}

	label, ok := tt.Find(a.catalog().AutoStartLabel())
	if !ok {
		t.Fatalf("no row %s", a.catalog().AutoStartLabel())
	}
	tt.ClickAt(850, label.Y+label.H/2)
	tt.Frame()

	if !a.openAtLogin {
		t.Fatalf("expected openAtLogin = true after click")
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

// Tests that naive and xray auto update switches are grouped with their sidecars (Law of Proximity),
// that geodata database is displayed inside the core manager section with recorded version, and toggles persist.
func TestSettings_CoreEnginesAndGeodataProximity(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)
	_ = os.MkdirAll(a.geodataDir(), 0o755)
	_ = os.WriteFile(filepath.Join(a.geodataDir(), "geoip.dat"), []byte("mock-geoip"), 0o644)
	_ = os.WriteFile(filepath.Join(a.geodataDir(), "geosite.dat"), []byte("mock-geosite"), 0o644)
	a.state.InstalledGeodataTag = "202611062204"
	a.state.AutoCheckUpdate = true
	a.state.AutoCheckXray = true
	a.state.AutoUpdateCore = true
	a.state.AutoUpdateXray = true
	a.refreshGeoDataStatus()

	// Navigate to settings workbench
	if err := tt.Click(a.catalog().NavSettings()); err != nil {
		t.Fatalf("click settings: %v", err)
	}
	tt.SetSize(900, 1400)
	tt.Frame()

	// Verify section title is present
	if !tt.HasText(a.catalog().TriCoreSectionTitle()) {
		t.Fatalf("expected %q section in settings", a.catalog().TriCoreSectionTitle())
	}

	// Verify geodata version badge is rendered
	expectedGeodataBadge := a.catalog().GeodataLocal() + "202611062204"
	if !tt.HasText(expectedGeodataBadge) {
		t.Fatalf("expected geodata version badge %q, got texts: %v", expectedGeodataBadge, tt.Texts())
	}

	// Toggle Naive auto check switch
	if err := tt.Click(a.catalog().CoreAutoCheckLabel()); err != nil {
		t.Fatalf("click CoreAutoCheckLabel: %v", err)
	}
	tt.Frame()
	if a.state.AutoCheckUpdate != false {
		t.Fatalf("expected AutoCheckUpdate to be false after toggle, got %v", a.state.AutoCheckUpdate)
	}

	// Toggle Naive auto update switch
	if err := tt.Click(a.catalog().CoreAutoUpdateLabel()); err != nil {
		t.Fatalf("click CoreAutoUpdateLabel: %v", err)
	}
	tt.Frame()
	if a.state.AutoUpdateCore != false {
		t.Fatalf("expected AutoUpdateCore to be false after toggle, got %v", a.state.AutoUpdateCore)
	}

	// Toggle Xray auto check switch
	if err := tt.Click(a.catalog().XrayAutoCheckLabel()); err != nil {
		t.Fatalf("click XrayAutoCheckLabel: %v", err)
	}
	tt.Frame()
	if a.state.AutoCheckXray != false {
		t.Fatalf("expected AutoCheckXray to be false after toggle, got %v", a.state.AutoCheckXray)
	}

	// Toggle Xray auto update switch
	if err := tt.Click(a.catalog().XrayAutoUpdateLabel()); err != nil {
		t.Fatalf("click XrayAutoUpdateLabel: %v", err)
	}
	tt.Frame()
	if a.state.AutoUpdateXray != false {
		t.Fatalf("expected AutoUpdateXray to be false after toggle, got %v", a.state.AutoUpdateXray)
	}
}

// Tests that update downloads and ruleset downloads route through the unified gateway when running.
func TestUpdater_DownloadThroughGateway(t *testing.T) {
	a, _, _ := newTestApp(t, nil)
	a.state.UseRunningServiceForUpd = true
	a.state.GatewayEnabled = true
	a.state.GatewayPort = freeLocalPort(t)
	if err := a.startGateway(); err != nil {
		t.Fatalf("startGateway failed: %v", err)
	}

	opts := a.buildUpdaterHTTPOptions(10 * time.Second)
	if opts.LocalEndpoint == nil {
		t.Fatalf("expected LocalEndpoint to be populated from running gateway")
	}
	if opts.LocalEndpoint.Port != a.gateway.Port() {
		t.Fatalf("expected LocalEndpoint.Port == %d, got %d", a.gateway.Port(), opts.LocalEndpoint.Port)
	}
	if opts.LocalEndpoint.Proto != "http" {
		t.Fatalf("expected LocalEndpoint.Proto == 'http', got %s", opts.LocalEndpoint.Proto)
	}
}

// Tests that Xray-core is seamlessly updated in the background when AutoUpdateXray is enabled.
func TestAutoXrayUpdateSilentHotSwap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skip on windows due to mock shell script")
	}

	a, tt, _ := newTestApp(t, nil)
	a.state.InstalledXrayTag = "v24.11.30"
	a.state.AutoUpdateXray = true
	a.syncXrayBinaryPathAndVersion()

	if a.localXrayVersion != "v24.11.30" {
		t.Fatalf("expected initial localXrayVersion = %q, got %q", "v24.11.30", a.localXrayVersion)
	}

	// Prepare mock zip archive for Xray v25.1.30
	newScript := "#!/bin/sh\nif [ \"$1\" = \"version\" ]; then echo \"Xray 25.1.30 (Custom)\"; exit 0; fi\ntrap 'exit 0' INT TERM\nwhile true; do sleep 0.1; done\n"
	assetSuffix, err := updater.ExpectedXrayAssetSuffix(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatalf("xray asset suffix: %v", err)
	}
	assetName := "Xray-" + assetSuffix

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(updater.XrayBinaryFilename(runtime.GOOS))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(newScript)); err != nil {
		t.Fatal(err)
	}
	_ = zw.Close()
	archiveBytes := buf.Bytes()
	sum := sha256.Sum256(archiveBytes)
	digest := hex.EncodeToString(sum[:])
	dgstContent := fmt.Sprintf("SHA256= %s\n", digest)

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest":
			rel := updater.Release{
				TagName: "v25.1.30",
				Name:    "v25.1.30",
				Assets: []updater.Asset{
					{
						Name:               assetName,
						Size:               int64(len(archiveBytes)),
						BrowserDownloadURL: srv.URL + "/download/" + assetName,
					},
					{
						Name:               assetName + ".dgst",
						BrowserDownloadURL: srv.URL + "/download/" + assetName + ".dgst",
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(rel)
		case "/download/" + assetName:
			_, _ = w.Write(archiveBytes)
		case "/download/" + assetName + ".dgst":
			_, _ = w.Write([]byte(dgstContent))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	oldAPI := updater.LatestXrayReleaseAPI
	updater.LatestXrayReleaseAPI = srv.URL + "/latest"
	t.Cleanup(func() {
		updater.LatestXrayReleaseAPI = oldAPI
	})

	// Trigger automatic background update check for Xray
	a.triggerCheckXrayUpdate(false)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !a.updatingXrayCore && a.localXrayVersion == "v25.1.30" {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	tt.Frame()

	if a.localXrayVersion != "v25.1.30" {
		t.Fatalf("localXrayVersion after auto update = %q, want v25.1.30 (err=%s)", a.localXrayVersion, a.updateXrayError)
	}
	if a.state.InstalledXrayTag != "v25.1.30" {
		t.Fatalf("expected state.InstalledXrayTag = %q, got %q", "v25.1.30", a.state.InstalledXrayTag)
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

	// Click Routing sidebar item to verify it is enabled and navigable
	if err := tt.Click(a.catalog().NavRouting()); err != nil {
		t.Fatalf("click %s failed: %v", a.catalog().NavRouting(), err)
	}
	tt.Frame()
	if a.activeTab != TabRouting {
		t.Fatalf("expected activeTab TabRouting, got %v", a.activeTab)
	}

	// Verify shortcut '⌘2' is rendered for Routing in the enabled sidebar
	if !tt.HasText("⌘2") {
		t.Fatalf("expected shortcut '⌘2' for enabled routing nav item")
	}

	// Switch back to Nodes
	if err := tt.Click(a.catalog().NavNodes()); err != nil {
		t.Fatalf("click %s failed: %v", a.catalog().NavNodes(), err)
	}
	tt.Frame()

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

// TestSidebarGatewayCardAndCompactCardUX verifies dynamic port reflection in the sidebar, traffic mode switching, and compact route rendering.
func TestSidebarGatewayCardAndCompactCardUX(t *testing.T) {
	svcs := []config.Service{
		{
			ID:      "svc-single",
			Name:    "naive-bwg",
			Listens: []string{"socks://127.0.0.1:1080"},
			Proxies: []string{"https://d_user:secret@proxy.example.com:443"},
		},
	}
	a, tt, _ := newTestApp(t, svcs)

	// 1. Sidebar reflects gateway label and traffic mode
	if !tt.HasText(a.catalog().MasterGateway()) {
		t.Fatalf("expected sidebar to reflect '%s', got texts: %v", a.catalog().MasterGateway(), tt.Texts())
	}
	if !tt.HasText(a.catalog().ModePortOnly()) {
		t.Fatalf("expected sidebar to reflect mode '%s', got texts: %v", a.catalog().ModePortOnly(), tt.Texts())
	}

	// 2. Single-service toolbar omits redundant '全部启动'/'全部停止' buttons
	if _, ok := tt.Find(a.catalog().ActionStartAll()); ok {
		t.Fatalf("expected '全部启动' to be hidden when only 1 service exists")
	}

	// 3. Card displays compact remote host without inline credentials
	if !tt.HasText("https://proxy.example.com:443") {
		t.Fatalf("expected compact remote endpoint 'https://proxy.example.com:443' on card, got: %v", tt.Texts())
	}

	a.state.GatewayPort = freeLocalPort(t)

	// 4. Clicking ModeTun switches to TUN
	if err := tt.Click(a.catalog().ModeTun()); err != nil {
		t.Fatalf("click ModeTun: %v", err)
	}
	tt.Frame()
	if a.state.TrafficMode != "tun" {
		t.Fatalf("expected traffic mode 'tun', got %q", a.state.TrafficMode)
	}

	// Switch back to PortOnly for remaining test steps
	if err := tt.Click(a.catalog().ModePortOnly()); err != nil {
		t.Fatalf("click ModePortOnly: %v", err)
	}
	tt.Frame()

	// 5. Clicking the sidebar gateway status row navigates directly to Settings
	if err := tt.Click(a.catalog().MasterGateway()); err != nil {
		t.Fatalf("click sidebar gateway row: %v", err)
	}
	tt.Frame()
	if a.activeTab != TabSettings {
		t.Fatalf("expected clicking gateway row to switch to TabSettings, got %v", a.activeTab)
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

	// Open mode dropdown and choose "系统代理"
	if err := tt.Click(a.catalog().ModePortOnly()); err != nil {
		t.Fatalf("open mode dropdown: %v", err)
	}
	tt.Frame()
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

	// Switch from sysproxy to TUN mode
	if err := tt.Click(a.catalog().ModeSysProxy()); err != nil {
		t.Fatalf("open mode dropdown: %v", err)
	}
	tt.Frame()
	if err := tt.Click(a.catalog().ModeTun()); err != nil {
		t.Fatalf("click ModeTun: %v", err)
	}
	tt.Frame()

	if a.state.TrafficMode != "tun" {
		t.Fatalf("expected trafficMode 'tun' after click, got %q", a.state.TrafficMode)
	}
	if a.tunDevice == nil {
		t.Fatalf("expected tunDevice to be active in TUN mode")
	}

	// Open dropdown to switch from TUN back to "仅端口"
	if err := tt.Click(a.catalog().ModeTun()); err != nil {
		t.Fatalf("open mode dropdown: %v", err)
	}
	tt.Frame()
	if err := tt.Click(a.catalog().ModePortOnly()); err != nil {
		t.Fatalf("click ModePortOnly: %v", err)
	}
	tt.Frame()

	if a.state.TrafficMode != "port" {
		t.Fatalf("expected trafficMode 'port' after click, got %q", a.state.TrafficMode)
	}
	if a.tunDevice != nil {
		t.Fatalf("expected tunDevice to be cleaned up after switching to port mode")
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
	connResp := make([]byte, 4)
	if _, err := io.ReadFull(clientConn, connResp); err != nil || connResp[0] != 0x05 || connResp[1] != 0x00 {
		t.Fatalf("client connect resp failed: %v, err: %v", connResp, err)
	}
	var remLen int
	switch connResp[3] {
	case 1: // IPv4
		remLen = 4 + 2
	case 3: // Domain
		var l [1]byte
		_, _ = io.ReadFull(clientConn, l[:])
		remLen = int(l[0]) + 2
	case 4: // IPv6
		remLen = 16 + 2
	}
	remBuf := make([]byte, remLen)
	_, _ = io.ReadFull(clientConn, remBuf)

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
	// Give rules test domain suffixes since preset rules no longer include hardcoded domains
	for i := range a.state.RoutingRules {
		switch a.state.RoutingRules[i].ID {
		case "preset-ai-services":
			a.state.RoutingRules[i].DomainSuffix = []string{"chatgpt.com"}
		case "preset-block-ads":
			a.state.RoutingRules[i].DomainSuffix = []string{"doubleclick.net"}
		}
	}
	a.syncRouter()
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
	if !tt.HasText("广告拦截") {
		t.Fatalf("expected preset rule '广告拦截' on page, got: %v", tt.Texts())
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

	// Verify BlockerBlockAds is automatically synchronized
	if a.state.BlockerBlockAds {
		t.Fatalf("expected BlockerBlockAds synchronized to false after toggle click")
	}

	// Toggle back via toggleBlockerBlockAds to test bidirectional synchronization
	a.toggleBlockerBlockAds()
	if !a.state.BlockerBlockAds {
		t.Fatalf("expected BlockerBlockAds to be true")
	}
	if !a.state.RoutingRules[0].Enabled {
		t.Fatalf("expected RoutingRules[0] preset-block-ads synchronized to true")
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
	// Give AI preset rule a test domain suffix since presets no longer include hardcoded domains
	for i := range a.state.RoutingRules {
		if a.state.RoutingRules[i].ID == "preset-ai-services" {
			a.state.RoutingRules[i].DomainSuffix = []string{"chatgpt.com"}
		}
	}
	a.syncRouter()
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

// Tests that when PROXY_POOL has 0 active nodes online, traffic does not silently fallback to direct (preventing IP leaks).
func TestGateway_ProxyPoolEmptyRejectsWithoutSilentDirect(t *testing.T) {
	a, _, _ := newTestApp(t, nil)
	gwPort := freeLocalPort(t)
	a.state.GatewayPort = gwPort
	a.state.GatewayEnabled = true
	a.syncRouter()

	if err := a.startGateway(); err != nil {
		t.Fatalf("startGateway: %v", err)
	}
	defer a.stopGateway()

	c, err := net.DialTimeout("tcp", a.gateway.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer c.Close()

	// SOCKS5 greeting
	_, _ = c.Write([]byte{0x05, 0x01, 0x00})
	rBuf := make([]byte, 2)
	if _, err := io.ReadFull(c, rBuf); err != nil {
		t.Fatalf("read greeting response: %v", err)
	}

	// SOCKS5 CONNECT request to a domain requiring proxy (hits finalAction PROXY_POOL)
	targetDomain := "blocked-external-site.com"
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(targetDomain))}
	req = append(req, []byte(targetDomain)...)
	req = append(req, 0x01, 0xbb)
	_, _ = c.Write(req)

	resp := make([]byte, 10)
	_, err = io.ReadFull(c, resp)
	// Must not succeed (0x00) with silent direct dial; must return error or SOCKS5 failure status
	if err == nil && resp[1] == 0x00 {
		t.Fatalf("expected failure when proxy pool is empty, but got SOCKS5 success (silent direct fallback leak)")
	}
}

// Tests that when a PROXY_TAG rule is hit but has 0 active nodes, traffic does not fall back to other proxies or direct.
func TestGateway_ProxyTagEmptyRejectsWithoutFallback(t *testing.T) {
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxyLn listen: %v", err)
	}
	defer proxyLn.Close()

	proxyHost, proxyPortStr, _ := net.SplitHostPort(proxyLn.Addr().String())
	proxyPort, _ := strconv.Atoi(proxyPortStr)

	svcHK := config.Service{
		ID:          "node-hk",
		Name:        "HK Node",
		Kind:        config.KindExternalProxy,
		ExternalURI: fmt.Sprintf("socks5://%s:%d", proxyHost, proxyPort),
		Tags:        []string{"HK"},
	}

	a, _, _ := newTestApp(t, []config.Service{svcHK})
	gwPort := freeLocalPort(t)
	a.state.GatewayPort = gwPort
	a.state.GatewayEnabled = true
	for i := range a.state.RoutingRules {
		if a.state.RoutingRules[i].ID == "preset-ai-services" {
			a.state.RoutingRules[i].DomainSuffix = []string{"chatgpt.com"}
		}
	}
	a.syncRouter()
	_ = a.mgr.Start(svcHK)

	if err := a.startGateway(); err != nil {
		t.Fatalf("startGateway: %v", err)
	}
	defer a.stopGateway()

	c, err := net.DialTimeout("tcp", a.gateway.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer c.Close()

	_, _ = c.Write([]byte{0x05, 0x01, 0x00})
	rBuf := make([]byte, 2)
	if _, err := io.ReadFull(c, rBuf); err != nil {
		t.Fatalf("read greeting response: %v", err)
	}

	// Request chatgpt.com which matches PROXY_TAG "AI", where 0 AI nodes exist
	targetDomain := "chatgpt.com"
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(targetDomain))}
	req = append(req, []byte(targetDomain)...)
	req = append(req, 0x01, 0xbb)
	_, _ = c.Write(req)

	resp := make([]byte, 10)
	_, err = io.ReadFull(c, resp)
	if err == nil && resp[1] == 0x00 {
		t.Fatalf("expected failure when tag has 0 online nodes, but got success (unexpected fallback)")
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
	if !tt.HasText(a.catalog().RulePendingGeoData()) {
		t.Fatalf("expected RulePendingGeoData warning status badge on card when geodata missing")
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
	// Verify in drawer that geosite:cn and geoip:cn are displayed
	a.activeRuleDrawerID = createdRule.ID
	tt.Frame()
	if !tt.HasText("geosite:cn") || !tt.HasText("geoip:cn") {
		t.Fatalf("expected geosite:cn and geoip:cn pills in the detail drawer")
	}
}

// Tests that filterSuggestedTags performs two-sided fuzzy matching (substring/contains)
// and prefix matching priority, without returning unrelated tags when query is non-empty.
func TestRouting_FilterSuggestedTags(t *testing.T) {
	allTags := []string{"category-ai-!cn", "openai", "apple", "google", "cn", "ai-chat"}
	current := []string{"openai"}

	// When query is "ai", should return "ai-chat" (prefix), "category-ai-!cn" (contains).
	// "openai" is already in current, so it must be excluded.
	// "apple", "google", "cn" do not contain "ai", so they must NOT be returned.
	matches := filterSuggestedTags(allTags, current, "ai", 10)
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches for 'ai', got %v", matches)
	}
	if matches[0] != "ai-chat" || matches[1] != "category-ai-!cn" {
		t.Fatalf("expected ['ai-chat', 'category-ai-!cn'], got %v", matches)
	}

	// Two-sided fuzzy: substring in the middle
	matchesLe := filterSuggestedTags(allTags, nil, "ppl", 10)
	if len(matchesLe) != 1 || matchesLe[0] != "apple" {
		t.Fatalf("expected ['apple'] for query 'ppl', got %v", matchesLe)
	}

	// Empty query returns top suggestions excluding current
	emptyMatches := filterSuggestedTags(allTags, current, "", 3)
	if len(emptyMatches) != 3 {
		t.Fatalf("expected 3 suggestions for empty query, got %v", emptyMatches)
	}
	for _, m := range emptyMatches {
		if m == "openai" {
			t.Fatalf("expected 'openai' to be excluded from empty query suggestions")
		}
	}
}

// Tests that Outbound Action Target Tags supports multi-chips and matches nodes with any of the tags.
func TestRouting_TargetTagsMultiChips(t *testing.T) {
	svcA := config.Service{
		ID:   "node-us",
		Name: "US Node",
		Tags: []string{"US", "Fast"},
	}
	svcB := config.Service{
		ID:   "node-ai",
		Name: "AI Node",
		Tags: []string{"AI"},
	}
	a, tt, _ := newTestApp(t, []config.Service{svcA, svcB})

	// Open create rule dialog
	a.openCreateRuleDialog()
	tt.Frame()

	// Target tag should default to blank
	if len(a.ruleEditor.tags) != 0 {
		t.Fatalf("expected tags to default to blank, got %v", a.ruleEditor.tags)
	}

	addTag(&a.ruleEditor.tags, "AI")
	addTag(&a.ruleEditor.tags, "US")
	if len(a.ruleEditor.tags) != 2 {
		t.Fatalf("expected 2 tags in editor, got %v", a.ruleEditor.tags)
	}

	a.ruleEditor.name = "Multi-tag rule"
	a.ruleEditor.domainsInput = "test.internal"
	a.saveRuleEditor()
	tt.Frame()

	createdRule := a.state.RoutingRules[len(a.state.RoutingRules)-1]
	tags := createdRule.Action.GetTags()
	if len(tags) != 2 || tags[0] != "AI" || tags[1] != "US" {
		t.Fatalf("expected tags ['AI', 'US'], got %v", tags)
	}

	// Verify allKnownServiceTags extracts distinct tags
	known := a.allKnownServiceTags()
	if len(known) != 3 {
		t.Fatalf("expected 3 distinct service tags, got %v", known)
	}

	// Verify saving with blank tags preserves empty tags without injecting "AI"
	a.openCreateRuleDialog()
	tt.Frame()
	a.ruleEditor.name = "Blank tag rule"
	a.ruleEditor.domainsInput = "blank-tag.internal"
	a.saveRuleEditor()
	tt.Frame()

	blankRule := a.state.RoutingRules[len(a.state.RoutingRules)-1]
	if len(blankRule.Action.GetTags()) != 0 {
		t.Fatalf("expected 0 tags on blank tag rule, got %v", blankRule.Action.GetTags())
	}
}

// Tests that the undeletable Final Fallback card renders at the end of the routing page,
// can be opened for editing, and updating its outbound action saves to state.RoutingFinal.
func TestRouting_FinalFallbackCardAndDialog(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)
	a.activeTab = TabRouting // Routing page
	tt.Frame()

	// 1. Verify card and match-all criteria exist
	if !tt.HasText(a.catalog().RoutingFinalFallback()) {
		t.Fatalf("expected final fallback card title %q", a.catalog().RoutingFinalFallback())
	}
	if !tt.HasText("FINAL") || !tt.HasText(a.catalog().RoutingFinalAlwaysActive()) {
		t.Fatalf("expected 'FINAL' badge and always-active pill")
	}

	// 2. Open edit dialog on final fallback rule
	a.openEditFinalRuleDialog()
	tt.Frame()

	if !a.ruleEditor.open || !a.ruleEditor.isFinal {
		t.Fatalf("expected rule editor to be open in isFinal mode")
	}
	if !tt.HasText(a.catalog().EditFinalRule()) {
		t.Fatalf("expected edit dialog title %q", a.catalog().EditFinalRule())
	}

	// 3. Change outbound action to DIRECT (index 2)
	a.ruleEditor.actionIndex = 2 // DIRECT
	a.saveRuleEditor()
	tt.Frame()

	if a.ruleEditor.open {
		t.Fatalf("expected rule editor to close after save")
	}
	if a.state.RoutingFinal.Type != routing.ActionDirect {
		t.Fatalf("expected RoutingFinal.Type to be DIRECT, got %v", a.state.RoutingFinal.Type)
	}

	// 4. Re-open and set to Tag Pool with custom tags
	a.openEditFinalRuleDialog()
	tt.Frame()

	a.ruleEditor.actionIndex = 0 // Tag Pool
	a.ruleEditor.tags = nil
	addTag(&a.ruleEditor.tags, "HK")
	addTag(&a.ruleEditor.tags, "US")
	a.saveRuleEditor()
	tt.Frame()

	if a.state.RoutingFinal.Type != routing.ActionProxyTag {
		t.Fatalf("expected RoutingFinal.Type to be PROXY_TAG, got %v", a.state.RoutingFinal.Type)
	}
	tags := a.state.RoutingFinal.GetTags()
	if len(tags) != 2 || tags[0] != "HK" || tags[1] != "US" {
		t.Fatalf("expected RoutingFinal tags ['HK', 'US'], got %v", tags)
	}
}

// Tests the UX optimizations: GeoData tab as default, no hardcoded preset domains,
// no concrete domain names rendered on cards, and 2-cards-per-row layout.
func TestRouting_PresetUXOptimizations(t *testing.T) {
	// 1. Verify default presets have no hardcoded domain suffixes (except preset-lan-direct for local/lan domains)
	lanPresetFound := false
	for _, r := range routing.DefaultPresets() {
		if r.ID == "preset-lan-direct" {
			lanPresetFound = true
			if len(r.IPCidr) != 8 {
				t.Fatalf("expected preset-lan-direct to have 8 default LAN IP CIDRs, got %v", r.IPCidr)
			}
		} else if len(r.DomainSuffix) > 0 {
			t.Fatalf("expected preset rule %s to have no DomainSuffix, got %v", r.Name, r.DomainSuffix)
		}
	}
	if !lanPresetFound {
		t.Fatalf("expected preset-lan-direct in DefaultPresets")
	}

	a, tt, _ := newTestApp(t, nil)
	a.activeTab = TabRouting
	tt.Frame()

	// 2. Verify editor defaults to tab 0 (GeoData)
	a.openCreateRuleDialog()
	tt.Frame()
	if a.ruleEditor.tab != 0 {
		t.Fatalf("expected create dialog tab to be 0 (GeoData), got %d", a.ruleEditor.tab)
	}
	a.ruleEditor.open = false

	// 3. Verify editing a preset defaults to tab 0 (GeoData)
	a.openEditRuleDialog(a.state.RoutingRules[0])
	tt.Frame()
	if a.ruleEditor.tab != 0 {
		t.Fatalf("expected edit preset dialog tab to be 0 (GeoData), got %d", a.ruleEditor.tab)
	}
	a.ruleEditor.open = false

	// 4. Verify custom domains and IP CIDRs do NOT render on rule cards (delegated to detail drawer)
	a.state.RoutingRules[0].DomainSuffix = []string{"super-secret-domain-1.xyz", "super-secret-domain-2.xyz"}
	a.state.RoutingRules[0].IPCidr = []string{"192.168.0.0/16", "10.0.0.0/8"}
	tt.Frame()
	if tt.HasText("super-secret-domain-1.xyz") || tt.HasText("super-secret-domain-2.xyz") {
		t.Fatalf("concrete domain names should not be displayed on rule cards")
	}
	if tt.HasText("192.168.0.0/16") || tt.HasText("10.0.0.0/8") {
		t.Fatalf("concrete IP CIDRs should not be displayed on rule cards")
	}
	if tt.HasText("+1") {
		t.Fatalf("overflow pill '+N' should no longer be displayed on rule cards")
	}

	// 5. Verify GFW 专线 preset exists with geosite:gfw
	foundGFW := false
	for _, r := range a.state.RoutingRules {
		if r.ID == "preset-gfw" && r.Name == "GFW 专线" {
			if len(r.GeoSite) == 1 && r.GeoSite[0] == "gfw" {
				foundGFW = true
			}
		}
	}
	if !foundGFW {
		t.Fatalf("expected preset-gfw with geosite:gfw")
	}
	if !tt.HasText("GFW 专线") {
		t.Fatalf("expected 'GFW 专线' on routing workbench")
	}
}

func TestRouting_RuleDrawerDetails(t *testing.T) {
	// Rule detail drawer shows full criteria details and 0 在线 warning badge, while cards stay clean without criteria tags
	a, tt, _ := newTestApp(t, nil)
	a.activeTab = TabRouting
	tt.Frame()

	// 1. Verify Outbound Action badge says '#AI (0 在线)' when no nodes online
	if !tt.HasText("#AI (0 在线)") {
		t.Fatalf("expected outbound tag badge '#AI (0 在线)' when 0 nodes online")
	}

	// 2. Setup preset-ai-services with criteria
	aiRuleIdx := -1
	for i, r := range a.state.RoutingRules {
		if r.ID == "preset-ai-services" {
			aiRuleIdx = i
			break
		}
	}
	if aiRuleIdx == -1 {
		t.Fatalf("preset-ai-services not found")
	}
	a.state.RoutingRules[aiRuleIdx].GeoSite = []string{"category-ai-!cn", "openai", "claude"}
	tt.Frame()

	// Criteria tags and +N are not shown on card
	if tt.HasText("+1") || tt.HasText("geosite:category-ai-!cn") {
		t.Fatalf("criteria tags and +N should not appear on card")
	}

	// 3. Open Rule Detail Drawer
	if a.activeRuleDrawerID != "" {
		t.Fatalf("drawer should initially be closed")
	}
	a.activeRuleDrawerID = "preset-ai-services"
	tt.Frame()

	if !tt.HasText(a.catalog().RuleDrawerTitle()) {
		t.Fatalf("expected rule drawer title %q", a.catalog().RuleDrawerTitle())
	}
	if !tt.HasText("0 个匹配节点在线 (无可用专线节点)") {
		t.Fatalf("expected zero nodes online warning text in drawer")
	}
	// Full criteria are shown in drawer
	if !tt.HasText("geosite:category-ai-!cn") || !tt.HasText("geosite:openai") {
		t.Fatalf("expected detailed geosite tags in drawer")
	}

	// 4. In drawer, click edit button -> opens edit dialog and closes drawer
	a.openEditRuleDialog(a.state.RoutingRules[aiRuleIdx])
	a.activeRuleDrawerID = ""
	tt.Frame()

	if a.activeRuleDrawerID != "" {
		t.Fatalf("expected drawer to close when editing")
	}
	if !a.ruleEditor.open {
		t.Fatalf("expected rule editor dialog to open")
	}
	a.ruleEditor.open = false

	// 5. Test Fallback detail drawer
	a.activeRuleDrawerID = "final"
	tt.Frame()
	if !tt.HasText("FINAL") {
		t.Fatalf("expected 'FINAL' badge in final rule drawer")
	}

	// 6. Test Esc closes rule drawer
	tt.Key(0, ui.KeyEscape)
	tt.Frame()
	if a.activeRuleDrawerID != "" {
		t.Fatalf("expected activeRuleDrawerID to be empty after Esc, got %q", a.activeRuleDrawerID)
	}
}

func TestRouting_PresetProtectionAndFallbackInPresetGroup(t *testing.T) {
	// Preset rules cannot be deleted but can be disabled; fallback card renders as the 6th card in preset group
	a, tt, _ := newTestApp(t, nil)
	a.activeTab = TabRouting
	tt.Frame()

	// 1. Preset rules should NOT have delete button (accessibility label ActionDelete)
	if _, found := tt.Find(a.catalog().ActionDelete()); found {
		t.Fatalf("preset rules should not have a delete button")
	}

	// 2. Calling deleteRule on a preset rule should do nothing
	presetID := "preset-block-ads"
	prevRuleCount := len(a.state.RoutingRules)
	a.deleteRule(presetID)
	if len(a.state.RoutingRules) != prevRuleCount {
		t.Fatalf("preset rule %q was deleted, but preset rules must be protected from deletion", presetID)
	}

	// 3. Preset rules can be disabled/enabled via switch
	toggleKey := "toggle-rule-" + presetID
	if _, found := tt.Find(toggleKey); !found {
		t.Fatalf("expected switch toggle for preset rule %q", presetID)
	}
	// Toggle preset rule to false
	a.state.RoutingRules[0].Enabled = false
	a.saveState()
	tt.Frame()
	if a.state.RoutingRules[0].Enabled {
		t.Fatalf("expected preset rule %q to be disabled", presetID)
	}

	// 4. Custom rule should have delete button and can be deleted
	a.state.RoutingRules = append(a.state.RoutingRules, routing.Rule{
		ID:      "custom-rule-1",
		Name:    "自定义规则 1",
		Enabled: true,
		Action:  routing.RouteAction{Type: routing.ActionDirect},
	})
	tt.Frame()

	if _, found := tt.Find(a.catalog().ActionDelete()); !found {
		t.Fatalf("custom rule should have a delete button")
	}
	a.deleteRule("custom-rule-1")
	foundCustom := false
	for _, r := range a.state.RoutingRules {
		if r.ID == "custom-rule-1" {
			foundCustom = true
		}
	}
	if foundCustom {
		t.Fatalf("custom rule was not deleted")
	}

	// 5. Preset Rule Group should have 6 items (5 presets + 1 fallback)
	if !tt.HasText(a.catalog().RoutingCustomSection()) {
		t.Fatalf("expected custom rules section title %q", a.catalog().RoutingCustomSection())
	}
	if !tt.HasText(a.catalog().RoutingPresetsSection()) {
		t.Fatalf("expected preset rules section title %q", a.catalog().RoutingPresetsSection())
	}
	// Preset count badge should be "6"
	if !tt.HasText("6") {
		t.Fatalf("expected preset count badge '6' in preset section header")
	}
	if !tt.HasText(a.catalog().RoutingFinalFallback()) {
		t.Fatalf("expected fallback card title %q", a.catalog().RoutingFinalFallback())
	}
	if !tt.HasText("FINAL") {
		t.Fatalf("expected 'FINAL' badge on fallback card")
	}
	if !tt.HasText("直连") {
		t.Fatalf("expected '直连' preset rule in preset group")
	}
}

func TestRouting_ProxyPoolActiveCountBadge(t *testing.T) {
	// ActionProxyPool shows 0 在线 when no services running, and updates when running
	p := freeLocalPort(t)
	a, tt, _ := newTestApp(t, []config.Service{
		{
			ID:      "svc-1",
			Name:    "Service 1",
			Tags:    []string{"hk"},
			Listens: []string{fmt.Sprintf("socks://127.0.0.1:%d", p)},
			Proxies: []string{"https://user:pass@example.com:443"},
		},
	})
	a.activeTab = TabRouting
	tt.Frame()

	// Initially 0 running -> "全局活跃代理池 (0 在线)"
	if !tt.HasText(a.catalog().RoutingProxyPool() + " (0 在线)") {
		t.Fatalf("expected proxy pool badge '%s (0 在线)', got texts: %v", a.catalog().RoutingProxyPool(), tt.Texts())
	}

	// Start svc-1 -> 1 running -> "全局活跃代理池 (1 在线)"
	if err := a.mgr.Start(a.state.Services[0]); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	tt.Frame()

	if !tt.HasText(a.catalog().RoutingProxyPool() + " (1 在线)") {
		t.Fatalf("expected proxy pool badge '%s (1 在线)', got texts: %v", a.catalog().RoutingProxyPool(), tt.Texts())
	}
}

func TestNodes_TagFilterBar(t *testing.T) {
	// Nodes page shows tag filter bar, filters services on click, and clears filter on 全部
	svcs := []config.Service{
		{ID: "svc-hk", Name: "Node HK", Tags: []string{"hk"}},
		{ID: "svc-us", Name: "Node US", Tags: []string{"us"}},
		{ID: "svc-all", Name: "Node Multi", Tags: []string{"hk", "us"}},
	}
	a, tt, _ := newTestApp(t, svcs)
	a.activeTab = TabNodes
	tt.Frame()

	// 1. Tag filter bar is rendered with '全部', '#hk', '#us'
	if !tt.HasText("全部") || !tt.HasText("#hk") || !tt.HasText("#us") {
		t.Fatalf("expected tag filter bar chips, got texts: %v", tt.Texts())
	}

	// All 3 nodes are initially displayed
	if !tt.HasText("Node HK") || !tt.HasText("Node US") || !tt.HasText("Node Multi") {
		t.Fatalf("all nodes should initially be displayed")
	}

	// 2. Click #hk filter -> should display Node HK and Node Multi, but NOT Node US
	a.activeTagFilter = "hk"
	tt.Frame()

	if !tt.HasText("Node HK") || !tt.HasText("Node Multi") {
		t.Fatalf("Node HK and Node Multi should be displayed for hk tag filter")
	}
	if tt.HasText("Node US") {
		t.Fatalf("Node US should be filtered out when hk tag is active")
	}

	// 3. Click #us filter -> should display Node US and Node Multi, but NOT Node HK
	a.activeTagFilter = "us"
	tt.Frame()

	if !tt.HasText("Node US") || !tt.HasText("Node Multi") {
		t.Fatalf("Node US and Node Multi should be displayed for us tag filter")
	}
	if tt.HasText("Node HK") {
		t.Fatalf("Node HK should be filtered out when us tag is active")
	}

	// 4. Click '全部' -> resets filter, all 3 nodes displayed
	a.activeTagFilter = ""
	tt.Frame()

	if !tt.HasText("Node HK") || !tt.HasText("Node US") || !tt.HasText("Node Multi") {
		t.Fatalf("all 3 nodes should be displayed when filter is cleared")
	}
}

func TestRouting_PresetI18nLanguageSwitching(t *testing.T) {
	// Preset rule names and descriptions dynamically follow the active language setting
	a, tt, _ := newTestApp(t, nil)
	a.state.Language = locales.LangZhHans
	a.activeTab = TabRouting
	tt.Frame()

	// 1. In Simplified Chinese, preset rules show Chinese names
	if !tt.HasText("广告拦截") || !tt.HasText("AI 服务") || !tt.HasText("流媒体服务") || !tt.HasText("GFW 专线") || !tt.HasText("直连") {
		t.Fatalf("expected Chinese preset rule names in zh-Hans mode, got texts: %v", tt.Texts())
	}

	// 2. Switch language to English
	a.state.Language = locales.LangEn
	tt.Frame()

	if !tt.HasText("Block Ads") || !tt.HasText("AI Services") || !tt.HasText("Streaming Services") || !tt.HasText("GFW Proxy") || !tt.HasText("Direct") {
		t.Fatalf("expected English preset rule names in en mode, got texts: %v", tt.Texts())
	}

	// 3. Open rule drawer in English
	a.activeRuleDrawerID = "preset-block-ads"
	tt.Frame()

	if !tt.HasText("Block Ads") || !tt.HasText("Basic Info") {
		t.Fatalf("expected English title and basic info in drawer, got texts: %v", tt.Texts())
	}
	a.activeRuleDrawerID = ""
	tt.Frame()

	// 4. Switch back to Simplified Chinese
	a.state.Language = locales.LangZhHans
	tt.Frame()

	if !tt.HasText("广告拦截") || !tt.HasText("AI 服务") {
		t.Fatalf("expected Chinese preset rule names after switching back, got texts: %v", tt.Texts())
	}
}

// Tests that custom 3-tier DNS settings update bootstrap domains.
func TestApp_CustomDoHConfiguration(t *testing.T) {
	a, _, _ := newTestApp(t, nil)
	a.initDNS()

	a.state.BootstrapDNS = "119.29.29.29"
	a.state.DomesticDNS = "https://custom-dns.mycorp.internal/dns-query"
	a.state.RemoteDNS = "https://9.9.9.9/dns-query, https://dns.quad9.net/dns-query"
	a.initDNS()

	domains := a.collectBootstrapDomains()
	foundInternal := false
	for _, d := range domains {
		if d == "custom-dns.mycorp.internal" {
			foundInternal = true
		}
		if d == "dns.quad9.net" {
			t.Fatalf("remote DoH domain dns.quad9.net must NOT be included in bootstrap domains")
		}
	}
	if !foundInternal {
		t.Fatalf("expected custom-dns.mycorp.internal in bootstrap domains, got %v", domains)
	}
}

// Tests that selecting DNS options in the settings UI dropdowns updates state.
func TestApp_DnsSelectDropdownUI(t *testing.T) {
	a, _, _ := newTestApp(t, nil)
	a.initDNS()

	tt := ui.NewTester(func(c *ui.Context) {
		a.renderSettingsPage(c, darkPalette)
	}, 800, 2000)

	// 1. Select Domestic DNS from preset
	if err := tt.Click("https://223.5.5.5/dns-query"); err != nil {
		t.Fatalf("click domestic DNS trigger: %v", err)
	}
	tt.Frame()
	if err := tt.Click("https://dns.alidns.com/dns-query"); err != nil {
		t.Fatalf("select domestic option: %v", err)
	}
	tt.Frame()
	if a.state.DomesticDNS != "https://dns.alidns.com/dns-query" {
		t.Fatalf("expected DomesticDNS to be https://dns.alidns.com/dns-query, got %q", a.state.DomesticDNS)
	}

	// 2. Select Remote DNS from preset
	if err := tt.Click("https://1.1.1.1/dns-query"); err != nil {
		t.Fatalf("click remote DNS trigger: %v", err)
	}
	tt.Frame()
	if err := tt.Click("https://dns.google/dns-query"); err != nil {
		t.Fatalf("select remote option: %v", err)
	}
	tt.Frame()
	if a.state.RemoteDNS != "https://dns.google/dns-query" {
		t.Fatalf("expected RemoteDNS to be https://dns.google/dns-query, got %q", a.state.RemoteDNS)
	}

	// 3. Select Bootstrap DNS from preset
	if err := tt.Click("223.5.5.5"); err != nil {
		t.Fatalf("click bootstrap DNS trigger: %v", err)
	}
	tt.Frame()
	if err := tt.Click("114.114.114.114"); err != nil {
		t.Fatalf("select bootstrap option: %v", err)
	}
	tt.Frame()
	if a.state.BootstrapDNS != "114.114.114.114" {
		t.Fatalf("expected BootstrapDNS to be 114.114.114.114, got %q", a.state.BootstrapDNS)
	}
}

// Tests that toggling PreferIPv4 switch updates persisted state.
func TestApp_PreferIPv4ToggleUI(t *testing.T) {
	a, _, _ := newTestApp(t, nil)
	a.initDNS()

	if !a.state.PreferIPv4 {
		t.Fatalf("expected PreferIPv4 to default to true")
	}

	tt := ui.NewTester(func(c *ui.Context) {
		a.renderSettingsPage(c, darkPalette)
	}, 800, 2000)

	// Click Prefer IPv4 switch on the right side of the row to toggle it off
	label, ok := tt.Find(a.catalog().DnsPreferIPv4Label())
	if !ok {
		t.Fatalf("no row %s", a.catalog().DnsPreferIPv4Label())
	}
	tt.ClickAt(750, label.Y+label.H/2)
	tt.Frame()

	if a.state.PreferIPv4 {
		t.Fatalf("expected state PreferIPv4 to be toggled to false")
	}
}

// Tests that the node card opens the details drawer on "详情" click, showing PID inside the drawer rather than on the list card.
func TestNodeDetailsDrawer_OpenCloseAndPIDDisplay(t *testing.T) {
	p := freeLocalPort(t)
	svcs := []config.Service{
		{
			ID:      "svc-1",
			Name:    "HK-01",
			Listens: []string{fmt.Sprintf("socks://127.0.0.1:%d", p)},
			Proxies: []string{"https://alice:secret@hk.example.com:443"},
		},
	}
	a, tt, _ := newTestApp(t, svcs)

	// Start service so it gets a PID
	if err := a.mgr.Start(svcs[0]); err != nil {
		t.Fatalf("start svc-1: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a.mgr.StatusOf("svc-1").State == runner.StateRunning && a.mgr.StatusOf("svc-1").PID > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	tt.Frame()

	pid := a.mgr.StatusOf("svc-1").PID
	if pid <= 0 {
		t.Fatalf("expected running service to have PID > 0, got %d", pid)
	}
	pidStr := fmt.Sprintf("PID %d", pid)

	// When drawer is closed, PID should not be visible on the node list page
	if tt.HasText(pidStr) {
		t.Fatalf("PID %q should not be displayed on the node list page", pidStr)
	}

	// Click "详情" button to open the Node Details Drawer
	if err := tt.Click(a.catalog().ActionDetails()); err != nil {
		t.Fatalf("click 详情 failed: %v", err)
	}
	tt.Frame()

	if a.activeNodeDrawerID != "svc-1" {
		t.Fatalf("expected activeNodeDrawerID to be 'svc-1', got %q", a.activeNodeDrawerID)
	}

	// Inside the drawer, the title and PID should be displayed
	if !tt.HasText(a.catalog().NodeDrawerTitle()) {
		t.Fatalf("expected drawer title %q to be visible", a.catalog().NodeDrawerTitle())
	}
	if !tt.HasText(pidStr) {
		t.Fatalf("expected PID %q to be visible in the details drawer", pidStr)
	}

	// Press Esc to dismiss the drawer
	tt.Key(0, ui.KeyEscape)
	tt.Frame()
	if a.activeNodeDrawerID != "" {
		t.Fatalf("expected activeNodeDrawerID to be empty after Esc, got %q", a.activeNodeDrawerID)
	}
	if tt.HasText(pidStr) {
		t.Fatalf("PID %q should no longer be visible after closing drawer", pidStr)
	}
}

// Tests that in-process nodes do not show local link on the card or drawer, and that the drawer shows configuration preview.
func TestInProcessNode_NoLocalLinkAndConfigPreviewInDrawer(t *testing.T) {
	svcs := []config.Service{
		{
			ID:         "svc-inprocess",
			Name:       "US-VLESS-InProcess",
			Protocol:   config.ProtoVLESS,
			Engine:     config.EngineSingBox,
			Server:     "vless.example.com",
			ServerPort: 443,
			UUID:       "11111111-2222-3333-4444-555555555555",
			Security:   "tls",
		},
		{
			ID:       "svc-sidecar",
			Name:     "HK-Naive-Sidecar",
			Protocol: config.ProtoNaive,
			Engine:   config.EngineSidecar,
			Listens:  []string{"socks://127.0.0.1:1088"},
			Proxies:  []string{"https://alice:secret@hk.example.com:443"},
		},
	}
	a, tt, _ := newTestApp(t, svcs)

	// 1. On node card:
	// For in-process node, "复制本地链接" should NOT be present.
	// Only sidecar node has "复制本地链接".
	localLinkCount := 0
	for _, text := range tt.Texts() {
		if text == a.catalog().ActionCopyV2rayN() {
			localLinkCount++
		}
	}
	if localLinkCount != 1 {
		t.Fatalf("expected exactly 1 '复制本地链接' for sidecar node, got %d", localLinkCount)
	}

	// Both should have "复制配置链接"
	shareLinkCount := 0
	for _, text := range tt.Texts() {
		if text == a.catalog().ActionCopyNaive() {
			shareLinkCount++
		}
	}
	if shareLinkCount != 2 {
		t.Fatalf("expected 2 '复制配置链接', got %d", shareLinkCount)
	}

	// 2. Open details drawer for in-process node
	a.activeNodeDrawerID = "svc-inprocess"
	tt.Frame()

	// In the drawer:
	// Local listen should show in-process summary
	if !tt.HasText(a.catalog().NodeDrawerLocalListenInProcess()) {
		t.Fatalf("expected in-process local listen text %q", a.catalog().NodeDrawerLocalListenInProcess())
	}
	// "配置预览" header should be visible
	if !tt.HasText(a.catalog().NodeDrawerConfigPreview()) {
		t.Fatalf("expected config preview title %q", a.catalog().NodeDrawerConfigPreview())
	}
	// Sing-box outbound JSON title should be visible
	if !tt.HasText(a.catalog().PreviewSingBoxJSON()) {
		t.Fatalf("expected sing-box preview title %q", a.catalog().PreviewSingBoxJSON())
	}
	// In-process drawer should NOT have "复制本地链接"
	inprocessDrawerLocalCount := 0
	for _, text := range tt.Texts() {
		if text == a.catalog().ActionCopyV2rayN() {
			inprocessDrawerLocalCount++
		}
	}
	// Only the card behind for sidecar has 1, the drawer for inprocess has 0
	if inprocessDrawerLocalCount != 1 {
		t.Fatalf("expected 1 '复制本地链接' (card only, none in in-process drawer), got %d", inprocessDrawerLocalCount)
	}

	// 3. Open details drawer for sidecar node
	a.activeNodeDrawerID = "svc-sidecar"
	tt.Frame()
	// Sidecar node drawer should show local loopback link preview
	if !tt.HasText(a.catalog().PreviewLocalLink()) {
		t.Fatalf("expected sidecar node drawer to have %q", a.catalog().PreviewLocalLink())
	}
}

// Tests that periodic auto-probe settings default to enabled (5 mins) and that silent probe triggers on running services.
func TestPeriodicAutoProbeSettingsAndSilentProbe(t *testing.T) {
	svc := config.Service{
		ID:         "probe-test-svc",
		Name:       "Probe Service",
		Protocol:   config.ProtoNaive,
		Server:     "example.com",
		ServerPort: 443,
		Listens:    []string{fmt.Sprintf("socks://127.0.0.1:%d", freeLocalPort(t))},
	}
	a, tt, _ := newTestApp(t, []config.Service{svc})

	// 1. Verify default periodic probe settings
	if !a.state.AutoProbeOnStart {
		t.Errorf("expected AutoProbeOnStart default true")
	}
	if !a.state.AutoProbePeriodic {
		t.Errorf("expected AutoProbePeriodic default true")
	}
	if a.state.AutoProbeInterval != 5 {
		t.Errorf("expected AutoProbeInterval default 5, got %d", a.state.AutoProbeInterval)
	}

	// 2. Start service and test probeAllRunningServicesSilent
	_ = a.mgr.Start(svc)
	tt.Frame()

	// Calling silent probe should not panic or set error toasts
	a.probeAllRunningServicesSilent()
	if a.pendingToast != "" {
		t.Errorf("expected silent probe to produce no toast, got %q", a.pendingToast)
	}
}

// Tests that DNS strategy and Smart Proxy Pool strategy are rendered side-by-side with one-line descriptions and popover details.
func TestRouting_DnsAndSmartPoolCardsWithPopover(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)
	a.state.Language = locales.LangZhHans
	a.activeTab = TabRouting
	tt.Frame()

	// 1. Both titles and one-line summaries are rendered
	if !tt.HasText(a.catalog().RoutingDnsAlignmentTitle()) {
		t.Fatalf("expected DNS title %q", a.catalog().RoutingDnsAlignmentTitle())
	}
	if !tt.HasText(a.catalog().RoutingSmartPoolTitle()) {
		t.Fatalf("expected Smart Pool title %q", a.catalog().RoutingSmartPoolTitle())
	}
	if !tt.HasText(a.catalog().RoutingDnsAlignmentDesc()) {
		t.Fatalf("expected DNS summary %q", a.catalog().RoutingDnsAlignmentDesc())
	}
	if !tt.HasText(a.catalog().RoutingSmartPoolDesc()) {
		t.Fatalf("expected Smart Pool summary %q", a.catalog().RoutingSmartPoolDesc())
	}

	// 2. Click DNS info button -> popover shows detailed direct, proxy port, tun info
	if err := tt.Click("DNS " + a.catalog().ActionDetails()); err != nil {
		t.Fatalf("click dns info button: %v", err)
	}
	tt.Frame()
	if !a.showRoutingDnsDetail {
		t.Fatalf("expected showRoutingDnsDetail to be true after click")
	}
	if !tt.HasText(a.catalog().RoutingDnsDescDirect()) {
		t.Fatalf("expected DNS detail %q in popover", a.catalog().RoutingDnsDescDirect())
	}

	// 3. Click Smart Pool info button -> popover shows detailed EWMA, circuit, affinity info
	if err := tt.Click("Pool " + a.catalog().ActionDetails()); err != nil {
		t.Fatalf("click pool info button: %v", err)
	}
	tt.Frame()
	if !a.showRoutingPoolDetail {
		t.Fatalf("expected showRoutingPoolDetail to be true after click")
	}
	if !tt.HasText(a.catalog().RoutingSmartPoolDetailEWMA()) {
		t.Fatalf("expected Smart Pool detail %q in popover", a.catalog().RoutingSmartPoolDetailEWMA())
	}
}

// Tests that EngineSingBox Reality node starts and verifies gateway lifecycle with PreStartChecker.
func TestGateway_SingBoxRealityNodeStartupAndDialer(t *testing.T) {
	svc := config.Service{
		ID:          "svc-vless-reality-mock",
		Name:        "mock-reality-test",
		Protocol:    config.ProtoVLESS,
		Engine:      config.EngineSingBox,
		Server:      "example.org",
		ServerPort:  443,
		UUID:        "00000000-0000-0000-0000-000000000001",
		Security:    "reality",
		SNI:         "example.org",
		Fingerprint: "chrome",
		PublicKey:   "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE",
		ShortID:     "0123456789abcdef",
		Flow:        "xtls-rprx-vision",
		Network:     "tcp",
		Listens:     []string{"socks://127.0.0.1:1088"},
	}

	a, _, _ := newTestApp(t, []config.Service{svc})
	a.state.GatewayEnabled = true
	a.state.GatewayPort = freeLocalPort(t)

	// 1. Starting gateway with reality node should succeed when with_utls is enabled
	if err := a.startGateway(); err != nil {
		t.Fatalf("startGateway failed for reality node: %v", err)
	}
	if a.gateway == nil {
		t.Fatalf("expected gateway to be running")
	}

	// 2. Starting service should pass PreStartChecker when gateway is running
	if err := a.mgr.Start(svc); err != nil {
		t.Fatalf("mgr.Start failed for singbox reality service: %v", err)
	}
	if st := a.mgr.StatusOf(svc.ID); st.State != runner.StateRunning {
		t.Fatalf("expected StateRunning, got %v", st.State)
	}

	// 3. Stopping gateway and starting another service without gateway auto-recovery should fail
	a.stopGateway()
	a.state.GatewayEnabled = false
	svc2 := svc
	svc2.ID = "svc-vless-reality-2"
	if err := a.mgr.Start(svc2); err == nil {
		t.Fatalf("expected Start to fail when gateway is disabled and stopped")
	}
}




