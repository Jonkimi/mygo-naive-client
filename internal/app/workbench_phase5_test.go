package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/egoist/mygo/ui"

	"naive-client/internal/config"
)

// Tests creating and editing multi-protocol services with execution engine toggles (SingBox vs Sidecar).
func TestEditor_MultiProtocolCreationAndEngineSwitch(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)

	// 1. Open create dialog
	a.openCreateServiceDialog()
	tt.Frame()

	if !a.editor.open || !a.editor.isNew {
		t.Fatalf("expected editor dialog to be open and isNew=true")
	}

	// 2. Configure VLESS protocol with REALITY
	a.editor.name = "US-VLESS-Node"
	a.editor.tagsInput = "us, fast"
	// Set protocol to VLESS (index 1 in editorProtocols)
	a.editor.protoIndex = 1
	a.editor.server = "vless.example.com"
	a.editor.serverPort = "443"
	a.editor.uuid = "12345678-1234-1234-1234-123456789abc"
	a.editor.securityIndex = 1 // REALITY
	a.editor.publicKey = "pbk-test-key-123"
	a.editor.shortID = "sid-test"
	a.editor.flowIndex = 0 // xtls-rprx-vision
	a.editor.engineIndex = 0 // SingBox default

	// 3. Verify preview tab generates sing-box outbound
	a.editor.tab = 2
	tt.Frame()
	svcPreview, err := a.buildServiceFromEditor()
	if err != nil {
		t.Fatalf("buildServiceFromEditor failed: %v", err)
	}
	if svcPreview.EffectiveProtocol() != config.ProtoVLESS || svcPreview.EffectiveEngine() != config.EngineSingBox {
		t.Fatalf("unexpected preview service: proto=%v, engine=%v", svcPreview.EffectiveProtocol(), svcPreview.EffectiveEngine())
	}

	// 4. Switch engine to Sidecar (Xray) and verify autoLoopback
	a.editor.tab = 0
	a.editor.engineIndex = 1 // Sidecar
	a.editor.autoLoopback = true

	// Verify preview tab generates Xray config
	a.editor.tab = 2
	tt.Frame()
	svcSidecar, err := a.buildServiceFromEditor()
	if err != nil {
		t.Fatalf("buildServiceFromEditor (sidecar) failed: %v", err)
	}
	if svcSidecar.EffectiveEngine() != config.EngineSidecar {
		t.Fatalf("expected EngineSidecar, got %v", svcSidecar.EffectiveEngine())
	}
	if len(svcSidecar.Listens) == 0 || svcSidecar.Listens[0] != "socks://127.0.0.1:0" {
		t.Fatalf("expected auto loopback listen socks://127.0.0.1:0, got %v", svcSidecar.Listens)
	}

	// 5. Save service and verify it is added to state
	a.saveEditorService()
	tt.Frame()

	if a.editor.open {
		t.Fatalf("expected editor dialog to close on save, errText=%q", a.editor.errText)
	}
	if len(a.state.Services) != 1 {
		t.Fatalf("expected 1 service in state, got %d", len(a.state.Services))
	}
	saved := a.state.Services[0]
	if saved.Name != "US-VLESS-Node" || saved.EffectiveProtocol() != config.ProtoVLESS || saved.EffectiveEngine() != config.EngineSidecar {
		t.Fatalf("saved service mismatch: %+v", saved)
	}
	if saved.PublicKey != "pbk-test-key-123" || saved.ShortID != "sid-test" {
		t.Fatalf("REALITY fields not preserved: %+v", saved)
	}

	// 6. Open edit dialog and switch back to SingBox
	a.openEditServiceDialog(saved)
	tt.Frame()

	if a.editor.isNew {
		t.Fatalf("expected isNew=false when editing existing service")
	}
	if a.editor.protoIndex != 1 || a.editor.engineIndex != 1 {
		t.Fatalf("editor did not populate protoIndex or engineIndex correctly: proto=%d, engine=%d", a.editor.protoIndex, a.editor.engineIndex)
	}

	// Switch to SingBox and save
	a.editor.engineIndex = 0
	a.saveEditorService()
	tt.Frame()

	if a.state.Services[0].EffectiveEngine() != config.EngineSingBox {
		t.Fatalf("expected updated EngineSingBox, got %v", a.state.Services[0].EffectiveEngine())
	}
}

// Tests clicking the sidebar Engine Status Pill to navigate to Settings.
func TestSidebar_EngineStatusPillAndNavigation(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)

	// Ensure on Nodes tab initially
	a.activeTab = TabNodes
	tt.Frame()

	// Click sidebar gateway status row
	if err := tt.Click(a.catalog().MasterGateway()); err != nil {
		t.Fatalf("click sidebar gateway row: %v", err)
	}
	tt.Frame()

	if a.activeTab != TabSettings {
		t.Fatalf("expected clicking gateway status row to navigate to TabSettings, got %v", a.activeTab)
	}
}

// Tests Settings Tri-Core manager displaying embedded Sing-Box, NaiveProxy, and Xray sidecar options.
func TestSettings_TriCoreManagerUI(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)

	// Create mock xray binary in temp dir
	xrayBin := filepath.Join(a.userDataDir(), "bin", "mock-xray")
	_ = os.MkdirAll(filepath.Dir(xrayBin), 0o755)
	script := `#!/bin/sh
if [ "$1" = "version" ]; then
  echo "Xray 1.8.24 (Xray, Penetrates Everything.) Custom"
  exit 0
fi
exit 0
`
	if err := os.WriteFile(xrayBin, []byte(script), 0o755); err != nil {
		t.Fatalf("write mock xray: %v", err)
	}

	// Navigate to Settings
	a.activeTab = TabSettings
	tt.Frame()

	// Set custom Xray path
	a.state.CustomXrayBinaryPath = xrayBin
	a.saveState()
	a.syncXrayBinaryPathAndVersion()
	tt.Frame()

	if a.localXrayVersion != "v1.8.24" {
		t.Fatalf("expected localXrayVersion = v1.8.24, got %q", a.localXrayVersion)
	}

	// Verify sing-box, naive, and xray labels exist in settings
	cat := a.catalog()
	if _, ok := tt.Find(cat.CoreSingBoxStatus()); !ok {
		t.Fatalf("expected to find sing-box in-memory ready badge %q", cat.CoreSingBoxStatus())
	}
	if _, ok := tt.Find(cat.CoreNaiveTitle()); !ok {
		t.Fatalf("expected to find naive card title %q", cat.CoreNaiveTitle())
	}
	if _, ok := tt.Find(cat.CoreXrayTitle()); !ok {
		t.Fatalf("expected to find xray card title %q", cat.CoreXrayTitle())
	}
}

// Tests service card renders protocol and execution engine capsule tag.
func TestServiceCard_ProtocolAndEngineCapsule(t *testing.T) {
	vlessSvc := config.Service{
		ID:         "vless-01",
		Name:       "US-Vision",
		Protocol:   config.ProtoVLESS,
		Engine:     config.EngineSingBox,
		Server:     "us.node.com",
		ServerPort: 443,
		UUID:       "uuid-123",
	}
	naiveSvc := config.Service{
		ID:        "naive-01",
		Name:      "SG-Naive",
		Protocol:  config.ProtoNaive,
		Engine:    config.EngineSidecar,
		Listens:   []string{"socks://127.0.0.1:0"},
		Proxies:   []string{"https://user:pass@sg.node.com"},
	}

	a, tt, _ := newTestApp(t, []config.Service{vlessSvc, naiveSvc})
	a.activeTab = TabNodes
	tt.Frame()

	// Check protocol and engine capsule pills
	vlessPill := "VLESS · SING-BOX"
	if _, ok := tt.Find(vlessPill); !ok {
		t.Fatalf("expected service card to show capsule %q", vlessPill)
	}

	naivePill := "NAIVE · SIDECAR"
	if _, ok := tt.Find(naivePill); !ok {
		t.Fatalf("expected service card to show capsule %q", naivePill)
	}

	// Check listen summaries
	if _, ok := tt.Find("sing-box (in-process)"); !ok {
		t.Fatalf("expected service card to show 'sing-box (in-process)' for singbox engine")
	}
	if _, ok := tt.Find("Auto Loopback (:0)"); !ok {
		t.Fatalf("expected service card to show 'Auto Loopback (:0)' for unstarted auto loopback sidecar")
	}
}

// Tests seamless language hot switching without app restart.
func TestSettings_LanguageHotSwitch(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)

	// Switch to English
	a.state.Language = "en"
	a.saveState()
	a.applyLanguagePolicy()
	a.activeTab = TabSettings
	tt.Frame()

	if _, ok := tt.Find("Core Engines & Geodata Manager"); !ok {
		t.Fatalf("expected English title 'Core Engines & Geodata Manager' after switching to en")
	}

	// Switch to Simplified Chinese
	a.state.Language = "zh-Hans"
	a.saveState()
	a.applyLanguagePolicy()
	tt.Frame()

	if _, ok := tt.Find("核心引擎与规则库管理"); !ok {
		t.Fatalf("expected Chinese title '核心引擎与规则库管理' after switching to zh-Hans")
	}
}

// Tests opening and closing the slide-out log drawer.
func TestLogDrawer_OpenClose(t *testing.T) {
	svc := config.Service{
		ID:       "log-svc-01",
		Name:     "HK-Node",
		Protocol: config.ProtoNaive,
		Engine:   config.EngineSidecar,
	}
	a, tt, _ := newTestApp(t, []config.Service{svc})
	a.activeTab = TabNodes
	tt.Frame()

	// Open log drawer for HK-Node
	a.activeLogDrawerID = "log-svc-01"
	tt.Frame()

	if a.activeLogDrawerID != "log-svc-01" {
		t.Fatalf("expected activeLogDrawerID to be log-svc-01")
	}

	// Verify log drawer title is present
	cat := a.catalog()
	if !tt.HasText(cat.LogDrawerTitle()) {
		t.Fatalf("expected log drawer title %q to be visible", cat.LogDrawerTitle())
	}

	// Press Esc to close log drawer
	tt.Key(0, ui.KeyEscape)
	tt.Frame()

	if a.activeLogDrawerID != "" {
		t.Fatalf("expected log drawer to close after Esc, got activeLogDrawerID=%q", a.activeLogDrawerID)
	}
}
