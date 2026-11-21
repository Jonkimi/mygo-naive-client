package app

import (
	"os"
	"path/filepath"
	"slices"
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

	// Navigate to Settings -> Core Engines tab
	a.activeTab = TabSettings
	a.settingsSubTab = 2
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

	// Check clean metadata line without noisy pill soup or redundant loopback/in-process text
	if _, ok := tt.Find("VLESS · Sing-Box"); !ok {
		t.Fatalf("expected service card to show compact meta %q, got texts: %v", "VLESS · Sing-Box", tt.Texts())
	}
	if _, ok := tt.Find("Naive · Sidecar"); !ok {
		t.Fatalf("expected service card to show compact meta %q, got texts: %v", "Naive · Sidecar", tt.Texts())
	}
	if _, ok := tt.Find("sing-box (in-process)"); ok {
		t.Fatalf("did not expect redundant 'sing-box (in-process)' on redesigned list card")
	}
	if _, ok := tt.Find("Auto Loopback (:0)"); ok {
		t.Fatalf("did not expect stopped 'Auto Loopback (:0)' on redesigned list card")
	}

	// Clicking the card opens the Node Details Drawer where full engine badge & local listen details live
	if err := tt.Click("US-Vision"); err != nil {
		t.Fatalf("click US-Vision card: %v", err)
	}
	tt.Frame()
	if !tt.HasText("VLESS · SING-BOX") || !tt.HasText(a.catalog().NodeDrawerLocalListenInProcess()) {
		t.Fatalf("expected node drawer to show VLESS · SING-BOX and in-process listen detail")
	}
	tt.Key(0, ui.KeyEscape)
	tt.Frame()
	if err := tt.Click("SG-Naive"); err != nil {
		t.Fatalf("click SG-Naive card: %v", err)
	}
	tt.Frame()
	if !tt.HasText("NAIVE · SIDECAR") || !tt.HasText("Auto Loopback (:0)") {
		t.Fatalf("expected node drawer to show NAIVE · SIDECAR and Auto Loopback (:0)")
	}
}

// Tests seamless language hot switching without app restart.
func TestSettings_LanguageHotSwitch(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)

	// Switch to English on Core Engines tab
	a.state.Language = "en"
	a.saveState()
	a.applyLanguagePolicy()
	a.activeTab = TabSettings
	a.settingsSubTab = 2
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

// Tests that built-in and in-process sing-box nodes retain "sing-box (in-process)" across app restart,
// and are never overwritten with "socks://127.0.0.1:1080".
func TestInProcessNodes_PersistListenSummaryAcrossRestart(t *testing.T) {
	inprocessNode := config.Service{
		ID:         "vless-inprocess-test",
		Name:       "Test VLESS Node",
		Protocol:   config.ProtoVLESS,
		Engine:     config.EngineSingBox,
		Server:     "vless.example.com",
		ServerPort: 443,
		UUID:       "11111111-2222-3333-4444-555555555555",
	}

	a, tt, _ := newTestApp(t, []config.Service{inprocessNode})
	a.setCnDirectWarpEnabled(true)
	tt.Frame()

	// 1. Initially, should show compact "VLESS · Sing-Box" and NOT "socks://127.0.0.1:1080"
	if _, ok := tt.Find("VLESS · Sing-Box"); !ok {
		t.Fatalf("expected 'VLESS · Sing-Box' on initial render, got texts: %v", tt.Texts())
	}
	if _, ok := tt.Find("socks://127.0.0.1:1080"); ok {
		t.Fatalf("did not expect 'socks://127.0.0.1:1080' on initial render")
	}

	// 2. Simulate app restart by saving and reloading state
	a.saveState()
	a.loadState()
	tt.Frame()

	// 3. Verify that after loadState, in-process node retains empty listens and shows in-process summary in drawer
	if _, ok := tt.Find("VLESS · Sing-Box"); !ok {
		t.Fatalf("expected 'VLESS · Sing-Box' after restart/loadState")
	}
	if _, ok := tt.Find("socks://127.0.0.1:1080"); ok {
		t.Fatalf("expected no 'socks://127.0.0.1:1080' for in-process node after restart/loadState")
	}
	a.activeNodeDrawerID = inprocessNode.ID
	tt.Frame()
	if !tt.HasText(a.catalog().NodeDrawerLocalListenInProcess()) {
		t.Fatalf("expected %q in drawer after restart/loadState", a.catalog().NodeDrawerLocalListenInProcess())
	}
}

func TestEditor_VMessSecurityNetworkAndProtocolSwitch(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)

	// 1. Create dialog -> select VMess via UI dropdown (verifies Select binds persistent protoName)
	a.openCreateServiceDialog()
	tt.Frame()

	if err := tt.Click("NaiveProxy"); err != nil {
		t.Fatalf("click protocol dropdown: %v", err)
	}
	tt.Frame()
	if err := tt.Click("VMess"); err != nil {
		t.Fatalf("select VMess in dropdown: %v", err)
	}
	tt.Frame()

	if editorProtocols[a.editor.protoIndex] != config.ProtoVMess {
		t.Fatalf("expected protoIndex to switch to VMess via UI click, got %v", editorProtocols[a.editor.protoIndex])
	}
	if a.editor.vmessSecIndex != 0 || a.editor.fingerprint != "chrome" {
		t.Fatalf("expected VMess default TLS with chrome fingerprint, got sec=%d fp=%q", a.editor.vmessSecIndex, a.editor.fingerprint)
	}

	// Verify toggling engine segmented control works directly on persistent state
	if err := tt.Click(a.catalog().EngineSidecarXray()); err != nil {
		t.Fatalf("click Xray engine segment: %v", err)
	}
	tt.Frame()
	if a.editor.engineIndex != 1 {
		t.Fatalf("expected engineIndex=1 after clicking Xray sidecar, got %d", a.editor.engineIndex)
	}
	if err := tt.Click(a.catalog().EngineSingBox()); err != nil {
		t.Fatalf("click SingBox engine segment: %v", err)
	}
	tt.Frame()
	if a.editor.engineIndex != 0 {
		t.Fatalf("expected engineIndex=0 after clicking Sing-Box, got %d", a.editor.engineIndex)
	}

	// Scroll down inside the editor form so transport controls are visible in the viewport
	a.editor.scroll.Y = 180
	tt.Frame()

	// Switch transport to ws, fill fields, and save via UI button
	if err := tt.Click("ws"); err != nil {
		t.Fatalf("click ws segment: %v", err)
	}
	tt.Frame()
	a.editor.name = "VMess-WSS"
	a.editor.server = "104.16.1.1"
	a.editor.uuid = "23ad6b10-8d1a-40f7-8ad0-e3e35ff382a3"
	a.editor.path = "/vmess"
	a.editor.host = "cdn.example.com"
	tt.Frame()

	if err := tt.Click(a.catalog().EditorSaveCreate()); err != nil {
		t.Fatalf("click save button: %v", err)
	}
	tt.Frame()

	if len(a.state.Services) != 1 {
		t.Fatalf("expected 1 saved service, got %d (err=%q)", len(a.state.Services), a.editor.errText)
	}
	saved := a.state.Services[0]
	if saved.EffectiveProtocol() != config.ProtoVMess || saved.Security != "tls" || saved.Network != "ws" || saved.Host != "cdn.example.com" {
		t.Fatalf("unexpected saved VMess service: %+v", saved)
	}

	// 2. Editing an existing Security="none" VMess node must not populate fingerprint="chrome"
	plainVMess := config.Service{
		ID:         "vmess-plain",
		Name:       "VMess-Plain",
		Protocol:   config.ProtoVMess,
		Server:     "plain.example.com",
		ServerPort: 80,
		UUID:       "23ad6b10-8d1a-40f7-8ad0-e3e35ff382a3",
		Security:   "none",
		Network:    "grpc",
		Path:       "LegacySvc",
	}
	a.openEditServiceDialog(plainVMess)
	tt.Frame()

	if a.editor.vmessSecIndex != 1 {
		t.Fatalf("expected vmessSecIndex=1 for Security=none, got %d", a.editor.vmessSecIndex)
	}
	if a.editor.fingerprint != "" {
		t.Fatalf("expected empty fingerprint for plain VMess, got %q", a.editor.fingerprint)
	}
	if a.editor.serviceName != "LegacySvc" {
		t.Fatalf("expected legacy grpc Path to populate serviceName, got %q", a.editor.serviceName)
	}
	// Toggling security from None -> TLS via UI must restore default chrome fingerprint
	if err := tt.Click("TLS"); err != nil {
		t.Fatalf("click TLS segment on plain VMess: %v", err)
	}
	tt.Frame()
	if a.editor.vmessSecIndex != 0 || a.editor.fingerprint != "chrome" {
		t.Fatalf("expected TLS switch to populate chrome fingerprint, got sec=%d fp=%q", a.editor.vmessSecIndex, a.editor.fingerprint)
	}
	if err := tt.Click("None"); err != nil {
		t.Fatalf("click None segment on VMess: %v", err)
	}
	tt.Frame()
	a.editor.serviceName = "UpdatedSvc"
	builtLegacy, err := a.buildServiceFromEditor()
	if err != nil {
		t.Fatalf("buildServiceFromEditor failed: %v", err)
	}
	if builtLegacy.Path != "" || builtLegacy.ServiceName != "UpdatedSvc" || builtLegacy.Fingerprint != "" {
		t.Fatalf("expected gRPC save to clear stale Path/Fingerprint and keep ServiceName, got Path=%q ServiceName=%q Fingerprint=%q", builtLegacy.Path, builtLegacy.ServiceName, builtLegacy.Fingerprint)
	}

	// 3. Regression: switching from VLESS (xhttp, networkIndex=3) to VMess must reset networkIndex to tcp (0),
	// not let UI Segmented clamp it to grpc (2).
	vlessXHTTP := config.Service{
		ID:       "vless-xhttp",
		Name:     "VLESS-XHTTP",
		Protocol: config.ProtoVLESS,
		Server:   "xhttp.example.com",
		UUID:     "23ad6b10-8d1a-40f7-8ad0-e3e35ff382a3",
		Network:  "xhttp",
	}
	a.openEditServiceDialog(vlessXHTTP)
	tt.Frame()
	if err := tt.Click("VLESS"); err != nil {
		t.Fatalf("open protocol dropdown: %v", err)
	}
	tt.Frame()
	if err := tt.Click("VMess"); err != nil {
		t.Fatalf("select VMess from VLESS xhttp: %v", err)
	}
	tt.Frame()
	if a.editor.networkIndex != 0 {
		t.Fatalf("expected networkIndex reset to 0 (tcp) when switching VLESS xhttp -> VMess, got %d", a.editor.networkIndex)
	}

	// 4. Regression: switching from Shadowsocks to VMess must clear SS method (even if shared cipher name)
	ssNode := config.Service{
		ID:       "ss-node",
		Name:     "SS-Node",
		Protocol: config.ProtoShadowsocks,
		Server:   "ss.example.com",
		Password: "secret",
		Method:   "aes-128-gcm",
	}
	a.openEditServiceDialog(ssNode)
	tt.Frame()
	if err := tt.Click("Shadowsocks"); err != nil {
		t.Fatalf("open protocol dropdown on SS: %v", err)
	}
	tt.Frame()
	if err := tt.Click("VMess"); err != nil {
		t.Fatalf("select VMess from SS: %v", err)
	}
	tt.Frame()
	if a.editor.method != "" {
		t.Fatalf("expected SS method to be cleared when switching to VMess, got %q", a.editor.method)
	}
}

func TestEditor_ALPNComboboxCandidates(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)
	cat := a.catalog()

	vmessSvc := config.Service{
		ID:         "vmess-alpn-ui",
		Name:       "VMess-ALPN",
		Protocol:   config.ProtoVMess,
		Server:     "ws.example.com",
		ServerPort: 443,
		UUID:       "23ad6b10-8d1a-40f7-8ad0-e3e35ff382a3",
		Security:   "tls",
		ALPN:       []string{"h2"},
		Network:    "ws",
		Path:       "/ws",
	}
	a.state.Services = []config.Service{vmessSvc}
	a.openEditServiceDialog(vmessSvc)
	tt.Frame()
	a.editor.scroll.Y = 160
	tt.Frame()

	// 1. Clicking the dropdown toggle opens preset ALPN candidates even before input focus.
	if err := tt.Click(cat.AlpnDropdownLabel()); err != nil {
		t.Fatalf("click ALPN dropdown toggle: %v", err)
	}
	tt.Frame()
	if !tt.HasText("http/1.1") || !tt.HasText("h2, http/1.1") || !tt.HasText(cat.AlpnAutoOption()) {
		t.Fatalf("expected ALPN candidates in popup, got texts: %q", tt.Texts())
	}

	// 2. Picking a candidate updates alpnInput and closes the popup.
	if err := tt.Click("http/1.1"); err != nil {
		t.Fatalf("click http/1.1 candidate: %v", err)
	}
	tt.Frame()
	if a.editor.alpnInput != "http/1.1" {
		t.Fatalf("expected alpnInput='http/1.1', got %q", a.editor.alpnInput)
	}
	if tt.HasText("h2, http/1.1") {
		t.Fatalf("expected ALPN popup to close after selection, still visible: %q", tt.Texts())
	}

	// 3. Reopening via toggle button and choosing Default (Auto) clears ALPN.
	if err := tt.Click(cat.AlpnDropdownLabel()); err != nil {
		t.Fatalf("reopen ALPN dropdown: %v", err)
	}
	tt.Frame()
	if err := tt.Click(cat.AlpnAutoOption()); err != nil {
		t.Fatalf("click auto option: %v", err)
	}
	tt.Frame()
	if a.editor.alpnInput != "" {
		t.Fatalf("expected alpnInput cleared by auto option, got %q", a.editor.alpnInput)
	}

	// 4. Blur, then click the input field itself -> opens candidates; typing filters them and preserves custom text on blur.
	tt.Key(0, ui.KeyTab)
	tt.Frame()
	toggleRect, ok := tt.Find(cat.AlpnDropdownLabel())
	if !ok {
		t.Fatalf("could not find ALPN dropdown toggle")
	}
	tt.ClickAt(toggleRect.X-40, toggleRect.Y+toggleRect.H/2)
	tt.Frame()
	if !tt.HasText("h3") {
		t.Fatalf("expected clicking input to show all ALPN candidates, got: %q", tt.Texts())
	}
	tt.Type("h2")
	tt.Frame()
	texts := tt.Texts()
	if !slices.Contains(texts, "h2") || !slices.Contains(texts, "h2, http/1.1") || !slices.Contains(texts, "h3, h2, http/1.1") {
		t.Fatalf("expected filtered h2 candidates while typing 'h2', got: %q", texts)
	}
	if slices.Contains(texts, "h3") || slices.Contains(texts, "http/1.1") {
		t.Fatalf("expected non-matching 'h3'/'http/1.1' candidates filtered out, got: %q", texts)
	}
	tt.Type(", custom/1")
	tt.Key(0, ui.KeyEscape)
	tt.Key(0, ui.KeyTab)
	tt.Frame()
	if a.editor.alpnInput != "h2, custom/1" {
		t.Fatalf("expected custom ALPN input preserved on blur, got %q", a.editor.alpnInput)
	}

	built, err := a.buildServiceFromEditor()
	if err != nil {
		t.Fatalf("buildServiceFromEditor failed: %v", err)
	}
	if len(built.ALPN) != 2 || built.ALPN[0] != "h2" || built.ALPN[1] != "custom/1" {
		t.Fatalf("expected saved ALPN [h2 custom/1], got %#v", built.ALPN)
	}
}
