package app

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"

	"naive-client/internal/config"
	"naive-client/internal/runner"
)

func TestNodesRedesign_SearchRunningOnlyAndResetFilters(t *testing.T) {
	svcs := []config.Service{
		{
			ID:       "svc-hk",
			Name:     "HK-Edge-01",
			Protocol: config.ProtoVLESS,
			Engine:   config.EngineSingBox,
			Server:   "hk01.edge.net",
			Tags:     []string{"HK", "Streaming"},
		},
		{
			ID:       "svc-jp",
			Name:     "JP-Tokyo-Naive",
			Protocol: config.ProtoNaive,
			Engine:   config.EngineSidecar,
			Proxies:  []string{"https://user:pass@jp.example.com:443"},
			Tags:     []string{"AI"},
		},
		{
			ID:       "svc-us",
			Name:     "US-LosAngeles",
			Protocol: config.ProtoTrojan,
			Engine:   config.EngineSingBox,
			Server:   "la.example.net",
			Tags:     []string{"US"},
		},
	}

	a, tt, _ := newTestApp(t, svcs)
	a.mgr.SetStatusForTest("svc-hk", runner.Status{State: runner.StateRunning, Latency: 42 * time.Millisecond})
	a.mgr.SetStatusForTest("svc-jp", runner.Status{State: runner.StateRunning, Latency: 88 * time.Millisecond})
	tt.Frame()

	cat := a.catalog()

	// 1. Header shows running / total summary
	if !tt.HasText(cat.NodesRunningSummary(2, 3)) {
		t.Fatalf("expected running summary %q, got texts: %v", cat.NodesRunningSummary(2, 3), tt.Texts())
	}

	// 2. Typing into SearchField filters by remote host
	if err := tt.Click(cat.SearchPlaceholder()); err != nil {
		t.Fatalf("click search field: %v", err)
	}
	tt.Type("jp.example")
	tt.Frame()
	if !tt.HasText("JP-Tokyo-Naive") || tt.HasText("HK-Edge-01") || tt.HasText("US-LosAngeles") {
		t.Fatalf("expected only JP-Tokyo-Naive after host search, got texts: %v", tt.Texts())
	}

	// 3. Clearing search with Escape restores all nodes, then toggling '仅运行中' filters stopped node out
	tt.Key(0, ui.KeyEscape)
	tt.Frame()
	if !tt.HasText("HK-Edge-01") || !tt.HasText("US-LosAngeles") {
		t.Fatalf("expected all nodes restored after clearing search, got texts: %v", tt.Texts())
	}

	if err := tt.Click(cat.FilterOnlyRunning()); err != nil {
		t.Fatalf("click FilterOnlyRunning: %v", err)
	}
	tt.Frame()
	if !tt.HasText("HK-Edge-01") || !tt.HasText("JP-Tokyo-Naive") || tt.HasText("US-LosAngeles") {
		t.Fatalf("expected only running nodes when FilterOnlyRunning is checked, got texts: %v", tt.Texts())
	}

	// 4. Combining filters to yield 0 matches shows empty state and ResetFilters restores all nodes
	if err := tt.Click(cat.SearchPlaceholder()); err != nil {
		t.Fatalf("click search field: %v", err)
	}
	tt.Type("nonexistent-node")
	tt.Frame()
	if !tt.HasText(cat.EmptyFilteredNodes()) {
		t.Fatalf("expected empty filtered state %q, got texts: %v", cat.EmptyFilteredNodes(), tt.Texts())
	}
	if err := tt.Click(cat.ResetFilters()); err != nil {
		t.Fatalf("click ResetFilters: %v", err)
	}
	tt.Frame()
	if !tt.HasText("HK-Edge-01") || !tt.HasText("JP-Tokyo-Naive") || !tt.HasText("US-LosAngeles") {
		t.Fatalf("expected all nodes restored after ResetFilters, got texts: %v", tt.Texts())
	}
}

func TestNodesRedesign_SwitchToggleAndOverflowMenuActions(t *testing.T) {
	p1 := freeLocalPort(t)
	svcs := []config.Service{
		{
			ID:        "svc-1",
			Name:      "HK-Primary",
			Protocol:  config.ProtoNaive,
			Engine:    config.EngineSidecar,
			AutoStart: true,
			Listens:   []string{fmt.Sprintf("socks://127.0.0.1:%d", p1)},
			Proxies:   []string{"https://alice:secret@hk.example.com:443"},
			Tags:      []string{"HK", "AI", "Backup"},
		},
	}

	a, tt, _ := newTestApp(t, svcs)
	a.setCnDirectWarpEnabled(true)
	tt.Frame()

	// 1. Healthy card suppresses pill soup (AutoStart / +N overflow OK, no Running/Stopped pills)
	if tt.HasText(a.catalog().TagAutoStart()) {
		t.Fatalf("did not expect AutoStart pill on redesigned card")
	}
	if !tt.HasText("+1") {
		t.Fatalf("expected '+1' overflow tag pill when node has 3 tags, got texts: %v", tt.Texts())
	}

	// 2. Clicking row Switch starts service without opening the details drawer
	if err := tt.Click("toggle-node-svc-1"); err != nil {
		t.Fatalf("click row switch: %v", err)
	}
	if !waitForUI(t, a, tt, 2*time.Second, func() bool {
		return a.mgr.StatusOf("svc-1").State == runner.StateRunning
	}) {
		t.Fatalf("expected svc-1 to start via Switch toggle")
	}
	if a.activeNodeDrawerID != "" {
		t.Fatalf("clicking row Switch must not open details drawer, got %q", a.activeNodeDrawerID)
	}

	// 3. Overflow menu: Clone creates a new node with non-colliding static port
	cat := a.catalog()
	if err := tt.Click(cat.MoreActionsForNode("HK-Primary")); err != nil {
		t.Fatalf("open overflow menu: %v", err)
	}
	tt.Frame()
	if err := tt.Click(cat.ActionClone()); err != nil {
		t.Fatalf("click Clone: %v", err)
	}
	tt.Frame()
	if len(a.state.Services) != 3 {
		t.Fatalf("expected 3 services after clone, got %d", len(a.state.Services))
	}
	cloned := a.state.Services[2]
	if cloned.Name != cat.ClonedNodeName("HK-Primary") {
		t.Fatalf("expected cloned name %q, got %q", cat.ClonedNodeName("HK-Primary"), cloned.Name)
	}
	if cloned.PrimaryListen() == svcs[0].PrimaryListen() {
		t.Fatalf("expected cloned static sidecar port to differ from original %q", svcs[0].PrimaryListen())
	}

	// 4. Overflow menu: Details & Telemetry opens Node Details Drawer
	if err := tt.Click(cat.MoreActionsForNode("HK-Primary")); err != nil {
		t.Fatalf("open overflow menu: %v", err)
	}
	tt.Frame()
	if err := tt.Click(cat.ActionDetailsTelemetry()); err != nil {
		t.Fatalf("click Details & Telemetry: %v", err)
	}
	tt.Frame()
	if a.activeNodeDrawerID != "svc-1" {
		t.Fatalf("expected activeNodeDrawerID 'svc-1', got %q", a.activeNodeDrawerID)
	}
	tt.Key(0, ui.KeyEscape)
	tt.Frame()

	// 5. Builtin WARP delete action is disabled; user node delete opens confirmation dialog
	if err := tt.Click(cat.MoreActionsForNode("Cloudflare WARP")); err != nil {
		t.Fatalf("open builtin warp overflow menu: %v", err)
	}
	tt.Frame()
	_ = tt.Click(cat.ActionDeleteNode())
	tt.Frame()
	if a.deleteDlg.open {
		t.Fatalf("expected Delete Node to remain disabled for builtin WARP node")
	}
	tt.Key(0, ui.KeyEscape)
	tt.Frame()

	if err := tt.Click(cat.MoreActionsForNode("HK-Primary")); err != nil {
		t.Fatalf("open HK-Primary overflow menu: %v", err)
	}
	tt.Frame()
	if err := tt.Click(cat.ActionDeleteNode()); err != nil {
		t.Fatalf("click Delete Node on HK-Primary: %v", err)
	}
	tt.Frame()
	if !a.deleteDlg.open || a.deleteDlg.svcID != "svc-1" {
		t.Fatalf("expected delete dialog open for svc-1, got open=%v id=%q", a.deleteDlg.open, a.deleteDlg.svcID)
	}
}

func TestNodesRedesign_ContextualLogsOnErrorAndUnhealthyStrips(t *testing.T) {
	svcs := []config.Service{
		{
			ID:       "svc-healthy",
			Name:     "Healthy-Node",
			Protocol: config.ProtoVLESS,
			Engine:   config.EngineSingBox,
			Server:   "ok.example.com",
		},
		{
			ID:       "svc-err",
			Name:     "Err-Node",
			Protocol: config.ProtoVLESS,
			Engine:   config.EngineSingBox,
			Server:   "err.example.com",
		},
		{
			ID:       "svc-unhealthy",
			Name:     "Warn-Node",
			Protocol: config.ProtoVLESS,
			Engine:   config.EngineSingBox,
			Server:   "warn.example.com",
		},
	}

	a, tt, _ := newTestApp(t, svcs)
	cat := a.catalog()

	// 1. When all nodes are healthy/stopped, no inline "日志" button appears on list rows
	if _, ok := tt.Find(cat.ActionLogs()); ok {
		t.Fatalf("did not expect inline Logs button on healthy rows")
	}

	// 2. Inject LastError on svc-err -> inline error strip exposes Logs button
	a.mgr.SetError("svc-err", "dial tcp: connection refused")
	tt.Frame()
	if err := tt.Click(cat.ActionLogs()); err != nil {
		t.Fatalf("click contextual Logs button on error strip: %v", err)
	}
	tt.Frame()
	if a.activeLogDrawerID != "svc-err" {
		t.Fatalf("expected log drawer to open for 'svc-err', got %q", a.activeLogDrawerID)
	}
	a.activeLogDrawerID = ""
	a.mgr.SetStatusForTest("svc-err", runner.Status{State: runner.StateStopped})

	// 3. Inject unhealthy probe failure on svc-unhealthy -> inline unhealthy strip exposes Logs button
	a.mgr.SetStatusForTest("svc-unhealthy", runner.Status{
		State:      runner.StateRunning,
		ProbeError: "timeout reaching probe target",
	})
	tt.Frame()
	if err := tt.Click(cat.ActionLogs()); err != nil {
		t.Fatalf("click contextual Logs button on unhealthy strip: %v", err)
	}
	tt.Frame()
	if a.activeLogDrawerID != "svc-unhealthy" {
		t.Fatalf("expected log drawer to open for 'svc-unhealthy', got %q", a.activeLogDrawerID)
	}
}

func TestNodesRedesign_EffectiveLatencyPriorityAndTooltip(t *testing.T) {
	svc := config.Service{
		ID:                  "svc-lat",
		Name:                "Latency-Node",
		Protocol:            config.ProtoVLESS,
		Engine:              config.EngineSingBox,
		Server:              "lat.example.com",
		AutoStart:           true,
		InsecureConcurrency: 4,
		NoPostQuantum:       true,
	}

	a, tt, _ := newTestApp(t, []config.Service{svc})
	a.mgr.SetStatusForTest(svc.ID, runner.Status{
		State:   runner.StateRunning,
		Latency: 95 * time.Millisecond,
	})
	tt.Frame()

	cat := a.catalog()
	// 1. Shows single Probe RTT when EWMA has not been sampled yet
	r, ok := tt.Find("95 ms")
	if !ok {
		t.Fatalf("expected probe latency '95 ms', got texts: %v", tt.Texts())
	}
	tt.Move(r.X+r.W/2, r.Y+r.H/2)
	tt.Advance(time.Second)
	if !tt.HasText(cat.LatencyTooltipProbe(95)) {
		t.Fatalf("expected tooltip %q, got texts: %v", cat.LatencyTooltipProbe(95), tt.Texts())
	}

	// 2. Once real traffic EWMA is recorded, card prioritizes EWMA and keeps probe in tooltip
	tt.Move(0, 0)
	tt.Advance(time.Second)
	a.tracker.RecordDial(svc.ID, "example.com", 48*time.Millisecond, nil)
	tt.Frame()
	r, ok = tt.Find("48 ms")
	if !ok {
		t.Fatalf("expected effective EWMA latency '48 ms', got texts: %v", tt.Texts())
	}
	if _, found := tt.Find("95 ms"); found {
		t.Fatalf("expected single effective latency on row rather than duplicate '95 ms' label")
	}
	tt.Move(r.X+r.W/2, r.Y+r.H/2)
	tt.Advance(time.Second)
	if !tt.HasText(cat.LatencyTooltipBoth(48, 95)) {
		t.Fatalf("expected combined breakdown tooltip %q, got texts: %v", cat.LatencyTooltipBoth(48, 95), tt.Texts())
	}
}

func TestNodeDetailsDrawer_TelemetryHelpCollapsibleJSONAndHeaderSwitch(t *testing.T) {
	svc := config.Service{
		ID:         "svc-details",
		Name:       "HK-Edge-01",
		Protocol:   config.ProtoVLESS,
		Engine:     config.EngineSingBox,
		AutoStart:  true,
		Server:     "hk01.edge.net",
		ServerPort: 443,
		UUID:       "11111111-2222-3333-4444-555555555555",
		Security:   "tls",
		Tags:       []string{"HK", "Streaming", "Fast"},
	}

	a, tt, _ := newTestApp(t, []config.Service{svc})
	a.state.GatewayPort = freeLocalPort(t)
	a.saveState()
	if err := a.mgr.Start(svc); err != nil {
		t.Fatalf("start sing-box service: %v", err)
	}
	a.mgr.SetStatusForTest(svc.ID, runner.Status{State: runner.StateRunning, Latency: 95 * time.Millisecond})
	a.tracker.RecordDial(svc.ID, "example.com", 48*time.Millisecond, nil)
	tt.Frame()

	cat := a.catalog()

	// 1. Open Details Drawer by clicking card
	if err := tt.Click("HK-Edge-01"); err != nil {
		t.Fatalf("click node card: %v", err)
	}
	tt.Advance(300 * time.Millisecond)
	if a.activeNodeDrawerID != svc.ID {
		t.Fatalf("expected activeNodeDrawerID=%q, got %q", svc.ID, a.activeNodeDrawerID)
	}

	// 2. Telemetry metrics visible, formula descriptions & raw JSON body collapsed initially
	if !tt.HasText("48 ms") || !tt.HasText("95 ms") {
		t.Fatalf("expected both EWMA '48 ms' and RTT '95 ms' in drawer telemetry, got texts: %v", tt.Texts())
	}
	if tt.HasText(cat.NodeDrawerProbeLatencyDesc()) {
		t.Fatalf("did not expect telemetry formula explanation inline before opening help popover")
	}
	if tt.HasText(`"server": "hk01.edge.net"`) {
		t.Fatalf("did not expect raw sing-box JSON body expanded by default")
	}

	// 3. Click '?' help button -> shows popover; Esc closes popover first without dismissing drawer
	if err := tt.Click(cat.NodeDrawerMetricsHelpButton()); err != nil {
		t.Fatalf("click telemetry help button: %v", err)
	}
	tt.Advance(250 * time.Millisecond)
	if !a.nodeDrawerHelpOpen || !tt.HasText(cat.NodeDrawerProbeLatencyDesc()) {
		t.Fatalf("expected telemetry help popover open with formula explanations")
	}
	tt.Key(0, ui.KeyEscape)
	tt.Frame()
	if a.nodeDrawerHelpOpen {
		t.Fatalf("expected first Esc to close telemetry help popover")
	}
	if a.activeNodeDrawerID != svc.ID {
		t.Fatalf("expected details drawer to stay open after closing help popover via Esc")
	}

	// 4. Expand collapsible core JSON preview
	if err := tt.Click(cat.PreviewSingBoxJSON()); err != nil {
		t.Fatalf("click collapsible JSON trigger: %v", err)
	}
	tt.Advance(250 * time.Millisecond)
	if !a.nodeDrawerJSONOpen || !tt.HasText(`"type": "vless"`) {
		t.Fatalf("expected collapsible JSON preview to expand, open=%v texts=%v", a.nodeDrawerJSONOpen, tt.Texts())
	}
	tt.Advance(500 * time.Millisecond)
	if tt.FramePending() {
		t.Fatalf("expected idle details drawer with expanded JSON to stop requesting frames")
	}

	// 5. Header Switch stops running node and starts it back up
	if err := tt.Click(cat.ActionStopNode()); err != nil {
		t.Fatalf("click header stop switch: %v", err)
	}
	if !waitForUI(t, a, tt, 2*time.Second, func() bool {
		return a.mgr.StatusOf(svc.ID).State == runner.StateStopped
	}) {
		t.Fatalf("expected service to stop via details drawer header switch")
	}
	if err := tt.Click(cat.ActionStartNode()); err != nil {
		t.Fatalf("click header start switch: %v", err)
	}
	if !waitForUI(t, a, tt, 2*time.Second, func() bool {
		return a.mgr.StatusOf(svc.ID).State == runner.StateRunning
	}) {
		t.Fatalf("expected service to start again via details drawer header switch")
	}
}

func TestNodeEditorDrawer_UnifiedSlideOverAndDetailsRoundTrip(t *testing.T) {
	svc := config.Service{
		ID:         "svc-edit-flow",
		Name:       "HK-Original",
		Protocol:   config.ProtoVLESS,
		Engine:     config.EngineSingBox,
		AutoStart:  false,
		Server:     "hk01.edge.net",
		ServerPort: 443,
		UUID:       "11111111-2222-3333-4444-555555555555",
		Security:   "tls",
	}

	a, tt, _ := newTestApp(t, []config.Service{svc})
	cat := a.catalog()

	// 1. Open Create Drawer from Toolbar: right-anchored 460px drawer without "Back to Details"
	if err := tt.Click(cat.NewNode()); err != nil {
		t.Fatalf("click NewNode CTA: %v", err)
	}
	tt.Advance(300 * time.Millisecond)
	if !a.editor.open || !a.editor.isNew || a.editor.returnToDrawer {
		t.Fatalf("unexpected create drawer state: open=%v isNew=%v returnToDrawer=%v", a.editor.open, a.editor.isNew, a.editor.returnToDrawer)
	}
	if !tt.HasText(cat.NewNodeTitle()) || !tt.HasText(cat.EditorSaveCreate()) {
		t.Fatalf("expected Create drawer title %q and CTA %q, got texts: %v", cat.NewNodeTitle(), cat.EditorSaveCreate(), tt.Texts())
	}
	if tt.HasText(cat.EditorBackToDetails()) {
		t.Fatalf("did not expect 'Back to Details' when creating new node from list")
	}
	saveRect, ok := tt.Find(cat.EditorSaveCreate())
	if !ok || saveRect.X < 440 || saveRect.X+saveRect.W > 900 {
		t.Fatalf("expected save CTA inside right-anchored 460px drawer [440, 900], got rect=%+v ok=%v", saveRect, ok)
	}

	// Verify English layout does not clip tabs/controls inside 460px drawer
	a.state.Language = "en"
	a.applyLanguagePolicy()
	tt.Frame()
	enCat := a.catalog()
	previewTab, ok := tt.Find(enCat.EditorTabPreview())
	if !ok || previewTab.X < 440 || previewTab.X+previewTab.W > 900 {
		t.Fatalf("expected English preview tab inside [440, 900], got rect=%+v ok=%v", previewTab, ok)
	}
	a.state.Language = "zh-Hans"
	a.applyLanguagePolicy()
	tt.Frame()

	// Press Esc to dismiss Create Drawer
	tt.Key(0, ui.KeyEscape)
	tt.Advance(300 * time.Millisecond)
	if a.editor.open {
		t.Fatalf("expected Esc to close editor drawer")
	}

	// 2. Details -> Edit -> Back to Details (discards unsaved edit & returns to Details Drawer)
	if err := tt.Click("HK-Original"); err != nil {
		t.Fatalf("click HK-Original card: %v", err)
	}
	tt.Advance(300 * time.Millisecond)
	if err := tt.Click(cat.NodeDrawerEdit()); err != nil {
		t.Fatalf("click Edit in details drawer: %v", err)
	}
	tt.Advance(300 * time.Millisecond)
	if !a.editor.open || !a.editor.returnToDrawer || a.activeNodeDrawerID != "" {
		t.Fatalf("expected transition from details to edit drawer with returnToDrawer=true, got editor.open=%v returnToDrawer=%v drawerID=%q",
			a.editor.open, a.editor.returnToDrawer, a.activeNodeDrawerID)
	}
	a.editor.name = "HK-TempUnsaved"
	if err := tt.Click(cat.EditorBackToDetails()); err != nil {
		t.Fatalf("click Back to Details: %v", err)
	}
	tt.Advance(300 * time.Millisecond)
	if a.editor.open || a.activeNodeDrawerID != svc.ID {
		t.Fatalf("expected Back to Details to close editor and restore details drawer %q, got open=%v drawerID=%q",
			svc.ID, a.editor.open, a.activeNodeDrawerID)
	}
	if a.state.Services[0].Name != "HK-Original" {
		t.Fatalf("expected Back to Details to leave saved service unchanged, got %q", a.state.Services[0].Name)
	}

	// 3. Details -> Edit -> Save returns cleanly to updated Details Drawer (toggling AutoStart from Group A)
	if err := tt.Click(cat.NodeDrawerEdit()); err != nil {
		t.Fatalf("reopen Edit from details drawer: %v", err)
	}
	tt.Advance(300 * time.Millisecond)
	if err := tt.Click(cat.EditorAutoStartDesc()); err != nil {
		t.Fatalf("toggle AutoStart switch in Group A card: %v", err)
	}
	tt.Frame()
	if !a.editor.autoStart {
		t.Fatalf("expected editor.autoStart=true after clicking AutoStart row in Group A")
	}
	a.editor.name = "HK-Updated"
	if err := tt.Click(cat.EditorSaveEdit()); err != nil {
		t.Fatalf("click Save Edit: %v", err)
	}
	tt.Advance(300 * time.Millisecond)
	if a.editor.open || a.activeNodeDrawerID != svc.ID {
		t.Fatalf("expected saving edit opened from details drawer to return to details drawer %q, got open=%v drawerID=%q",
			svc.ID, a.editor.open, a.activeNodeDrawerID)
	}
	if a.state.Services[0].Name != "HK-Updated" || !a.state.Services[0].AutoStart {
		t.Fatalf("expected saved service updated with Name='HK-Updated' AutoStart=true, got %+v", a.state.Services[0])
	}
	if !tt.HasText("HK-Updated") {
		t.Fatalf("expected updated node name visible immediately in returned details drawer")
	}

	// 4. Details -> Edit -> Cancel closes completely back to node list
	if err := tt.Click(cat.NodeDrawerEdit()); err != nil {
		t.Fatalf("open Edit again from details drawer: %v", err)
	}
	tt.Advance(400 * time.Millisecond)
	if tt.FramePending() {
		t.Fatalf("expected settled editor drawer to be idle with FramePending=false")
	}
	if err := tt.Click(cat.Cancel()); err != nil {
		t.Fatalf("click Cancel in editor drawer: %v", err)
	}
	tt.Advance(400 * time.Millisecond)
	if a.editor.open || a.activeNodeDrawerID != "" {
		t.Fatalf("expected Cancel to close editor and not reopen details drawer, got open=%v drawerID=%q",
			a.editor.open, a.activeNodeDrawerID)
	}
	if tt.FramePending() {
		t.Fatalf("expected settled node list after closing editor drawer to have FramePending=false")
	}
}

func TestLogDrawer_RedesignFiltersPauseAndCrossDrawerNavigation(t *testing.T) {
	svc := config.Service{
		ID:       "svc-log",
		Name:     "HK-Log-Node",
		Protocol: config.ProtoVLESS,
		Engine:   config.EngineSingBox,
		Server:   "hk01.edge.net",
	}

	a, tt, _ := newTestApp(t, []config.Service{svc})
	cat := a.catalog()
	logs := a.mgr.LogsOf(svc.ID)
	logs.AppendLine("[10:00:01] [INFO] dialer initialized cleanly")
	logs.AppendLine("[10:00:02] [WARN] upstream TLS handshake retry timeout")
	logs.AppendLine("[10:00:03] [ERROR] connection refused by remote")

	a.activeLogDrawerID = svc.ID
	tt.Frame()
	tt.Advance(300 * time.Millisecond)

	// 1. Unified 460px drawer header controls stay within [440, 900] in both zh-Hans and en
	if !tt.HasText(cat.LogDrawerTitle()) || !tt.HasText(cat.LogsStatusLive()) || !tt.HasText(cat.LogsLineCount(3, 3)) {
		t.Fatalf("expected log drawer header title, live status, and 3/3 line count, got texts: %v", tt.Texts())
	}
	closeRect, ok := tt.Find(cat.LogClose())
	if !ok || closeRect.X < 440 || closeRect.X+closeRect.W > 900 {
		t.Fatalf("expected close button inside [440, 900], got rect=%+v ok=%v", closeRect, ok)
	}
	a.state.Language = "en"
	a.applyLanguagePolicy()
	tt.Frame()
	enCat := a.catalog()
	enCloseRect, ok := tt.Find(enCat.LogClose())
	if !ok || enCloseRect.X < 440 || enCloseRect.X+enCloseRect.W > 900 {
		t.Fatalf("expected English log close button inside [440, 900], got rect=%+v ok=%v", enCloseRect, ok)
	}
	a.state.Language = "zh-Hans"
	a.applyLanguagePolicy()
	tt.Frame()

	// 2. Level filter pill
	if err := tt.Click("btn-drawer-level-error"); err != nil {
		t.Fatalf("click error filter pill: %v", err)
	}
	tt.Frame()
	if !tt.HasText("[ERROR] connection refused by remote") || tt.HasText("[INFO] dialer initialized cleanly") {
		t.Fatalf("expected only ERROR line after clicking Error filter, got texts: %v", tt.Texts())
	}
	if err := tt.Click("btn-drawer-level-all"); err != nil {
		t.Fatalf("click all filter pill: %v", err)
	}
	tt.Frame()

	// 3. Search input + no-match reset + Esc clears search before closing drawer
	if err := tt.Click(cat.LogsSearchPlaceholder()); err != nil {
		t.Fatalf("click drawer search: %v", err)
	}
	tt.Type("timeout")
	tt.Frame()
	if !tt.HasText("[WARN] upstream TLS handshake retry timeout") || tt.HasText("[ERROR] connection refused by remote") {
		t.Fatalf("expected search 'timeout' to match only WARN line, got texts: %v", tt.Texts())
	}
	tt.Key(0, ui.KeyEscape)
	tt.Frame()
	if a.logDrawerSearch != "" || a.activeLogDrawerID == "" {
		t.Fatalf("expected first Esc in search field to clear search while keeping drawer open, search=%q drawerID=%q",
			a.logDrawerSearch, a.activeLogDrawerID)
	}

	if err := tt.Click(cat.LogsSearchPlaceholder()); err != nil {
		t.Fatalf("click drawer search for unmatched test: %v", err)
	}
	tt.Type("no-such-log-entry")
	tt.Frame()
	if !tt.HasText(cat.LogsNoMatch()) {
		t.Fatalf("expected no-match message %q", cat.LogsNoMatch())
	}
	if err := tt.Click(cat.ResetFilters()); err != nil {
		t.Fatalf("click reset filters: %v", err)
	}
	tt.Frame()
	if !tt.HasText("[INFO] dialer initialized cleanly") {
		t.Fatalf("expected all log lines restored after ResetFilters")
	}

	// 4. Pause freezes visible entries until resumed
	if err := tt.Click(cat.LogsActionPause()); err != nil {
		t.Fatalf("click Pause in log drawer: %v", err)
	}
	tt.Frame()
	if !a.logDrawerPaused || !tt.HasText(cat.LogsStatusPaused()) {
		t.Fatalf("expected paused state and label, paused=%v texts=%v", a.logDrawerPaused, tt.Texts())
	}
	logs.AppendLine("[10:00:04] [INFO] hidden while paused")
	tt.Frame()
	if tt.HasText("hidden while paused") {
		t.Fatalf("did not expect newly appended log to appear while drawer is paused")
	}
	if err := tt.Click(cat.LogsActionResume()); err != nil {
		t.Fatalf("click Resume in log drawer: %v", err)
	}
	tt.Frame()
	if a.logDrawerPaused || !tt.HasText("hidden while paused") {
		t.Fatalf("expected resumed drawer to show new log line")
	}

	// 5. Cross-drawer transition: Logs -> Details Drawer -> Clear & close settles cleanly
	if err := tt.Click(cat.NodeDrawerTitle()); err != nil {
		t.Fatalf("click Details icon in log drawer header: %v", err)
	}
	tt.Advance(300 * time.Millisecond)
	if a.activeLogDrawerID != "" || a.activeNodeDrawerID != svc.ID {
		t.Fatalf("expected switch from log drawer to details drawer %q, got logID=%q nodeID=%q",
			svc.ID, a.activeLogDrawerID, a.activeNodeDrawerID)
	}
	tt.Key(0, ui.KeyEscape)
	tt.Advance(400 * time.Millisecond)
	if tt.FramePending() {
		t.Fatalf("expected idle frame budget after closing drawer, got FramePending=true")
	}
}

func TestLogDrawer_MouseSelectionAndCopyAcrossLines(t *testing.T) {
	svc := config.Service{
		ID:       "svc-log-sel",
		Name:     "Sel-Node",
		Protocol: config.ProtoVLESS,
		Engine:   config.EngineSingBox,
		Server:   "hk01.edge.net",
	}

	a, tt, _ := newTestApp(t, []config.Service{svc})
	lineA := "[10:00:01] [INFO] dialed hk01.edge.net"
	lineB := "[10:00:02] [WARN] retry handshake attempt 1"
	lineC := "[10:00:03] [ERROR] connection reset by peer"

	logs := a.mgr.LogsOf(svc.ID)
	logs.AppendLine(lineA)
	logs.AppendLine(lineB)
	logs.AppendLine(lineC)

	a.activeLogDrawerID = svc.ID
	tt.Frame()
	tt.Advance(300 * time.Millisecond)

	rA, ok := tt.Find(lineA)
	if !ok {
		t.Fatalf("could not find lineA in log drawer")
	}
	if rA.X < 440 || rA.X+rA.W > 900 {
		t.Fatalf("expected selectable log line inside [440, 900], got rect=%+v", rA)
	}
	rB, ok := tt.Find(lineB)
	if !ok {
		t.Fatalf("could not find lineB in log drawer")
	}

	// 1. Mouse drag from middle of lineA across lineB, verify selection survives new streaming append, then Cmd+C copies substring span
	startX := rA.X + 4
	startY := rA.Y + rA.H/2
	endX := rB.X + rB.W*0.75
	endY := rB.Y + rB.H/2

	tt.Press(startX, startY)
	tt.Move(endX, endY)
	tt.Release(endX, endY)
	tt.Frame()

	// Append a new log line while user still holds selection -> must NOT wipe selection!
	logs.AppendLine("[10:00:04] [INFO] background heartbeat ok")
	tt.Frame()

	tt.Key(ui.Cmd, ui.KeyC)
	copied := tt.Clipboard()
	if !strings.HasPrefix(copied, "10:00:01] [INFO] dialed hk01.edge.net\n[10:00:02] [WARN]") {
		t.Fatalf("expected Cmd+C on mouse drag selection across lineA..lineB to copy partial multi-line substring, got %q", copied)
	}
	if strings.Contains(copied, lineC) || strings.Contains(copied, "background heartbeat ok") {
		t.Fatalf("did not expect unselected lineC or newer line in copied selection, got %q", copied)
	}

	// 2. Right-clicking selected region opens native context menu with Copy & Select All
	tt.SetClipboard("")
	midX := rB.X + rB.W*0.25
	midY := rB.Y + rB.H/2
	tt.RightClickAt(midX, midY)
	if err := tt.ChooseMenuItem("Copy"); err != nil {
		t.Fatalf("right-click Copy on selected log text: %v (menu=%v)", err, tt.Menu())
	}
	if tt.Clipboard() != copied {
		t.Fatalf("expected right-click Copy %q to match Cmd+C %q", tt.Clipboard(), copied)
	}

	// 3. Header Copy button still copies all visible filtered logs into app clipboard
	if err := tt.Click(a.catalog().LogCopy()); err != nil {
		t.Fatalf("click header Copy button: %v", err)
	}
	tt.Frame()
	if !strings.Contains(a.clipboardMem, lineC) || !strings.Contains(a.clipboardMem, "background heartbeat ok") {
		t.Fatalf("expected header Copy button to copy full log stream, got %q", a.clipboardMem)
	}
}
