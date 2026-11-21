package app

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"

	"naive-client/internal/config"
	"naive-client/internal/routing"
	"naive-client/internal/runner"
	"naive-client/internal/warp"
	"naive-client/locales"
)

func TestP1Redesign_RoutingSearchAndMoreMenu(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)
	a.state.RoutingRules = append(a.state.RoutingRules, routing.Rule{
		ID:           "cust-corp",
		Name:         "Corp Internal",
		Description:  "Internal git and wiki",
		Enabled:      true,
		DomainSuffix: []string{"corp.example.internal"},
		Action:       routing.RouteAction{Type: routing.ActionDirect},
	})
	a.saveState()

	tt.Key(ui.Cmd, ui.Key2)
	tt.Frame()

	cat := a.catalog()
	if err := tt.Click(cat.RoutingSearchPlaceholder()); err != nil {
		t.Fatalf("click routing search: %v", err)
	}
	tt.Type("corp.example.internal")
	tt.Frame()

	if !tt.HasText("Corp Internal") || tt.HasText(cat.PresetRuleAIServices()) {
		t.Fatalf("expected search to isolate Corp Internal rule, got texts: %v", tt.Texts())
	}

	// Non-matching search shows empty state with ResetFilters action
	a.routingSearch = "definitely-no-rule-matches"
	tt.Frame()
	if !tt.HasText(cat.RoutingEmptySearch()) {
		t.Fatalf("expected empty search state %q", cat.RoutingEmptySearch())
	}
	if err := tt.Click(cat.ResetFilters()); err != nil {
		t.Fatalf("click ResetFilters: %v", err)
	}
	tt.Frame()
	if a.routingSearch != "" || !tt.HasText("Corp Internal") || !tt.HasText(cat.PresetRuleAIServices()) {
		t.Fatalf("expected ResetFilters to clear search and restore all rules")
	}

	// More overflow menu resets presets back to defaults
	if err := tt.Click(cat.RoutingMoreActions()); err != nil {
		t.Fatalf("click RoutingMoreActions: %v", err)
	}
	tt.Frame()
	if !a.openRoutingMoreMenu {
		t.Fatalf("expected openRoutingMoreMenu = true")
	}
	if err := tt.Click(cat.ResetPresets()); err != nil {
		t.Fatalf("click ResetPresets in more menu: %v", err)
	}
	tt.Frame()
	if a.openRoutingMoreMenu {
		t.Fatalf("expected more menu to close after clicking ResetPresets")
	}
	if tt.HasText("Corp Internal") {
		t.Fatalf("expected custom rule removed after ResetPresets")
	}

	// Switching away from TabRouting cleans up open popovers
	a.openRoutingMoreMenu = true
	a.showRoutingStrategyHelp = true
	tt.Key(ui.Cmd, ui.Key1)
	tt.Frame()
	if a.openRoutingMoreMenu || a.showRoutingStrategyHelp {
		t.Fatalf("expected routing popovers reset when switching tabs")
	}
}

func TestP1Redesign_RuleDetailsToEditorRoundTripAndToggle(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)
	a.activeTab = TabRouting
	tt.Frame()

	cat := a.catalog()

	// 1. Open Details Drawer for preset-block-ads and toggle via drawer Switch
	if err := tt.Click(cat.PresetRuleBlockAds()); err != nil {
		t.Fatalf("click preset-block-ads card: %v", err)
	}
	tt.Advance(300 * time.Millisecond)
	if a.activeRuleDrawerID != "preset-block-ads" {
		t.Fatalf("expected activeRuleDrawerID = 'preset-block-ads', got %q", a.activeRuleDrawerID)
	}

	if err := tt.Click("drawer-toggle-rule"); err != nil {
		t.Fatalf("click drawer-toggle-rule: %v", err)
	}
	tt.Frame()
	if a.state.BlockerBlockAds || a.state.RoutingRules[0].Enabled {
		t.Fatalf("expected drawer toggle to disable preset-block-ads and sync BlockerBlockAds")
	}

	// 2. Click Edit in Details Drawer -> closes details, opens 460px Rule Editor Drawer with Back to Details
	if err := tt.Click(cat.RuleDrawerEdit()); err != nil {
		t.Fatalf("click RuleDrawerEdit: %v", err)
	}
	tt.Advance(300 * time.Millisecond)
	if a.activeRuleDrawerID != "" || !a.ruleEditor.open || !a.ruleEditor.returnToDrawer {
		t.Fatalf("expected transition from details drawer to rule editor drawer, active=%q open=%v return=%v",
			a.activeRuleDrawerID, a.ruleEditor.open, a.ruleEditor.returnToDrawer)
	}

	// 3. Click Back to Details -> restores Details Drawer
	if err := tt.Click(cat.EditorBackToDetails()); err != nil {
		t.Fatalf("click EditorBackToDetails: %v", err)
	}
	tt.Advance(300 * time.Millisecond)
	if a.ruleEditor.open || a.activeRuleDrawerID != "preset-block-ads" {
		t.Fatalf("expected Back to Details to restore rule details drawer, open=%v active=%q",
			a.ruleEditor.open, a.activeRuleDrawerID)
	}

	// 4. Edit again, save -> returns to Details Drawer
	if err := tt.Click(cat.RuleDrawerEdit()); err != nil {
		t.Fatalf("re-open rule editor from details: %v", err)
	}
	tt.Advance(300 * time.Millisecond)
	if err := tt.Click(cat.Confirm()); err != nil {
		t.Fatalf("save rule from editor drawer: %v", err)
	}
	tt.Advance(300 * time.Millisecond)
	if a.ruleEditor.open || a.activeRuleDrawerID != "preset-block-ads" {
		t.Fatalf("expected saving from details-originated editor to reopen details drawer, open=%v active=%q",
			a.ruleEditor.open, a.activeRuleDrawerID)
	}

	// 5. Re-open editor and press Escape -> dismisses editor without reopening details
	if err := tt.Click(cat.RuleDrawerEdit()); err != nil {
		t.Fatalf("open editor for Esc test: %v", err)
	}
	tt.Advance(300 * time.Millisecond)
	tt.Key(0, ui.KeyEscape)
	tt.Advance(300 * time.Millisecond)
	if a.ruleEditor.open || a.activeRuleDrawerID != "" {
		t.Fatalf("expected Escape to dismiss rule editor drawer cleanly, open=%v active=%q",
			a.ruleEditor.open, a.activeRuleDrawerID)
	}
}

func TestP1Redesign_IdleFrameBudgetAndWidthsAndLocales(t *testing.T) {
	svc := config.Service{
		ID:         "svc-warp-p1",
		Name:       "HK-WARP",
		Protocol:   config.ProtoVLESS,
		Server:     "hk.example.com",
		ServerPort: 443,
		EnableWARP: true,
	}
	a, tt, _ := newTestApp(t, []config.Service{svc})

	for _, lang := range []string{locales.LangZhHans, locales.LangEn} {
		a.state.Language = lang
		a.applyLanguagePolicy()
		for _, width := range []int{440, 900} {
			tt.SetSize(width, 660)

			// Routing list idle check
			a.activeTab = TabRouting
			a.activeRuleDrawerID = ""
			a.ruleEditor.open = false
			tt.Frame()
			tt.Advance(500 * time.Millisecond)
			if tt.FramePending() {
				t.Fatalf("idle Routing page requested frames (lang=%s width=%d)", lang, width)
			}

			// Routing details drawer idle check
			a.activeRuleDrawerID = "preset-ai-services"
			tt.Frame()
			tt.Advance(500 * time.Millisecond)
			if tt.FramePending() {
				t.Fatalf("idle Rule Details drawer requested frames (lang=%s width=%d)", lang, width)
			}
			a.activeRuleDrawerID = ""
			tt.Frame()

			// Routing editor drawer idle check
			a.openCreateRuleDialog()
			tt.Frame()
			tt.Advance(500 * time.Millisecond)
			if tt.FramePending() {
				t.Fatalf("idle Rule Editor drawer requested frames (lang=%s width=%d)", lang, width)
			}
			a.ruleEditor.open = false
			tt.Frame()

			// Cloudflare WARP & Tunnel subtabs idle check
			a.activeTab = TabCloudflare
			for sub := 0; sub <= 1; sub++ {
				a.cloudflareSubTab = sub
				tt.Frame()
				tt.Advance(500 * time.Millisecond)
				if tt.FramePending() {
					t.Fatalf("idle Cloudflare subtab %d requested frames (lang=%s width=%d)", sub, lang, width)
				}
			}
		}
	}
}

func TestP1Redesign_CloudflareHTMLAlignment(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)
	a.state.Cloudflare.Account = warp.Account{
		DeviceID:     "dev-html-123",
		WGPrivateKey: "wg-priv-ok",
		IPv4:         "172.16.0.2/32",
		IPv6:         "2606:4700:110::2/128",
	}
	a.saveState()

	tt.Key(ui.Cmd, ui.Key5)
	tt.Frame()
	if a.activeTab != TabCloudflare {
		t.Fatalf("expected TabCloudflare, got %v", a.activeTab)
	}

	cat := a.catalog()

	// 1. Whole Device ID cell copies device ID cleanly
	if err := tt.Click("btn-copy-warp-device-id"); err != nil {
		t.Fatalf("click btn-copy-warp-device-id: %v", err)
	}
	tt.Frame()
	if a.clipboardMem != "dev-html-123" {
		t.Fatalf("expected clipboard = dev-html-123, got %q", a.clipboardMem)
	}
	if !tt.HasText(cat.CloudflareWarpToastCopiedDeviceID()) {
		t.Fatalf("expected copied toast %q", cat.CloudflareWarpToastCopiedDeviceID())
	}

	// 2. Side-by-side Direct & Chained transport switches operate independently
	if err := tt.Click(cat.CloudflareWarpTransportWireGuard()); err != nil {
		t.Fatalf("click direct WireGuard: %v", err)
	}
	tt.Frame()
	if err := tt.Click("btn-warp-chained-masque"); err != nil {
		t.Fatalf("click chained MASQUE: %v", err)
	}
	tt.Frame()
	if a.state.Cloudflare.DefaultMode != warp.ModeWireGuard || a.state.Cloudflare.ChainedMode != warp.ModeMASQUE {
		t.Fatalf("expected independent Direct=wireguard Chained=masque, got direct=%s chained=%s",
			a.state.Cloudflare.DefaultMode, a.state.Cloudflare.ChainedMode)
	}

	// 3. Switch to Tunnel subtab and verify unified card controls
	if err := tt.Click(cat.CloudflareSubtabTunnel()); err != nil {
		t.Fatalf("click CloudflareSubtabTunnel: %v", err)
	}
	tt.Frame()
	if a.cloudflareSubTab != 1 {
		t.Fatalf("expected cloudflareSubTab = 1, got %d", a.cloudflareSubTab)
	}

	if err := tt.Click(cat.CloudflareTunnelEnable()); err != nil {
		t.Fatalf("click CloudflareTunnelEnable: %v", err)
	}
	tt.Frame()
	if !a.state.Cloudflare.Tunnel.Enabled {
		t.Fatalf("expected Tunnel.Enabled = true")
	}

	if err := tt.Click("QUIC"); err != nil {
		t.Fatalf("click QUIC protocol: %v", err)
	}
	tt.Frame()
	if a.state.Cloudflare.Tunnel.Protocol != "quic" {
		t.Fatalf("expected Tunnel.Protocol = quic, got %q", a.state.Cloudflare.Tunnel.Protocol)
	}
	if err := tt.Click("HTTP/2"); err != nil {
		t.Fatalf("click HTTP/2 protocol: %v", err)
	}
	tt.Frame()
	if a.state.Cloudflare.Tunnel.Protocol != "http2" {
		t.Fatalf("expected Tunnel.Protocol = http2, got %q", a.state.Cloudflare.Tunnel.Protocol)
	}

	if err := tt.Click(cat.CloudflareTunnelPostQuantum()); err != nil {
		t.Fatalf("click CloudflareTunnelPostQuantum: %v", err)
	}
	tt.Frame()
	if !a.state.Cloudflare.Tunnel.PostQuantum {
		t.Fatalf("expected Tunnel.PostQuantum = true")
	}
}

// Regression: ButtonBase defaults to centered flex alignment, which centered scan candidates
// and attached WARP node rows instead of stretching edge-to-edge, while raw H3/H2 protocol
// strings, duplicate "→ WARP" suffixes, "warp://auto", and un-unified latency formatting
// diverged from the design system.
func TestP1Redesign_CloudflareScanAndAttachedNodesAlignmentAndContent(t *testing.T) {
	chainedSvc := config.Service{
		ID:         "cf-sg-warp",
		Name:       "SG-Xray-WARP",
		Protocol:   config.ProtoVLESS,
		Engine:     config.EngineSingBox,
		Server:     "sg.example.com",
		ServerPort: 443,
		UUID:       "11111111-2222-3333-4444-555555555555",
		EnableWARP: true,
	}
	a, tt, _ := newTestApp(t, []config.Service{chainedSvc})
	a.warpRegistering = true
	a.setCnDirectWarpEnabled(true)

	// Mark built-in WARP running with timeout error, and chained node healthy at 48ms.
	a.mgr.SetStatusForTest(config.BuiltinWarpServiceID, runner.Status{
		State:      runner.StateRunning,
		ProbeError: "warp server (162.159.198.2:443) connection failed: i/o timeout",
	})
	a.mgr.SetStatusForTest(chainedSvc.ID, runner.Status{
		State:   runner.StateRunning,
		Latency: 48 * time.Millisecond,
	})

	a.warpScanResults = []warp.EndpointCandidateResult{
		{Endpoint: "162.159.193.5:2408", Protocol: "wireguard", RTT: 34 * time.Millisecond, LossRate: 0},
		{Endpoint: "162.159.198.2:443", Protocol: "h3", RTT: 41 * time.Millisecond, LossRate: 0.02},
		{Endpoint: "188.114.97.3:443", Protocol: "h2", RTT: 55 * time.Millisecond, LossRate: 0.05},
	}

	tt.SetSize(900, 660)
	a.activeTab = TabCloudflare
	a.cloudflareSubTab = 0
	tt.Frame()

	// 1. Verify scan result data formatting
	for _, want := range []string{"WireGuard", "MASQUE H3", "MASQUE H2", "34 ms", "41 ms", "55 ms"} {
		if !tt.HasText(want) {
			t.Fatalf("expected scan results to contain %q, got texts: %v", want, tt.Texts())
		}
	}

	// 2. Verify attached nodes data content & clean metadata (no duplicate "→ WARP" or "warp://auto")
	cat := a.catalog()
	for _, want := range []string{"48 ms", "sg.example.com:443", "Built-in", cat.StatusUnhealthy(), cat.WarpServerUnreachablePill()} {
		if !tt.HasText(want) {
			t.Fatalf("expected attached WARP nodes to display %q, got texts: %v", want, tt.Texts())
		}
	}
	for _, txt := range tt.Texts() {
		if strings.Contains(txt, "→ WARP") {
			t.Fatalf("unexpected duplicate '→ WARP' suffix in Cloudflare attached node metadata: %q", txt)
		}
		if strings.Contains(txt, "warp://auto") {
			t.Fatalf("unexpected 'warp://auto' in Cloudflare attached node metadata: %q", txt)
		}
	}

	// 3. Verify scan rows stretch edge-to-edge and align vertically across columns on 900x660
	ep1, ok := tt.Find("162.159.193.5:2408")
	if !ok || ep1.X >= 300 {
		t.Fatalf("expected scan endpoint flush-left (X < 300), got ok=%v rect=%+v", ok, ep1)
	}
	rtt1, ok1 := tt.Find("34 ms")
	rtt2, ok2 := tt.Find("41 ms")
	if !ok1 || !ok2 {
		t.Fatalf("missing scan RTT rects: ok1=%v ok2=%v", ok1, ok2)
	}
	if rtt1.X+rtt1.W <= 780 {
		t.Fatalf("expected scan RTT flush-right (X+W > 780), got rect=%+v", rtt1)
	}
	if diff := math.Abs(float64((rtt1.X + rtt1.W) - (rtt2.X + rtt2.W))); diff > 1 {
		t.Fatalf("expected scan RTT right edges aligned within 1px, diff=%.2f (%+v vs %+v)", diff, rtt1, rtt2)
	}
	loss1, okL1 := tt.Find("0% loss")
	loss2, okL2 := tt.Find("2% loss")
	if !okL1 || !okL2 {
		t.Fatalf("missing scan loss rects: okL1=%v okL2=%v", okL1, okL2)
	}
	if diff := math.Abs(float64((loss1.X + loss1.W) - (loss2.X + loss2.W))); diff > 1 {
		t.Fatalf("expected scan loss right edges aligned within 1px, diff=%.2f (%+v vs %+v)", diff, loss1, loss2)
	}
	pH3, okP1 := tt.Find("MASQUE H3")
	pH2, okP2 := tt.Find("MASQUE H2")
	if !okP1 || !okP2 {
		t.Fatalf("missing scan protocol rects: okP1=%v okP2=%v", okP1, okP2)
	}
	if diff := math.Abs(float64((pH3.X + pH3.W) - (pH2.X + pH2.W))); diff > 1 {
		t.Fatalf("expected scan protocol right edges aligned within 1px, diff=%.2f (%+v vs %+v)", diff, pH3, pH2)
	}

	// 4. Verify attached WARP node rows stretch edge-to-edge on 900x660
	nameRect, okName := tt.Find("SG-Xray-WARP")
	if !okName || nameRect.X >= 300 {
		t.Fatalf("expected attached node name flush-left (X < 300), got ok=%v rect=%+v", okName, nameRect)
	}
	latRect, okLat := tt.Find("48 ms")
	if !okLat || latRect.X <= 700 {
		t.Fatalf("expected attached node latency aligned right (X > 700), got ok=%v rect=%+v", okLat, latRect)
	}
}

// Regression test: previously the Outbound Action segmented control (rule-set-action) in New/Edit Rule
// used compactSegmentedControl inside a stretched Column, producing a thin (~17px) track with the
// three segments clustered on the left and empty track space on the right. It must render as a
// full-width, equal-column segmented control with comfortable vertical sizing and interactive clicks.
func TestP1Redesign_RuleEditorActionSegmentedLayout(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)
	a.activeTab = TabRouting
	tt.Frame()
	cat := a.catalog()

	assertActionSegments := func(mode string) {
		t.Helper()
		proxyRect, okP := tt.Find(cat.RoutingProxy())
		directRect, okD := tt.Find(cat.RoutingDirect())
		blockRect, okB := tt.Find(cat.RoutingBlock())
		if !okP || !okD || !okB {
			t.Fatalf("[%s] missing action segment rects: proxy=%v direct=%v block=%v", mode, okP, okD, okB)
		}
		if proxyRect.H < 24 || directRect.H < 24 || blockRect.H < 24 {
			t.Fatalf("[%s] expected comfortable action segment height >= 24px, got proxy=%.1f direct=%.1f block=%.1f",
				mode, proxyRect.H, directRect.H, blockRect.H)
		}
		if proxyRect.W < 100 || math.Abs(float64(proxyRect.W-directRect.W)) > 1 || math.Abs(float64(directRect.W-blockRect.W)) > 1 {
			t.Fatalf("[%s] expected equal full-width segments >= 100px, got proxy=%+v direct=%+v block=%+v",
				mode, proxyRect, directRect, blockRect)
		}
		if math.Abs(float64(proxyRect.Y-directRect.Y)) > 0.5 || math.Abs(float64(directRect.Y-blockRect.Y)) > 0.5 {
			t.Fatalf("[%s] expected segments aligned on same row, got proxy=%+v direct=%+v block=%+v",
				mode, proxyRect, directRect, blockRect)
		}
	}

	// 1. New Rule drawer
	if err := tt.Click(cat.NewRule()); err != nil {
		t.Fatalf("click NewRule: %v", err)
	}
	tt.Frame()
	tt.Advance(500 * time.Millisecond)
	tt.Frame()
	assertActionSegments("new-rule")

	if err := tt.Click(cat.RoutingDirect()); err != nil {
		t.Fatalf("click Direct segment: %v", err)
	}
	tt.Frame()
	if a.ruleEditor.actionIndex != 1 {
		t.Fatalf("expected actionIndex=1 after clicking Direct, got %d", a.ruleEditor.actionIndex)
	}

	if err := tt.Click(cat.RoutingBlock()); err != nil {
		t.Fatalf("click Block segment: %v", err)
	}
	tt.Frame()
	if a.ruleEditor.actionIndex != 2 {
		t.Fatalf("expected actionIndex=2 after clicking Block, got %d", a.ruleEditor.actionIndex)
	}

	a.dismissRuleEditorDrawer(false)
	tt.Advance(500 * time.Millisecond)
	tt.Frame()

	// 2. Edit Rule drawer
	a.openEditRuleDialog(a.state.RoutingRules[1])
	tt.Frame()
	tt.Advance(500 * time.Millisecond)
	tt.Frame()
	assertActionSegments("edit-rule")
}
