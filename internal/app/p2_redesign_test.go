package app

import (
	"testing"
	"time"

	"github.com/egoist/mygo/ui"

	"naive-client/internal/config"
	"naive-client/locales"
)

func TestP2Redesign_InsightsSwitchesAndBlockerDrawer(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)

	if err := tt.Click(a.catalog().NavInsights()); err != nil {
		t.Fatalf("click NavInsights: %v", err)
	}
	tt.Frame()

	initBlocker := a.state.BlockerEnabled
	initAds := a.state.BlockerBlockAds

	// Header Switch toggles
	if err := tt.Click("btn-toggle-blocker"); err != nil {
		t.Fatalf("click btn-toggle-blocker: %v", err)
	}
	tt.Frame()
	if a.state.BlockerEnabled == initBlocker {
		t.Fatalf("expected BlockerEnabled to toggle from %v", initBlocker)
	}
	if err := tt.Click("btn-toggle-blocker"); err != nil {
		t.Fatalf("restore btn-toggle-blocker: %v", err)
	}
	tt.Frame()
	if a.state.BlockerEnabled != initBlocker {
		t.Fatalf("expected BlockerEnabled restored to %v", initBlocker)
	}

	if err := tt.Click("btn-toggle-ads"); err != nil {
		t.Fatalf("click btn-toggle-ads: %v", err)
	}
	tt.Frame()
	if a.state.BlockerBlockAds == initAds {
		t.Fatalf("expected BlockerBlockAds to toggle from %v", initAds)
	}

	// Open 460px Blocker Rules Drawer
	if err := tt.Click("btn-manage-rules"); err != nil {
		t.Fatalf("click btn-manage-rules: %v", err)
	}
	tt.Frame()
	tt.Advance(300 * time.Millisecond)
	if !a.insightsShowManageRules {
		t.Fatalf("expected insightsShowManageRules = true")
	}

	closeRect, ok := tt.Find("btn-close-rules")
	if !ok || closeRect.X < 440 || closeRect.X+closeRect.W > 900 {
		t.Fatalf("expected drawer close button inside [440, 900], got rect=%+v ok=%v", closeRect, ok)
	}

	// Escape closes drawer
	tt.Key(0, ui.KeyEscape)
	tt.Advance(300 * time.Millisecond)
	if a.insightsShowManageRules {
		t.Fatalf("expected Escape to close insights blocker rules drawer")
	}

	// Reopen drawer and add/remove denylist + subscription
	if err := tt.Click("btn-manage-rules"); err != nil {
		t.Fatalf("reopen btn-manage-rules: %v", err)
	}
	tt.Frame()
	tt.Advance(300 * time.Millisecond)

	a.blockerDenylistInput = "ads.bad.example"
	tt.Frame()
	if err := tt.Click("btn-add-denylist"); err != nil {
		t.Fatalf("click btn-add-denylist: %v", err)
	}
	tt.Frame()
	if len(a.state.BlockerDenylist) != 1 || a.state.BlockerDenylist[0] != "ads.bad.example" {
		t.Fatalf("expected denylist to contain ads.bad.example, got %v", a.state.BlockerDenylist)
	}
	if err := tt.Click("btn-del-denylist-ads.bad.example"); err != nil {
		t.Fatalf("click btn-del-denylist: %v", err)
	}
	tt.Frame()
	if len(a.state.BlockerDenylist) != 0 {
		t.Fatalf("expected denylist empty after delete, got %v", a.state.BlockerDenylist)
	}

	subURL := "https://example.com/blocklist.txt"
	a.blockerSubscriptionInput = subURL
	tt.Frame()
	if err := tt.Click("btn-add-sub"); err != nil {
		t.Fatalf("click btn-add-sub: %v", err)
	}
	tt.Frame()
	if len(a.state.BlockerSubscriptions) != 1 || a.state.BlockerSubscriptions[0] != subURL {
		t.Fatalf("expected subscription added, got %v", a.state.BlockerSubscriptions)
	}
	if err := tt.Click("btn-del-sub-" + subURL); err != nil {
		t.Fatalf("click btn-del-sub: %v", err)
	}
	tt.Frame()
	if len(a.state.BlockerSubscriptions) != 0 {
		t.Fatalf("expected subscriptions empty after delete, got %v", a.state.BlockerSubscriptions)
	}

	// Close via btn-close-rules
	if err := tt.Click("btn-close-rules"); err != nil {
		t.Fatalf("click btn-close-rules: %v", err)
	}
	tt.Frame()
	tt.Advance(300 * time.Millisecond)
	if a.insightsShowManageRules {
		t.Fatalf("expected btn-close-rules to dismiss drawer")
	}

	// Switching away from TabInsights clears open drawer state
	a.insightsShowManageRules = true
	tt.Key(ui.Cmd, ui.Key1)
	tt.Frame()
	if a.insightsShowManageRules {
		t.Fatalf("expected leaving TabInsights to close insightsShowManageRules")
	}
}

func TestP2Redesign_LogsSelectsAndPauseReset(t *testing.T) {
	services := []config.Service{
		{ID: "svc-hk", Name: "HK-Edge", Protocol: config.ProtoNaive, Server: "hk.example.com", ServerPort: 443, Listens: []string{"socks://127.0.0.1:10801"}},
		{ID: "svc-us", Name: "US-Core", Protocol: config.ProtoVLESS, Server: "us.example.com", ServerPort: 443, Listens: []string{"socks://127.0.0.1:10802"}},
	}
	a, tt, _ := newTestApp(t, services)
	a.mgr.LogsOf("svc-hk").AppendLine("[10:00:01] [INFO] hk initialized")
	a.mgr.LogsOf("svc-us").AppendLine("[10:00:02] [WARN] us retrying dial")

	if err := tt.Click(a.catalog().NavLogs()); err != nil {
		t.Fatalf("click NavLogs: %v", err)
	}
	tt.Frame()

	// Pause, then verify engine level Select changes state + logsEngineLevel
	if err := tt.Click(a.catalog().LogsActionPause()); err != nil {
		t.Fatalf("click pause: %v", err)
	}
	tt.Frame()
	if !a.logsPaused {
		t.Fatalf("expected logsPaused = true")
	}

	if err := tt.Click("select-engine-level"); err != nil {
		t.Fatalf("open select-engine-level: %v", err)
	}
	tt.Frame()
	if err := tt.Click("btn-engine-level-warn"); err != nil {
		t.Fatalf("click btn-engine-level-warn: %v", err)
	}
	tt.Frame()
	if a.state.LogLevel != "warn" || a.logsEngineLevel != "warn" {
		t.Fatalf("expected warn level persisted and synced, got state=%q select=%q", a.state.LogLevel, a.logsEngineLevel)
	}

	// Switching sub-tab to Nodes resets pause
	if err := tt.Click(a.catalog().LogsTabNodes()); err != nil {
		t.Fatalf("click LogsTabNodes: %v", err)
	}
	tt.Frame()
	if a.logsSubTab != 1 || a.logsPaused {
		t.Fatalf("expected logsSubTab=1 and logsPaused reset to false, got tab=%d paused=%v", a.logsSubTab, a.logsPaused)
	}

	// Pause on first node, then switch node via select-logs-node -> resets pause
	if err := tt.Click(a.catalog().LogsActionPause()); err != nil {
		t.Fatalf("pause on svc-hk: %v", err)
	}
	tt.Frame()
	if !a.logsPaused {
		t.Fatalf("expected logsPaused = true on svc-hk")
	}

	if err := tt.Click("select-logs-node"); err != nil {
		t.Fatalf("open select-logs-node: %v", err)
	}
	tt.Frame()
	if err := tt.Click("btn-logs-node-svc-us"); err != nil {
		t.Fatalf("select svc-us: %v", err)
	}
	tt.Frame()
	if a.logsSelectedNodeID != "svc-us" {
		t.Fatalf("expected logsSelectedNodeID = svc-us, got %q", a.logsSelectedNodeID)
	}
	if a.logsPaused {
		t.Fatalf("expected switching node via select-logs-node to reset logsPaused")
	}
	if !tt.HasText("[10:00:02] [WARN] us retrying dial") {
		t.Fatalf("expected svc-us log line rendered after switching node")
	}
}

func TestP2Redesign_IdleFrameBudgetAndWidthsAndLocales(t *testing.T) {
	svc := config.Service{
		ID:         "svc-p2",
		Name:       "HK-Relay",
		Protocol:   config.ProtoNaive,
		Server:     "hk.example.com",
		ServerPort: 443,
		Listens:    []string{"socks://127.0.0.1:10808"},
	}
	a, tt, _ := newTestApp(t, []config.Service{svc})
	a.appendGatewayLog("INFO", "gateway started")
	a.mgr.LogsOf(svc.ID).AppendLine("[12:00:00] [INFO] sidecar ready")

	for _, lang := range []string{locales.LangZhHans, locales.LangEn} {
		a.state.Language = lang
		a.applyLanguagePolicy()
		for _, width := range []int{440, 900} {
			tt.SetSize(width, 660)

			// Insights page idle check
			a.activeTab = TabInsights
			a.insightsShowManageRules = false
			tt.Frame()
			tt.Advance(500 * time.Millisecond)
			if tt.FramePending() {
				t.Fatalf("idle Insights page requested frames (lang=%s width=%d)", lang, width)
			}

			// Insights Manage Rules drawer idle check
			a.insightsShowManageRules = true
			tt.Frame()
			tt.Advance(500 * time.Millisecond)
			if tt.FramePending() {
				t.Fatalf("idle Insights rules drawer requested frames (lang=%s width=%d)", lang, width)
			}
			a.insightsShowManageRules = false
			tt.Frame()

			// Logs Gateway sub-tab idle check
			a.activeTab = TabLogs
			a.logsSubTab = 0
			tt.Frame()
			tt.Advance(500 * time.Millisecond)
			if tt.FramePending() {
				t.Fatalf("idle Logs Gateway view requested frames (lang=%s width=%d)", lang, width)
			}

			// Logs Nodes sub-tab idle check
			a.logsSubTab = 1
			tt.Frame()
			tt.Advance(500 * time.Millisecond)
			if tt.FramePending() {
				t.Fatalf("idle Logs Nodes view requested frames (lang=%s width=%d)", lang, width)
			}
		}
	}
}
