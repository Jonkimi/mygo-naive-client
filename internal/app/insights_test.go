package app

import (
	"testing"
	"time"

	"github.com/egoist/mygo/ui"

	"naive-client/internal/blocker"
	"naive-client/internal/config"
)

// Tests that pressing Cmd+3 navigates to TabInsights and displays the Pi-hole dashboard.
func TestInsights_NavigationAndMetricsDashboard(t *testing.T) {
	a, tt, _ := newTestApp(t, []config.Service{})

	// 1. Initial tab is TabNodes
	if a.activeTab != TabNodes {
		t.Fatalf("expected initial tab TabNodes, got %v", a.activeTab)
	}

	// 2. Press Cmd+3 to navigate to TabInsights
	tt.Key(ui.Cmd, ui.Key3)
	tt.Frame()
	if a.activeTab != TabInsights {
		t.Fatalf("expected activeTab TabInsights after Cmd+3, got %v", a.activeTab)
	}

	// 3. Inject queries into blocker logger
	now := time.Now()
	a.blocker.Logger().RecordAt("ad.doubleclick.net", blocker.SourceDNS, blocker.VerdictBlocked, "category-ads-all", now)
	a.blocker.Logger().RecordAt("tracker.analytics.com", blocker.SourceGateway, blocker.VerdictBlocked, "ad-rule", now)
	a.blocker.Logger().RecordAt("api.github.com", blocker.SourceGateway, blocker.VerdictAllowed, "", now)
	a.blocker.Logger().RecordAt("my-nas.ts.net", blocker.SourceDNS, blocker.VerdictWhitelisted, blocker.RuleTailnetBypass, now)

	tt.Frame()

	// Verify Summary stats reflect queries
	tot, blk := a.blocker.Logger().GetStatsSummary()
	if tot != 4 || blk != 2 {
		t.Fatalf("expected total 4, blocked 2, got (%d, %d)", tot, blk)
	}

	// 4. Test Top Blocked quick-whitelist button
	if err := tt.Click("btn-quick-whitelist-ad.doubleclick.net"); err != nil {
		t.Fatalf("failed to click quick-whitelist button: %v", err)
	}
	tt.Frame()

	// Verify ad.doubleclick.net is now in allowlist
	if !a.blockerMatchesAllowlist("ad.doubleclick.net") {
		t.Fatalf("expected ad.doubleclick.net to be in allowlist after quick-whitelist click")
	}

	// 5. Test Top Allowed quick-denylist button
	if err := tt.Click("btn-quick-denylist-api.github.com"); err != nil {
		t.Fatalf("failed to click quick-denylist button: %v", err)
	}
	tt.Frame()

	// Verify api.github.com is now in denylist
	if !a.blockerMatchesDenylist("api.github.com") {
		t.Fatalf("expected api.github.com to be in denylist after quick-denylist click")
	}

	// 6. Test Blocker Enable/Disable toggle
	if err := tt.Click("btn-toggle-blocker"); err != nil {
		t.Fatalf("failed to click btn-toggle-blocker: %v", err)
	}
	tt.Frame()

	if a.state.BlockerEnabled {
		t.Fatalf("expected BlockerEnabled to be false after toggle")
	}
	if a.blocker.IsEnabled() {
		t.Fatalf("expected blocker engine to be disabled")
	}
}

// Tests live query log filter buttons (All, Blocked, Allowed).
func TestInsights_LogFilterAndSearch(t *testing.T) {
	a, tt, _ := newTestApp(t, []config.Service{})

	a.activeTab = TabInsights
	tt.Frame()

	a.blocker.Logger().Record("bad1.com", blocker.SourceDNS, blocker.VerdictBlocked, "ad-rule")
	a.blocker.Logger().Record("good1.com", blocker.SourceGateway, blocker.VerdictAllowed, "")
	tt.Frame()

	// Switch filter to "blocked"
	if err := tt.Click("btn-filter-blocked"); err != nil {
		t.Fatalf("failed to click btn-filter-blocked: %v", err)
	}
	tt.Frame()

	if a.insightsFilter != "blocked" {
		t.Fatalf("expected insightsFilter to be 'blocked', got %q", a.insightsFilter)
	}

	// Switch filter to "allowed"
	if err := tt.Click("btn-filter-allowed"); err != nil {
		t.Fatalf("failed to click btn-filter-allowed: %v", err)
	}
	tt.Frame()

	if a.insightsFilter != "allowed" {
		t.Fatalf("expected insightsFilter to be 'allowed', got %q", a.insightsFilter)
	}
}

// Tests adding and removing rules in the rule management drawer.
func TestInsights_RuleManagementDrawer(t *testing.T) {
	a, tt, _ := newTestApp(t, []config.Service{})

	a.activeTab = TabInsights
	tt.Frame()

	// Open rule management
	if err := tt.Click("btn-manage-rules"); err != nil {
		t.Fatalf("failed to click btn-manage-rules: %v", err)
	}
	tt.Frame()

	if !a.insightsShowManageRules {
		t.Fatalf("expected insightsShowManageRules to be true")
	}

	// Add manual domain to allowlist
	a.blockerAllowlistInput = "custom-allowed.com"
	if err := tt.Click("btn-add-allowlist"); err != nil {
		t.Fatalf("failed to click btn-add-allowlist: %v", err)
	}
	tt.Frame()

	if !a.blockerMatchesAllowlist("custom-allowed.com") {
		t.Fatalf("expected custom-allowed.com in allowlist")
	}

	// Delete from allowlist
	if err := tt.Click("btn-del-allowlist-custom-allowed.com"); err != nil {
		t.Fatalf("failed to click btn-del-allowlist: %v", err)
	}
	tt.Frame()

	if a.blockerMatchesAllowlist("custom-allowed.com") {
		t.Fatalf("expected custom-allowed.com removed from allowlist")
	}
}
