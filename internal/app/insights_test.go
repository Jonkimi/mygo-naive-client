package app

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"

	"naive-client/internal/blocker"
	"naive-client/internal/config"
	"naive-client/internal/telemetry"
	"naive-client/locales"
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

// Tests that Top Blocked Domains panel and Top Allowed Domains panel are equal in height,
// even when they contain an uneven number of items.
func TestInsights_TopPanelsEqualHeight(t *testing.T) {
	a, tt, _ := newTestApp(t, []config.Service{})

	a.activeTab = TabInsights
	tt.Frame()

	// 5 blocked items vs 1 allowed item
	for i := 1; i <= 5; i++ {
		a.blocker.Logger().Record(fmt.Sprintf("blocked-%d.com", i), blocker.SourceDNS, blocker.VerdictBlocked, "ad-rule")
	}
	a.blocker.Logger().Record("only-allowed.com", blocker.SourceGateway, blocker.VerdictAllowed, "")
	tt.Frame()

	rectBlocked, ok1 := tt.Find("panel-top-blocked")
	if !ok1 {
		t.Fatalf("expected panel-top-blocked")
	}
	rectAllowed, ok2 := tt.Find("panel-top-allowed")
	if !ok2 {
		t.Fatalf("expected panel-top-allowed")
	}

	if rectBlocked.H != rectAllowed.H {
		t.Fatalf("expected top blocked and allowed panels to be equal height, got blocked=%.1f allowed=%.1f",
			rectBlocked.H, rectAllowed.H)
	}
}

// Tests that abnormal connection failure cards display up to maxInsightsFailures, show total counts,
// and that individual ignore and resolve-all buttons resolve failures and remove them from the view.
// Regression: renderInsightsFailures previously rendered all failures (including resolved ones) causing screen flood
// and making the ignore button appear unresponsive.
func TestInsights_FailuresIgnoreAndResolveAll(t *testing.T) {
	a, tt, _ := newTestApp(t, []config.Service{})
	a.activeTab = TabInsights
	tt.Frame()

	// 1. Record 7 failures into failureMonitor
	for i := 1; i <= 7; i++ {
		a.failureMonitor.Record(telemetry.FailureEvent{
			Category:       telemetry.FailureProxy,
			Target:         fmt.Sprintf("host%d.example.com", i),
			Port:           443,
			OriginalAction: "PROXY_POOL",
			Error:          errors.New("connection timeout"),
		})
	}
	tt.Frame()

	// Total count 7 should be displayed, and the first 5 items rendered
	if !tt.HasText("共 7 项异常") {
		t.Fatalf("expected '共 7 项异常', got texts: %v", tt.Texts())
	}
	if !tt.HasText("已显示前 5 项，还有 2 项异常") {
		t.Fatalf("expected overflow text '已显示前 5 项，还有 2 项异常'")
	}
	if !tt.HasText("host7.example.com") {
		t.Fatalf("expected newest failure host7.example.com to be rendered")
	}

	// 2. Click ignore button for the newest item (host7.example.com)
	if err := tt.Click("btn-resolve-host7.example.com"); err != nil {
		t.Fatalf("failed to click btn-resolve-host7.example.com: %v", err)
	}
	tt.Frame()

	// host7 should now be resolved and removed from the active failures
	if tt.HasText("host7.example.com") {
		t.Fatalf("expected host7.example.com to disappear after being ignored")
	}
	if !tt.HasText("共 6 项异常") {
		t.Fatalf("expected '共 6 项异常' after resolving 1 item")
	}

	// 3. Click resolve-all button
	if err := tt.Click("btn-resolve-all-failures"); err != nil {
		t.Fatalf("failed to click btn-resolve-all-failures: %v", err)
	}
	tt.Frame()

	// All failures should be resolved and the entire card hidden
	if tt.HasText("异常连接与分流诊断") {
		t.Fatalf("expected failure diagnostics card to disappear after resolve-all")
	}
	if a.failureMonitor.UnresolvedCount() != 0 {
		t.Fatalf("expected 0 unresolved count, got %d", a.failureMonitor.UnresolvedCount())
	}
}

func encodeTestBytesField(fieldNum int, data []byte) []byte {
	val := uint64((fieldNum << 3) | 2)
	var out []byte
	buf := make([]byte, 10)
	n := binary.PutUvarint(buf, val)
	out = append(out, buf[:n]...)
	n = binary.PutUvarint(buf, uint64(len(data)))
	out = append(out, buf[:n]...)
	out = append(out, data...)
	return out
}

func encodeTestVarintField(fieldNum int, v uint64) []byte {
	val := uint64((fieldNum << 3) | 0)
	var out []byte
	buf := make([]byte, 10)
	n := binary.PutUvarint(buf, val)
	out = append(out, buf[:n]...)
	n = binary.PutUvarint(buf, v)
	out = append(out, buf[:n]...)
	return out
}

// Tests that enabling and disabling built-in ad blocking or protection shares a single GeoSiteDB instance and releases cachedAdsRules when turned off.
// Regression: setBlockerBlockAds previously ran syncBlockerRules before saveState, loading a duplicate GeoSiteDB copy and never clearing cachedAdsRules on disable.
func TestInsights_BlockerSharesAndReleasesGeoAdsMemory(t *testing.T) {
	a, _, _ := newTestApp(t, []config.Service{})

	// Write a mock geosite.dat containing CATEGORY-ADS-ALL and CN
	var domAd []byte
	domAd = append(domAd, encodeTestVarintField(1, 2)...)
	domAd = append(domAd, encodeTestBytesField(2, []byte("doubleclick.net"))...)
	var entryAds []byte
	entryAds = append(entryAds, encodeTestBytesField(1, []byte("CATEGORY-ADS-ALL"))...)
	entryAds = append(entryAds, encodeTestBytesField(2, domAd)...)

	var domCN []byte
	domCN = append(domCN, encodeTestVarintField(1, 2)...)
	domCN = append(domCN, encodeTestBytesField(2, []byte("baidu.com"))...)
	var entryCN []byte
	entryCN = append(entryCN, encodeTestBytesField(1, []byte("CN"))...)
	entryCN = append(entryCN, encodeTestBytesField(2, domCN)...)

	var geoSiteList []byte
	geoSiteList = append(geoSiteList, encodeTestBytesField(1, entryAds)...)
	geoSiteList = append(geoSiteList, encodeTestBytesField(1, entryCN)...)

	geoDir := a.geodataDir()
	if err := os.MkdirAll(geoDir, 0o755); err != nil {
		t.Fatalf("mkdir geodata: %v", err)
	}
	if err := os.WriteFile(filepath.Join(geoDir, "geosite.dat"), geoSiteList, 0o644); err != nil {
		t.Fatalf("write geosite.dat: %v", err)
	}

	// Start with ad blocking disabled
	a.setBlockerBlockAds(false)
	if a.cachedAdsRules != nil {
		t.Fatalf("expected cachedAdsRules to be nil when BlockerBlockAds is false")
	}
	if a.cachedSiteDB != nil && a.cachedSiteDB.HasTag("category-ads-all") {
		t.Fatalf("expected cachedSiteDB not to hold category-ads-all when disabled")
	}

	// Enable ad blocking: cachedSiteDB and cachedAdsRules.GeoAds must point to the exact same GeoSiteDB
	a.setBlockerBlockAds(true)
	if a.cachedSiteDB == nil || !a.cachedSiteDB.HasTag("category-ads-all") {
		t.Fatalf("expected cachedSiteDB to load category-ads-all when enabled")
	}
	if a.cachedAdsRules == nil || a.cachedAdsRules.GeoAds != a.cachedSiteDB {
		t.Fatalf("expected cachedAdsRules.GeoAds (%p) to share the exact same pointer as cachedSiteDB (%p)",
			a.cachedAdsRules.GeoAds, a.cachedSiteDB)
	}
	if a.blocker.RuleCount() == 0 {
		t.Fatalf("expected blocker RuleCount > 0 when enabled")
	}

	// Pause protection: cachedAdsRules and blocker ruleset must be cleared
	a.toggleBlockerEnabled()
	if a.cachedAdsRules != nil {
		t.Fatalf("expected cachedAdsRules to be nil when protection is paused")
	}
	if a.blocker.RuleCount() != 0 {
		t.Fatalf("expected blocker RuleCount == 0 when protection is paused, got %d", a.blocker.RuleCount())
	}

	// Re-enable protection, then disable ad blocking: both cachedAdsRules and category-ads-all in cachedSiteDB must be released
	a.toggleBlockerEnabled()
	if a.cachedAdsRules == nil || a.cachedAdsRules.GeoAds != a.cachedSiteDB {
		t.Fatalf("expected cachedAdsRules to re-bind to cachedSiteDB when protection is re-enabled")
	}
	a.setBlockerBlockAds(false)
	if a.cachedAdsRules != nil {
		t.Fatalf("expected cachedAdsRules to be cleared when BlockerBlockAds is disabled")
	}
	if a.cachedSiteDB != nil && a.cachedSiteDB.HasTag("category-ads-all") {
		t.Fatalf("expected category-ads-all to be unloaded from cachedSiteDB when disabled")
	}
}

// Tests that switching language dynamically updates Insights page labels between English and Simplified Chinese.
func TestInsights_I18nLanguageSwitching(t *testing.T) {
	a, tt, _ := newTestApp(t, []config.Service{})

	a.activeTab = TabInsights
	tt.Frame()

	// 1. Initial language is zh-Hans
	if !tt.HasText(locales.In("zh-Hans").InsightsProtectionActive()) {
		t.Fatalf("expected Chinese '防护运行中' in Insights, got texts: %v", tt.Texts())
	}
	if !tt.HasText(locales.In("zh-Hans").InsightsKpi24hQueries()) {
		t.Fatalf("expected Chinese '24h 总查询/连接' in Insights, got texts: %v", tt.Texts())
	}

	// 2. Switch to English
	a.state.Language = locales.LangEn
	a.applyLanguagePolicy()
	tt.Frame()

	if !tt.HasText(locales.In("en").InsightsProtectionActive()) {
		t.Fatalf("expected English 'Protection Active' in Insights, got texts: %v", tt.Texts())
	}
	if !tt.HasText(locales.In("en").InsightsKpi24hQueries()) {
		t.Fatalf("expected English '24h Total Queries' in Insights, got texts: %v", tt.Texts())
	}
}

// Tests that the 24-hour activity trend chart displays X-axis timestamps, current hour label,
// and shows peak query metrics when queries are recorded.
// Regression: renderInsightsTrendChart previously lacked X-axis time labels, lacked peak scale indication,
// and had mismatched legend colors.
func TestInsights_TrendChartLayoutAndXAxis(t *testing.T) {
	a, tt, _ := newTestApp(t, []config.Service{})
	a.activeTab = TabInsights
	tt.Frame()

	// Initial state with 0 queries should render X-axis labels with "现在"
	if !tt.HasText("现在") {
		t.Fatalf("expected X-axis to contain '现在', got texts: %v", tt.Texts())
	}

	// Record queries in current hour
	now := time.Now()
	a.blocker.Logger().RecordAt("ad.test.com", blocker.SourceDNS, blocker.VerdictBlocked, "ad-rule", now)
	a.blocker.Logger().RecordAt("api.test.com", blocker.SourceGateway, blocker.VerdictAllowed, "", now)
	a.blocker.Logger().RecordAt("cdn.test.com", blocker.SourceGateway, blocker.VerdictAllowed, "", now)
	tt.Frame()

	// Peak indicator should now be displayed
	if !tt.HasText("峰值: 3/时") {
		t.Fatalf("expected peak tag '峰值: 3/时', got texts: %v", tt.Texts())
	}

	// Switch to English and verify peak and Now labels
	a.state.Language = locales.LangEn
	a.applyLanguagePolicy()
	tt.Frame()

	if !tt.HasText("Peak: 3/h") {
		t.Fatalf("expected 'Peak: 3/h' in English, got texts: %v", tt.Texts())
	}
	if !tt.HasText("Now") {
		t.Fatalf("expected 'Now' on X-axis in English, got texts: %v", tt.Texts())
	}
}


