package app

import (
	"testing"
	"time"

	"github.com/egoist/mygo/ui"

	"naive-client/internal/config"
	"naive-client/internal/routing"
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

			// Cloudflare page idle check
			a.activeTab = TabCloudflare
			a.cloudflareSubTab = 0
			tt.Frame()
			tt.Advance(500 * time.Millisecond)
			if tt.FramePending() {
				t.Fatalf("idle Cloudflare page requested frames (lang=%s width=%d)", lang, width)
			}
		}
	}
}
