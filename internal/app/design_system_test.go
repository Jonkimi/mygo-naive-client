package app

import (
	"math"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"

	"naive-client/internal/config"
)

func srgbChannelLinear(v uint8) float64 {
	c := float64(v) / 255.0
	if c <= 0.03928 {
		return c / 12.92
	}
	return math.Pow((c+0.055)/1.055, 2.4)
}

func relativeLuminance(col ui.Color) float64 {
	return 0.2126*srgbChannelLinear(col.R) +
		0.7152*srgbChannelLinear(col.G) +
		0.0722*srgbChannelLinear(col.B)
}

func blendOverOpaque(fg, bg ui.Color) ui.Color {
	if fg.A >= 255 {
		return fg
	}
	a := float64(fg.A) / 255.0
	return ui.RGB(
		uint8(math.Round(float64(fg.R)*a+float64(bg.R)*(1-a))),
		uint8(math.Round(float64(fg.G)*a+float64(bg.G)*(1-a))),
		uint8(math.Round(float64(fg.B)*a+float64(bg.B)*(1-a))),
	)
}

func contrastRatio(fg, bg ui.Color) float64 {
	l1 := relativeLuminance(blendOverOpaque(fg, bg))
	l2 := relativeLuminance(bg)
	if l1 < l2 {
		l1, l2 = l2, l1
	}
	return (l1 + 0.05) / (l2 + 0.05)
}

func TestDesignSystem_WCAGContrastAA(t *testing.T) {
	// Light and dark palette foreground/background pairs must meet WCAG AA (>= 4.5:1) to prevent unreadable dimmed or tinted text.
	white := ui.RGB(255, 255, 255)
	palettes := []struct {
		name string
		p    palette
	}{
		{"light", lightPalette},
		{"dark", darkPalette},
	}

	for _, tc := range palettes {
		p := tc.p
		pairs := []struct {
			label string
			fg    ui.Color
			bg    ui.Color
		}{
			{"text on card", p.text, p.card},
			{"text on surface", p.text, p.surface},
			{"textMuted on card", p.textMuted, p.card},
			{"textMuted on surface", p.textMuted, p.surface},
			{"textMuted on elevated", p.textMuted, p.elevated},
			{"textDim on card", p.textDim, p.card},
			{"textDim on surface", p.textDim, p.surface},
			{"textDim on elevated", p.textDim, p.elevated},
			{"textDim on sidebarBg", p.textDim, p.sidebarBg},
			{"white on accent", white, p.accent},
			{"white on red", white, p.red},
			{"accentText on accentBg(card)", p.accentText, blendOverOpaque(p.accentBg, p.card)},
			{"accentText on elevated", p.accentText, p.elevated},
			{"greenText on card", p.greenText, p.card},
			{"greenText on greenBg(card)", p.greenText, blendOverOpaque(p.greenBg, p.card)},
			{"amberText on card", p.amberText, p.card},
			{"amberText on amberBg(card)", p.amberText, blendOverOpaque(p.amberBg, p.card)},
			{"redText on card", p.redText, p.card},
			{"redText on redBg(card)", p.redText, blendOverOpaque(p.redBg, p.card)},
		}
		for _, pair := range pairs {
			ratio := contrastRatio(pair.fg, pair.bg)
			if ratio < 4.5 {
				t.Errorf("%s palette %q contrast %.2f:1 is below WCAG AA 4.5:1", tc.name, pair.label, ratio)
			}
		}
	}
}

func TestDesignSystem_SidebarKeyboardAndAccessibility(t *testing.T) {
	// Expanded sidebar navigation, collapse toggle, and status card rows must expose focusable button roles and settle with zero idle frames.
	a, tt, _ := newTestApp(t, nil)
	tt.Frame()
	cat := a.catalog()

	for _, label := range []string{
		cat.NavNodes(),
		cat.NavRouting(),
		cat.NavInsights(),
		cat.NavTailnet(),
		cat.NavCloudflare(),
		cat.NavLogs(),
		cat.NavSettings(),
		cat.SidebarCollapse(),
		cat.MasterGateway(),
	} {
		node, ok := tt.AccessByRole(ui.RoleButton, label)
		if !ok {
			t.Fatalf("expected RoleButton accessibility node for %q in expanded sidebar", label)
		}
		if !node.Focusable {
			t.Fatalf("expected sidebar button %q to be keyboard focusable", label)
		}
	}

	if err := tt.Click(cat.NavRouting()); err != nil {
		t.Fatalf("click Routing nav button: %v", err)
	}
	tt.Frame()
	if a.activeTab != TabRouting {
		t.Fatalf("expected TabRouting after clicking nav button, got %v", a.activeTab)
	}

	if err := tt.Click(cat.SidebarCollapse()); err != nil {
		t.Fatalf("click collapse sidebar button: %v", err)
	}
	tt.Advance(800 * time.Millisecond)
	tt.Frame()
	if !a.state.SidebarCollapsed {
		t.Fatalf("expected sidebar to be collapsed")
	}
	if tt.FramePending() {
		t.Fatalf("expected no pending animation frames after sidebar collapse settled")
	}
}

func TestDesignSystem_DisabledVsSoftDisabledControls(t *testing.T) {
	// Hard-disabled actionChip must block clicks and remove focusability, while soft-disabled node probe button stays focusable/clickable (AccessDisabled) for tooltip and toast guidance.
	var hardClicks int
	ttChip := ui.NewTester(func(c *ui.Context) {
		p := lightPalette
		if actionChip(c.Key("hard-disabled-chip"), p, nil, "Locked", true).Clicked() {
			hardClicks++
		}
	}, 400, 120)
	ttChip.Frame()
	if lockedNode, ok := ttChip.AccessByRole(ui.RoleButton, "Locked"); !ok || !lockedNode.Disabled || lockedNode.Focusable {
		t.Fatalf("expected hard-disabled actionChip to have Disabled=true Focusable=false, got ok=%v node=%+v", ok, lockedNode)
	}
	_ = ttChip.Click("Locked")
	ttChip.Frame()
	if hardClicks != 0 {
		t.Fatalf("expected disabled actionChip to block clicks, got %d clicks", hardClicks)
	}

	svc := config.Service{
		ID:       "svc-stopped",
		Name:     "Stopped-Node",
		Protocol: config.ProtoVLESS,
		Engine:   config.EngineSingBox,
		Server:   "example.com",
	}
	a, tt, _ := newTestApp(t, []config.Service{svc})
	tt.Frame()
	cat := a.catalog()

	probeNode, ok := tt.AccessByRole(ui.RoleButton, cat.ActionLatency())
	if !ok {
		t.Fatalf("expected RoleButton for soft-disabled latency button")
	}
	if !probeNode.Disabled || !probeNode.Focusable {
		t.Fatalf("expected soft-disabled probe button to be AccessDisabled (Disabled=true, Focusable=true), got %+v", probeNode)
	}
	if err := tt.Click(cat.ActionLatency()); err != nil {
		t.Fatalf("click soft-disabled probe button: %v", err)
	}
	tt.Frame()
	if !tt.HasText(cat.TestRequiresRunning()) {
		t.Fatalf("expected toast %q after clicking stopped probe button", cat.TestRequiresRunning())
	}
}
