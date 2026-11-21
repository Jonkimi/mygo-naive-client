package app

import (
	"context"
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/sagernet/tailscale/ipn/ipnstate"
	"github.com/sagernet/tailscale/tailcfg"
	"github.com/sagernet/tailscale/types/key"

	"naive-client/internal/config"
	"naive-client/internal/tailnet"
	"naive-client/locales"
)

func TestP3Redesign_TailnetCopyAddressAndPeerStatus(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)

	kOnline := key.NewNode().Public()
	kOffline := key.NewNode().Public()
	mockClient := &mockAppHostClient{
		statusFunc: func(ctx context.Context) (*ipnstate.Status, error) {
			return &ipnstate.Status{
				BackendState:   "Running",
				MagicDNSSuffix: "testnet.ts.net",
				Self: &ipnstate.PeerStatus{
					HostName:     "raw-mac",
					DNSName:      "my-mac.testnet.ts.net.",
					TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.10")},
					Online:       true,
				},
				Peer: map[key.NodePublic]*ipnstate.PeerStatus{
					kOnline: {
						ID:             tailcfg.StableNodeID("peer-online"),
						HostName:       "raw-sg",
						DNSName:        "sg-exit.testnet.ts.net.",
						OS:             "linux",
						TailscaleIPs:   []netip.Addr{netip.MustParseAddr("100.64.0.20")},
						Online:         true,
						ExitNodeOption: true,
					},
					kOffline: {
						ID:           tailcfg.StableNodeID("peer-offline"),
						HostName:     "raw-win",
						DNSName:      "win-laptop.testnet.ts.net.",
						OS:           "windows",
						TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.30")},
						Online:       false,
					},
				},
			}, nil
		},
	}

	a.state.TailnetEnabled = true
	a.state.TailnetMode = string(tailnet.ModeHost)
	det := tailnet.NewDetectorWithClient(mockClient)
	a.tailnetMgr = tailnet.NewManager(tailnet.Config{Enabled: true, Mode: tailnet.ModeHost}, det)
	a.tailnetMgr.Refresh(context.Background())

	a.activeTab = TabTailnet
	tt.Frame()

	cat := a.catalog()
	if !tt.HasText(cat.TailnetOnlinePeersSummary(1, 2)) {
		t.Fatalf("expected online peers summary %q, got texts: %v", cat.TailnetOnlinePeersSummary(1, 2), tt.Texts())
	}
	if !tt.HasText(cat.TailnetPeerOffline()) {
		t.Fatalf("expected offline marker %q for offline peer, got texts: %v", cat.TailnetPeerOffline(), tt.Texts())
	}

	if err := tt.Click("btn-copy-tailnet-addr"); err != nil {
		t.Fatalf("click btn-copy-tailnet-addr: %v", err)
	}
	tt.Frame()
	if a.clipboardMem != "100.64.0.10" {
		t.Fatalf("expected clipboard = 100.64.0.10, got %q", a.clipboardMem)
	}
	if !tt.HasText(cat.TailnetAddressCopied()) {
		t.Fatalf("expected toast %q after copying address, got texts: %v", cat.TailnetAddressCopied(), tt.Texts())
	}
}

func TestP3Redesign_SettingsTabsAdvancedAndContextJumps(t *testing.T) {
	svc := config.Service{
		ID:       "svc-ctx",
		Name:     "HK-Missing-Core",
		Protocol: config.ProtoNaive,
		Engine:   config.EngineSidecar,
		Listens:  []string{"socks://127.0.0.1:10805"},
		Proxies:  []string{"https://user:pass@proxy.example.com:443"},
	}
	a, tt, _ := newTestApp(t, []config.Service{svc})
	a.mgr.SetError(svc.ID, "未找到 naive 核心文件，请先点击顶部栏下载安装")
	tt.Frame()

	cat := a.catalog()

	// 1. Sidebar Gateway row jumps directly to Settings -> Gateway & DoH (tab 1)
	if err := tt.Click(cat.MasterGateway()); err != nil {
		t.Fatalf("click MasterGateway: %v", err)
	}
	tt.Frame()
	if a.activeTab != TabSettings || a.settingsSubTab != 1 {
		t.Fatalf("expected Gateway jump to TabSettings tab 1, got activeTab=%v subTab=%d", a.activeTab, a.settingsSubTab)
	}

	// 2. Node error card GoToSettings jumps directly to Settings -> Core Engines (tab 2)
	tt.Key(ui.Cmd, ui.Key1)
	tt.Frame()
	if err := tt.Click("btn-goto-settings-" + svc.ID); err != nil {
		t.Fatalf("click btn-goto-settings-%s: %v", svc.ID, err)
	}
	tt.Frame()
	if a.activeTab != TabSettings || a.settingsSubTab != 2 {
		t.Fatalf("expected Core error jump to TabSettings tab 2, got activeTab=%v subTab=%d", a.activeTab, a.settingsSubTab)
	}

	// 3. NaiveProxy & Xray advanced panels collapse by default and expand/collapse on toggle
	if tt.HasText(cat.CustomCorePathLabel()) {
		t.Fatalf("expected NaiveProxy custom path collapsed by default")
	}
	if err := tt.Click("btn-toggle-naive-adv"); err != nil {
		t.Fatalf("click btn-toggle-naive-adv: %v", err)
	}
	tt.Frame()
	if !a.settingsExpandNaiveAdv || !tt.HasText(cat.CustomCorePathLabel()) || !tt.HasText(cat.CoreAutoCheckLabel()) {
		t.Fatalf("expected NaiveProxy advanced panel expanded")
	}
	if err := tt.Click("btn-toggle-naive-adv"); err != nil {
		t.Fatalf("collapse btn-toggle-naive-adv: %v", err)
	}
	tt.Frame()
	if a.settingsExpandNaiveAdv || tt.HasText(cat.CustomCorePathLabel()) {
		t.Fatalf("expected NaiveProxy advanced panel collapsed")
	}

	if err := tt.Click("btn-toggle-xray-adv"); err != nil {
		t.Fatalf("click btn-toggle-xray-adv: %v", err)
	}
	tt.Frame()
	if !a.settingsExpandXrayAdv || !tt.HasText(cat.CustomXrayPathLabel()) || !tt.HasText(cat.XrayAutoCheckLabel()) {
		t.Fatalf("expected Xray advanced panel expanded")
	}
	if err := tt.Click("btn-toggle-xray-adv"); err != nil {
		t.Fatalf("collapse btn-toggle-xray-adv: %v", err)
	}
	tt.Frame()
	if a.settingsExpandXrayAdv || tt.HasText(cat.CustomXrayPathLabel()) {
		t.Fatalf("expected Xray advanced panel collapsed")
	}

	// 4. Clicking all 4 Segmented Settings tabs updates settingsSubTab cleanly
	tabs := []struct {
		label string
		want  int
	}{
		{cat.SettingsTabGeneral(), 0},
		{cat.SettingsTabGateway(), 1},
		{cat.SettingsTabCore(), 2},
		{cat.SettingsTabTelemetry(), 3},
	}
	for _, tc := range tabs {
		if err := tt.Click(tc.label); err != nil {
			t.Fatalf("click settings tab %q: %v", tc.label, err)
		}
		tt.Frame()
		if a.settingsSubTab != tc.want {
			t.Fatalf("expected settingsSubTab = %d after clicking %q, got %d", tc.want, tc.label, a.settingsSubTab)
		}
	}
}

func TestP3Redesign_IdleFrameBudgetAndWidthsAndLocales(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)

	kPeer := key.NewNode().Public()
	mockClient := &mockAppHostClient{
		statusFunc: func(ctx context.Context) (*ipnstate.Status, error) {
			return &ipnstate.Status{
				BackendState:   "Running",
				MagicDNSSuffix: "testnet.ts.net",
				Self: &ipnstate.PeerStatus{
					DNSName:      "mac.testnet.ts.net.",
					TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
					Online:       true,
				},
				Peer: map[key.NodePublic]*ipnstate.PeerStatus{
					kPeer: {
						ID:             tailcfg.StableNodeID("peer-1"),
						DNSName:        "peer.testnet.ts.net.",
						OS:             "linux",
						TailscaleIPs:   []netip.Addr{netip.MustParseAddr("100.64.0.2")},
						Online:         true,
						ExitNodeOption: true,
					},
				},
			}, nil
		},
	}
	a.state.TailnetEnabled = true
	a.state.TailnetMode = string(tailnet.ModeEmbedded)
	a.tailnetMgr = tailnet.NewManager(tailnet.Config{Enabled: true, Mode: tailnet.ModeEmbedded}, tailnet.NewDetectorWithClient(mockClient))
	a.tailnetMgr.Refresh(context.Background())

	for _, lang := range []string{locales.LangZhHans, locales.LangEn} {
		a.state.Language = lang
		a.applyLanguagePolicy()
		for _, width := range []int{440, 900} {
			tt.SetSize(width, 660)

			// Tailnet idle check
			a.activeTab = TabTailnet
			tt.Frame()
			tt.Advance(500 * time.Millisecond)
			if tt.FramePending() {
				t.Fatalf("idle Tailnet page requested frames (lang=%s width=%d)", lang, width)
			}

			// All 4 Settings tabs idle checks (including expanded Core advanced section)
			a.activeTab = TabSettings
			for sub := 0; sub < 4; sub++ {
				a.settingsSubTab = sub
				a.settingsExpandNaiveAdv = (sub == 2)
				a.settingsExpandXrayAdv = (sub == 2)
				tt.Frame()
				tt.Advance(500 * time.Millisecond)
				if tt.FramePending() {
					t.Fatalf("idle Settings tab %d requested frames (lang=%s width=%d)", sub, lang, width)
				}
			}
		}
	}
}

func TestUnifiedSegmentedHierarchyAndInteraction(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)
	tt.SetSize(900, 660)

	// 1. Settings page: Header tabs and General form controls share standard ~28px height,
	//    and Light vs Dark themes preserve identical segment height (borderless).
	a.activeTab = TabSettings
	a.settingsSubTab = 0
	a.state.Appearance = appearanceLight
	tt.Frame()

	cat := a.catalog()
	stdHeaderRect, ok1 := tt.Find(cat.SettingsTabGeneral())
	stdFormRect, ok2 := tt.Find(cat.LanguageSystem())
	if !ok1 || !ok2 {
		t.Fatalf("expected Settings segmented controls visible, ok1=%v ok2=%v", ok1, ok2)
	}
	if diff := math.Abs(float64(stdHeaderRect.H - stdFormRect.H)); diff > 1 {
		t.Fatalf("expected Settings header and form segments to share standard height, diff=%.2f (header=%.1f form=%.1f)",
			diff, stdHeaderRect.H, stdFormRect.H)
	}

	if err := tt.Click(cat.LanguageEn()); err != nil {
		t.Fatalf("click LanguageEn: %v", err)
	}
	tt.Frame()
	if a.state.Language != locales.LangEn {
		t.Fatalf("expected Language = en after click, got %q", a.state.Language)
	}
	if err := tt.Click(a.catalog().AppearanceDark()); err != nil {
		t.Fatalf("click AppearanceDark: %v", err)
	}
	tt.Frame()
	if a.state.Appearance != appearanceDark {
		t.Fatalf("expected Appearance = dark after click, got %q", a.state.Appearance)
	}
	darkHeaderRect, okDark := tt.Find(a.catalog().SettingsTabGeneral())
	if !okDark {
		t.Fatalf("expected Settings header segment visible in dark theme")
	}
	if diff := math.Abs(float64(stdHeaderRect.H - darkHeaderRect.H)); diff > 1 {
		t.Fatalf("expected light and dark segmented controls to have identical height, diff=%.2f (light=%.1f dark=%.1f)",
			diff, stdHeaderRect.H, darkHeaderRect.H)
	}
	a.state.Language = locales.LangZhHans
	a.state.Appearance = appearanceSystem
	a.applyLanguagePolicy()
	tt.Frame()

	// 2. Cloudflare page: Standard header segment is taller than compact embedded WARP/Tunnel tile segments,
	//    and both compact tiles share identical height.
	cat = a.catalog()
	a.activeTab = TabCloudflare
	a.cloudflareSubTab = 0
	tt.Frame()

	stdCfRect, okCf1 := tt.Find(cat.CloudflareSubtabWarp())
	cmpWarpRect, okCf2 := tt.Find(cat.CloudflareWarpTransportMasque())
	if !okCf1 || !okCf2 {
		t.Fatalf("expected Cloudflare segmented controls visible, ok1=%v ok2=%v", okCf1, okCf2)
	}
	if stdCfRect.H <= cmpWarpRect.H {
		t.Fatalf("expected Cloudflare standard header segment taller than compact tile segment, std=%.1f cmp=%.1f",
			stdCfRect.H, cmpWarpRect.H)
	}

	a.cloudflareSubTab = 1
	tt.Frame()
	cmpTunRect, okTun := tt.Find("QUIC")
	if !okTun {
		t.Fatalf("expected Tunnel compact protocol segment 'QUIC'")
	}
	if diff := math.Abs(float64(cmpWarpRect.H - cmpTunRect.H)); diff > 1 {
		t.Fatalf("expected consistent compact height across WARP and Tunnel tiles, diff=%.2f (warp=%.1f tunnel=%.1f)",
			diff, cmpWarpRect.H, cmpTunRect.H)
	}

	// 3. Logs Layer 2 filter matches standard height and Insights compact filter keeps zero idle FramePending
	a.activeTab = TabLogs
	a.logsSubTab = 0
	tt.Frame()
	logsHeaderRect, okLH := tt.Find(cat.LogsTabGateway())
	logsFilterRect, okLF := tt.Find("btn-logs-filter-error")
	if !okLH || !okLF {
		t.Fatalf("expected Logs segments visible, header=%v filter=%v", okLH, okLF)
	}
	if diff := math.Abs(float64(logsHeaderRect.H - logsFilterRect.H)); diff > 1 {
		t.Fatalf("expected Logs Layer 2 filter segment to match standard height, diff=%.2f (header=%.1f filter=%.1f)",
			diff, logsHeaderRect.H, logsFilterRect.H)
	}
	if err := tt.Click("btn-logs-filter-error"); err != nil {
		t.Fatalf("click btn-logs-filter-error: %v", err)
	}
	tt.Frame()
	if a.logsLevelFilter != "error" {
		t.Fatalf("expected logsLevelFilter = 'error', got %q", a.logsLevelFilter)
	}
	tt.Advance(500 * time.Millisecond)
	tt.Frame()
	if tt.FramePending() {
		t.Fatalf("expected zero idle frames on Logs after filter click")
	}

	a.activeTab = TabInsights
	tt.Frame()
	if err := tt.Click("btn-filter-blocked"); err != nil {
		t.Fatalf("click btn-filter-blocked: %v", err)
	}
	tt.Frame()
	if a.insightsFilter != "blocked" {
		t.Fatalf("expected insightsFilter = 'blocked', got %q", a.insightsFilter)
	}
	tt.Advance(500 * time.Millisecond)
	tt.Frame()
	if tt.FramePending() {
		t.Fatalf("expected zero idle frames on Insights after filter click")
	}
}
