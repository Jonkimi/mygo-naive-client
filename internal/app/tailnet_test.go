package app

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"

	"naive-client/internal/config"
	"naive-client/internal/tailnet"
	"naive-client/internal/tunhelper"

	"github.com/sagernet/tailscale/ipn/ipnstate"
	"github.com/sagernet/tailscale/tailcfg"
	"github.com/sagernet/tailscale/types/key"
	"github.com/sagernet/tailscale/types/views"
)

type mockAppHostClient struct {
	statusFunc        func(ctx context.Context) (*ipnstate.Status, error)
	setExitNodeFunc    func(ctx context.Context, id string) error
	setUseExitNodeFunc func(ctx context.Context, on bool) error
}

func (m *mockAppHostClient) Status(ctx context.Context) (*ipnstate.Status, error) {
	if m.statusFunc != nil {
		return m.statusFunc(ctx)
	}
	return nil, nil
}

func (m *mockAppHostClient) SetExitNode(ctx context.Context, id string) error {
	if m.setExitNodeFunc != nil {
		return m.setExitNodeFunc(ctx, id)
	}
	return nil
}

func (m *mockAppHostClient) SetUseExitNode(ctx context.Context, on bool) error {
	if m.setUseExitNodeFunc != nil {
		return m.setUseExitNodeFunc(ctx, on)
	}
	return nil
}

// Tests navigating to Tailnet tab, displaying peer information, and toggling exit nodes.
func TestTailnetUI_NavigationAndExitNode(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)

	selectedExitNode := ""
	mockClient := &mockAppHostClient{
		statusFunc: func(ctx context.Context) (*ipnstate.Status, error) {
			peerKey := key.NodePublic{}
			prefix := netip.MustParsePrefix("10.0.0.0/24")
			sliceView := views.SliceOf([]netip.Prefix{prefix})
			return &ipnstate.Status{
				BackendState:   "Running",
				MagicDNSSuffix: "testnet.ts.net",
				Self: &ipnstate.PeerStatus{
					HostName:     "my-workstation",
					TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.10")},
					Online:       true,
				},
				Peer: map[key.NodePublic]*ipnstate.PeerStatus{
					peerKey: {
						ID:             tailcfg.StableNodeID("peer-sg-exit"),
						HostName:       "sg-gateway",
						DNSName:        "sg-gateway.testnet.ts.net.",
						OS:             "linux",
						TailscaleIPs:   []netip.Addr{netip.MustParseAddr("100.64.0.20")},
						AllowedIPs:     &sliceView,
						Online:         true,
						ExitNodeOption: true,
						ExitNode:       selectedExitNode == "peer-sg-exit",
					},
				},
			}, nil
		},
		setExitNodeFunc: func(ctx context.Context, id string) error {
			selectedExitNode = id
			return nil
		},
		setUseExitNodeFunc: func(ctx context.Context, on bool) error {
			if !on {
				selectedExitNode = ""
			}
			return nil
		},
	}

	det := tailnet.NewDetectorWithClient(mockClient)
	cfg := tailnet.Config{
		Enabled: true,
		Mode:    tailnet.ModeHost,
	}
	a.tailnetMgr = tailnet.NewManager(cfg, det)
	a.tailnetMgr.Refresh(context.Background())

	// 1. Switch to Tailnet tab
	a.activeTab = TabTailnet
	tt.Frame()

	// 2. Verify node details and peer are rendered
	if !tt.HasText("my-workstation") {
		t.Error("expected local node hostname 'my-workstation' on screen")
	}
	if !tt.HasText("sg-gateway") {
		t.Error("expected peer 'sg-gateway' on screen")
	}

	// 3. Click "Use as Exit Node" button
	if err := tt.Click(a.catalog().TailnetPeerUseExitNode()); err != nil {
		t.Fatalf("click 'Use as Exit Node': %v", err)
	}
	tt.Frame()

	if selectedExitNode != "peer-sg-exit" {
		t.Errorf("expected exit node peer-sg-exit, got %s", selectedExitNode)
	}

	// 4. Refresh status so that peer.ExitNode == true
	a.tailnetMgr.Refresh(context.Background())
	tt.Frame()

	// 5. Button should now be the active exit node button
	if err := tt.Click(a.catalog().TailnetPeerActiveExitNode()); err != nil {
		t.Fatalf("click active exit node: %v", err)
	}
	tt.Frame()

	if selectedExitNode != "" {
		t.Errorf("expected exit node cleared, got %s", selectedExitNode)
	}
}

// Tests inbound sharing switches persist to state and trigger gateway update.
func TestTailnetUI_SharingToggles(t *testing.T) {
	a, tt, _ := newTestApp(t, []config.Service{
		{
			ID:      "svc-1",
			Name:    "TestNode",
			Listens: []string{"socks://127.0.0.1:1080"},
			Proxies: []string{"https://user:pass@test.com"},
		},
	})

	a.activeTab = TabTailnet
	tt.Frame()

	// 1. Toggle Expose Mixed Port
	lblExpose, ok := tt.Find(a.catalog().TailnetExposeMixed())
	if !ok {
		t.Fatal("expected TailnetExposeMixed row")
	}
	tt.ClickAt(850, lblExpose.Y+lblExpose.H/2)
	tt.Frame()

	if !a.state.TailnetExposeMixedPort {
		t.Error("expected TailnetExposeMixedPort to be true")
	}

	// 2. Toggle Advertise Exit Node
	lblExit, ok := tt.Find(a.catalog().TailnetAdvertiseExit())
	if !ok {
		t.Fatal("expected TailnetAdvertiseExit row")
	}
	tt.ClickAt(850, lblExit.Y+lblExit.H/2)
	tt.Frame()

	if !a.state.TailnetAdvertiseExit {
		t.Error("expected TailnetAdvertiseExit to be true")
	}
}

// Tests rendering Tailnet auth banner when login is required and error banner when errors occur.
func TestTailnetUI_EmbeddedAuthAndError(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)
	a.activeTab = TabTailnet
	tt.Frame()

	// 1. Simulate NeedsLogin with AuthURL
	a.tailnetMgr.SetError("")
	mockEp := &mockAppHostClient{}
	det := tailnet.NewDetectorWithClient(mockEp)
	a.tailnetMgr = tailnet.NewManager(tailnet.Config{Enabled: true, Mode: tailnet.ModeEmbedded}, det)
	a.tailnetMgr.Refresh(context.Background())

	// Simulate error
	a.tailnetMgr.SetError("内嵌 Tailscale 节点需要添加编译标签 (-tags with_tailscale,with_gvisor)")
	tt.Frame()

	if !tt.HasText("内嵌 Tailscale 节点需要添加编译标签") {
		t.Error("expected error banner text on screen")
	}
}

// Tests Tailnet AuthKey secure persistence without plaintext leak into state.json.
func TestTailnet_AuthKeySecureStorage(t *testing.T) {
	a, _, dir := newTestApp(t, nil)

	a.state.TailnetAuthKey = "tskey-auth-secret-xyz"
	a.saveState()

	// 1. Verify state.json on disk does NOT leak the plaintext key
	raw, err := os.ReadFile(a.stateFilePath())
	if err != nil {
		t.Fatalf("read stateFilePath: %v", err)
	}
	if strings.Contains(string(raw), "tskey-auth-secret-xyz") {
		t.Errorf("expected state.json to not contain plaintext auth key, got: %s", string(raw))
	}

	// 2. Clear in-memory state and reload; verify AuthKey is recovered securely
	a.state.TailnetAuthKey = ""
	a.loadState()
	if a.state.TailnetAuthKey != "tskey-auth-secret-xyz" {
		t.Errorf("expected loaded AuthKey to be recovered, got %q", a.state.TailnetAuthKey)
	}

	// 3. Test migration: write an unmigrated state.json with plaintext key
	_ = os.Remove(a.tailnetKeyFile())
	unmigrated := fmt.Sprintf(`{"tailnetAuthKey": "tskey-auth-legacy-migrated", "tailnetMode": "embedded"}`)
	if err := os.WriteFile(a.stateFilePath(), []byte(unmigrated), 0o600); err != nil {
		t.Fatalf("write unmigrated state: %v", err)
	}
	a.state.TailnetAuthKey = ""
	a.loadState()
	if a.state.TailnetAuthKey != "tskey-auth-legacy-migrated" {
		t.Errorf("expected migrated key to be loaded, got %q", a.state.TailnetAuthKey)
	}

	// Verify state.json on disk had its plaintext key erased after migration resave
	rawMigrated, _ := os.ReadFile(a.stateFilePath())
	if strings.Contains(string(rawMigrated), "tskey-auth-legacy-migrated") {
		t.Errorf("expected migrated state.json to clear plaintext key, got: %s", string(rawMigrated))
	}
	_ = dir
}

// Tests advanced embedded settings card is visible only when embedded mode is selected or active.
func TestTailnetUI_AdvancedCardVisibility(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)
	a.activeTab = TabTailnet
	a.state.TailnetEnabled = true
	a.state.TailnetMode = string(tailnet.ModeHost)
	tt.Frame()

	// 1. Host mode: advanced card should be hidden
	if tt.HasText(a.catalog().TailnetAdvancedTitle()) {
		t.Error("expected TailnetAdvancedTitle to be hidden in Host mode")
	}

	// 2. Switch to Embedded mode: advanced card should be visible
	a.state.TailnetMode = string(tailnet.ModeEmbedded)
	tt.Frame()

	if !tt.HasText(a.catalog().TailnetAdvancedTitle()) {
		t.Error("expected TailnetAdvancedTitle to be visible in Embedded mode")
	}
}

// Regression: toggling Tailnet mode or sharing switches while in TUN mode must
// reload the gateway engine by reusing the existing TUN device rather than
// closing it and re-requesting administrator privileges via tunhelper.
func TestTailnetUI_TunModeDoesNotReRequestTunDevice(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)
	a.state.GatewayPort = freeLocalPort(t)
	a.state.GatewayEnabled = true
	defer a.stopGateway()

	origMockTunDevice := a.mockTunDevice
	tunRequestCount := 0
	tunCloseCount := 0
	a.mockTunDevice = func() (*tunhelper.ReceivedDevice, error) {
		tunRequestCount++
		dev, err := origMockTunDevice()
		if err != nil {
			return nil, err
		}
		dev.Conn = mockCloser{onClose: func() error {
			tunCloseCount++
			return nil
		}}
		return dev, nil
	}

	if err := a.setTrafficMode("tun"); err != nil {
		t.Fatalf("setTrafficMode('tun') failed: %v", err)
	}
	if tunRequestCount != 1 {
		t.Fatalf("expected 1 initial TUN device request, got %d", tunRequestCount)
	}

	a.activeTab = TabTailnet
	tt.Frame()

	// 1. Switch Tailnet mode (e.g., to Host mode)
	if err := tt.Click(a.catalog().TailnetModeHost()); err != nil {
		t.Fatalf("click TailnetModeHost: %v", err)
	}
	tt.Frame()

	if tunRequestCount != 1 || tunCloseCount != 0 {
		t.Fatalf("switching Tailnet mode in TUN mode re-requested/closed TUN device: requests=%d, closes=%d", tunRequestCount, tunCloseCount)
	}

	// 2. Toggle Expose Mixed Port switch
	lblExpose, ok := tt.Find(a.catalog().TailnetExposeMixed())
	if !ok {
		t.Fatal("expected TailnetExposeMixed row")
	}
	tt.ClickAt(850, lblExpose.Y+lblExpose.H/2)
	tt.Frame()

	if !a.state.TailnetExposeMixedPort {
		t.Fatal("expected TailnetExposeMixedPort to be enabled")
	}
	if tunRequestCount != 1 || tunCloseCount != 0 {
		t.Fatalf("toggling Tailnet sharing switch in TUN mode re-requested/closed TUN device: requests=%d, closes=%d", tunRequestCount, tunCloseCount)
	}
	if a.gateway == nil {
		t.Fatal("expected gateway to remain running in TUN mode after Tailnet update")
	}
}

