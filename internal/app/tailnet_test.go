package app

import (
	"context"
	"net/netip"
	"testing"

	"naive-client/internal/config"
	"naive-client/internal/tailnet"

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
