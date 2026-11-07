package tailnet

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/sagernet/tailscale/ipn/ipnstate"
	"github.com/sagernet/tailscale/tailcfg"
	"github.com/sagernet/tailscale/types/key"
	"github.com/sagernet/tailscale/types/views"
)

type mockHostClient struct {
	statusFunc        func(ctx context.Context) (*ipnstate.Status, error)
	setExitNodeFunc    func(ctx context.Context, id string) error
	setUseExitNodeFunc func(ctx context.Context, on bool) error
}

func (m *mockHostClient) Status(ctx context.Context) (*ipnstate.Status, error) {
	if m.statusFunc != nil {
		return m.statusFunc(ctx)
	}
	return nil, errors.New("not implemented")
}

func (m *mockHostClient) SetExitNode(ctx context.Context, id string) error {
	if m.setExitNodeFunc != nil {
		return m.setExitNodeFunc(ctx, id)
	}
	return nil
}

func (m *mockHostClient) SetUseExitNode(ctx context.Context, on bool) error {
	if m.setUseExitNodeFunc != nil {
		return m.setUseExitNodeFunc(ctx, on)
	}
	return nil
}

func TestDetector_DetectHost_Running(t *testing.T) {
	mockClient := &mockHostClient{
		statusFunc: func(ctx context.Context) (*ipnstate.Status, error) {
			peerKey := key.NodePublic{}
			prefix1 := netip.MustParsePrefix("192.168.1.0/24")
			sliceView := views.SliceOf([]netip.Prefix{prefix1})

			return &ipnstate.Status{
				BackendState:   "Running",
				MagicDNSSuffix: "example.ts.net",
				Self: &ipnstate.PeerStatus{
					HostName:     "my-mac",
					DNSName:      "my-mac.example.ts.net.",
					OS:           "macOS",
					TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("fd7a:115c:a1e0::1")},
					Online:       true,
				},
				Peer: map[key.NodePublic]*ipnstate.PeerStatus{
					peerKey: {
						ID:             tailcfg.StableNodeID("node-exit-1"),
						HostName:       "nas-exit",
						DNSName:        "nas-exit.example.ts.net.",
						OS:             "linux",
						TailscaleIPs:   []netip.Addr{netip.MustParseAddr("100.64.0.2")},
						AllowedIPs:     &sliceView,
						Online:         true,
						ExitNodeOption: true,
						ExitNode:       true,
					},
				},
			}, nil
		},
	}

	det := NewDetectorWithClient(mockClient)
	status, err := det.DetectHost(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if status.ActiveMode != ModeHost {
		t.Errorf("expected ModeHost, got %s", status.ActiveMode)
	}
	if status.BackendState != "Running" {
		t.Errorf("expected Running, got %s", status.BackendState)
	}
	if status.Self.Hostname != "my-mac" {
		t.Errorf("expected my-mac, got %s", status.Self.Hostname)
	}
	if len(status.Self.IPs) != 2 || status.Self.IPs[0] != "100.64.0.1" {
		t.Errorf("unexpected IPs: %v", status.Self.IPs)
	}
	if status.MagicDNSSuffix != "example.ts.net" {
		t.Errorf("unexpected MagicDNSSuffix: %s", status.MagicDNSSuffix)
	}
	if len(status.Peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(status.Peers))
	}
	peer := status.Peers[0]
	if peer.Hostname != "nas-exit" || !peer.ExitNode || !peer.ExitNodeOption {
		t.Errorf("unexpected peer attributes: %+v", peer)
	}
	if status.CurrentExitNode != "node-exit-1" {
		t.Errorf("expected CurrentExitNode node-exit-1, got %s", status.CurrentExitNode)
	}
	if len(status.SubnetRoutes) != 1 || status.SubnetRoutes[0] != "192.168.1.0/24" {
		t.Errorf("unexpected SubnetRoutes: %v", status.SubnetRoutes)
	}
}

func TestDetector_DetectHost_NotRunning(t *testing.T) {
	mockClient := &mockHostClient{
		statusFunc: func(ctx context.Context) (*ipnstate.Status, error) {
			return nil, errors.New("connection refused")
		},
	}

	det := NewDetectorWithClient(mockClient)
	_, err := det.DetectHost(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
