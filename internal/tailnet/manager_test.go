package tailnet

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/tailscale/ipn/ipnstate"
	"github.com/sagernet/tailscale/types/key"
	"github.com/sagernet/tailscale/types/views"
)

type mockEmbeddedEndpoint struct {
	mu           sync.Mutex
	subscribed   chan struct{}
	statusFn     func(*adapter.TailscaleEndpointStatus)
	exitNodeID   string
	loggedOut    bool
}

func newMockEmbeddedEndpoint() *mockEmbeddedEndpoint {
	return &mockEmbeddedEndpoint{
		subscribed: make(chan struct{}),
	}
}

func (m *mockEmbeddedEndpoint) SubscribeTailscaleStatus(ctx context.Context, fn func(*adapter.TailscaleEndpointStatus)) error {
	m.mu.Lock()
	m.statusFn = fn
	close(m.subscribed)
	m.mu.Unlock()
	<-ctx.Done()
	return ctx.Err()
}

func (m *mockEmbeddedEndpoint) emitStatus(st *adapter.TailscaleEndpointStatus) {
	m.mu.Lock()
	fn := m.statusFn
	m.mu.Unlock()
	if fn != nil {
		fn(st)
	}
}

func (m *mockEmbeddedEndpoint) SetTailscaleExitNode(ctx context.Context, stableID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.exitNodeID = stableID
	return nil
}

func (m *mockEmbeddedEndpoint) StartTailscalePing(ctx context.Context, peerIP string, fn func(*adapter.TailscalePingResult)) error {
	return nil
}

func (m *mockEmbeddedEndpoint) Logout(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loggedOut = true
	return nil
}

func (m *mockEmbeddedEndpoint) GetTailscaleCertificate(ctx context.Context, domain string, minValidity time.Duration) ([]byte, []byte, error) {
	return nil, nil, nil
}

func (m *mockEmbeddedEndpoint) SubscribeTaildropInbox(ctx context.Context, fn func(*adapter.TaildropInbox)) error {
	return nil
}

func (m *mockEmbeddedEndpoint) MarkTaildropInboxRead() error {
	return nil
}

func (m *mockEmbeddedEndpoint) SendTaildropFile(ctx context.Context, peerStableID string, fileName string, size int64, content io.Reader, progress func(int64)) error {
	return nil
}

func (m *mockEmbeddedEndpoint) OpenTaildropFile(fileName string) (io.ReadCloser, int64, error) {
	return nil, 0, nil
}

func (m *mockEmbeddedEndpoint) DeleteTaildropFile(fileName string) error {
	return nil
}

func (m *mockEmbeddedEndpoint) CancelTaildropReceiving(senderID string, fileName string) error {
	return nil
}

func TestManager_AutoMode_WithHostRunning(t *testing.T) {
	mockClient := &mockHostClient{
		statusFunc: func(ctx context.Context) (*ipnstate.Status, error) {
			return &ipnstate.Status{
				BackendState:   "Running",
				MagicDNSSuffix: "corp.ts.net",
				Self: &ipnstate.PeerStatus{
					HostName:     "dev-box",
					TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.1.2")},
					Online:       true,
				},
			}, nil
		},
	}

	det := NewDetectorWithClient(mockClient)
	cfg := Config{
		Enabled: true,
		Mode:    ModeAuto,
	}

	mgr := NewManager(cfg, det)
	defer mgr.Close()

	mgr.Refresh(context.Background())
	st := mgr.Status()

	if st.ActiveMode != ModeHost {
		t.Errorf("expected ModeHost, got %s", st.ActiveMode)
	}
	if st.BackendState != "Running" {
		t.Errorf("expected Running, got %s", st.BackendState)
	}
	if st.MagicDNSSuffix != "corp.ts.net" {
		t.Errorf("expected corp.ts.net, got %s", st.MagicDNSSuffix)
	}
	if !mgr.ShouldUseHostMode() {
		t.Error("expected ShouldUseHostMode to be true")
	}
	if mgr.ShouldUseEmbeddedMode() {
		t.Error("expected ShouldUseEmbeddedMode to be false")
	}

	excludes := mgr.GetHostExcludeAddresses()
	if len(excludes) < 2 {
		t.Errorf("expected default CGNAT & ULA excludes, got %v", excludes)
	}
}

func TestManager_AutoMode_FallbackEmbedded(t *testing.T) {
	mockClient := &mockHostClient{
		statusFunc: func(ctx context.Context) (*ipnstate.Status, error) {
			return nil, errors.New("daemon not running")
		},
	}

	det := NewDetectorWithClient(mockClient)
	cfg := Config{
		Enabled: true,
		Mode:    ModeAuto,
	}

	mgr := NewManager(cfg, det)
	defer mgr.Close()

	mgr.Refresh(context.Background())
	st := mgr.Status()

	if st.ActiveMode != ModeEmbedded {
		t.Errorf("expected fallback to ModeEmbedded, got %s", st.ActiveMode)
	}
	if mgr.ShouldUseHostMode() {
		t.Error("expected ShouldUseHostMode to be false")
	}
	if !mgr.ShouldUseEmbeddedMode() {
		t.Error("expected ShouldUseEmbeddedMode to be true")
	}
}

func TestManager_EmbeddedMode_StatusBinding(t *testing.T) {
	det := NewDetectorWithClient(&mockHostClient{
		statusFunc: func(ctx context.Context) (*ipnstate.Status, error) {
			return nil, errors.New("not running")
		},
	})
	cfg := Config{
		Enabled: true,
		Mode:    ModeEmbedded,
	}

	mgr := NewManager(cfg, det)
	defer mgr.Close()

	endpoint := newMockEmbeddedEndpoint()
	mgr.BindEmbeddedEndpoint(endpoint)
	<-endpoint.subscribed

	// Simulate endpoint status update from sing-box
	endpoint.emitStatus(&adapter.TailscaleEndpointStatus{
		BackendState:   "Running",
		MagicDNSSuffix: "embedded.ts.net",
		Self: &adapter.TailscalePeer{
			HostName:     "embedded-node",
			TailscaleIPs: []string{"100.64.99.1"},
			Online:       true,
		},
		UserGroups: []*adapter.TailscaleUserGroup{
			{
				Peers: []*adapter.TailscalePeer{
					{
						StableID:       "peer-remote-1",
						HostName:       "home-nas",
						TailscaleIPs:   []string{"100.64.99.2"},
						Online:         true,
						ExitNodeOption: true,
					},
				},
			},
		},
	})

	st := mgr.Status()
	if st.ActiveMode != ModeEmbedded {
		t.Errorf("expected ModeEmbedded, got %s", st.ActiveMode)
	}
	if st.Self.Hostname != "embedded-node" {
		t.Errorf("expected embedded-node, got %s", st.Self.Hostname)
	}
	if len(st.Peers) != 1 || st.Peers[0].Hostname != "home-nas" {
		t.Errorf("unexpected peers: %+v", st.Peers)
	}

	// Test SetExitNode in embedded mode
	err := mgr.SetExitNode(context.Background(), "peer-remote-1")
	if err != nil {
		t.Fatalf("unexpected error setting exit node: %v", err)
	}
	if endpoint.exitNodeID != "peer-remote-1" {
		t.Errorf("expected endpoint exitNodeID peer-remote-1, got %s", endpoint.exitNodeID)
	}
}

func TestManager_DisabledMode(t *testing.T) {
	det := NewDetectorWithClient(&mockHostClient{})
	cfg := Config{
		Enabled: false,
		Mode:    ModeOff,
	}

	mgr := NewManager(cfg, det)
	defer mgr.Close()

	mgr.Refresh(context.Background())
	st := mgr.Status()

	if st.ActiveMode != ModeOff {
		t.Errorf("expected ModeOff, got %s", st.ActiveMode)
	}
	if mgr.ShouldUseHostMode() || mgr.ShouldUseEmbeddedMode() {
		t.Error("expected both ShouldUseHostMode and ShouldUseEmbeddedMode to be false")
	}
}

// SetError updates status error message and transitions state to offline.
func TestManager_SetError(t *testing.T) {
	mgr := NewManager(Config{Enabled: true, Mode: ModeEmbedded}, nil)
	defer mgr.Close()

	mgr.SetError("missing build tags -tags with_tailscale,with_gvisor")
	st := mgr.Status()
	if st.Error != "missing build tags -tags with_tailscale,with_gvisor" {
		t.Errorf("expected error recorded, got %q", st.Error)
	}
	if st.BackendState != "Offline" {
		t.Errorf("expected state Offline, got %q", st.BackendState)
	}
}

// Switching mode from embedded to host detaches embedded endpoint and ignores stale updates.
func TestManager_SwitchFromEmbeddedToHost(t *testing.T) {
	det := NewDetectorWithClient(&mockHostClient{
		statusFunc: func(ctx context.Context) (*ipnstate.Status, error) {
			return &ipnstate.Status{
				BackendState: "Running",
				Self: &ipnstate.PeerStatus{
					HostName:     "host-laptop",
					TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
					Online:       true,
				},
			}, nil
		},
	})
	mgr := NewManager(Config{Enabled: true, Mode: ModeEmbedded}, det)
	defer mgr.Close()

	endpoint := newMockEmbeddedEndpoint()
	mgr.BindEmbeddedEndpoint(endpoint)
	<-endpoint.subscribed

	// Switch to Host mode
	mgr.UpdateConfig(Config{Enabled: true, Mode: ModeHost})

	// Simulate stale NeedsLogin from embedded endpoint
	endpoint.emitStatus(&adapter.TailscaleEndpointStatus{
		BackendState: "NeedsLogin",
		AuthURL:      "https://login.tailscale.com/a/stale",
	})

	st := mgr.Status()
	if st.ActiveMode != ModeHost {
		t.Errorf("expected ActiveMode ModeHost, got %s", st.ActiveMode)
	}
	if st.BackendState != "Running" {
		t.Errorf("expected BackendState Running, got %s", st.BackendState)
	}
	if st.AuthURL != "" {
		t.Errorf("expected empty AuthURL in host mode, got %s", st.AuthURL)
	}
}

// Regression: embedded mode status updates previously displayed raw OS HostName
// instead of the configured Tailnet node name from DNSName.
func TestManager_EmbeddedMode_PrefersConfiguredNodeNameOverOSHostName(t *testing.T) {
	det := NewDetectorWithClient(&mockHostClient{
		statusFunc: func(ctx context.Context) (*ipnstate.Status, error) {
			return nil, errors.New("not running")
		},
	})
	mgr := NewManager(Config{Enabled: true, Mode: ModeEmbedded}, det)
	defer mgr.Close()

	endpoint := newMockEmbeddedEndpoint()
	mgr.BindEmbeddedEndpoint(endpoint)
	<-endpoint.subscribed

	endpoint.emitStatus(&adapter.TailscaleEndpointStatus{
		BackendState:   "Running",
		MagicDNSSuffix: "tail8bfe1c.ts.net",
		Self: &adapter.TailscalePeer{
			HostName: "localhost",
			DNSName:  "naive-client.tail8bfe1c.ts.net.",
			Online:   true,
		},
		UserGroups: []*adapter.TailscaleUserGroup{
			{
				Peers: []*adapter.TailscalePeer{
					{
						StableID: "peer-1",
						HostName: "localhost",
						DNSName:  "iphone-13.tail8bfe1c.ts.net.",
						Online:   true,
					},
					{
						StableID: "peer-2",
						HostName: "instance-20220211-1708",
						DNSName:  "ts-opc1.tail8bfe1c.ts.net.",
						Online:   true,
					},
					{
						StableID: "peer-3",
						HostName: "nas-fallback",
						DNSName:  "",
						Online:   false,
					},
				},
			},
		},
	})

	st := mgr.Status()
	if st.Self.Hostname != "naive-client" {
		t.Errorf("self hostname = %q, want %q", st.Self.Hostname, "naive-client")
	}
	if st.Self.DNSName != "naive-client.tail8bfe1c.ts.net" {
		t.Errorf("self dnsName = %q, want %q", st.Self.DNSName, "naive-client.tail8bfe1c.ts.net")
	}

	got := make(map[string]string, len(st.Peers))
	for _, p := range st.Peers {
		got[p.ID] = p.Hostname
	}
	if got["peer-1"] != "iphone-13" {
		t.Errorf("peer-1 hostname = %q, want %q", got["peer-1"], "iphone-13")
	}
	if got["peer-2"] != "ts-opc1" {
		t.Errorf("peer-2 hostname = %q, want %q", got["peer-2"], "ts-opc1")
	}
	if got["peer-3"] != "nas-fallback" {
		t.Errorf("peer-3 hostname = %q, want %q", got["peer-3"], "nas-fallback")
	}
}

// Regression: DetectHostStatus previously failed to sync Manager.status when Enabled=true
// in host/auto mode and didn't expose normalized peer records, leaving MagicDNS suffixes
// and peer hostname-to-IP mappings empty until a later poll cycle.
func TestManager_DetectHostStatus_SyncsCacheAndHostRecords(t *testing.T) {
	allowed := views.SliceOf([]netip.Prefix{
		netip.MustParsePrefix("100.64.1.5/32"),
		netip.MustParsePrefix("10.88.0.0/16"),
	})
	det := NewDetectorWithClient(&mockHostClient{
		statusFunc: func(ctx context.Context) (*ipnstate.Status, error) {
			peerKey := key.NodePublic{}
			return &ipnstate.Status{
				BackendState:   "Running",
				MagicDNSSuffix: "tail8bfe1c.ts.net.",
				Self: &ipnstate.PeerStatus{
					HostName:     "macbook",
					DNSName:      "macbook.tail8bfe1c.ts.net.",
					TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
					Online:       true,
				},
				Peer: map[key.NodePublic]*ipnstate.PeerStatus{
					peerKey: {
						ID:           "peer-vps",
						HostName:     "vps-raw",
						DNSName:      "my-vps.tail8bfe1c.ts.net.",
						TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.1.5"), netip.MustParseAddr("fd7a:115c:a1e0::5")},
						AllowedIPs:   &allowed,
						Online:       true,
					},
				},
			}, nil
		},
	})

	// 1. Enabled host mode: DetectHostStatus populates status, excludes, suffix, and records.
	mgr := NewManager(Config{Enabled: true, Mode: ModeHost}, det)
	defer mgr.Close()

	st := mgr.DetectHostStatus()
	if st == nil || st.BackendState != "Running" {
		t.Fatalf("DetectHostStatus() = %+v, want Running", st)
	}
	if got := mgr.GetMagicDNSSuffix(); got != "tail8bfe1c.ts.net" {
		t.Errorf("GetMagicDNSSuffix() = %q, want %q", got, "tail8bfe1c.ts.net")
	}
	excludes := mgr.GetHostExcludeAddresses()
	wantRoute := false
	for _, ex := range excludes {
		if ex == "10.88.0.0/16" {
			wantRoute = true
		}
	}
	if !wantRoute {
		t.Errorf("GetHostExcludeAddresses() = %v, expected advertised subnet 10.88.0.0/16", excludes)
	}
	recs := mgr.GetHostRecords()
	wantIPs := []string{"100.64.1.5", "fd7a:115c:a1e0::5"}
	if !reflect.DeepEqual(recs["my-vps"], wantIPs) {
		t.Errorf("records[my-vps] = %v, want %v", recs["my-vps"], wantIPs)
	}
	if !reflect.DeepEqual(recs["my-vps.tail8bfe1c.ts.net"], wantIPs) {
		t.Errorf("records[my-vps.tail8bfe1c.ts.net] = %v, want %v", recs["my-vps.tail8bfe1c.ts.net"], wantIPs)
	}

	// 2. Disabled manager: DetectHostStatus returns host status without flipping ActiveMode to ModeHost.
	passiveMgr := NewManager(DefaultConfig(), det)
	defer passiveMgr.Close()
	if got := passiveMgr.DetectHostStatus(); got == nil || got.MagicDNSSuffix != "tail8bfe1c.ts.net" {
		t.Fatalf("passive DetectHostStatus() = %+v", got)
	}
	if passiveMgr.ShouldUseHostMode() {
		t.Error("passive manager with Enabled=false should not report ShouldUseHostMode=true")
	}
}

func TestIsTailnetHostnameAndTarget(t *testing.T) {
	recs := map[string][]string{
		"my-vps":                   {"100.64.1.5"},
		"my-vps.tail8bfe1c.ts.net": {"100.64.1.5"},
	}

	if IsTailnetHostname(ModeOff, "my-vps.tail8bfe1c.ts.net", "tail8bfe1c.ts.net") {
		t.Error("expected ModeOff to return false for Tailnet hostnames")
	}
	if IsTailnetTarget("", "100.64.1.5", "tail8bfe1c.ts.net", recs) {
		t.Error("expected empty mode to return false for Tailnet IPs")
	}
	for _, host := range []string{"my-vps", "my-vps.", "my-vps.tail8bfe1c.ts.net", "node.ts.net", "node.corp.custom"} {
		if !IsTailnetHostname(ModeHost, host, "corp.custom") {
			t.Errorf("IsTailnetHostname(ModeHost, %q) = false, want true", host)
		}
	}
	for _, nonTailnet := range []string{"", "localhost", "printer.local", "foo.localhost", "127.0.0.1", "example.com"} {
		if IsTailnetHostname(ModeHost, nonTailnet, "tail8bfe1c.ts.net") {
			t.Errorf("IsTailnetHostname(ModeHost, %q) = true, want false", nonTailnet)
		}
	}

	// When hostRecords is known, non-Tailnet single-label LAN hosts must not bind to Tailnet interface,
	// whereas Tailnet IPs/FQDNs/known peers do match.
	if IsTailnetTarget(ModeHost, "lan-router", "tail8bfe1c.ts.net", recs) {
		t.Error("unexpected match for non-Tailnet single-label host when hostRecords is populated")
	}
	for _, target := range []string{"my-vps", "other.tail8bfe1c.ts.net", "100.64.9.9", "[fd7a:115c:a1e0::9]", "100.100.100.100"} {
		if !IsTailnetTarget(ModeHost, target, "tail8bfe1c.ts.net", recs) {
			t.Errorf("IsTailnetTarget(ModeHost, %q) = false, want true", target)
		}
	}
	if IsTailnetTarget(ModeHost, "100.63.255.254", "tail8bfe1c.ts.net", recs) {
		t.Error("100.63.255.254 is outside 100.64.0.0/10 and must not match")
	}
}
