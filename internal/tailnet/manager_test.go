package tailnet

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/tailscale/ipn/ipnstate"
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
