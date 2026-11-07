package boxengine

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"naive-client/internal/telemetry"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

// mockOutbound simulates an adapter.Outbound for unit testing PoolOutbound.
type mockOutbound struct {
	tag     string
	dialErr error
	dialed  int
}

func (m *mockOutbound) Type() string         { return "mock" }
func (m *mockOutbound) Tag() string          { return m.tag }
func (m *mockOutbound) Network() []string    { return []string{"tcp", "udp"} }
func (m *mockOutbound) Dependencies() []string { return nil }

func (m *mockOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	m.dialed++
	if m.dialErr != nil {
		return nil, m.dialErr
	}
	// Return mock connection (pipe)
	c1, _ := net.Pipe()
	return c1, nil
}

func (m *mockOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if m.dialErr != nil {
		return nil, m.dialErr
	}
	return nil, errors.New("mock packet conn not implemented")
}

type testNodeProvider struct {
	candidates map[string][]string
	nodes      map[string]adapter.Outbound
	sidecars   map[string]bool
}

func (p *testNodeProvider) GetCandidates(tag string) []string {
	return p.candidates[tag]
}

func (p *testNodeProvider) GetOutbound(nodeID string) (adapter.Outbound, bool) {
	ob, ok := p.nodes[nodeID]
	return ob, ok
}

func (p *testNodeProvider) IsSidecar(nodeID string) bool {
	if p.sidecars != nil {
		return p.sidecars[nodeID]
	}
	return false
}

// Tests that PoolOutbound selects candidate using tracker and fails over when primary candidate fails.
func TestPoolOutbound_DialAndFailover(t *testing.T) {
	tracker := telemetry.NewTracker()
	fm := telemetry.NewFailureMonitor(100)

	nodeA := &mockOutbound{tag: "node-a", dialErr: errors.New("connection refused")}
	nodeB := &mockOutbound{tag: "node-b", dialErr: nil}

	provider := &testNodeProvider{
		candidates: map[string][]string{
			"PROXY_POOL": {"node-a", "node-b"},
		},
		nodes: map[string]adapter.Outbound{
			"node-a": nodeA,
			"node-b": nodeB,
		},
	}

	pool := NewPoolOutbound(PoolOutboundOptions{
		Tag:            "PROXY_POOL",
		PoolTag:        "",
		Tracker:        tracker,
		FailureMonitor: fm,
		NodeProvider:   provider,
	})

	dest := M.ParseSocksaddr("chat.openai.com:443")
	conn, err := pool.DialContext(context.Background(), "tcp", dest)
	if err != nil {
		t.Fatalf("expected dial to succeed via failover to node-b, got error: %v", err)
	}
	if conn != nil {
		_ = conn.Close()
	}

	// node-a should have been attempted first and failed
	if nodeA.dialed != 1 {
		t.Errorf("expected node-a to be dialed 1 time, got %d", nodeA.dialed)
	}
	// node-b should have been dialed and succeeded
	if nodeB.dialed != 1 {
		t.Errorf("expected node-b to be dialed 1 time, got %d", nodeB.dialed)
	}

	// Affinity table should now prefer node-b for openai.com
	best, _, ok := tracker.PeekBest([]string{"node-a", "node-b"}, "api.openai.com")
	if !ok || best != "node-b" {
		t.Errorf("expected sticky affinity to lock to node-b, got %s (ok=%v)", best, ok)
	}
}

// Tests that when all candidates fail, PoolOutbound reports failure to FailureMonitor.
func TestPoolOutbound_AllCandidatesFail(t *testing.T) {
	tracker := telemetry.NewTracker()
	fm := telemetry.NewFailureMonitor(100)

	nodeA := &mockOutbound{tag: "node-a", dialErr: errors.New("dial timeout")}
	nodeB := &mockOutbound{tag: "node-b", dialErr: errors.New("connection reset")}

	provider := &testNodeProvider{
		candidates: map[string][]string{
			"PROXY_POOL": {"node-a", "node-b"},
		},
		nodes: map[string]adapter.Outbound{
			"node-a": nodeA,
			"node-b": nodeB,
		},
	}

	pool := NewPoolOutbound(PoolOutboundOptions{
		Tag:            "PROXY_POOL",
		PoolTag:        "",
		Tracker:        tracker,
		FailureMonitor: fm,
		NodeProvider:   provider,
	})

	dest := M.ParseSocksaddr("blocked.com:443")
	conn, err := pool.DialContext(context.Background(), "tcp", dest)
	if err == nil {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("expected error when all candidates fail")
	}

	// FailureMonitor should have captured 1 failure event for blocked.com
	list := fm.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 captured failure, got %d", len(list))
	}
	if list[0].Target != "blocked.com" {
		t.Errorf("expected target blocked.com, got %s", list[0].Target)
	}
	if list[0].Category != telemetry.FailureProxy {
		t.Errorf("expected FailureProxy category, got %v", list[0].Category)
	}
}

// Regression test: sidecar nodes (running over local loopback socks5) pass rtt=0 to tracker
// so local IPC connect time does not overwrite real EWMA latency with 1ms.
func TestPoolOutbound_SidecarZeroRTT(t *testing.T) {
	tracker := telemetry.NewTracker()
	// Pre-seed real probe latency
	tracker.RecordProbe("sidecar-node", 95*time.Millisecond)

	node := &mockOutbound{tag: "node-sidecar-node", dialErr: nil}
	provider := &testNodeProvider{
		candidates: map[string][]string{
			"PROXY_POOL": {"sidecar-node"},
		},
		nodes: map[string]adapter.Outbound{
			"sidecar-node": node,
		},
		sidecars: map[string]bool{
			"sidecar-node": true,
		},
	}

	pool := NewPoolOutbound(PoolOutboundOptions{
		Tag:          "PROXY_POOL",
		Tracker:      tracker,
		NodeProvider: provider,
	})

	dest := M.ParseSocksaddr("openai.com:443")
	conn, err := pool.DialContext(context.Background(), "tcp", dest)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if conn != nil {
		_ = conn.Close()
	}

	sc := tracker.GetScore("sidecar-node")
	if sc.EWMA != 95*time.Millisecond {
		t.Fatalf("expected sidecar EWMA preserved at 95ms, got %v", sc.EWMA)
	}
}
