package boxengine

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"naive-client/internal/telemetry"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/bufio"
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

// Tests that real business traffic on sidecar nodes measures first-packet RTT and updates tracker EWMA and triggers UI callback.
func TestFirstRTTConn_SingBufioCopyRealTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var rttReported time.Duration
	var rttMu sync.Mutex

	// Remote target server
	go func() {
		sConn, err := ln.Accept()
		if err != nil {
			return
		}
		defer sConn.Close()
		buf := make([]byte, 4)
		_, _ = sConn.Read(buf)
		time.Sleep(30 * time.Millisecond)
		_, _ = sConn.Write([]byte("pong"))
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	wrapped := wrapFirstRTTConn(clientConn, func(rtt time.Duration) {
		rttMu.Lock()
		rttReported = rtt
		rttMu.Unlock()
	})

	// Inbound connection from curl / client
	inLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer inLn.Close()

	curlErrCh := make(chan error, 1)
	go func() {
		curlConn, err := net.Dial("tcp", inLn.Addr().String())
		if err != nil {
			curlErrCh <- err
			return
		}
		defer curlConn.Close()
		if _, err := curlConn.Write([]byte("ping")); err != nil {
			curlErrCh <- err
			return
		}
		buf := make([]byte, 4)
		if _, err := curlConn.Read(buf); err != nil {
			curlErrCh <- err
			return
		}
		curlErrCh <- nil
	}()

	inConn, err := inLn.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer inConn.Close()

	// Sing-box pipes inConn -> wrapped and wrapped -> inConn
	go func() {
		_, _ = bufio.Copy(wrapped, inConn)
	}()
	_, _ = bufio.Copy(inConn, wrapped)

	if err := <-curlErrCh; err != nil {
		t.Fatalf("curl err: %v", err)
	}

	rttMu.Lock()
	rtt := rttReported
	rttMu.Unlock()

	t.Logf("RTT reported: %v", rtt)
	if rtt < 20*time.Millisecond || rtt > 100*time.Millisecond {
		t.Fatalf("expected RTT around 30ms, got %v", rtt)
	}
}

func TestPoolOutbound_SidecarFirstPacketTTFBUpdatesTracker(t *testing.T) {
	tracker := telemetry.NewTracker()
	var uiUpdated int
	var uiMu sync.Mutex

	cClient, cServer := net.Pipe()

	customMock := &customMockOutbound{
		tag:  "node-sidecar",
		conn: cClient,
	}

	provider := &testNodeProvider{
		candidates: map[string][]string{
			"PROXY_POOL": {"sidecar-node"},
		},
		nodes: map[string]adapter.Outbound{
			"sidecar-node": customMock,
		},
		sidecars: map[string]bool{
			"sidecar-node": true,
		},
	}

	pool := NewPoolOutbound(PoolOutboundOptions{
		Tag:          "PROXY_POOL",
		Tracker:      tracker,
		NodeProvider: provider,
		OnTelemetryUpdate: func() {
			uiMu.Lock()
			uiUpdated++
			uiMu.Unlock()
		},
	})

	dest := M.ParseSocksaddr("api.openai.com:443")
	conn, err := pool.DialContext(context.Background(), "tcp", dest)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Server goroutine to simulate remote endpoint echo with artificial delay
	serverErrCh := make(chan error, 1)
	go func() {
		defer cServer.Close()
		buf := make([]byte, 5)
		if _, err := cServer.Read(buf); err != nil {
			serverErrCh <- err
			return
		}
		time.Sleep(25 * time.Millisecond)
		if _, err := cServer.Write([]byte("pong!")); err != nil {
			serverErrCh <- err
			return
		}
		serverErrCh <- nil
	}()

	// Client sends request and reads response
	if _, err := conn.Write([]byte("ping!")); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp := make([]byte, 5)
	if _, err := conn.Read(resp); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(resp) != "pong!" {
		t.Fatalf("unexpected resp: %s", string(resp))
	}
	if err := <-serverErrCh; err != nil {
		t.Fatalf("server error: %v", err)
	}

	sc := tracker.GetScore("sidecar-node")
	if sc.EWMA < 20*time.Millisecond || sc.EWMA > 100*time.Millisecond {
		t.Fatalf("expected EWMA around 25ms from real traffic RTT, got %v", sc.EWMA)
	}

	uiMu.Lock()
	count := uiUpdated
	uiMu.Unlock()
	if count == 0 {
		t.Fatalf("expected OnTelemetryUpdate to be called on traffic RTT sample")
	}
}

type customMockOutbound struct {
	tag  string
	conn net.Conn
}

func (m *customMockOutbound) Type() string                                                  { return "custom" }
func (m *customMockOutbound) Tag() string                                                   { return m.tag }
func (m *customMockOutbound) Network() []string                                             { return []string{"tcp", "udp"} }
func (m *customMockOutbound) Dependencies() []string                                        { return nil }
func (m *customMockOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return m.conn, nil
}
func (m *customMockOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

