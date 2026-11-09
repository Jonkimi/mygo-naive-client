package boxengine

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"naive-client/internal/blocker"
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

	wrapped := wrapFirstRTTConn(clientConn, func(rtt time.Duration, _ error) {
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
	if sc.TotalDials != 1 || sc.SuccessfulDials != 1 {
		t.Fatalf("expected exactly 1 dial recorded (not double-counted with loopback connect), got %d/%d", sc.SuccessfulDials, sc.TotalDials)
	}

	uiMu.Lock()
	count := uiUpdated
	uiMu.Unlock()
	if count == 0 {
		t.Fatalf("expected OnTelemetryUpdate to be called on traffic RTT sample")
	}
}

// Regression test: previously, sidecar loopback DialContext always recorded err=nil on 127.0.0.1 connect
// and firstRTTConn ignored read errors/premature closes before the first response byte, leaving sidecar
// SuccessRate permanently at 100% and preventing CircuitBreaker from ever tripping on remote blackholes.
func TestPoolOutbound_SidecarRemoteFailureAndCircuitBreaker(t *testing.T) {
	tracker := telemetry.NewTracker()
	tracker.RecordProbe("sidecar-bad", 50*time.Millisecond)
	tracker.RecordProbe("sidecar-good", 600*time.Millisecond)

	// sidecar-bad accepts local loopback connections, but remote tunnel either EOFs or hangs until client closes
	badOutbound := &funcMockOutbound{
		tag: "node-sidecar-bad",
		dialFn: func() (net.Conn, error) {
			cClient, cServer := net.Pipe()
			go func() {
				buf := make([]byte, 64)
				_, _ = cServer.Read(buf)
				// Simulate remote proxy tunnel closing without sending any response byte
				_ = cServer.Close()
			}()
			return cClient, nil
		},
	}
	goodOutbound := &funcMockOutbound{
		tag: "node-sidecar-good",
		dialFn: func() (net.Conn, error) {
			cClient, cServer := net.Pipe()
			go func() {
				defer cServer.Close()
				buf := make([]byte, 64)
				_, _ = cServer.Read(buf)
				time.Sleep(10 * time.Millisecond)
				_, _ = cServer.Write([]byte("ok"))
			}()
			return cClient, nil
		},
	}

	provider := &testNodeProvider{
		candidates: map[string][]string{
			"PROXY_POOL": {"sidecar-bad", "sidecar-good"},
		},
		nodes: map[string]adapter.Outbound{
			"sidecar-bad":  badOutbound,
			"sidecar-good": goodOutbound,
		},
		sidecars: map[string]bool{
			"sidecar-bad":  true,
			"sidecar-good": true,
		},
	}

	pool := NewPoolOutbound(PoolOutboundOptions{
		Tag:          "PROXY_POOL",
		Tracker:      tracker,
		NodeProvider: provider,
	})

	dest := M.ParseSocksaddr("cp.cloudflare.com:443")

	// 1. First two requests to distinct domains fail via remote EOF before first response byte
	failDomains := []string{"site1.com:443", "site2.com:443"}
	for i, d := range failDomains {
		conn, err := pool.DialContext(context.Background(), "tcp", M.ParseSocksaddr(d))
		if err != nil {
			t.Fatalf("attempt %d dial: %v", i, err)
		}
		_, _ = conn.Write([]byte("HEAD /generate_204 HTTP/1.1\r\n\r\n"))
		buf := make([]byte, 16)
		_, readErr := conn.Read(buf)
		if readErr == nil {
			t.Fatalf("attempt %d expected read error from EOF tunnel", i)
		}
		_ = conn.Close()
	}

	scBad := tracker.GetScore("sidecar-bad")
	if scBad.ConsecutiveFailures != 2 || scBad.SuccessRate >= 1.0 {
		t.Fatalf("expected 2 consecutive failures and SuccessRate < 100%%, got %+v", scBad)
	}

	// 2. Third request hangs on remote side and client times out & closes conn before receiving first byte
	badOutbound.dialFn = func() (net.Conn, error) {
		cClient, cServer := net.Pipe()
		go func() {
			buf := make([]byte, 64)
			_, _ = cServer.Read(buf)
			// Hang without replying until client closes
		}()
		return cClient, nil
	}
	conn3, err := pool.DialContext(context.Background(), "tcp", M.ParseSocksaddr("other.com:443"))
	if err != nil {
		t.Fatalf("attempt 3 dial: %v", err)
	}
	_, _ = conn3.Write([]byte("ClientHello"))
	// Client gives up waiting and closes connection before any byte is read
	_ = conn3.Close()

	scBadAfter3 := tracker.GetScore("sidecar-bad")
	if !scBadAfter3.IsBroken || scBadAfter3.ConsecutiveFailures != 3 {
		t.Fatalf("expected sidecar-bad circuit breaker tripped after 3 remote failures, got %+v", scBadAfter3)
	}

	// 3. Next request must automatically route to sidecar-good because sidecar-bad is now broken
	conn4, err := pool.DialContext(context.Background(), "tcp", dest)
	if err != nil {
		t.Fatalf("attempt 4 dial: %v", err)
	}
	defer conn4.Close()
	_, _ = conn4.Write([]byte("ping"))
	resp := make([]byte, 2)
	if _, err := conn4.Read(resp); err != nil || string(resp) != "ok" {
		t.Fatalf("expected failover to healthy sidecar-good returning 'ok', got %q (err=%v)", string(resp), err)
	}
}

type funcMockOutbound struct {
	tag    string
	dialFn func() (net.Conn, error)
}

func (m *funcMockOutbound) Type() string                                          { return "func-mock" }
func (m *funcMockOutbound) Tag() string                                           { return m.tag }
func (m *funcMockOutbound) Network() []string                                     { return []string{"tcp", "udp"} }
func (m *funcMockOutbound) Dependencies() []string                                { return nil }
func (m *funcMockOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return m.dialFn()
}
func (m *funcMockOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
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

// Tests that when a connection encounters EOF/failure, the Blocker QueryLogger entry is annotated with the failure reason.
func TestPoolOutbound_AnnotatesFailureOnLogEntry(t *testing.T) {
	bl := blocker.NewEngine(blocker.Options{})
	bl.Logger().SetDedupWindow(0)

	// Pre-record Gateway connection entry and bind client source address
	logID := bl.Logger().RecordWithChain("api.test.com", blocker.SourceGateway, blocker.VerdictAllowed, "", "final -> PROXY_POOL -> test-node")
	bl.Logger().BindSourceConn("127.0.0.1:54321", logID)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	provider := &testNodeProvider{
		candidates: map[string][]string{
			"PROXY_POOL": {"test-node"},
		},
		nodes: map[string]adapter.Outbound{
			"test-node": &customMockOutbound{
				tag:  "test-node",
				conn: clientConn,
			},
		},
		sidecars: map[string]bool{
			"test-node": true,
		},
	}

	poolOb := NewPoolOutbound(PoolOutboundOptions{
		Tag:          "PROXY_POOL",
		PoolTag:      "PROXY_POOL",
		NodeProvider: provider,
		Blocker:      bl,
	})

	inboundCtx := &adapter.InboundContext{
		Source: M.ParseSocksaddr("127.0.0.1:54321"),
	}
	ctx := adapter.WithContext(context.Background(), inboundCtx)
	dest := M.ParseSocksaddr("api.test.com:443")
	conn, err := poolOb.DialContext(ctx, "tcp", dest)
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}

	// Write request from client side
	go func() {
		_, _ = conn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	}()

	// Server reads request and immediately closes with EOF without responding
	buf := make([]byte, 64)
	_, _ = serverConn.Read(buf)
	_ = serverConn.Close()

	// Read on client side triggers io.EOF
	_, readErr := conn.Read(make([]byte, 64))
	if readErr == nil {
		t.Fatalf("expected EOF error on read")
	}

	// Check that QueryLogger was annotated with (远端断开: EOF)
	entries := bl.Logger().GetEntries(10)
	if len(entries) == 0 {
		t.Fatalf("expected log entries")
	}
	if entries[0].Error != "远端断开: EOF" {
		t.Errorf("expected entry error %q, got %q", "远端断开: EOF", entries[0].Error)
	}
}

// Tests that when no nodes are active/running (candidates=0), the Gateway log entry is annotated with (节点未启动).
func TestPoolOutbound_NoActiveNodesAnnotatesFailure(t *testing.T) {
	bl := blocker.NewEngine(blocker.Options{})
	bl.Logger().SetDedupWindow(0)

	logID := bl.Logger().RecordWithChain("unreachable.com", blocker.SourceGateway, blocker.VerdictAllowed, "", "domain_suffix(unreachable.com) -> PROXY_POOL")
	bl.Logger().BindSourceConn("127.0.0.1:56789", logID)

	provider := &testNodeProvider{
		candidates: map[string][]string{
			"PROXY_POOL": nil, // No running nodes!
		},
		nodes: make(map[string]adapter.Outbound),
	}

	poolOb := NewPoolOutbound(PoolOutboundOptions{
		Tag:          "PROXY_POOL",
		PoolTag:      "PROXY_POOL",
		NodeProvider: provider,
		Blocker:      bl,
	})

	inboundCtx := &adapter.InboundContext{
		Source: M.ParseSocksaddr("127.0.0.1:56789"),
	}
	ctx := adapter.WithContext(context.Background(), inboundCtx)
	dest := M.ParseSocksaddr("unreachable.com:443")
	_, err := poolOb.DialContext(ctx, "tcp", dest)
	if err == nil {
		t.Fatalf("expected DialContext to return error when candidates=0")
	}

	entries := bl.Logger().GetEntries(10)
	if len(entries) == 0 {
		t.Fatalf("expected log entries")
	}
	if entries[0].Error != "节点未启动" {
		t.Errorf("expected entry error %q, got %q", "节点未启动", entries[0].Error)
	}
}

// Tests that on successful First RTT, PoolOutbound annotates the Gateway log entry with duration.
func TestPoolOutbound_RecordsDurationOnLogEntry(t *testing.T) {
	bl := blocker.NewEngine(blocker.Options{})
	bl.Logger().SetDedupWindow(0)

	logID := bl.Logger().RecordWithChain("example.com", blocker.SourceGateway, blocker.VerdictAllowed, "", "final -> PROXY_POOL -> test-node")
	bl.Logger().BindSourceConn("127.0.0.1:54321", logID)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer serverConn.Close()
		buf := make([]byte, 64)
		_, _ = serverConn.Read(buf)
		time.Sleep(10 * time.Millisecond)
		_, _ = serverConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	}()

	provider := &testNodeProvider{
		candidates: map[string][]string{
			"PROXY_POOL": {"node-test"},
		},
		nodes: map[string]adapter.Outbound{
			"node-test": &customMockOutbound{
				tag:  "node-test",
				conn: clientConn,
			},
		},
		sidecars: map[string]bool{
			"node-test": true,
		},
	}

	poolOb := NewPoolOutbound(PoolOutboundOptions{
		Tag:          "PROXY_POOL",
		PoolTag:      "PROXY_POOL",
		NodeProvider: provider,
		Blocker:      bl,
	})

	inboundCtx := &adapter.InboundContext{
		Source: M.ParseSocksaddr("127.0.0.1:54321"),
	}
	ctx := adapter.WithContext(context.Background(), inboundCtx)
	dest := M.ParseSocksaddr("example.com:80")
	conn, err := poolOb.DialContext(ctx, "tcp", dest)
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	defer conn.Close()

	_, _ = conn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	respBuf := make([]byte, 64)
	n, readErr := conn.Read(respBuf)
	if readErr != nil || n == 0 {
		t.Fatalf("Read failed: %v", readErr)
	}
	<-done

	entries := bl.Logger().GetEntries(10)
	if len(entries) == 0 {
		t.Fatalf("expected log entries")
	}
	if entries[0].Duration <= 0 {
		t.Errorf("expected positive duration on log entry, got %v", entries[0].Duration)
	}
	if entries[0].Error != "" {
		t.Errorf("expected no error on log entry, got %q", entries[0].Error)
	}
}

// Regression test: when remote proxy blackholes/hangs, firstRTTConn times out within
// firstPacketTimeout, annotates the query log with elapsed duration and "连接超时",
// and records the dial failure in the tracker instead of hanging for 30s-120s.
func TestPoolOutbound_FirstPacketTimeout_FastFail(t *testing.T) {
	origTimeout := firstPacketTimeout
	origStall := firstPacketStall
	firstPacketTimeout = 60 * time.Millisecond
	firstPacketStall = 30 * time.Millisecond
	defer func() {
		firstPacketTimeout = origTimeout
		firstPacketStall = origStall
	}()

	bl := blocker.NewEngine(blocker.Options{})
	bl.Logger().SetDedupWindow(0)
	tr := telemetry.NewTracker()

	logID := bl.Logger().RecordWithChain("timeout.com", blocker.SourceGateway, blocker.VerdictAllowed, "", "final -> PROXY_POOL -> node-blackhole")
	bl.Logger().BindSourceConn("127.0.0.1:58888", logID)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		buf := make([]byte, 64)
		_, _ = serverConn.Read(buf)
		// Server intentionally does not reply to simulate remote blackhole
	}()

	provider := &testNodeProvider{
		candidates: map[string][]string{
			"PROXY_POOL": {"node-blackhole"},
		},
		nodes: map[string]adapter.Outbound{
			"node-blackhole": &customMockOutbound{
				tag:  "node-blackhole",
				conn: clientConn,
			},
		},
		sidecars: map[string]bool{
			"node-blackhole": true,
		},
	}

	poolOb := NewPoolOutbound(PoolOutboundOptions{
		Tag:          "PROXY_POOL",
		NodeProvider: provider,
		Tracker:      tr,
		Blocker:      bl,
	})

	inboundCtx := &adapter.InboundContext{
		Source: M.ParseSocksaddr("127.0.0.1:58888"),
	}
	ctx := adapter.WithContext(context.Background(), inboundCtx)
	dest := M.ParseSocksaddr("timeout.com:80")

	conn, err := poolOb.DialContext(ctx, "tcp", dest)
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	defer conn.Close()

	// Client sends HTTP request
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Server does NOT send any response data. Read must time out around 60ms.
	buf := make([]byte, 64)
	n, readErr := conn.Read(buf)
	if readErr == nil {
		t.Fatalf("expected read error due to deadline, got n=%d", n)
	}

	entries := bl.Logger().GetEntries(10)
	if len(entries) == 0 {
		t.Fatalf("expected log entries")
	}
	if entries[0].Duration <= 0 {
		t.Errorf("expected positive duration on timed-out log entry, got %v", entries[0].Duration)
	}
	if entries[0].Error != "连接超时" {
		t.Errorf("expected error to be '连接超时', got %q", entries[0].Error)
	}

	sc := tr.GetScore("node-blackhole")
	if sc.ConsecutiveFailures == 0 {
		t.Errorf("expected consecutive failures >= 1, got %d", sc.ConsecutiveFailures)
	}
}

// Regression test: when a connection hangs for longer than firstPacketStall,
// RecordStall immediately evicts domain affinity so subsequent requests do not
// continue being funneled into the blackholed node while waiting for full timeout.
func TestPoolOutbound_InFlightStallEvictsAffinity(t *testing.T) {
	origTimeout := firstPacketTimeout
	origStall := firstPacketStall
	firstPacketTimeout = 200 * time.Millisecond
	firstPacketStall = 30 * time.Millisecond
	defer func() {
		firstPacketTimeout = origTimeout
		firstPacketStall = origStall
	}()

	tr := telemetry.NewTracker()
	// Pre-seed affinity for target domain to node-bad
	_, _ = tr.SelectBest([]string{"node-bad", "node-good"}, "example.com")

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		buf := make([]byte, 64)
		_, _ = serverConn.Read(buf)
		// Server intentionally does not reply to simulate remote blackhole
	}()

	provider := &testNodeProvider{
		candidates: map[string][]string{
			"PROXY_POOL": {"node-bad", "node-good"},
		},
		nodes: map[string]adapter.Outbound{
			"node-bad": &customMockOutbound{
				tag:  "node-bad",
				conn: clientConn,
			},
			"node-good": &customMockOutbound{
				tag: "node-good",
			},
		},
		sidecars: map[string]bool{
			"node-bad":  true,
			"node-good": true,
		},
	}

	poolOb := NewPoolOutbound(PoolOutboundOptions{
		Tag:          "PROXY_POOL",
		NodeProvider: provider,
		Tracker:      tr,
	})

	ctx := context.Background()
	dest := M.ParseSocksaddr("example.com:80")

	conn, err := poolOb.DialContext(ctx, "tcp", dest)
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	defer conn.Close()

	// Write request to arm stall timer
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Wait for stall timer (30ms) to trigger
	time.Sleep(50 * time.Millisecond)

	// Subsequent request for example.com must NOT pick node-bad
	nextCand := poolOb.SelectCandidate("example.com")
	if nextCand == "node-bad" {
		t.Errorf("expected affinity to be evicted after in-flight stall, but got %q", nextCand)
	}
	if nextCand != "node-good" {
		t.Errorf("expected next candidate to be node-good, got %q", nextCand)
	}
}

// Regression test: when client aborts/closes the connection before receiving the first response byte,
// firstRTTConn must record the elapsed duration instead of 0, correctly annotating "首包未响应中断".
func TestPoolOutbound_ClientPrematureCloseRecordsDurationAndError(t *testing.T) {
	origTimeout := firstPacketTimeout
	origStall := firstPacketStall
	firstPacketTimeout = 500 * time.Millisecond
	firstPacketStall = 500 * time.Millisecond
	defer func() {
		firstPacketTimeout = origTimeout
		firstPacketStall = origStall
	}()

	bl := blocker.NewEngine(blocker.Options{})
	bl.Logger().SetDedupWindow(0)
	tr := telemetry.NewTracker()

	logID := bl.Logger().RecordWithChain("abort.com", blocker.SourceGateway, blocker.VerdictAllowed, "", "final -> PROXY_POOL -> node-abort")
	bl.Logger().BindSourceConn("127.0.0.1:59999", logID)

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	go func() {
		buf := make([]byte, 64)
		_, _ = serverConn.Read(buf)
	}()

	provider := &testNodeProvider{
		candidates: map[string][]string{
			"PROXY_POOL": {"node-abort"},
		},
		nodes: map[string]adapter.Outbound{
			"node-abort": &customMockOutbound{
				tag:  "node-abort",
				conn: clientConn,
			},
		},
		sidecars: map[string]bool{
			"node-abort": true,
		},
	}

	poolOb := NewPoolOutbound(PoolOutboundOptions{
		Tag:          "PROXY_POOL",
		NodeProvider: provider,
		Tracker:      tr,
		Blocker:      bl,
	})

	inboundCtx := &adapter.InboundContext{
		Source: M.ParseSocksaddr("127.0.0.1:59999"),
	}
	ctx := adapter.WithContext(context.Background(), inboundCtx)
	dest := M.ParseSocksaddr("abort.com:80")

	conn, err := poolOb.DialContext(ctx, "tcp", dest)
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}

	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	time.Sleep(15 * time.Millisecond)

	// Client closes prematurely
	_ = conn.Close()

	entries := bl.Logger().GetEntries(10)
	if len(entries) == 0 {
		t.Fatalf("expected log entries")
	}
	if entries[0].Duration <= 0 {
		t.Errorf("expected positive duration on prematurely aborted log entry, got %v", entries[0].Duration)
	}
	if entries[0].Error != "首包未响应中断" {
		t.Errorf("expected error to be '首包未响应中断', got %q", entries[0].Error)
	}
}

// Tests that firstRTTConn accurately detects TLS ClientHello records to measure pure 1-RTT TLS handshake.
func TestPoolOutbound_TLSClientHelloSniffing(t *testing.T) {
	// Standard TLS 1.2/1.3 ClientHello packet header (0x16 0x03 0x01 ... 0x01)
	clientHello := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00}
	if !isTLSClientHello(clientHello) {
		t.Fatalf("expected isTLSClientHello to return true for standard ClientHello")
	}

	// Plaintext HTTP request
	httpReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if isTLSClientHello(httpReq) {
		t.Fatalf("expected isTLSClientHello to return false for plaintext HTTP")
	}

	// Truncated packet
	truncated := []byte{0x16, 0x03}
	if isTLSClientHello(truncated) {
		t.Fatalf("expected isTLSClientHello to return false for truncated buffer")
	}
}

