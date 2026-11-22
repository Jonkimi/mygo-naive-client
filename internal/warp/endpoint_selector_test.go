package warp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestEndpointSelector_SelectLowestRTTAndCache(t *testing.T) {
	sel := NewEndpointSelector()
	sel.masqueCandidates = []string{"162.159.198.1:443", "162.159.198.2:443", "162.159.198.3:443"}
	sel.raceWindow = 120 * time.Millisecond

	var probeCalls atomic.Int32
	sel.masqueProbeFn = func(ctx context.Context, dialer Dialer, endpoint string, acc *Account, opts MASQUEOptions) (string, time.Duration, error) {
		probeCalls.Add(1)
		switch endpoint {
		case "162.159.198.1:443":
			time.Sleep(45 * time.Millisecond)
			return "h3", 45 * time.Millisecond, nil
		case "162.159.198.2:443":
			time.Sleep(10 * time.Millisecond)
			return "h3", 10 * time.Millisecond, nil
		default:
			return "", 0, errors.New("unreachable")
		}
	}

	res, err := sel.SelectMASQUEEndpoint(context.Background(), "node-jp", nil, &Account{}, MASQUEOptions{})
	if err != nil {
		t.Fatalf("SelectMASQUEEndpoint failed: %v", err)
	}
	if res.Endpoint != "162.159.198.2:443" {
		t.Errorf("expected lowest-RTT endpoint 162.159.198.2:443, got %s", res.Endpoint)
	}
	if res.Protocol != "h3" {
		t.Errorf("expected protocol h3, got %s", res.Protocol)
	}

	// Second call within TTL should hit cache without probing
	callsBefore := probeCalls.Load()
	res2, err := sel.SelectMASQUEEndpoint(context.Background(), "node-jp", nil, &Account{}, MASQUEOptions{})
	if err != nil {
		t.Fatalf("cached SelectMASQUEEndpoint failed: %v", err)
	}
	if res2.Endpoint != "162.159.198.2:443" {
		t.Errorf("expected cached endpoint 162.159.198.2:443, got %s", res2.Endpoint)
	}
	if probeCalls.Load() != callsBefore {
		t.Errorf("expected cache hit with 0 new probes, got %d new probes", probeCalls.Load()-callsBefore)
	}
}

func TestEndpointSelector_PerScopeIsolation(t *testing.T) {
	sel := NewEndpointSelector()
	sel.masqueCandidates = []string{"162.159.198.1:443", "162.159.198.2:443"}
	sel.raceWindow = 80 * time.Millisecond

	sel.SetCached(EndpointCacheKey{ScopeKey: "direct", Mode: ModeMASQUE}, "162.159.198.1:443", "h3", 15*time.Millisecond)
	sel.SetCached(EndpointCacheKey{ScopeKey: "node-us", Mode: ModeMASQUE}, "162.159.198.2:443", "h3", 8*time.Millisecond)

	epDirect, ok := sel.GetCached(EndpointCacheKey{ScopeKey: "direct", Mode: ModeMASQUE})
	if !ok || epDirect != "162.159.198.1:443" {
		t.Fatalf("expected direct cached endpoint 162.159.198.1:443, got %q (%v)", epDirect, ok)
	}
	epUS, ok := sel.GetCached(EndpointCacheKey{ScopeKey: "node-us", Mode: ModeMASQUE})
	if !ok || epUS != "162.159.198.2:443" {
		t.Fatalf("expected node-us cached endpoint 162.159.198.2:443, got %q (%v)", epUS, ok)
	}

	// TCPOnly key must also be isolated from UDP/H3 key for the same scope
	if _, ok := sel.GetCached(EndpointCacheKey{ScopeKey: "node-us", Mode: ModeMASQUE, TCPOnly: true}); ok {
		t.Errorf("expected TCPOnly cache key to be isolated from default key")
	}

	// Marking node-us failed must not evict direct's cache
	sel.MarkFailed(EndpointCacheKey{ScopeKey: "node-us", Mode: ModeMASQUE}, "162.159.198.2:443")
	if _, ok := sel.GetCached(EndpointCacheKey{ScopeKey: "node-us", Mode: ModeMASQUE}); ok {
		t.Errorf("expected node-us cache to be evicted after MarkFailed")
	}
	if ep, ok := sel.GetCached(EndpointCacheKey{ScopeKey: "direct", Mode: ModeMASQUE}); !ok || ep != "162.159.198.1:443" {
		t.Errorf("expected direct cache to remain untouched, got %q (%v)", ep, ok)
	}
}

func TestEndpointSelector_MarkFailedCooldownAndReSelection(t *testing.T) {
	sel := NewEndpointSelector()
	sel.masqueCandidates = []string{"162.159.198.1:443", "162.159.198.2:443"}
	sel.raceWindow = 60 * time.Millisecond

	key := EndpointCacheKey{ScopeKey: "node-hk", Mode: ModeMASQUE}
	sel.SetCached(key, "162.159.198.1:443", "h3", 10*time.Millisecond)
	sel.MarkFailed(key, "162.159.198.1:443")

	sel.masqueProbeFn = func(ctx context.Context, dialer Dialer, endpoint string, acc *Account, opts MASQUEOptions) (string, time.Duration, error) {
		if endpoint == "162.159.198.1:443" {
			t.Errorf("cooled-down endpoint 162.159.198.1:443 should not be probed while healthy candidates exist")
		}
		if endpoint == "162.159.198.2:443" {
			return "h3", 12 * time.Millisecond, nil
		}
		return "", 0, errors.New("not selected")
	}

	res, err := sel.SelectMASQUEEndpoint(context.Background(), "node-hk", nil, &Account{}, MASQUEOptions{})
	if err != nil {
		t.Fatalf("re-selection failed: %v", err)
	}
	if res.Endpoint != "162.159.198.2:443" {
		t.Errorf("expected fallback healthy endpoint 162.159.198.2:443, got %s", res.Endpoint)
	}
}

func TestEndpointSelector_WireGuardProbeAndPacket(t *testing.T) {
	priv, _, err := GenerateWireGuardKeypair()
	if err != nil {
		t.Fatalf("GenerateWireGuardKeypair failed: %v", err)
	}
	var peerPub [32]byte
	if _, err := rand.Read(peerPub[:]); err != nil {
		t.Fatal(err)
	}
	peerPubB64 := base64.StdEncoding.EncodeToString(peerPub[:])

	// Start a mock UDP responder simulating Cloudflare WireGuard Handshake Response (Type=2, 92 bytes)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket failed: %v", err)
	}
	defer pc.Close()

	receivedReserved := make(chan [3]byte, 1)
	go func() {
		buf := make([]byte, 256)
		n, addr, rErr := pc.ReadFrom(buf)
		if rErr != nil || n != 148 || buf[0] != 1 {
			return
		}
		var resv [3]byte
		copy(resv[:], buf[1:4])
		receivedReserved <- resv

		senderIdx := binary.LittleEndian.Uint32(buf[4:8])
		resp := make([]byte, 92)
		binary.LittleEndian.PutUint32(resp[0:4], 2)          // Type=2 Handshake Response
		binary.LittleEndian.PutUint32(resp[4:8], 9999)       // Responder index
		binary.LittleEndian.PutUint32(resp[8:12], senderIdx) // Echoed sender index
		_, _ = pc.WriteTo(resp, addr)
	}()

	acc := &Account{
		WGPrivateKey:    priv,
		WGPeerPublicKey: peerPubB64,
		Reserved:        []uint8{0x12, 0x34, 0x56},
	}

	sel := NewEndpointSelector()
	sel.wgCandidates = []string{pc.LocalAddr().String()}

	res, err := sel.SelectWireGuardEndpoint(context.Background(), "direct", nil, acc)
	if err != nil {
		t.Fatalf("SelectWireGuardEndpoint failed: %v", err)
	}
	if res.Endpoint != pc.LocalAddr().String() || res.Protocol != "wireguard" {
		t.Errorf("unexpected WG result: %+v", res)
	}
	select {
	case gotResv := <-receivedReserved:
		if gotResv != [3]byte{0x12, 0x34, 0x56} {
			t.Errorf("expected Reserved [0x12 0x34 0x56], got %x", gotResv)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for WG handshake packet")
	}
}

func TestScanBestEndpoints_SortsTopNAndSamplesCIDRs(t *testing.T) {
	if len(WireGuardPorts) < 50 {
		t.Fatalf("expected 50+ official Cloudflare WireGuard UDP ports, got %d", len(WireGuardPorts))
	}

	sampledMASQUE := sampleMASQUECandidates(16)
	if len(sampledMASQUE) != 16 {
		t.Fatalf("expected 16 sampled MASQUE candidates, got %d", len(sampledMASQUE))
	}
	for _, ep := range sampledMASQUE {
		if !strings.Contains(ep, ":") {
			t.Errorf("invalid sampled endpoint: %s", ep)
		}
	}

	sampledWG := sampleWireGuardCandidates(12)
	if len(sampledWG) != 12 {
		t.Fatalf("expected 12 sampled WG candidates, got %d", len(sampledWG))
	}

	var slowCalls atomic.Int32
	fakeMASQUE := func(ctx context.Context, dialer Dialer, endpoint string, acc *Account, mOpts MASQUEOptions) (string, time.Duration, error) {
		switch endpoint {
		case "ep-slow":
			// 1st probe succeeds with low RTT (10ms), follow-up 2 probes drop -> 66.7% loss!
			// Score = 10ms + 0.667*2000ms = ~1343ms, so it must rank BELOW ep-mid (0% loss, 45ms).
			n := slowCalls.Add(1)
			if n == 1 {
				return "h3", 10 * time.Millisecond, nil
			}
			return "", 0, errors.New("packet loss")
		case "ep-fast":
			return "h2", 18 * time.Millisecond, nil
		case "ep-mid":
			return "h3", 45 * time.Millisecond, nil
		default:
			return "", 0, errors.New("timeout")
		}
	}
	fakeWG := func(ctx context.Context, dialer Dialer, endpoint string, acc *Account) (time.Duration, error) {
		return 0, errors.New("unused")
	}

	results, err := scanBestEndpointsWithProbers(context.Background(), ScanOptions{
		Mode:        ModeMASQUE,
		Candidates:  []string{"ep-slow", "ep-dead", "ep-fast", "ep-mid"},
		ProbeRounds: 3,
		TopN:        3,
	}, fakeMASQUE, fakeWG)
	if err != nil {
		t.Fatalf("scanBestEndpointsWithProbers failed: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected TopN=3 results, got %d", len(results))
	}
	if results[0].Endpoint != "ep-fast" || results[1].Endpoint != "ep-mid" || results[2].Endpoint != "ep-slow" {
		t.Errorf("expected sorted [ep-fast (0%% loss), ep-mid (0%% loss), ep-slow (lossy)], got %+v", results)
	}
	if results[0].LossRate != 0 || results[2].LossRate <= 0.5 {
		t.Errorf("expected ep-fast loss=0 and ep-slow loss>0.5, got %+v", results)
	}
}

type stallingCancelDialer struct {
	startedOnce sync.Once
	started     chan struct{}
}

func (d *stallingCancelDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.startedOnce.Do(func() {
		close(d.started)
	})
	<-ctx.Done()
	return nil, ctx.Err()
}

func (d *stallingCancelDialer) ListenPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	d.startedOnce.Do(func() {
		close(d.started)
	})
	<-ctx.Done()
	return nil, ctx.Err()
}

// Regression: canceling SelectMASQUEAndConnect during engine shutdown (both pre-canceled
// and mid-dial) must not mark a healthy cached endpoint as failed and put it on cooldown.
func TestEndpointSelector_SelectMASQUEAndConnect_CanceledContextDoesNotMarkFailed(t *testing.T) {
	priv, _, certPEM, err := GenerateMASQUEKeypair()
	if err != nil {
		t.Fatalf("GenerateMASQUEKeypair: %v", err)
	}
	acc := &Account{
		MASQUEPrivateKey: priv,
		MASQUECertPEM:    certPEM,
		MASQUEIPv4:       "172.16.0.2",
	}

	sel := NewEndpointSelector()
	key := EndpointCacheKey{
		ScopeKey: "direct",
		Mode:     ModeMASQUE,
	}
	const ep = "162.159.198.2:443"
	sel.SetCached(key, ep, "h3", 15*time.Millisecond)

	// 1. Pre-canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := sel.SelectMASQUEAndConnect(ctx, "direct", nil, acc, MASQUEOptions{}); err == nil {
		t.Fatalf("expected error for pre-canceled context")
	}
	if cached, ok := sel.GetCached(key); !ok || cached != ep {
		t.Fatalf("expected cached endpoint %q to stay intact after pre-cancel, got %q (ok=%v)", ep, cached, ok)
	}

	// 2. Mid-dial cancellation while ConnectMASQUEWithOptions is in flight
	midCtx, midCancel := context.WithCancel(context.Background())
	d := &stallingCancelDialer{started: make(chan struct{})}
	go func() {
		<-d.started
		midCancel()
	}()
	if _, _, err := sel.SelectMASQUEAndConnect(midCtx, "direct", d, acc, MASQUEOptions{}); err == nil {
		t.Fatalf("expected error for mid-dial canceled context")
	}
	if cached, ok := sel.GetCached(key); !ok || cached != ep {
		t.Fatalf("expected cached endpoint %q to stay intact after mid-dial cancellation, got %q (ok=%v)", ep, cached, ok)
	}
	tcpKey := EndpointCacheKey{ScopeKey: "direct", Mode: ModeMASQUE, TCPOnly: true}
	sel.SetCached(tcpKey, ep, "h2", 15*time.Millisecond)
	midCtx2, midCancel2 := context.WithCancel(context.Background())
	d2 := &stallingCancelDialer{started: make(chan struct{})}
	go func() {
		<-d2.started
		midCancel2()
	}()
	if _, _, err := sel.SelectMASQUEAndConnect(midCtx2, "direct", d2, acc, MASQUEOptions{TCPOnly: true}); err == nil {
		t.Fatalf("expected error for mid-dial canceled TCPOnly context")
	}
	if cached, ok := sel.GetCached(tcpKey); !ok || cached != ep {
		t.Fatalf("expected cached endpoint %q to stay intact after mid-dial cancellation, got %q (ok=%v)", ep, cached, ok)
	}
}

// Regression: SelectMASQUEAndConnect's retry branch previously checked !errors.Is(err, context.Canceled)
// using the first attempt's error rather than err2, putting ep2 on cooldown when canceled mid-dial.
func TestEndpointSelector_SelectMASQUEAndConnect_SecondAttemptCancelDoesNotMarkFailed(t *testing.T) {
	priv, _, certPEM, err := GenerateMASQUEKeypair()
	if err != nil {
		t.Fatalf("GenerateMASQUEKeypair: %v", err)
	}
	acc := &Account{
		MASQUEPrivateKey: priv,
		MASQUECertPEM:    certPEM,
		MASQUEIPv4:       "172.16.0.2",
	}

	const ep1 = "198.51.100.1:443"
	const ep2 = "198.51.100.2:443"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sel := NewEndpointSelector()
	sel.masqueCandidates = []string{ep1, ep2}
	probeCount := map[string]int{}
	var probeMu sync.Mutex
	sel.masqueProbeFn = func(pCtx context.Context, dialer Dialer, endpoint string, a *Account, opts MASQUEOptions) (string, time.Duration, error) {
		probeMu.Lock()
		probeCount[endpoint]++
		probeMu.Unlock()
		return "h2", 5 * time.Millisecond, nil
	}
	// Pre-seed ep1 so first dial tries ep1 -> fails cleanly -> retry picks ep2 from selector -> cancels!
	key := EndpointCacheKey{ScopeKey: "direct", Mode: ModeMASQUE, TCPOnly: true}
	sel.SetCached(key, ep1, "h2", 5*time.Millisecond)

	dialer := &switchingCancelDialer{
		failEP:   ep1,
		cancelEP: ep2,
		cancel:   cancel,
	}
	_, _, connErr := sel.SelectMASQUEAndConnect(ctx, "direct", dialer, acc, MASQUEOptions{TCPOnly: true})
	if !errors.Is(connErr, context.Canceled) {
		t.Fatalf("expected context.Canceled on canceled retry, got %v", connErr)
	}

	sel.mu.RLock()
	ep1Failed := !sel.failedUntil[key][ep1].IsZero()
	ep2Failed := !sel.failedUntil[key][ep2].IsZero()
	sel.mu.RUnlock()
	if !ep1Failed {
		t.Fatalf("expected first failing endpoint %q to be marked failed", ep1)
	}
	if ep2Failed {
		t.Fatalf("expected canceled second endpoint %q NOT to be marked failed", ep2)
	}
}

type switchingCancelDialer struct {
	failEP   string
	cancelEP string
	cancel   context.CancelFunc
}

func (d *switchingCancelDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if addr == d.failEP {
		return nil, errors.New("connection refused")
	}
	if addr == d.cancelEP {
		d.cancel()
		return nil, ctx.Err()
	}
	return nil, errors.New("unexpected endpoint")
}

func (d *switchingCancelDialer) ListenPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	return nil, errors.New("unused")
}

func TestMASQUEPoolsAndKnownH2OnlyClassifier(t *testing.T) {
	wantPorts := []int{443, 500, 1701, 4500, 4443, 8443, 8095}
	if !slices.Equal(MASQUEPorts, wantPorts) {
		t.Fatalf("MASQUEPorts = %v, want %v", MASQUEPorts, wantPorts)
	}
	if !slices.Contains(MASQUEAnycastCIDRs, "162.159.198.0/24") || !slices.Contains(MASQUEAnycastCIDRs, "162.159.199.0/24") {
		t.Fatalf("MASQUEAnycastCIDRs missing expected subnets: %v", MASQUEAnycastCIDRs)
	}

	quicCapable := []string{
		"162.159.198.1:443",
		"162.159.198.2:8095",
		"[2606:4700:103::1]:443",
		"[2606:4700:103::2]:4500",
		"[2606:4700:104::1]:500",
		"[2606:4700:104::2]:8443",
		"127.0.0.1:443",
		"engage.cloudflareclient.com:443",
	}
	for _, ep := range quicCapable {
		if isKnownMASQUEH2OnlyEndpoint(ep) {
			t.Errorf("isKnownMASQUEH2OnlyEndpoint(%q) = true, want false", ep)
		}
	}

	h2Only := []string{
		"162.159.198.3:443",
		"162.159.198.250:8443",
		"162.159.199.1:443",
		"162.159.199.42:8095",
		"[2606:4700:103::5]:443",
		"[2606:4700:104::beef]:4443",
	}
	for _, ep := range h2Only {
		if !isKnownMASQUEH2OnlyEndpoint(ep) {
			t.Errorf("isKnownMASQUEH2OnlyEndpoint(%q) = false, want true", ep)
		}
	}

	quicV4 := sampleMASQUEQUICCandidates(64, false)
	if len(quicV4) != len(MASQUEQUICAnycastCIDRs)*len(MASQUEPorts) {
		t.Fatalf("expected %d IPv4 QUIC endpoints, got %d", len(MASQUEQUICAnycastCIDRs)*len(MASQUEPorts), len(quicV4))
	}
	for _, ep := range quicV4 {
		if isKnownMASQUEH2OnlyEndpoint(ep) {
			t.Errorf("QUIC candidate %q should not be classified H2-only", ep)
		}
	}

	quicDual := sampleMASQUEQUICCandidates(64, true)
	wantDual := (len(MASQUEQUICAnycastCIDRs) + len(MASQUEQUICAnycastCIDRsV6)) * len(MASQUEPorts)
	if len(quicDual) != wantDual {
		t.Fatalf("expected %d dual-stack QUIC endpoints, got %d", wantDual, len(quicDual))
	}

	h2Dual := sampleMASQUEH2Candidates(32, true)
	if len(h2Dual) != 32 {
		t.Fatalf("expected 32 H2 dual-stack candidates, got %d", len(h2Dual))
	}
	has199, hasV6 := false, false
	for _, ep := range h2Dual {
		ap, err := netip.ParseAddrPort(ep)
		if err != nil {
			t.Fatalf("invalid H2 candidate %q: %v", ep, err)
		}
		if masqueH2Subnet199.Contains(ap.Addr()) {
			has199 = true
		}
		if ap.Addr().Is6() {
			hasV6 = true
		}
	}
	if !has199 || !hasV6 {
		t.Fatalf("expected H2 dual-stack candidates to cover 162.159.199.0/24 (has199=%v) and IPv6 (hasV6=%v)", has199, hasV6)
	}
}

func TestScanBestEndpoints_MASQUEQUICTier1AndH2Tier2Fallback(t *testing.T) {
	noV6 := false

	// Case 1: QUIC-first scan where .1/.2 responds on H3 -> stops at Tier 1 without sweeping .199.x
	var tier1Probed []string
	var mu sync.Mutex
	resH3, err := scanBestEndpointsWithProbers(context.Background(), ScanOptions{
		Mode:        ModeMASQUE,
		IncludeIPv6: &noV6,
		SampleCount: 64,
		ProbeRounds: 2,
		TopN:        4,
	}, func(ctx context.Context, dialer Dialer, endpoint string, acc *Account, mOpts MASQUEOptions) (string, time.Duration, error) {
		mu.Lock()
		tier1Probed = append(tier1Probed, endpoint)
		mu.Unlock()
		if endpoint == "162.159.198.2:4500" {
			return "h3", 12 * time.Millisecond, nil
		}
		if endpoint == "162.159.198.1:443" {
			return "h3", 25 * time.Millisecond, nil
		}
		return "", 0, errors.New("unreachable")
	}, nil)
	if err != nil {
		t.Fatalf("Tier 1 QUIC scan failed: %v", err)
	}
	if len(resH3) != 2 || resH3[0].Endpoint != "162.159.198.2:4500" || resH3[0].Protocol != "h3" {
		t.Fatalf("unexpected Tier 1 QUIC results: %+v", resH3)
	}
	for _, ep := range tier1Probed {
		if isKnownMASQUEH2OnlyEndpoint(ep) {
			t.Fatalf("Tier 1 QUIC scan should not probe H2-only endpoint %q when H3 succeeded", ep)
		}
	}

	// Case 2: UDP/QUIC blocked (0 H3 hits on Tier 1) -> expands to Tier 2 H2 subnets with ForceH2=true
	var tier2ForceH2Seen atomic.Bool
	resH2, err := scanBestEndpointsWithProbers(context.Background(), ScanOptions{
		Mode:        ModeMASQUE,
		IncludeIPv6: &noV6,
		SampleCount: 32,
		ProbeRounds: 2,
		TopN:        4,
	}, func(ctx context.Context, dialer Dialer, endpoint string, acc *Account, mOpts MASQUEOptions) (string, time.Duration, error) {
		if mOpts.ForceH2 {
			tier2ForceH2Seen.Store(true)
		}
		if strings.HasPrefix(endpoint, "162.159.199.") && mOpts.ForceH2 {
			return "h2", 15 * time.Millisecond, nil
		}
		return "", 0, errors.New("udp blocked")
	}, nil)
	if err != nil {
		t.Fatalf("Tier 2 H2 fallback scan failed: %v", err)
	}
	if !tier2ForceH2Seen.Load() {
		t.Fatalf("expected Tier 2 fallback to invoke probe with ForceH2=true")
	}
	if len(resH2) == 0 || resH2[0].Protocol != "h2" {
		t.Fatalf("expected Tier 2 H2 fallback results, got %+v", resH2)
	}
}

type h2FallbackTestDialer struct {
	tlsAddr      string
	udpCalls     atomic.Int32
	tcpCalls     atomic.Int32
	stallUDP     bool
}

func (d *h2FallbackTestDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.tcpCalls.Add(1)
	var nd net.Dialer
	return nd.DialContext(ctx, network, d.tlsAddr)
}

func (d *h2FallbackTestDialer) ListenPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	d.udpCalls.Add(1)
	if d.stallUDP {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return nil, errors.New("udp unexpected")
}

func TestProbeMASQUEEndpoint_SubTimeoutFallbackAndH2OnlySkip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{DefaultMASQUESNI},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				if tc, ok := conn.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
			}(c)
		}
	}()

	// 1. Stalled UDP (blackholed) on a QUIC-capable endpoint must still leave time for H2 fallback.
	dStall := &h2FallbackTestDialer{tlsAddr: ln.Addr().String(), stallUDP: true}
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	proto, _, err := probeMASQUEEndpoint(ctx, dStall, "162.159.198.1:443", nil, MASQUEOptions{})
	if err != nil {
		t.Fatalf("expected H2 fallback to succeed after bounded H3 sub-timeout, got %v", err)
	}
	if proto != "h2" {
		t.Fatalf("expected protocol h2, got %q", proto)
	}
	if dStall.udpCalls.Load() == 0 || dStall.tcpCalls.Load() == 0 {
		t.Fatalf("expected both UDP attempt and TCP fallback, got udp=%d tcp=%d", dStall.udpCalls.Load(), dStall.tcpCalls.Load())
	}

	// 2. Known H2-only endpoint (162.159.199.5:443) skips ListenPacket (QUIC) completely.
	dSkip := &h2FallbackTestDialer{tlsAddr: ln.Addr().String(), stallUDP: true}
	proto2, _, err := probeMASQUEEndpoint(context.Background(), dSkip, "162.159.199.5:443", nil, MASQUEOptions{})
	if err != nil {
		t.Fatalf("H2-only probe failed: %v", err)
	}
	if proto2 != "h2" {
		t.Fatalf("expected protocol h2, got %q", proto2)
	}
	if dSkip.udpCalls.Load() != 0 {
		t.Fatalf("expected 0 UDP ListenPacket calls for H2-only endpoint, got %d", dSkip.udpCalls.Load())
	}
}

// Regression: when MASQUE account credentials are enrolled, probeMASQUEEndpoint must verify
// real cf-connect-ip HTTP/2 CONNECT-IP (not just TLS handshake) to reject DPI/blackhole false positives.
func TestProbeMASQUEEndpoint_EnrolledAccountVerifiesConnectIP(t *testing.T) {
	priv, _, certPEM, err := GenerateMASQUEKeypair()
	if err != nil {
		t.Fatalf("GenerateMASQUEKeypair: %v", err)
	}
	acc := &Account{
		MASQUEPrivateKey: priv,
		MASQUECertPEM:    certPEM,
		MASQUEIPv4:       "172.16.0.2",
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{DefaultMASQUESNI},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"h2"},
	}

	// 1. Server accepts TLS H2 handshake but stalls cf-connect-ip CONNECT -> must fail probe.
	stallLn, err := tls.Listen("tcp", "127.0.0.1:0", srvTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer stallLn.Close()
	stallSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}),
	}
	_ = http2.ConfigureServer(stallSrv, &http2.Server{})
	go func() { _ = stallSrv.Serve(stallLn) }()
	defer stallSrv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if _, _, pErr := probeMASQUEEndpoint(ctx, nil, stallLn.Addr().String(), acc, MASQUEOptions{ForceH2: true}); pErr == nil {
		t.Fatalf("expected enrolled H2 probe to fail when server stalls cf-connect-ip CONNECT")
	}

	// 2. Server handles cf-connect-ip CONNECT with 200 OK -> must succeed with protocol "h2".
	okLn, err := tls.Listen("tcp", "127.0.0.1:0", srvTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer okLn.Close()
	var sawConnectProto atomic.Bool
	okSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect && r.Header.Get("cf-connect-proto") == "cf-connect-ip" {
				sawConnectProto.Store(true)
				w.WriteHeader(http.StatusOK)
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				<-r.Context().Done()
				return
			}
			http.Error(w, "bad request", http.StatusBadRequest)
		}),
	}
	_ = http2.ConfigureServer(okSrv, &http2.Server{})
	go func() { _ = okSrv.Serve(okLn) }()
	defer okSrv.Close()

	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	proto, _, okErr := probeMASQUEEndpoint(ctx2, nil, okLn.Addr().String(), acc, MASQUEOptions{ForceH2: true})
	if okErr != nil {
		t.Fatalf("expected enrolled H2 probe to succeed on 200 OK cf-connect-ip, got %v", okErr)
	}
	if proto != "h2" {
		t.Fatalf("expected protocol h2, got %q", proto)
	}
	if !sawConnectProto.Load() {
		t.Fatalf("expected server to receive cf-connect-proto: cf-connect-ip header")
	}
}
