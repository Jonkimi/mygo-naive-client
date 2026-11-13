package warp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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
		binary.LittleEndian.PutUint32(resp[0:4], 2)         // Type=2 Handshake Response
		binary.LittleEndian.PutUint32(resp[4:8], 9999)      // Responder index
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

	fakeMASQUE := func(ctx context.Context, dialer Dialer, endpoint string, acc *Account, mOpts MASQUEOptions) (string, time.Duration, error) {
		switch endpoint {
		case "ep-slow":
			return "h3", 120 * time.Millisecond, nil
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
		Mode:       ModeMASQUE,
		Candidates: []string{"ep-slow", "ep-dead", "ep-fast", "ep-mid"},
		TopN:       2,
	}, fakeMASQUE, fakeWG)
	if err != nil {
		t.Fatalf("scanBestEndpointsWithProbers failed: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected TopN=2 results, got %d", len(results))
	}
	if results[0].Endpoint != "ep-fast" || results[1].Endpoint != "ep-mid" {
		t.Errorf("expected sorted [ep-fast, ep-mid], got %+v", results)
	}
}
