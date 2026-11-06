package blocker_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"naive-client/internal/blocker"
	dnsResolver "naive-client/internal/dns"
	"naive-client/internal/gateway"
)

// Tests the dual-layer architecture:
// 1. DNS queries for blocked domains return 0.0.0.0 with 60s TTL and log SourceDNS.
// 2. Gateway connections for blocked domains are rejected locally and log SourceGateway.
// 3. Adding domain to User Allowlist takes effect immediately across both layers.
func TestDualLayer_DNSAndGatewayBlocking(t *testing.T) {
	rules, err := blocker.ParseRuleStream(strings.NewReader(`
||ad.doubleclick.net^
0.0.0.0 telemetry.tracker.com
`), "test-rule")
	if err != nil {
		t.Fatalf("parse rules: %v", err)
	}

	engine := blocker.NewEngine(blocker.Options{
		Ruleset: rules,
	})

	// 1. Setup DNS Resolver with blocker.AsDNS()
	res := dnsResolver.NewResolver(dnsResolver.ResolverOptions{
		Blocker: engine.AsDNS(),
	})

	// DNS Query 1: blocked domain
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	dnsResp, err := res.Resolve(ctx, "ad.doubleclick.net", dns.TypeA)
	if err != nil {
		t.Fatalf("dns resolve error: %v", err)
	}
	if len(dnsResp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(dnsResp.Answer))
	}
	ansA := dnsResp.Answer[0].(*dns.A)
	if ansA.A.String() != "0.0.0.0" || ansA.Hdr.Ttl != 60 {
		t.Fatalf("expected 0.0.0.0/60s, got %v (%ds)", ansA.A, ansA.Hdr.Ttl)
	}

	// 2. Setup Gateway with blocker.AsGateway()
	gw, err := gateway.New(gateway.Options{
		BindAddr: "127.0.0.1:0",
		Blocker:  engine.AsGateway(),
		DialTarget: func(ctx context.Context, target string) (net.Conn, string, error) {
			return nil, "", fmt.Errorf("should not dial blocked target")
		},
	})
	if err != nil {
		t.Fatalf("create gateway: %v", err)
	}
	if err := gw.Start(); err != nil {
		t.Fatalf("start gateway: %v", err)
	}
	defer gw.Stop()

	// SOCKS5 connection to blocked domain
	c, err := net.DialTimeout("tcp", gw.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer c.Close()

	// SOCKS5 handshake
	_, _ = c.Write([]byte{0x05, 0x01, 0x00})
	initResp := make([]byte, 2)
	_, _ = io.ReadFull(c, initResp)

	// SOCKS5 CONNECT to ad.doubleclick.net:443
	host := "ad.doubleclick.net"
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, 0x01, 0xbb)
	_, _ = c.Write(req)

	reply := make([]byte, 10)
	_, err = io.ReadFull(c, reply)
	// Expect connection rejected (0x02: connection not allowed by ruleset)
	if err == nil && reply[1] == 0x00 {
		t.Fatalf("expected gateway connection to be blocked, but received success")
	}

	// 3. Verify Telemetry in QueryLogger
	entries := engine.Logger().GetEntries(10)
	if len(entries) < 2 {
		t.Fatalf("expected at least 2 log entries, got %d", len(entries))
	}

	hasDNSEntry := false
	hasGatewayEntry := false
	for _, entry := range entries {
		if entry.Domain == "ad.doubleclick.net" {
			if entry.Source == blocker.SourceDNS && entry.Verdict == blocker.VerdictBlocked {
				hasDNSEntry = true
			}
			if entry.Source == blocker.SourceGateway && entry.Verdict == blocker.VerdictBlocked {
				hasGatewayEntry = true
			}
		}
	}
	if !hasDNSEntry {
		t.Fatalf("missing DNS blocked entry in QueryLogger")
	}
	if !hasGatewayEntry {
		t.Fatalf("missing Gateway blocked entry in QueryLogger")
	}

	// 4. Hot-whitelist: Add to allowlist and verify immediate unblock
	engine.AddAllowlist("ad.doubleclick.net")
	if blocked, rule := engine.Match("ad.doubleclick.net"); blocked {
		t.Fatalf("expected domain to be allowed after AddAllowlist, got blocked with rule: %s", rule)
	}

	// Verify HTTP CONNECT through gateway records whitelisted verdict
	c2, err := net.DialTimeout("tcp", gw.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer c2.Close()
	br := bufio.NewReader(c2)
	_, _ = c2.Write([]byte("CONNECT ad.doubleclick.net:443 HTTP/1.1\r\nHost: ad.doubleclick.net:443\r\n\r\n"))
	// It will proceed to DialTarget which returns error, not blocked by Blocker (403)
	respLine, _ := br.ReadString('\n')
	if strings.Contains(respLine, "403") {
		t.Fatalf("expected domain to NOT be blocked (403), got: %s", respLine)
	}

	latestEntries := engine.Logger().GetEntries(1)
	if len(latestEntries) > 0 && latestEntries[0].Verdict != blocker.VerdictWhitelisted {
		t.Fatalf("expected latest entry verdict to be WHITELISTED, got %v", latestEntries[0].Verdict)
	}
}
