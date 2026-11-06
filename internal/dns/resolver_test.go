package dns_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	internaldns "naive-client/internal/dns"
	"naive-client/internal/dns/ipcache"
	"naive-client/internal/routing"
)

type mockBlocker struct {
	blockedDomains map[string]bool
}

func (m *mockBlocker) Match(domain string) (bool, string) {
	if m.blockedDomains[strings.ToLower(domain)] {
		return true, "ads-filter"
	}
	return false, ""
}

// Tests the 4-stage DNS resolution pipeline:
// 1) Hosts & MagicDNS
// 2) Blocker (0.0.0.0 / 60s TTL)
// 3) Bootstrap DNS (pure IP UDP for node & DoH domains)
// 4) Domestic DoH (direct) & Remote DoH (proxy)
func TestResolver_FourStagePipeline(t *testing.T) {
	// Setup Mock DoH servers
	var domesticCalls atomic.Int32
	var remoteCalls atomic.Int32
	var bootDNSCalls atomic.Int32

	// Mock UDP Bootstrap DNS (e.g. 223.5.5.5)
	bootPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen packet: %v", err)
	}
	bootDNSAddr := bootPC.LocalAddr().String()
	bootDNSServer := &dns.Server{
		PacketConn: bootPC,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			bootDNSCalls.Add(1)
			m := new(dns.Msg)
			m.SetReply(r)
			rr, _ := dns.NewRR(r.Question[0].Name + " 120 IN A 198.51.100.88")
			m.Answer = append(m.Answer, rr)
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = bootDNSServer.ActivateAndServe() }()
	defer bootDNSServer.Shutdown()

	domesticServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		domesticCalls.Add(1)
		body, _ := io.ReadAll(r.Body)
		req := new(dns.Msg)
		_ = req.Unpack(body)

		resp := new(dns.Msg)
		resp.SetReply(req)
		q := req.Question[0]
		if q.Qtype == dns.TypeA {
			rr, _ := dns.NewRR(q.Name + " 300 IN A 114.114.114.114")
			resp.Answer = append(resp.Answer, rr)
		}
		out, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))
	defer domesticServer.Close()

	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remoteCalls.Add(1)
		body, _ := io.ReadAll(r.Body)
		req := new(dns.Msg)
		_ = req.Unpack(body)

		resp := new(dns.Msg)
		resp.SetReply(req)
		q := req.Question[0]
		if q.Qtype == dns.TypeA {
			rr, _ := dns.NewRR(q.Name + " 300 IN A 104.244.42.1")
			resp.Answer = append(resp.Answer, rr)
		}
		out, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))
	defer remoteServer.Close()

	// Setup Mock MagicDNS Server (miekg/dns UDP server)
	magicPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen packet: %v", err)
	}
	magicAddr := magicPC.LocalAddr().String()
	magicServer := &dns.Server{
		PacketConn: magicPC,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			rr, _ := dns.NewRR(r.Question[0].Name + " 120 IN A 100.64.0.5")
			m.Answer = append(m.Answer, rr)
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = magicServer.ActivateAndServe() }()
	defer magicServer.Shutdown()

	// Setup Router with direct rule for cn domain
	router := routing.NewRouter([]routing.Rule{
		{
			ID:           "direct-cn",
			Enabled:      true,
			DomainSuffix: []string{"cn", "baidu.com"},
			Action:       routing.RouteAction{Type: routing.ActionDirect},
		},
	}, routing.RouteAction{Type: routing.ActionProxyPool})

	ipCache := ipcache.New(100)
	var bypassedIPs []string
	var mu sync.Mutex
	ipCache.SetOnBypassIP(func(ip net.IP) {
		mu.Lock()
		defer mu.Unlock()
		bypassedIPs = append(bypassedIPs, ip.String())
	})

	blocker := &mockBlocker{
		blockedDomains: map[string]bool{
			"adservice.google.com": true,
		},
	}

	res := internaldns.NewResolver(internaldns.ResolverOptions{
		Hosts: map[string]string{
			"router.lan": "192.168.1.1",
		},
		MagicDNSEndpoint: magicAddr,
		Blocker:          blocker,
		BootstrapDomains: []string{"node1.naiveproxy.com"},
		BootstrapDNS:     []string{bootDNSAddr},
		DomesticDoH:      []string{domesticServer.URL},
		RemoteDoH:        []string{remoteServer.URL},
		Router:           router,
		IPCache:          ipCache,
	})

	ctx := context.Background()

	// 1. Stage 1: Static Hosts
	t.Run("Stage1_Hosts", func(t *testing.T) {
		resp, err := res.Resolve(ctx, "router.lan", dns.TypeA)
		if err != nil {
			t.Fatalf("resolve router.lan failed: %v", err)
		}
		if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "192.168.1.1" {
			t.Fatalf("unexpected answer: %v", resp.Answer)
		}
	})

	// 1b. Stage 1: Tailnet MagicDNS (*.ts.net)
	t.Run("Stage1_MagicDNS", func(t *testing.T) {
		resp, err := res.Resolve(ctx, "myhost.ts.net", dns.TypeA)
		if err != nil {
			t.Fatalf("resolve myhost.ts.net failed: %v", err)
		}
		if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "100.64.0.5" {
			t.Fatalf("unexpected answer: %v", resp.Answer)
		}
	})

	// 2. Stage 2: Blocker
	t.Run("Stage2_Blocker", func(t *testing.T) {
		resp, err := res.Resolve(ctx, "adservice.google.com", dns.TypeA)
		if err != nil {
			t.Fatalf("resolve blocked domain error: %v", err)
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
		}
		a := resp.Answer[0].(*dns.A)
		if a.A.String() != "0.0.0.0" || a.Hdr.Ttl != 60 {
			t.Fatalf("expected 0.0.0.0 with 60s TTL, got %v (%ds)", a.A, a.Hdr.Ttl)
		}
	})

	// 3. Stage 3a: Bootstrap Domain (node1.naiveproxy.com via pure IP Bootstrap DNS)
	t.Run("Stage3_BootstrapDomain", func(t *testing.T) {
		beforeBootDNS := bootDNSCalls.Load()
		beforeDomestic := domesticCalls.Load()
		beforeRemote := remoteCalls.Load()

		resp, err := res.Resolve(ctx, "node1.naiveproxy.com", dns.TypeA)
		if err != nil {
			t.Fatalf("resolve bootstrap domain error: %v", err)
		}
		if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "198.51.100.88" {
			t.Fatalf("unexpected answer: %v", resp.Answer)
		}
		if bootDNSCalls.Load() <= beforeBootDNS {
			t.Fatalf("expected bootstrap DNS UDP query for bootstrap domain")
		}
		if domesticCalls.Load() != beforeDomestic {
			t.Fatalf("expected domestic DoH not called for bootstrap domain")
		}
		if remoteCalls.Load() != beforeRemote {
			t.Fatalf("expected remote DoH not called for bootstrap domain")
		}

		// Verify IPDomainCache and OnBypassIP triggered
		mu.Lock()
		defer mu.Unlock()
		if len(bypassedIPs) != 1 || bypassedIPs[0] != "198.51.100.88" {
			t.Fatalf("expected bypass callback for 198.51.100.88, got %v", bypassedIPs)
		}
	})

	// 3b. Stage 3b: Mainland Direct Domain (baidu.com via Domestic DoH)
	t.Run("Stage3_DirectDomain", func(t *testing.T) {
		beforeDomestic := domesticCalls.Load()
		resp, err := res.Resolve(ctx, "www.baidu.com", dns.TypeA)
		if err != nil {
			t.Fatalf("resolve baidu.com error: %v", err)
		}
		if len(resp.Answer) == 0 {
			t.Fatalf("expected answer")
		}
		if domesticCalls.Load() <= beforeDomestic {
			t.Fatalf("expected domestic direct DoH called for direct domain")
		}
	})

	// 4. Stage 4: Remote Foreign Domain (twitter.com via Remote DoH)
	t.Run("Stage4_RemoteDomain", func(t *testing.T) {
		beforeRemote := remoteCalls.Load()
		resp, err := res.Resolve(ctx, "twitter.com", dns.TypeA)
		if err != nil {
			t.Fatalf("resolve twitter.com error: %v", err)
		}
		if len(resp.Answer) == 0 || resp.Answer[0].(*dns.A).A.String() != "104.244.42.1" {
			t.Fatalf("unexpected answer: %v", resp.Answer)
		}
		if remoteCalls.Load() <= beforeRemote {
			t.Fatalf("expected remote DoH call for foreign domain")
		}
	})
}

// Tests in-memory DNS TTL caching and Stale-While-Revalidate optimistic background refresh.
func TestResolver_CacheAndStaleWhileRevalidate(t *testing.T) {
	var queryCount atomic.Int32
	dohServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := queryCount.Add(1)
		body, _ := io.ReadAll(r.Body)
		req := new(dns.Msg)
		_ = req.Unpack(body)

		resp := new(dns.Msg)
		resp.SetReply(req)
		q := req.Question[0]
		// Return TTL of 1 second for testing rapid expiration
		ip := "1.2.3." + string('0'+byte(count))
		rr, _ := dns.NewRR(q.Name + " 1 IN A " + ip)
		resp.Answer = append(resp.Answer, rr)

		out, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))
	defer dohServer.Close()

	res := internaldns.NewResolver(internaldns.ResolverOptions{
		DomesticDoH: []string{dohServer.URL},
		Router: routing.NewRouter([]routing.Rule{
			{
				ID:           "test-direct",
				Enabled:      true,
				DomainSuffix: []string{"example.org"},
				Action:       routing.RouteAction{Type: routing.ActionDirect},
			},
		}, routing.RouteAction{Type: routing.ActionDirect}),
	})

	ctx := context.Background()

	// 1. Initial query: triggers upstream DoH
	resp1, err := res.Resolve(ctx, "example.org", dns.TypeA)
	if err != nil {
		t.Fatalf("initial resolve failed: %v", err)
	}
	if queryCount.Load() != 1 {
		t.Fatalf("expected 1 upstream query, got %d", queryCount.Load())
	}
	ans1 := resp1.Answer[0].(*dns.A).A.String()
	if ans1 != "1.2.3.1" {
		t.Fatalf("expected 1.2.3.1, got %v", ans1)
	}

	// 2. Second immediate query: hits in-memory cache without incrementing queryCount
	resp2, err := res.Resolve(ctx, "example.org", dns.TypeA)
	if err != nil {
		t.Fatalf("second resolve failed: %v", err)
	}
	if queryCount.Load() != 1 {
		t.Fatalf("expected cache hit (count=1), got %d", queryCount.Load())
	}
	ans2 := resp2.Answer[0].(*dns.A).A.String()
	if ans2 != "1.2.3.1" {
		t.Fatalf("expected cached 1.2.3.1, got %v", ans2)
	}

	// 3. Wait for TTL (1s) to expire into stale window
	time.Sleep(1100 * time.Millisecond)

	// Third query: should return stale record immediately (<1ms) and trigger background refresh
	start := time.Now()
	resp3, err := res.Resolve(ctx, "example.org", dns.TypeA)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("stale resolve failed: %v", err)
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("expected optimistic instant stale response, took %v", elapsed)
	}
	ans3 := resp3.Answer[0].(*dns.A).A.String()
	if ans3 != "1.2.3.1" {
		t.Fatalf("expected stale answer 1.2.3.1, got %v", ans3)
	}

	// Wait up to 500ms for background goroutine to complete
	deadline := time.Now().Add(500 * time.Millisecond)
	for queryCount.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if queryCount.Load() < 2 {
		t.Fatalf("expected background refresh to increment query count")
	}

	// Fourth query should now return the freshly cached value (1.2.3.2)
	resp4, err := res.Resolve(ctx, "example.org", dns.TypeA)
	if err != nil {
		t.Fatalf("fourth resolve failed: %v", err)
	}
	ans4 := resp4.Answer[0].(*dns.A).A.String()
	if ans4 != "1.2.3.2" {
		t.Fatalf("expected refreshed value 1.2.3.2, got %v", ans4)
	}
}

// Tests updating DNS upstreams dynamically with SetUpstreams.
func TestResolver_SetUpstreams(t *testing.T) {
	res := internaldns.NewResolver(internaldns.ResolverOptions{})
	boot, domestic, remote := res.Upstreams()
	if len(boot) != 2 || boot[0] != internaldns.DefaultBootstrapDNS[0] {
		t.Fatalf("expected default bootstrap DNS, got %v", boot)
	}
	if len(domestic) != 2 || domestic[0] != internaldns.DefaultDomesticDoH[0] {
		t.Fatalf("expected default domestic DoH, got %v", domestic)
	}
	if len(remote) != 2 || remote[0] != internaldns.DefaultRemoteDoH[0] {
		t.Fatalf("expected default remote DoH, got %v", remote)
	}

	customBoot := []string{"1.1.1.1:53"}
	customDomestic := []string{"https://custom-dom.com/dns-query"}
	customRemote := []string{"https://custom-remote.com/dns-query"}
	res.SetUpstreams(customBoot, customDomestic, customRemote)

	newBoot, newDomestic, newRemote := res.Upstreams()
	if len(newBoot) != 1 || newBoot[0] != customBoot[0] {
		t.Fatalf("expected custom bootstrap DNS, got %v", newBoot)
	}
	if len(newDomestic) != 1 || newDomestic[0] != customDomestic[0] {
		t.Fatalf("expected custom domestic DoH, got %v", newDomestic)
	}
	if len(newRemote) != 1 || newRemote[0] != customRemote[0] {
		t.Fatalf("expected custom remote DoH, got %v", newRemote)
	}

	// Reset to empty -> reverts to default
	res.SetUpstreams(nil, nil, nil)
	revertBoot, revertDomestic, revertRemote := res.Upstreams()
	if len(revertBoot) != 2 || revertBoot[0] != internaldns.DefaultBootstrapDNS[0] {
		t.Fatalf("expected reverted default bootstrap DNS, got %v", revertBoot)
	}
	if len(revertDomestic) != 2 || revertDomestic[0] != internaldns.DefaultDomesticDoH[0] {
		t.Fatalf("expected reverted default domestic DoH, got %v", revertDomestic)
	}
	if len(revertRemote) != 2 || revertRemote[0] != internaldns.DefaultRemoteDoH[0] {
		t.Fatalf("expected reverted default remote DoH, got %v", revertRemote)
	}
}
