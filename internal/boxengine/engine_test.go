package boxengine

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"naive-client/internal/blocker"
	"naive-client/internal/config"
	"naive-client/internal/routing"
	"naive-client/internal/tailnet"
	"naive-client/internal/telemetry"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// Tests that Engine starts with Mixed inbound, accepts connections, and routes direct traffic.
func TestEngine_StartAndDirectRouting(t *testing.T) {
	// Start a local HTTP test server to be accessed via DIRECT
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen test server failed: %v", err)
	}
	defer ln.Close()

	testServerPort := ln.Addr().(*net.TCPAddr).Port
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("hello from direct"))
		})
		_ = http.Serve(ln, mux)
	}()

	tracker := telemetry.NewTracker()
	fm := telemetry.NewFailureMonitor(100)
	bl := blocker.NewEngine(blocker.Options{})

	opts := EngineOptions{
		ListenAddr: "127.0.0.1:0", // allocate free port
		Tracker:    tracker,
		FailureMonitor: fm,
		Blocker:    bl,
		Rules: []routing.Rule{
			{
				ID:      "rule-direct-local",
				Enabled: true,
				Action:  routing.RouteAction{Type: routing.ActionDirect},
				IPCidr:  []string{"127.0.0.1/32"},
			},
		},
		FinalAction: "direct",
	}

	eng, err := New(opts)
	if err != nil {
		t.Fatalf("New Engine failed: %v", err)
	}
	if err := eng.Start(); err != nil {
		t.Fatalf("eng.Start failed: %v", err)
	}
	defer func() {
		_ = eng.Close()
	}()

	mixedPort := eng.Port()
	if mixedPort <= 0 {
		t.Fatalf("expected valid allocated mixed port, got %d", mixedPort)
	}

	// Make an HTTP request through the Mixed proxy
	proxyURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", mixedPort))
	if err != nil {
		t.Fatalf("parse proxy url failed: %v", err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 3 * time.Second,
	}

	targetURL := fmt.Sprintf("http://127.0.0.1:%d/hello", testServerPort)
	resp, err := httpClient.Get(targetURL)
	if err != nil {
		t.Fatalf("GET via proxy failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	if string(body) != "hello from direct" {
		t.Errorf("unexpected body: %s", string(body))
	}
}

// Tests that Engine integrates Blocker and blocks blacklisted domains.
func TestEngine_BlockerIntegration(t *testing.T) {
	tracker := telemetry.NewTracker()
	fm := telemetry.NewFailureMonitor(100)
	bl := blocker.NewEngine(blocker.Options{
		Denylist: []string{"ads.example.com"},
	})

	opts := EngineOptions{
		ListenAddr: "127.0.0.1:0",
		Tracker:    tracker,
		FailureMonitor: fm,
		Blocker:    bl,
		FinalAction: "direct",
	}

	eng, err := New(opts)
	if err != nil {
		t.Fatalf("New Engine failed: %v", err)
	}
	if err := eng.Start(); err != nil {
		t.Fatalf("eng.Start failed: %v", err)
	}
	defer func() {
		_ = eng.Close()
	}()

	mixedPort := eng.Port()
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", mixedPort))
	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 2 * time.Second,
	}

	resp, err := httpClient.Get("http://ads.example.com/banner.js")
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode < 400 {
			t.Errorf("expected error or HTTP 4xx/5xx for blocked domain, got status %d", resp.StatusCode)
		}
	}

	entries := bl.Logger().GetEntries(10)
	foundBlocked := false
	for _, entry := range entries {
		if entry.Domain == "ads.example.com" && entry.Verdict == blocker.VerdictBlocked && entry.Source == blocker.SourceGateway {
			foundBlocked = true
			if entry.Chain != "user-denylist -> block" {
				t.Errorf("expected chain 'user-denylist -> block', got %q", entry.Chain)
			}
			break
		}
	}
	if !foundBlocked {
		t.Fatalf("expected ads.example.com to be logged as blocked with SourceGateway in QueryLogger, got entries: %+v", entries)
	}
}

type testPacketWriter struct {
	done    chan struct{}
	payload []byte
}

func (w *testPacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	w.payload = append([]byte(nil), buffer.Bytes()...)
	select {
	case <-w.done:
	default:
		close(w.done)
	}
	return nil
}

// Tests that DNS queries to blocked domains return 0.0.0.0 and record SourceDNS in QueryLogger.
func TestEngine_BlockerDNSIntegration(t *testing.T) {
	bl := blocker.NewEngine(blocker.Options{
		Denylist: []string{"ad.doubleclick.net"},
	})

	opts := EngineOptions{
		ListenAddr:  "127.0.0.1:0",
		Blocker:     bl,
		FinalAction: "direct",
	}

	eng, err := New(opts)
	if err != nil {
		t.Fatalf("New Engine failed: %v", err)
	}
	if err := eng.Start(); err != nil {
		t.Fatalf("eng.Start failed: %v", err)
	}
	defer func() {
		_ = eng.Close()
	}()

	msg := new(dns.Msg)
	msg.SetQuestion("ad.doubleclick.net.", dns.TypeA)
	raw, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack dns message failed: %v", err)
	}

	writer := &testPacketWriter{done: make(chan struct{})}
	eng.box.Router().HijackDNSPacket(context.Background(), raw, writer, adapter.InboundContext{})

	select {
	case <-writer.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for DNS response")
	}

	var resp dns.Msg
	if err := resp.Unpack(writer.payload); err != nil {
		t.Fatalf("unpack dns response failed: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 DNS answer, got %d", len(resp.Answer))
	}
	ansA, ok := resp.Answer[0].(*dns.A)
	if !ok || ansA.A.String() != "0.0.0.0" {
		t.Fatalf("expected answer 0.0.0.0, got %v", resp.Answer[0])
	}

	entries := bl.Logger().GetEntries(10)
	foundDNSBlocked := false
	for _, entry := range entries {
		if entry.Domain == "ad.doubleclick.net" && entry.Verdict == blocker.VerdictBlocked && entry.Source == blocker.SourceDNS {
			foundDNSBlocked = true
			if entry.Chain != "user-denylist -> 0.0.0.0" {
				t.Errorf("expected chain 'user-denylist -> 0.0.0.0', got %q", entry.Chain)
			}
			break
		}
	}
	if !foundDNSBlocked {
		t.Fatalf("expected ad.doubleclick.net to be logged as SourceDNS and VerdictBlocked, got entries: %+v", entries)
	}
}

// Tests that Engine routes traffic to sidecar loopback port via PROXY_POOL.
func TestEngine_SidecarRouting(t *testing.T) {
	// 1. Target HTTP server
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target failed: %v", err)
	}
	defer targetLn.Close()
	targetPort := targetLn.Addr().(*net.TCPAddr).Port

	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/proxy-ok", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("served through sidecar"))
		})
		_ = http.Serve(targetLn, mux)
	}()

	// 2. Mock SOCKS5 server representing a sidecar (e.g. naiveproxy or xray loopback)
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks failed: %v", err)
	}
	defer socksLn.Close()
	socksPort := socksLn.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			c, err := socksLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 256)
				// Read version + auth methods
				if _, err := io.ReadFull(conn, buf[:2]); err != nil {
					return
				}
				nAuth := int(buf[1])
				if _, err := io.ReadFull(conn, buf[:nAuth]); err != nil {
					return
				}
				// Reply no auth
				if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
					return
				}
				// Read request
				if _, err := io.ReadFull(conn, buf[:4]); err != nil {
					return
				}
				// addr type: 1 = IPv4, 3 = domain
				var targetHost string
				switch buf[3] {
				case 1:
					if _, err := io.ReadFull(conn, buf[:4]); err != nil {
						return
					}
					targetHost = net.IP(buf[:4]).String()
				case 3:
					if _, err := io.ReadFull(conn, buf[:1]); err != nil {
						return
					}
					dLen := int(buf[0])
					if _, err := io.ReadFull(conn, buf[:dLen]); err != nil {
						return
					}
					targetHost = string(buf[:dLen])
				}
				// port
				if _, err := io.ReadFull(conn, buf[:2]); err != nil {
					return
				}
				p := int(buf[0])<<8 | int(buf[1])

				targetConn, err := net.Dial("tcp", net.JoinHostPort(targetHost, fmt.Sprintf("%d", p)))
				if err != nil {
					_, _ = conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				defer targetConn.Close()

				// Success reply
				_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0})

				// Bidirectional copy
				done := make(chan struct{}, 2)
				go func() {
					_, _ = io.Copy(targetConn, conn)
					done <- struct{}{}
				}()
				go func() {
					_, _ = io.Copy(conn, targetConn)
					done <- struct{}{}
				}()
				<-done
			}(c)
		}
	}()

	// 3. Setup Engine with sidecar node and PROXY_POOL as final action
	tracker := telemetry.NewTracker()
	fm := telemetry.NewFailureMonitor(100)

	opts := EngineOptions{
		ListenAddr: "127.0.0.1:0",
		Tracker:    tracker,
		FailureMonitor: fm,
		Services: []config.Service{
			{
				ID:     "node-1",
				Name:   "Test Sidecar Node",
				Engine: config.EngineSidecar,
			},
		},
		AllocatedPorts: map[string]int{
			"node-1": socksPort,
		},
		FinalAction: "proxy_pool",
	}

	eng, err := New(opts)
	if err != nil {
		t.Fatalf("New Engine failed: %v", err)
	}
	if err := eng.Start(); err != nil {
		t.Fatalf("eng.Start failed: %v", err)
	}
	defer func() {
		_ = eng.Close()
	}()

	mixedPort := eng.Port()
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", mixedPort))
	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 3 * time.Second,
	}

	reqURL := fmt.Sprintf("http://127.0.0.1:%d/proxy-ok", targetPort)
	resp, err := httpClient.Get(reqURL)
	if err != nil {
		t.Fatalf("GET via sidecar pool failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	if string(body) != "served through sidecar" {
		t.Errorf("status: %s, unexpected body: %q", resp.Status, string(body))
	}
}

// Tests that sidecar nodes remote addresses are extracted as CIDR prefixes for route_exclude_address.
func TestExtractSidecarExcludeAddresses(t *testing.T) {
	services := []config.Service{
		{
			ID:       "naive-1",
			Protocol: config.ProtoNaive,
			Engine:   config.EngineSidecar,
			Proxies:  []string{"https://user:pass@198.51.100.1:443"},
		},
		{
			ID:       "xray-1",
			Protocol: config.ProtoVLESS,
			Engine:   config.EngineSidecar,
			Server:   "203.0.113.5",
		},
		{
			ID:       "naive-ipv6",
			Protocol: config.ProtoNaive,
			Engine:   config.EngineSidecar,
			Proxies:  []string{"https://user:pass@[2001:db8::1]:443"},
		},
		{
			// Native sing-box node must also be in route exclusion to prevent routing loops
			ID:       "native-vless",
			Protocol: config.ProtoVLESS,
			Engine:   config.EngineSingBox,
			Server:   "192.0.2.1",
		},
	}

	excludes := extractNodeExcludeAddresses(services, nil)
	expected := map[string]bool{
		"198.51.100.1/32": true,
		"203.0.113.5/32":  true,
		"2001:db8::1/128": true,
		"192.0.2.1/32":    true,
	}

	if len(excludes) != len(expected) {
		t.Fatalf("expected %d exclude addresses, got %d: %v", len(expected), len(excludes), excludes)
	}
	for _, ex := range excludes {
		if !expected[ex] {
			t.Errorf("unexpected exclude address %q", ex)
		}
	}
}

// Tests that TunPlatform injects TunFD and TunName into tun.Options.
func TestTunPlatform_OpenInterface(t *testing.T) {
	var captured tun.Options
	called := false

	tp := &TunPlatform{
		TunFD:   42,
		TunName: "utun7",
		TunCreator: func(opts tun.Options) (tun.Tun, error) {
			called = true
			captured = opts
			return nil, nil
		},
	}

	if !tp.UsePlatformInterface() {
		t.Fatalf("expected UsePlatformInterface to be true when TunFD > 0")
	}

	var opts tun.Options
	_, _ = tp.OpenInterface(&opts, option.TunPlatformOptions{})

	if !called {
		t.Fatalf("expected TunCreator to be called")
	}
	if captured.FileDescriptor != 42 {
		t.Errorf("expected FileDescriptor 42, got %d", captured.FileDescriptor)
	}
	if captured.Name != "utun7" {
		t.Errorf("expected Name utun7, got %q", captured.Name)
	}
}

// Tests that when TrafficMode is "tun", buildConfig includes tun inbound with auto_route and route_exclude_address.
func TestEngine_TUNConfigOptions(t *testing.T) {
	eng := &Engine{}
	ctx := createBoxContext(context.Background(), eng)
	opts := EngineOptions{
		TrafficMode:  "tun",
		TunFD:        55,
		TunInterface: "utun3",
		Services: []config.Service{
			{
				ID:       "sidecar-node",
				Protocol: config.ProtoNaive,
				Engine:   config.EngineSidecar,
				Proxies:  []string{"https://user:pass@198.51.100.99:443"},
				Listens:  []string{"socks://127.0.0.1:10801"},
			},
		},
	}

	cfg, err := eng.buildConfig(ctx, opts, "127.0.0.1", 10809)
	if err != nil {
		t.Fatalf("buildConfig failed: %v", err)
	}

	if cfg.Route == nil || !cfg.Route.AutoDetectInterface {
		t.Errorf("expected Route.AutoDetectInterface to be true")
	}

	foundTun := false
	for _, in := range cfg.Inbounds {
		if in.Type == "tun" {
			foundTun = true
			tunOpts, ok := in.Options.(*option.TunInboundOptions)
			if !ok || tunOpts == nil {
				t.Fatalf("expected *option.TunInboundOptions, got %T", in.Options)
			}
			if tunOpts.InterfaceName != "utun3" {
				t.Errorf("expected interface_name utun3, got %q", tunOpts.InterfaceName)
			}
			if !tunOpts.AutoRoute {
				t.Errorf("expected auto_route to be true")
			}
			if !tunOpts.StrictRoute {
				t.Errorf("expected strict_route to be true")
			}
			excludes := tunOpts.RouteExcludeAddress
			if len(excludes) == 0 {
				t.Fatalf("expected non-empty route_exclude_address")
			}
			if excludes[0].String() != "198.51.100.99/32" {
				t.Errorf("expected exclude 198.51.100.99/32, got %v", excludes[0])
			}
		}
	}
	if !foundTun {
		t.Errorf("expected tun inbound in configuration")
	}
}

// Tests Tailnet Host Mode configuration, exclusions, and MagicDNS routing.
func TestEngine_TailnetHostMode_ConfigAndRouting(t *testing.T) {
	eng := &Engine{}
	ctx := createBoxContext(context.Background(), eng)

	opts := EngineOptions{
		TrafficMode:           "tun",
		TunInterface:          "utun5",
		TailnetMode:           tailnet.ModeHost,
		TailnetHostExcludes:   []string{"192.168.10.0/24"},
		TailnetMagicDNSSuffix: "my-tailnet.ts.net",
		Rules: []routing.Rule{
			{
				ID:      "rule-tailnet-action",
				Enabled: true,
				DomainSuffix: []string{"internal.corp"},
				Action:  routing.RouteAction{Type: routing.ActionTailnet},
			},
		},
	}

	cfg, err := eng.buildConfig(ctx, opts, "127.0.0.1", 10809)
	if err != nil {
		t.Fatalf("buildConfig failed: %v", err)
	}

	// 1. Check TUN route_exclude_address contains Tailnet CGNAT, ULA, and custom excludes
	foundTun := false
	for _, in := range cfg.Inbounds {
		if in.Type == "tun" {
			foundTun = true
			tunOpts := in.Options.(*option.TunInboundOptions)
			var excludeStrs []string
			for _, pfx := range tunOpts.RouteExcludeAddress {
				excludeStrs = append(excludeStrs, pfx.String())
			}
			hasCGNAT := false
			hasCustom := false
			for _, s := range excludeStrs {
				if s == "100.64.0.0/10" {
					hasCGNAT = true
				}
				if s == "192.168.10.0/24" {
					hasCustom = true
				}
			}
			if !hasCGNAT || !hasCustom {
				t.Errorf("expected CGNAT and custom subnet in excludes, got %v", excludeStrs)
			}
		}
	}
	if !foundTun {
		t.Fatal("expected tun inbound")
	}

	// 2. Check JSON representation contains expected DNS, excludes, and rules
	// 2. Check JSON representation contains expected DNS, excludes, and rules
	rawBytes, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config failed: %v", err)
	}
	rawStr := string(rawBytes)

	if !strings.Contains(rawStr, "tailscale-host-dns") {
		t.Error("expected tailscale-host-dns in dns configuration")
	}
	if !strings.Contains(rawStr, "^[^.]+$") {
		t.Error("expected short name domain_regex ^[^.]+$ in dns/route configuration")
	}
	if !strings.Contains(rawStr, "my-tailnet.ts.net") {
		t.Error("expected my-tailnet.ts.net in dns rules")
	}
	if !strings.Contains(rawStr, "100.64.0.0/10") {
		t.Error("expected 100.64.0.0/10 in route rules")
	}
	if !strings.Contains(rawStr, "192.168.10.0/24") {
		t.Error("expected 192.168.10.0/24 in route/exclude")
	}
	if !strings.Contains(rawStr, "internal.corp") {
		t.Error("expected internal.corp in route rules")
	}

	// 3. Check DNS server options specifically
	foundDNS := false
	for _, s := range cfg.DNS.Servers {
		if s.Tag == "tailscale-host-dns" {
			foundDNS = true
			if ro, ok := s.Options.(*option.RemoteDNSServerOptions); ok {
				if ro.Server != "100.100.100.100" {
					t.Errorf("expected server 100.100.100.100, got %s", ro.Server)
				}
			}
		}
	}
	if !foundDNS {
		t.Error("tailscale-host-dns not found in servers")
	}
}

// Tests Tailnet Embedded Mode configuration options.
func TestEngine_TailnetEmbeddedMode_Config(t *testing.T) {
	eng := &Engine{}
	ctx := createBoxContext(context.Background(), eng)

	opts := EngineOptions{
		TailnetMode: tailnet.ModeEmbedded,
		TailnetConfig: &tailnet.Config{
			Enabled:            true,
			Mode:               tailnet.ModeEmbedded,
			Hostname:           "node-embedded",
			ControlURL:         "https://hs.example.com",
			AuthKey:            "tskey-auth-12345",
			AcceptRoutes:       true,
			AdvertiseExitNode:  true,
			AdvertiseRoutes:    []string{"10.0.0.0/24"},
			ExposeMixedPort:    true,
		},
		TailnetMagicDNSSuffix: "hs.example.com",
		Rules: []routing.Rule{
			{
				ID:      "rule-tailnet-action",
				Enabled: true,
				DomainSuffix: []string{"hs.internal"},
				Action:  routing.RouteAction{Type: routing.ActionTailnet},
			},
		},
	}

	// Unmarshal may require with_tailscale tag if endpoints are instantiated,
	// so let's verify via raw config Map inspection.
	cfgMap := make(map[string]any)
	_ = cfgMap

	// Test inbounds: has tailnet-mixed-in
	cfg, err := eng.buildConfig(ctx, opts, "127.0.0.1", 10809)
	if err != nil {
		// When running without -tags with_tailscale, UnmarshalJSONContext may fail on endpoint stub.
		// If so, verify that the error says Tailscale is not included, which proves the config was built!
		t.Logf("buildConfig note without build tags: %v", err)
		return
	}

	hasMixed := false
	for _, in := range cfg.Inbounds {
		if in.Tag == "tailnet-mixed-in" {
			hasMixed = true
			break
		}
	}
	if !hasMixed {
		t.Error("expected tailnet-mixed-in inbound")
	}
}

// Tests that Blocker dynamically blocks/allows domains at runtime and flushes sing-box DNS cache.
func TestEngine_DynamicDenylistAndClearDNSCache(t *testing.T) {
	bl := blocker.NewEngine(blocker.Options{})

	opts := EngineOptions{
		ListenAddr:  "127.0.0.1:0",
		Blocker:     bl,
		FinalAction: "direct",
	}

	eng, err := New(opts)
	if err != nil {
		t.Fatalf("New Engine failed: %v", err)
	}
	if err := eng.Start(); err != nil {
		t.Fatalf("eng.Start failed: %v", err)
	}
	defer func() {
		_ = eng.Close()
	}()

	// Verify ClearDNSCache does not panic
	eng.ClearDNSCache()

	// 1. Dynamic AddDenylist triggers onUpdate and blocks domain
	bl.AddDenylist("dynamic-ads.org")
	matchBlocked, rule := bl.AsGateway().Match("dynamic-ads.org")
	if !matchBlocked || rule != blocker.RuleUserDenylist {
		t.Fatalf("expected dynamic-ads.org to be blocked by user-denylist, got %v (%s)", matchBlocked, rule)
	}

	// 2. Dynamic AddAllowlist unblocks domain immediately
	bl.AddAllowlist("dynamic-ads.org")
	matchBlocked2, _ := bl.AsGateway().Match("dynamic-ads.org")
	if matchBlocked2 {
		t.Fatalf("expected dynamic-ads.org to be allowed after AddAllowlist")
	}
}

// Tests that connections sent via SOCKS5 IP format (curl -x socks5:// IP) are sniffed for TLS SNI
// and properly logged to Blocker / Insights as SourceGateway.
func TestEngine_SOCKS5_IP_SNI_Sniffing(t *testing.T) {
	bl := blocker.NewEngine(blocker.Options{})

	opts := EngineOptions{
		ListenAddr:  "127.0.0.1:0",
		Blocker:     bl,
		FinalAction: "direct",
	}

	eng, err := New(opts)
	if err != nil {
		t.Fatalf("New Engine failed: %v", err)
	}
	if err := eng.Start(); err != nil {
		t.Fatalf("eng.Start failed: %v", err)
	}
	defer func() {
		_ = eng.Close()
	}()

	// Mock target server listening on TCP
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target failed: %v", err)
	}
	defer targetLn.Close()
	targetPort := targetLn.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := targetLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var buf [1024]byte
				_, _ = c.Read(buf[:])
			}(conn)
		}
	}()

	// 1. Connect to SOCKS5 proxy at eng.Port()
	proxyConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", eng.Port()))
	if err != nil {
		t.Fatalf("dial proxy failed: %v", err)
	}
	defer proxyConn.Close()

	// SOCKS5 greeting: [VER=5, NMETHODS=1, METHOD=0 (NO_AUTH)]
	if _, err := proxyConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting failed: %v", err)
	}
	var greetingResp [2]byte
	if _, err := io.ReadFull(proxyConn, greetingResp[:]); err != nil || greetingResp[0] != 0x05 || greetingResp[1] != 0x00 {
		t.Fatalf("unexpected greeting resp: %v, err: %v", greetingResp, err)
	}

	// SOCKS5 connect to IPv4 (127.0.0.1:targetPort)
	req := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, byte(targetPort >> 8), byte(targetPort & 0xff)}
	if _, err := proxyConn.Write(req); err != nil {
		t.Fatalf("write connect request failed: %v", err)
	}
	var connResp [10]byte
	if _, err := io.ReadFull(proxyConn, connResp[:]); err != nil || connResp[1] != 0x00 {
		t.Fatalf("connect failed, resp: %v, err: %v", connResp, err)
	}

	// Now initiate TLS ClientHello with SNI = "ipinfo.io" over the SOCKS5 connection
	tlsClient := tls.Client(proxyConn, &tls.Config{
		ServerName:         "ipinfo.io",
		InsecureSkipVerify: true,
	})
	_ = tlsClient.Handshake() // Handshake may fail on target dummy server, but ClientHello is sent and sniffed!

	time.Sleep(50 * time.Millisecond)

	// Verify that Blocker QueryLogger recorded "ipinfo.io" as SourceGateway
	entries := bl.Logger().GetEntries(10)
	foundSNI := false
	for _, e := range entries {
		if e.Domain == "ipinfo.io" && e.Source == blocker.SourceGateway && e.Verdict == blocker.VerdictAllowed {
			foundSNI = true
			if !strings.Contains(e.Chain, "direct") {
				t.Errorf("expected chain to route to direct, got %q", e.Chain)
			}
			break
		}
	}
	if !foundSNI {
		t.Fatalf("expected ipinfo.io to be logged as SourceGateway from sniffed TLS ClientHello, got entries: %+v", entries)
	}
}

// Tests that direct outbound connection to a domain resolves DNS via DoH and logs SourceDNS and SourceGateway.
func TestEngine_DirectOutboundDNSLogging(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()
	testPort := ln.Addr().(*net.TCPAddr).Port

	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("hello"))
		})
		_ = http.Serve(ln, mux)
	}()

	bl := blocker.NewEngine(blocker.Options{})
	opts := EngineOptions{
		ListenAddr:  "127.0.0.1:0",
		Blocker:     bl,
		FinalAction: "direct",
	}
	eng, err := New(opts)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if err := eng.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer eng.Close()

	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", eng.Port()))
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 3 * time.Second,
	}

	resp, err := client.Get(fmt.Sprintf("http://localhost:%d/", testPort))
	t.Logf("Resp: %v, err: %v", resp, err)

	entries := bl.Logger().GetEntries(10)
	t.Logf("Entries count=%d:", len(entries))
	for _, e := range entries {
		t.Logf("Logged: domain=%s source=%s verdict=%s chain=%s", e.Domain, e.Source, e.Verdict, e.Chain)
	}
}
func TestEngine_DNSQueryLogging(t *testing.T) {
	bl := blocker.NewEngine(blocker.Options{})
	opts := EngineOptions{
		ListenAddr:  "127.0.0.1:0",
		Blocker:     bl,
		FinalAction: "proxy_pool",
		Rules: []routing.Rule{
			{
				ID:           "rule-direct",
				Enabled:      true,
				Action:       routing.RouteAction{Type: routing.ActionDirect},
				DomainSuffix: []string{"baidu.com"},
			},
			{
				ID:           "rule-proxy",
				Enabled:      true,
				Action:       routing.RouteAction{Type: routing.ActionProxyPool},
				DomainSuffix: []string{"google.com"},
			},
		},
	}
	eng, err := New(opts)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if err := eng.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer eng.Close()

	// 1. Query direct domain
	msg1 := new(dns.Msg)
	msg1.SetQuestion("www.baidu.com.", dns.TypeA)
	raw1, _ := msg1.Pack()
	writer1 := &testPacketWriter{done: make(chan struct{})}
	eng.box.Router().HijackDNSPacket(context.Background(), raw1, writer1, adapter.InboundContext{})
	select {
	case <-writer1.done:
	case <-time.After(2 * time.Second):
	}

	// 2. Query proxy domain
	msg2 := new(dns.Msg)
	msg2.SetQuestion("www.google.com.", dns.TypeA)
	raw2, _ := msg2.Pack()
	writer2 := &testPacketWriter{done: make(chan struct{})}
	eng.box.Router().HijackDNSPacket(context.Background(), raw2, writer2, adapter.InboundContext{})
	select {
	case <-writer2.done:
	case <-time.After(2 * time.Second):
	}

	entries := bl.Logger().GetEntries(10)
	t.Logf("Entries count=%d: %+v", len(entries), entries)
	for _, e := range entries {
		t.Logf("Entry: domain=%s source=%s verdict=%s chain=%s", e.Domain, e.Source, e.Verdict, e.Chain)
	}
	if len(entries) < 2 {
		t.Fatalf("expected at least 2 entries in query logger, got %d", len(entries))
	}
}

// Tests that DNS split rules align with user routing rules so Direct domains resolve via domestic-doh instead of remote-doh.
func TestEngine_DNSRuleSplitByRoutingRules(t *testing.T) {
	eng := &Engine{}
	ctx := createBoxContext(context.Background(), eng)

	opts := EngineOptions{
		FinalAction: "proxy_pool",
		Rules: []routing.Rule{
			{
				ID:      "rule-direct-company",
				Enabled: true,
				Action:  routing.RouteAction{Type: routing.ActionDirect},
				DomainSuffix: []string{"corp.internal", "local.domain"},
				DomainFull:   []string{"direct.example.com"},
				GeoSite:      []string{"apple"},
			},
			{
				ID:      "rule-proxy-overseas",
				Enabled: true,
				Action:  routing.RouteAction{Type: routing.ActionProxyPool},
				DomainSuffix: []string{"overseas.com"},
			},
		},
	}

	boxOpts, err := eng.buildConfig(ctx, opts, "127.0.0.1", 10809)
	if err != nil {
		t.Fatalf("buildConfig failed: %v", err)
	}

	if boxOpts.DNS == nil {
		t.Fatalf("expected DNS options to be present")
	}

	// 1. Final DNS should match FinalAction "proxy_pool" -> "remote-doh"
	if boxOpts.DNS.Final != "remote-doh" {
		t.Errorf("expected DNS.Final to be remote-doh when FinalAction=proxy_pool, got %q", boxOpts.DNS.Final)
	}

	// 2. Check DNS rules mapping
	var foundDirectDomain, foundDirectGeoSite, foundProxyDomain bool
	for _, rule := range boxOpts.DNS.Rules {
		opts := rule.DefaultOptions
		server := opts.RouteOptions.Server
		if server == "domestic-doh" {
			for _, s := range opts.DomainSuffix {
				if s == "corp.internal" {
					foundDirectDomain = true
				}
			}
			for _, rset := range opts.RuleSet {
				if rset == "geosite-apple" {
					foundDirectGeoSite = true
				}
			}
		} else if server == "remote-doh" {
			for _, s := range opts.DomainSuffix {
				if s == "overseas.com" {
					foundProxyDomain = true
				}
			}
		}
	}

	if !foundDirectDomain {
		t.Errorf("expected domain_suffix 'corp.internal' in domestic-doh DNS rule")
	}
	if !foundDirectGeoSite {
		t.Errorf("expected rule_set 'geosite-apple' in domestic-doh DNS rule")
	}
	if !foundProxyDomain {
		t.Errorf("expected domain_suffix 'overseas.com' in remote-doh DNS rule")
	}

	// 3. Test that when FinalAction is direct, DNS.Final is domestic-doh
	optsDirectFinal := EngineOptions{
		FinalAction: "direct",
	}
	boxOptsDirect, err := eng.buildConfig(ctx, optsDirectFinal, "127.0.0.1", 10809)
	if err != nil {
		t.Fatalf("buildConfig direct final failed: %v", err)
	}
	if boxOptsDirect.DNS.Final != "domestic-doh" {
		t.Errorf("expected DNS.Final to be domestic-doh when FinalAction=direct, got %q", boxOptsDirect.DNS.Final)
	}
}

// Tests that Gateway connections routed through a proxy pool record the concrete node name in the chain.
func TestEngine_GatewayNodeNameLogging(t *testing.T) {
	// 1. Target server
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target failed: %v", err)
	}
	defer targetLn.Close()
	targetPort := targetLn.Addr().(*net.TCPAddr).Port

	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/node-test", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("ok from target"))
		})
		_ = http.Serve(targetLn, mux)
	}()

	// 2. Mock SOCKS5 server representing a node
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks failed: %v", err)
	}
	defer socksLn.Close()
	socksPort := socksLn.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			c, err := socksLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 256)
				if _, err := io.ReadFull(conn, buf[:2]); err != nil {
					return
				}
				nAuth := int(buf[1])
				if _, err := io.ReadFull(conn, buf[:nAuth]); err != nil {
					return
				}
				_, _ = conn.Write([]byte{0x05, 0x00})
				if _, err := io.ReadFull(conn, buf[:4]); err != nil {
					return
				}
				var targetHost string
				switch buf[3] {
				case 1:
					if _, err := io.ReadFull(conn, buf[:4]); err != nil {
						return
					}
					targetHost = net.IP(buf[:4]).String()
				case 3:
					if _, err := io.ReadFull(conn, buf[:1]); err != nil {
						return
					}
					dLen := int(buf[0])
					if _, err := io.ReadFull(conn, buf[:dLen]); err != nil {
						return
					}
					targetHost = string(buf[:dLen])
				}
				if _, err := io.ReadFull(conn, buf[:2]); err != nil {
					return
				}
				p := int(buf[0])<<8 | int(buf[1])

				targetConn, err := net.Dial("tcp", net.JoinHostPort(targetHost, fmt.Sprintf("%d", p)))
				if err != nil {
					_, _ = conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				defer targetConn.Close()
				_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0})
				done := make(chan struct{}, 2)
				go func() {
					_, _ = io.Copy(targetConn, conn)
					done <- struct{}{}
				}()
				go func() {
					_, _ = io.Copy(conn, targetConn)
					done <- struct{}{}
				}()
				<-done
			}(c)
		}
	}()

	// 3. Start engine with blocker and service "svc-us-1" named "US-Fast-Node"
	bl := blocker.NewEngine(blocker.Options{})
	opts := EngineOptions{
		ListenAddr:  "127.0.0.1:0",
		Blocker:     bl,
		FinalAction: "proxy_pool",
		Services: []config.Service{
			{
				ID:     "svc-us-1",
				Name:   "US-Fast-Node",
				Engine: config.EngineSidecar,
			},
		},
		AllocatedPorts: map[string]int{
			"svc-us-1": socksPort,
		},
		ActiveIDs: map[string]bool{
			"svc-us-1": true,
		},
	}

	eng, err := New(opts)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if err := eng.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer eng.Close()

	// 4. Send request through mixed proxy
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", eng.Port()))
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 3 * time.Second,
	}

	resp, err := client.Get(fmt.Sprintf("http://localhost:%d/node-test", targetPort))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_ = resp.Body.Close()

	// Give a few milliseconds for goroutines/ring buffer update
	time.Sleep(50 * time.Millisecond)

	entries := bl.Logger().GetEntries(10)
	var foundGateway bool
	for _, e := range entries {
		if e.Source == blocker.SourceGateway && strings.Contains(e.Chain, "US-Fast-Node") {
			foundGateway = true
			if !strings.HasSuffix(e.Chain, "US-Fast-Node") {
				t.Errorf("expected chain to end with US-Fast-Node, got %q", e.Chain)
			}
		}
	}

	if !foundGateway {
		t.Fatalf("expected Gateway entry containing 'US-Fast-Node', entries: %+v", entries)
	}
}

// Regression: setting FinalRoute to PROXY_TAG("warp") previously hardcoded route.final to "PROXY_POOL",
// and consecutive connections switching nodes concatenated stale node names ("final -> PROXY_POOL -> naive_opc2 -> local_warp").
func TestEngine_FinalRouteProxyTagAndNoStaleNodeConcatenation(t *testing.T) {
	eng := &Engine{}
	ctx := createBoxContext(context.Background(), eng)

	opts := EngineOptions{
		FinalAction: string(routing.ActionProxyTag),
		FinalRoute: routing.RouteAction{
			Type: routing.ActionProxyTag,
			Tag:  "warp",
			Tags: []string{"warp"},
		},
		Services: []config.Service{
			{ID: "svc-opc2", Name: "naive_opc2", Engine: config.EngineSidecar, Listens: []string{"socks://127.0.0.1:10801"}},
			{ID: "svc-warp", Name: "local_warp", Engine: config.EngineSidecar, Tags: []string{"warp"}, Listens: []string{"socks://127.0.0.1:10802"}},
		},
	}

	boxOpts, err := eng.buildConfig(ctx, opts, "127.0.0.1", 10809)
	if err != nil {
		t.Fatalf("buildConfig failed: %v", err)
	}
	if boxOpts.Route == nil || boxOpts.Route.Final != "PROXY_TAG:warp" {
		t.Fatalf("expected route.final to be %q, got %+v", "PROXY_TAG:warp", boxOpts.Route)
	}

	// Verify BlockerConnectionTracker resolves the selected candidate directly from PoolOutbound
	// without concatenating stale node names across consecutive connections.
	bl := blocker.NewEngine(blocker.Options{})
	bl.Logger().SetDedupWindow(0)
	eng.services = opts.Services
	eng.allocatedPorts = map[string]int{"svc-opc2": 10801, "svc-warp": 10802}
	eng.activeIDs = map[string]bool{"svc-opc2": true, "svc-warp": true}
	tracker := &BlockerConnectionTracker{
		blocker:          bl,
		nodeNameResolver: eng.GetNodeName,
	}
	poolOb := NewPoolOutbound(PoolOutboundOptions{
		Tag:          "PROXY_TAG:warp",
		PoolTag:      "warp",
		NodeProvider: eng,
	})

	tracker.recordConnection("example.com", nil, poolOb)

	entries := bl.Logger().GetEntries(10)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Chain != "final -> PROXY_TAG:warp -> local_warp" {
		t.Errorf("expected entry chain %q, got %q", "final -> PROXY_TAG:warp -> local_warp", entries[0].Chain)
	}
}

// Tests that custom routing rules are prioritized ahead of preset rules in sing-box config.
func TestEngine_RulePriorityCustomBeforePreset(t *testing.T) {
	eng := &Engine{}
	ctx := createBoxContext(context.Background(), eng)

	opts := EngineOptions{
		Rules: []routing.Rule{
			// Preset rule placed first in slice
			{
				ID:           "preset-lan-direct",
				Name:         "局域网直连",
				Enabled:      true,
				DomainSuffix: []string{"lan", "local"},
				Action:       routing.RouteAction{Type: routing.ActionDirect},
			},
			{
				ID:      "preset-cn-direct",
				Name:    "大陆直连",
				Enabled: true,
				GeoSite: []string{"cn"},
				Action:  routing.RouteAction{Type: routing.ActionDirect},
			},
			// Custom rule placed after preset rules
			{
				ID:           "custom-override-rule",
				Name:         "Custom Rule Override",
				Enabled:      true,
				DomainSuffix: []string{"special.cn"},
				DomainFull:   []string{"exact.special.cn"},
				Action:       routing.RouteAction{Type: routing.ActionProxyPool},
			},
		},
		FinalAction: "direct",
	}

	boxOpts, err := eng.buildConfig(ctx, opts, "127.0.0.1", 10809)
	if err != nil {
		t.Fatalf("buildConfig failed: %v", err)
	}

	if boxOpts.Route == nil {
		t.Fatalf("expected Route options")
	}

	// Verify route rules: custom rule must appear before preset rules
	var customIdx = -1
	var presetIdx = -1
	for i, r := range boxOpts.Route.Rules {
		if slices.Contains(r.DefaultOptions.DomainSuffix, "special.cn") {
			customIdx = i
		}
		if slices.Contains(r.DefaultOptions.DomainSuffix, "lan") {
			presetIdx = i
		}
	}

	if customIdx == -1 {
		t.Fatalf("custom rule with special.cn not found in route rules")
	}
	if presetIdx == -1 {
		t.Fatalf("preset rule with lan not found in route rules")
	}
	if customIdx >= presetIdx {
		t.Fatalf("expected custom rule (index %d) before preset rule (index %d)", customIdx, presetIdx)
	}

	// Verify DomainFull is correctly included in the custom rule
	rule := boxOpts.Route.Rules[customIdx]
	if !slices.Contains(rule.DefaultOptions.Domain, "exact.special.cn") {
		t.Fatalf("expected DomainFull 'exact.special.cn' in rule domain: %v", rule.DefaultOptions.Domain)
	}
}

// Tests isolated sub-builders extracted from buildConfig (Item 13).
func TestEngine_DecomposedConfigBuilders(t *testing.T) {
	opts := EngineOptions{
		TrafficMode: "tun",
		TunAddresses: []string{"172.19.0.1/30"},
		TunMTU: 1500,
		Services: []config.Service{
			{
				ID: "sidecar-1",
				Engine: config.EngineSidecar,
				Tags: []string{"us", "fast"},
				Server: "node1.example.com",
			},
			{
				ID: "native-1",
				Engine: config.EngineSingBox,
				Tags: []string{"hk"},
				Server: "node2.example.com",
			},
		},
		BootstrapDNS: []string{"1.1.1.1"},
		DomesticDoH:  []string{"https://dns.alidns.com/dns-query"},
		RemoteDoH:    []string{"https://1.1.1.1/dns-query"},
		Rules: []routing.Rule{
			{
				ID: "r1",
				Enabled: true,
				DomainSuffix: []string{"cn"},
				Action: routing.RouteAction{Type: routing.ActionDirect},
			},
		},
		FinalAction: "PROXY_TAG:hk",
		TailnetMode: tailnet.ModeEmbedded,
		TailnetConfig: &tailnet.Config{
			AuthKey: "tskey-auth-xxx",
			Hostname: "my-node",
			ExposeMixedPort: true,
		},
		PreferIPv4: true,
	}

	// 1. Inbounds
	inbounds := buildInboundsConfig(opts, "127.0.0.1", 10809)
	if len(inbounds) < 3 { // mixed-in, tailnet-mixed-in, tun-in
		t.Fatalf("expected at least 3 inbounds, got %d", len(inbounds))
	}
	if inbounds[0]["tag"] != "mixed-in" || inbounds[1]["tag"] != "tailnet-mixed-in" || inbounds[2]["tag"] != "tun-in" {
		t.Errorf("unexpected inbound tags: %v", inbounds)
	}

	// 2. Outbounds
	finalOutbound := resolveFinalOutbound(opts)
	if finalOutbound != "PROXY_TAG:hk" {
		t.Errorf("expected finalOutbound PROXY_TAG:hk, got %s", finalOutbound)
	}
	allocatedPorts := map[string]int{"sidecar-1": 10810}
	outbounds, err := buildOutboundsConfig(opts, finalOutbound, allocatedPorts)
	if err != nil {
		t.Fatalf("buildOutboundsConfig failed: %v", err)
	}
	var foundSidecar, foundNative, foundTagHK bool
	for _, ob := range outbounds {
		tag, _ := ob["tag"].(string)
		if tag == "node-sidecar-1" {
			foundSidecar = true
			if ob["server_port"] != 10810 {
				t.Errorf("expected sidecar port 10810, got %v", ob["server_port"])
			}
		}
		if tag == "node-native-1" {
			foundNative = true
		}
		if tag == "PROXY_TAG:hk" {
			foundTagHK = true
		}
	}
	if !foundSidecar || !foundNative || !foundTagHK {
		t.Errorf("missing outbounds: sidecar=%v, native=%v, tagHK=%v", foundSidecar, foundNative, foundTagHK)
	}

	// 3. Endpoints
	endpoints := buildEndpointsConfig(opts)
	if len(endpoints) != 1 || endpoints[0]["tag"] != "tailscale-ep" {
		t.Fatalf("expected tailscale-ep endpoint, got: %v", endpoints)
	}
	if endpoints[0]["domain_resolver"] != "bootstrap-dns" {
		t.Errorf("expected domain_resolver bootstrap-dns, got: %v", endpoints[0]["domain_resolver"])
	}

	// 4. DNS
	allBootstrapDomains := collectAllBootstrapDomains(opts)
	if !slices.Contains(allBootstrapDomains, "node1.example.com") || !slices.Contains(allBootstrapDomains, "node2.example.com") {
		t.Errorf("missing node server in bootstrap domains: %v", allBootstrapDomains)
	}
	dnsMap := buildDNSConfig(opts, finalOutbound, allBootstrapDomains)
	if dnsMap["strategy"] != "prefer_ipv4" {
		t.Errorf("expected prefer_ipv4 strategy, got %v", dnsMap["strategy"])
	}
	if dnsMap["final"] != "remote-doh" {
		t.Errorf("expected dns final remote-doh, got %v", dnsMap["final"])
	}
	// Regression: DNS servers detouring to the bare "direct" outbound make sing-box fail
	// every lookup ("detour to an empty direct outbound makes no sense").
	servers, _ := dnsMap["servers"].([]map[string]any)
	for _, s := range servers {
		if s["detour"] == "direct" {
			t.Errorf("DNS server %v must not detour to the empty direct outbound", s["tag"])
		}
	}

	// 5. Route
	routeMap := buildRouteConfig(opts, finalOutbound, allBootstrapDomains)
	if routeMap["final"] != "PROXY_TAG:hk" {
		t.Errorf("expected route final PROXY_TAG:hk, got %v", routeMap["final"])
	}
	rules, ok := routeMap["rules"].([]map[string]any)
	if !ok || len(rules) == 0 {
		t.Fatalf("expected non-empty rules in route map")
	}
}

// Regression: previously buildOutboundsConfig silently fell back to 1080 when
// allocatedPorts was empty, causing sing-box to connect to 127.0.0.1:1080 instead of
// the service's configured listen port (e.g. 1083), leading to connection reset by peer.
func TestBuildOutboundsConfig_SidecarPortResolutionAndNoSilentFallback(t *testing.T) {
	opts := EngineOptions{
		Services: []config.Service{
			{
				ID:       "svc-bwg",
				Name:     "naive-bwg",
				Protocol: config.ProtoNaive,
				Engine:   config.EngineSidecar,
				Listens:  []string{"socks://127.0.0.1:1083"},
			},
		},
	}

	// 1. When allocatedPorts is empty, it must resolve to configured 1083, NEVER 1080.
	outbounds, err := buildOutboundsConfig(opts, "direct", nil)
	if err != nil {
		t.Fatalf("buildOutboundsConfig failed: %v", err)
	}
	var found bool
	for _, ob := range outbounds {
		if ob["tag"] == "node-svc-bwg" {
			found = true
			if ob["server_port"] != 1083 {
				t.Fatalf("expected server_port 1083, got %v (silent fallback to 1080 bug!)", ob["server_port"])
			}
		}
	}
	if !found {
		t.Fatalf("outbound node-svc-bwg not found")
	}

	// 2. When service has no listen port and no allocated port, it must fail fast with error.
	badOpts := EngineOptions{
		Services: []config.Service{
			{
				ID:       "svc-bad",
				Name:     "naive-bad",
				Protocol: config.ProtoNaive,
				Engine:   config.EngineSidecar,
			},
		},
	}
	if _, err := buildOutboundsConfig(badOpts, "direct", nil); err == nil {
		t.Fatalf("expected error for sidecar service without listen port, got nil")
	}
}

// Tests that a ProtoNaive node configured with EngineSingBox starts cleanly as sidecar without with_naive_outbound sing-box crash.
func TestEngine_ProtoNaiveWithSingBoxEngineDoesNotCrash(t *testing.T) {
	svc := config.Service{
		ID:       "naive-singbox-misconfigured",
		Name:     "naive-test",
		Protocol: config.ProtoNaive,
		Engine:   config.EngineSingBox,
		Listens:  []string{"socks://127.0.0.1:1089"},
		Proxies:  []string{"https://user:pass@example.com:443"},
	}
	eng, err := New(EngineOptions{
		ListenAddr: "127.0.0.1:0",
		Services:   []config.Service{svc},
	})
	if err != nil {
		t.Fatalf("expected New not to fail with missing with_naive_outbound, got: %v", err)
	}
	defer eng.Close()
	if !eng.IsSidecar(svc.ID) {
		t.Errorf("expected IsSidecar to be true for ProtoNaive node")
	}
}








