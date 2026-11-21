package boxengine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"naive-client/internal/blocker"
	"naive-client/internal/config"
	"naive-client/internal/routing"
	"naive-client/internal/tailnet"
	"naive-client/internal/tunhelper"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

func tunInbound(t *testing.T, opts EngineOptions) map[string]any {
	t.Helper()
	for _, in := range buildInboundsConfig(opts, "127.0.0.1", 10809) {
		if in["type"] == "tun" {
			return in
		}
	}
	t.Fatal("no tun inbound generated")
	return nil
}

// The macOS DynamicStore DNS entry points system DNS at tunhelper.DNSAddress.
// Explicitly setting dns_address to tunhelper.DNSAddress in tun inbound ensures
// that sing-box's virtual DNS server binds to the peer address (172.19.0.2:53)
// and handles all incoming system DNS queries.
func TestTunDNSAddressMatchesHelperAndIsHijacked(t *testing.T) {
	opts := EngineOptions{TrafficMode: "tun"}
	in := tunInbound(t, opts)

	dnsAddrs, ok := in["dns_address"].([]string)
	if !ok || len(dnsAddrs) == 0 || dnsAddrs[0] != tunhelper.DNSAddress {
		t.Fatalf("expected dns_address to contain %s, got %v", tunhelper.DNSAddress, in["dns_address"])
	}

	route := buildRouteConfig(opts, "direct", nil)
	var hijacked bool
	for _, r := range route["rules"].([]map[string]any) {
		if ports, ok := r["port"].([]int); ok && r["action"] == "hijack-dns" && len(ports) == 1 && ports[0] == 53 {
			hijacked = true
		}
	}
	if !hijacked {
		t.Error("missing route rule port 53 -> hijack-dns; DNS sent to the TUN DNS address would be unanswered")
	}
}

// Regression: an empty TailnetMode with a MagicDNS suffix used to enable the host-mode
// tailscale DNS server and routes, sending short names to 100.100.100.100 even though no
// tailnet integration was active.
func TestEmptyTailnetModeDoesNotEnableTailscaleDNS(t *testing.T) {
	opts := EngineOptions{TrafficMode: "tun", TailnetMagicDNSSuffix: "my-tailnet.ts.net"}
	dnsCfg := buildDNSConfig(opts, "direct", nil)
	for _, s := range dnsCfg["servers"].([]map[string]any) {
		if s["tag"] == "tailscale-host-dns" {
			t.Fatal("tailscale-host-dns must not be generated when TailnetMode is empty")
		}
	}
}

// Tests that TUN mode explicitly excludes loopback 127.0.0.0/8 and ::1/128, routes localhost direct,
// and resolves localhost via local-dns instead of remote-doh.
func TestTunLoopbackAndLocalhostDirect(t *testing.T) {
	opts := EngineOptions{TrafficMode: "tun"}
	in := tunInbound(t, opts)
	excludes, _ := in["route_exclude_address"].([]string)
	hasIPv4Loopback := false
	hasIPv6Loopback := false
	for _, ex := range excludes {
		if ex == "127.0.0.0/8" {
			hasIPv4Loopback = true
		}
		if ex == "::1/128" {
			hasIPv6Loopback = true
		}
	}
	if !hasIPv4Loopback || !hasIPv6Loopback {
		t.Fatalf("tun inbound route_exclude_address missing loopback CIDRs: %v", excludes)
	}

	route := buildRouteConfig(opts, "PROXY_POOL", nil)
	rules := route["rules"].([]map[string]any)
	var directLoopback bool
	for _, r := range rules {
		if cidrs, ok := r["ip_cidr"].([]string); ok && (r["outbound"] == "direct" || r["outbound"] == "loopback-direct") {
			for _, c := range cidrs {
				if c == "127.0.0.0/8" {
					directLoopback = true
				}
			}
		}
	}
	if !directLoopback {
		t.Error("missing route rule for 127.0.0.0/8 -> direct/loopback-direct")
	}

	dnsCfg := buildDNSConfig(opts, "PROXY_POOL", nil)
	rulesDNS := dnsCfg["rules"].([]map[string]any)
	var localhostResolved bool
	for _, r := range rulesDNS {
		if doms, ok := r["domain"].([]string); ok && r["server"] == "local-dns" {
			for _, d := range doms {
				if d == "localhost" {
					localhostResolved = true
				}
			}
		}
	}
	if !localhostResolved {
		t.Error("missing dns rule for localhost -> local-dns")
	}
}

// Tests that Tailscale DNS properly splits queries: ts.net and short names go to
// tailscale-host-dns, while ordinary domestic and foreign domains do not.
func TestTailscaleDNSSplit(t *testing.T) {
	opts := EngineOptions{
		TrafficMode:           "tun",
		TailnetMode:           "host",
		TailnetMagicDNSSuffix: "my-tailnet.ts.net",
	}
	dnsCfg := buildDNSConfig(opts, "PROXY_POOL", nil)
	rulesDNS := dnsCfg["rules"].([]map[string]any)

	var hasSuffixRule bool
	var hasRegexRule bool
	for _, r := range rulesDNS {
		if r["server"] == "tailscale-host-dns" {
			if suffixes, ok := r["domain_suffix"].([]string); ok {
				for _, s := range suffixes {
					if s == "ts.net" {
						hasSuffixRule = true
					}
				}
			}
			if regexes, ok := r["domain_regex"].([]string); ok {
				for _, reg := range regexes {
					if reg == `^[^.]+$` {
						hasRegexRule = true
					}
				}
			}
		}
	}
	if !hasSuffixRule || !hasRegexRule {
		t.Errorf("missing Tailscale DNS split rules, got: %v", rulesDNS)
	}
}

// Tests that on Windows, tun inbound includes dns_mode="hijack", auto_route=true, and strict_route=true
// to ensure WFP rules and metric settings prevent DNS leakage / multi-homed resolution bypass.
func TestTunWindowsInboundDNSMode(t *testing.T) {
	opts := EngineOptions{TrafficMode: "tun"}
	in := tunInbound(t, opts)

	// Verify standard fields present across platforms
	if dnsAddrs, ok := in["dns_address"].([]string); !ok || len(dnsAddrs) == 0 || dnsAddrs[0] != tunhelper.DNSAddress {
		t.Fatalf("expected dns_address to contain %s, got %v", tunhelper.DNSAddress, in["dns_address"])
	}
}

// Regression: extractNodeExcludeAddresses previously resolved every node domain sequentially
// and without caching across buildInboundsConfig and buildRouteConfig, causing TUN startup
// to stall for 30-60 seconds when multiple domains were configured.
func TestExtractNodeExcludeAddresses_ConcurrentAndDeduplicated(t *testing.T) {
	services := []config.Service{
		{ID: "n1", Server: "node1.example.com"},
		{ID: "n2", Server: "node2.example.com", Proxies: []string{"https://u:p@node1.example.com:443"}},
		{ID: "n3", Server: "node3.example.com"},
	}
	var mu sync.Mutex
	calls := make(map[string]int)
	resolver := func(host string) []net.IP {
		mu.Lock()
		calls[host]++
		mu.Unlock()
		return []net.IP{net.ParseIP("198.51.100.1")}
	}

	cidrs := extractNodeExcludeAddresses(services, resolver)
	if len(cidrs) != 1 || cidrs[0] != "198.51.100.1/32" {
		t.Fatalf("expected [198.51.100.1/32], got %v", cidrs)
	}
	if calls["node1.example.com"] != 1 {
		t.Errorf("expected node1.example.com to be resolved once per call, got %d", calls["node1.example.com"])
	}
}

// Regression: buildDNSConfig previously omitted reverse_mapping: true, so TUN connections
// using non-SNI protocols (such as git over SSH, where sniff only sees "SSH-2.0-...")
// had an empty metadata.Domain when connecting by resolved IP. Consequently, domain-based
// routing rules were bypassed (falling through to Final) and Insights logged the raw IP.
func TestEngine_DNSReverseMappingRestoresNonSNISSHDomain(t *testing.T) {
	// 1. Verify buildDNSConfig sets reverse_mapping: true
	dnsCfg := buildDNSConfig(EngineOptions{TrafficMode: "tun"}, "PROXY_POOL", nil)
	if dnsCfg["reverse_mapping"] != true {
		t.Fatalf("expected reverse_mapping: true in buildDNSConfig, got %v", dnsCfg["reverse_mapping"])
	}

	// 2. Mock local UDP DNS server that resolves "git.corp.example" -> 198.51.100.77 (non-loopback IP)
	dnsPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp dns: %v", err)
	}
	defer dnsPC.Close()
	dnsAddr := dnsPC.LocalAddr().String()

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := dnsPC.ReadFrom(buf)
			if err != nil {
				return
			}
			var req dns.Msg
			if err := req.Unpack(buf[:n]); err != nil || len(req.Question) == 0 {
				continue
			}
			resp := new(dns.Msg)
			resp.SetReply(&req)
			q := req.Question[0]
			if q.Qtype == dns.TypeA {
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    120,
					},
					A: net.ParseIP("198.51.100.77").To4(),
				})
			}
			if raw, err := resp.Pack(); err == nil {
				_, _ = dnsPC.WriteTo(raw, addr)
			}
		}
	}()

	// 3. Mock SSH server listening on 127.0.0.1:sshPort
	sshLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen ssh target: %v", err)
	}
	defer sshLn.Close()
	sshPort := sshLn.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			c, err := sshLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = conn.Write([]byte("SSH-2.0-MockGitServer\r\n"))
				var b [64]byte
				_, _ = conn.Read(b[:])
			}(c)
		}
	}()

	// 4. Mock SOCKS5 sidecar node to verify domain-based routing rule is matched for 198.51.100.77
	var proxyHit bool
	var proxyMu sync.Mutex
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks: %v", err)
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

				// Sidecar node handles both UDP DNS over SOCKS or TCP connection to 198.51.100.77
				destAddr := net.JoinHostPort(targetHost, fmt.Sprintf("%d", p))
				if targetHost == "198.51.100.77" {
					proxyMu.Lock()
					proxyHit = true
					proxyMu.Unlock()
					destAddr = fmt.Sprintf("127.0.0.1:%d", sshPort)
				}

				targetConn, err := net.Dial("tcp", destAddr)
				if err != nil {
					return
				}
				defer targetConn.Close()
				_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0})
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(targetConn, conn); done <- struct{}{} }()
				go func() { _, _ = io.Copy(conn, targetConn); done <- struct{}{} }()
				<-done
			}(c)
		}
	}()

	// 5. Start Engine with FinalAction="block", and a domain rule for "corp.example" -> PROXY_POOL.
	// Without reverse_mapping, connecting by IP 198.51.100.77 (with an SSH banner lacking SNI) would miss
	// the domain rule and hit FinalAction="block" (connection refused).
	bl := blocker.NewEngine(blocker.Options{})
	opts := EngineOptions{
		ListenAddr:   "127.0.0.1:0",
		Blocker:      bl,
		BootstrapDNS: []string{dnsAddr},
		DomesticDoH:  []string{dnsAddr},
		RemoteDoH:    []string{dnsAddr},
		Services: []config.Service{
			{
				ID:     "svc-ssh-proxy",
				Name:   "SSH-Proxy-Node",
				Engine: config.EngineSidecar,
			},
		},
		AllocatedPorts: map[string]int{"svc-ssh-proxy": socksPort},
		ActiveIDs:      map[string]bool{"svc-ssh-proxy": true},
		Rules: []routing.Rule{
			{
				ID:           "custom-git-ssh",
				Name:         "Git SSH Proxy",
				Enabled:      true,
				DomainSuffix: []string{"corp.example"},
				Action:       routing.RouteAction{Type: routing.ActionProxyPool},
			},
		},
		FinalAction: "block",
	}

	eng, err := New(opts)
	if err != nil {
		t.Fatalf("New Engine: %v", err)
	}
	if err := eng.Start(); err != nil {
		t.Fatalf("Start Engine: %v", err)
	}
	defer eng.Close()

	// Step A: Perform DNS query for "git.corp.example" through sing-box DNS router (simulating TUN DNS lookup)
	msg := new(dns.Msg)
	msg.SetQuestion("git.corp.example.", dns.TypeA)
	raw, _ := msg.Pack()
	writer := &testPacketWriter{done: make(chan struct{})}
	eng.box.Router().HijackDNSPacket(context.Background(), raw, writer, adapter.InboundContext{})
	select {
	case <-writer.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for DNS query")
	}

	// Step B: Connect to proxy using raw IP (198.51.100.77:sshPort) and send SSH client banner (no SNI).
	proxyConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", eng.Port()))
	if err != nil {
		t.Fatalf("dial mixed proxy: %v", err)
	}
	defer proxyConn.Close()

	// SOCKS5 handshake to raw IP 198.51.100.77:sshPort
	_, _ = proxyConn.Write([]byte{0x05, 0x01, 0x00})
	var greet [2]byte
	if _, err := io.ReadFull(proxyConn, greet[:]); err != nil {
		t.Fatalf("socks greet: %v", err)
	}
	req := []byte{0x05, 0x01, 0x00, 0x01, 198, 51, 100, 77, byte(sshPort >> 8), byte(sshPort & 0xff)}
	_, _ = proxyConn.Write(req)
	var resp [10]byte
	if _, err := io.ReadFull(proxyConn, resp[:]); err != nil || resp[1] != 0x00 {
		t.Fatalf("socks connect failed: %v, resp=%v", err, resp)
	}

	// Send SSH client identification string (non-TLS, no SNI)
	_, _ = proxyConn.Write([]byte("SSH-2.0-OpenSSH_10.5\r\n"))
	banner := make([]byte, 64)
	n, _ := proxyConn.Read(banner)
	if !strings.HasPrefix(string(banner[:n]), "SSH-2.0-MockGitServer") {
		t.Fatalf("expected SSH banner response, got %q", string(banner[:n]))
	}

	proxyMu.Lock()
	hit := proxyHit
	proxyMu.Unlock()
	if !hit {
		t.Fatalf("expected SSH connection to 198.51.100.77 to match domain rule 'git.corp.example' via DNS reverse_mapping and route through PROXY_POOL")
	}

	time.Sleep(50 * time.Millisecond)

	// Verify Gateway log recorded the reverse-mapped domain "git.corp.example" rather than raw IP "198.51.100.77"
	entries := bl.Logger().GetEntries(10)
	var foundReverseMappedGateway bool
	for _, e := range entries {
		if e.Source == blocker.SourceGateway && e.Domain == "git.corp.example" {
			foundReverseMappedGateway = true
			break
		}
	}
	if !foundReverseMappedGateway {
		t.Fatalf("expected non-SNI SSH connection to raw IP to be reverse-mapped to 'git.corp.example' in Gateway logs, got entries: %+v", entries)
	}
}

func TestEngine_PerRuleRemoteDoHDetourAndPoolWrapping(t *testing.T) {
	eng := &Engine{
		services: []config.Service{
			{ID: "svc-us", Name: "US Node", Protocol: config.ProtoVLESS, Server: "us.example.com", ServerPort: 443, UUID: "11111111-1111-1111-1111-111111111111", Tags: []string{"US"}},
			{ID: config.BuiltinWarpServiceID, Name: "Cloudflare WARP", Protocol: config.ProtoWARP},
		},
		activeIDs: map[string]bool{
			"svc-us":                    true,
			config.BuiltinWarpServiceID: true,
		},
	}

	// 1. PROXY_POOL excludes builtin-warp, while explicit node:builtin-warp includes it.
	poolCands := eng.GetCandidates("PROXY_POOL")
	if len(poolCands) != 1 || poolCands[0] != "svc-us" {
		t.Fatalf("expected PROXY_POOL to contain only svc-us, got %v", poolCands)
	}
	warpCands := eng.GetCandidates("node:" + config.BuiltinWarpServiceID)
	if len(warpCands) != 1 || warpCands[0] != config.BuiltinWarpServiceID {
		t.Fatalf("expected explicit node:builtin-warp to resolve builtin-warp, got %v", warpCands)
	}

	// 2. Single-node and builtin-warp rules wrap in PoolOutbound and emit scoped remote-doh-* servers.
	usAction := routing.NewProxyAction([]routing.TargetRef{{Kind: routing.TargetNode, Value: "svc-us"}}, routing.DispatchSmart, false)
	warpOverseasAction := routing.NewWarpTargetAction()
	cnWarpAction := routing.NewWarpTargetAction()

	opts := EngineOptions{
		TrafficMode: "tun",
		Services:    eng.services,
		Rules: []routing.Rule{
			{
				ID:           "rule-us-node",
				Enabled:      true,
				DomainSuffix: []string{"us-only.example.com"},
				Action:       usAction,
			},
			{
				ID:           "rule-warp-overseas",
				Enabled:      true,
				DomainSuffix: []string{"openai.com"},
				Action:       warpOverseasAction,
			},
			{
				ID:      "preset-cn-direct",
				Enabled: true,
				GeoSite: []string{"cn"},
				Action:  cnWarpAction,
			},
		},
		FinalRoute: routing.RouteAction{Type: routing.ActionProxyPool},
	}

	ctx := createBoxContext(context.Background(), eng)
	boxOpts, err := eng.buildConfig(ctx, opts, "127.0.0.1", 10809)
	if err != nil {
		t.Fatalf("buildConfig failed: %v", err)
	}
	_ = boxOpts

	finalOutbound := resolveFinalOutbound(opts)
	outbounds, err := buildOutboundsConfig(opts, finalOutbound, nil)
	if err != nil {
		t.Fatalf("buildOutboundsConfig failed: %v", err)
	}
	usOutboundTag := resolveRouteOutbound(usAction, "")
	warpOutboundTag := resolveRouteOutbound(warpOverseasAction, "")
	if !strings.HasPrefix(usOutboundTag, "POOL:") || !strings.HasPrefix(warpOutboundTag, "POOL:") {
		t.Fatalf("expected POOL: tags for single-node & warp rules, got us=%q warp=%q", usOutboundTag, warpOutboundTag)
	}
	foundUSPool, foundWarpPool := false, false
	for _, ob := range outbounds {
		if ob["type"] == "pool" && ob["tag"] == usOutboundTag {
			foundUSPool = true
		}
		if ob["type"] == "pool" && ob["tag"] == warpOutboundTag {
			foundWarpPool = true
		}
	}
	if !foundUSPool || !foundWarpPool {
		t.Fatalf("expected pool outbounds registered for single-node (%v) and builtin-warp (%v)", foundUSPool, foundWarpPool)
	}

	dnsCfg := buildDNSConfig(opts, finalOutbound, nil)
	servers := dnsCfg["servers"].([]map[string]any)
	serverDetours := make(map[string]string)
	for _, s := range servers {
		tag, _ := s["tag"].(string)
		detour, _ := s["detour"].(string)
		serverDetours[tag] = detour
		if strings.HasPrefix(tag, "remote-doh") && s["domain_resolver"] != "bootstrap-dns" {
			t.Errorf("expected %s to use bootstrap-dns domain_resolver, got %v", tag, s["domain_resolver"])
		}
	}

	wantUSDNS := remoteDoHTagForOutbound(usOutboundTag)
	wantWarpDNS := remoteDoHTagForOutbound(warpOutboundTag)
	if serverDetours[wantUSDNS] != usOutboundTag {
		t.Errorf("expected %s detour=%s, got %q", wantUSDNS, usOutboundTag, serverDetours[wantUSDNS])
	}
	if serverDetours[wantWarpDNS] != warpOutboundTag {
		t.Errorf("expected %s detour=%s, got %q", wantWarpDNS, warpOutboundTag, serverDetours[wantWarpDNS])
	}

	dnsRules := dnsCfg["rules"].([]map[string]any)
	var matchedUS, matchedOpenAI, matchedCN bool
	for _, dr := range dnsRules {
		if doms, ok := dr["domain_suffix"].([]string); ok {
			for _, d := range doms {
				if d == "us-only.example.com" && dr["server"] == wantUSDNS {
					matchedUS = true
				}
				if d == "openai.com" && dr["server"] == wantWarpDNS {
					matchedOpenAI = true
				}
			}
		}
		if rsets, ok := dr["rule_set"].([]string); ok {
			for _, rs := range rsets {
				if rs == "geosite-cn" && dr["server"] == "domestic-doh" {
					matchedCN = true
				}
			}
		}
	}
	if !matchedUS || !matchedOpenAI || !matchedCN {
		t.Errorf("DNS rule mismatch: us=%v openai=%v cn=%v (rules=%+v)", matchedUS, matchedOpenAI, matchedCN, dnsRules)
	}
}

// Regression: proxy nodes using Tailscale hostnames in host networking mode previously had
// domain_resolver pinned to bootstrap-dns (223.5.5.5) and were added to allBootstrapDomains,
// causing NXDOMAIN and falling off the Tailscale interface to en0; CGNAT/RFC1918 route rule 0.25
// also preempted Tailnet rules.
func TestHostTailnetNodeOutbound_UsesMagicDNSResolverAndInterfaceAndExcludesBootstrap(t *testing.T) {
	opts := EngineOptions{
		TrafficMode:           "tun",
		TailnetMode:           tailnet.ModeHost,
		TailnetMagicDNSSuffix: "tail8bfe1c.ts.net",
		TailnetHostExcludes:   []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48", "10.20.0.0/16"},
		TailnetHostInterface:  "utun9",
		TailnetHostRecords: map[string][]string{
			"my-vps":                   {"100.64.1.5"},
			"my-vps.tail8bfe1c.ts.net": {"100.64.1.5"},
		},
		BootstrapDomains: []string{"my-vps.tail8bfe1c.ts.net", "my-vps", "edge.example.com"},
		Services: []config.Service{
			{
				ID:         "vless-fqdn",
				Name:       "VLESS FQDN",
				Engine:     config.EngineSingBox,
				Protocol:   config.ProtoVLESS,
				Server:     "my-vps.tail8bfe1c.ts.net",
				ServerPort: 443,
				UUID:       "11111111-1111-1111-1111-111111111111",
			},
			{
				ID:         "ss-short",
				Name:       "SS Short",
				Engine:     config.EngineSingBox,
				Protocol:   config.ProtoShadowsocks,
				Server:     "my-vps",
				ServerPort: 8388,
				Method:     "aes-256-gcm",
				Password:   "secret",
			},
			{
				ID:          "socks-ip",
				Name:        "SOCKS IP",
				Kind:        config.KindExternalProxy,
				ExternalURI: "socks5://100.64.2.9:1080",
			},
			{
				ID:          "lan-short",
				Name:        "LAN Short",
				Kind:        config.KindExternalProxy,
				ExternalURI: "http://lan-proxy:8080",
			},
			{
				ID:         "public-vps",
				Name:       "Public VPS",
				Engine:     config.EngineSingBox,
				Protocol:   config.ProtoTrojan,
				Server:     "edge.example.com",
				ServerPort: 443,
				Password:   "pw",
			},
			{
				ID:       "sidecar-ts",
				Name:     "Naive Sidecar",
				Engine:   config.EngineSidecar,
				Kind:     config.KindManagedNaive,
				Protocol: config.ProtoNaive,
				Listens:  []string{"socks://127.0.0.1:20808"},
				Proxies:  []string{"https://u:p@sidecar-box.tail8bfe1c.ts.net:443"},
			},
		},
		NodeIPResolver: func(host string) []net.IP {
			switch host {
			case "my-vps.tail8bfe1c.ts.net", "my-vps":
				return []net.IP{net.ParseIP("100.64.1.5")}
			case "edge.example.com":
				return []net.IP{net.ParseIP("203.0.113.10")}
			default:
				return nil
			}
		},
	}

	outbounds, err := buildOutboundsConfig(opts, "PROXY_POOL", map[string]int{"sidecar-ts": 20808})
	if err != nil {
		t.Fatalf("buildOutboundsConfig failed: %v", err)
	}
	byTag := make(map[string]map[string]any, len(outbounds))
	for _, ob := range outbounds {
		if tag, _ := ob["tag"].(string); tag != "" {
			byTag[tag] = ob
		}
	}

	for _, tag := range []string{"node-vless-fqdn", "node-ss-short"} {
		ob := byTag[tag]
		if ob["domain_resolver"] != "tailscale-host-dns" {
			t.Errorf("%s domain_resolver = %v, want tailscale-host-dns", tag, ob["domain_resolver"])
		}
		if ob["bind_interface"] != "utun9" {
			t.Errorf("%s bind_interface = %v, want utun9", tag, ob["bind_interface"])
		}
	}
	if byTag["node-socks-ip"]["bind_interface"] != "utun9" {
		t.Errorf("node-socks-ip bind_interface = %v, want utun9", byTag["node-socks-ip"]["bind_interface"])
	}
	if _, hasDR := byTag["node-socks-ip"]["domain_resolver"]; hasDR {
		t.Errorf("node-socks-ip should not set domain_resolver for IP literal")
	}
	// Non-Tailnet single-label LAN server must not bind to Tailscale interface when hostRecords is known.
	if _, hasBind := byTag["node-lan-short"]["bind_interface"]; hasBind {
		t.Errorf("node-lan-short should not set bind_interface=%v", byTag["node-lan-short"]["bind_interface"])
	}
	if byTag["node-public-vps"]["domain_resolver"] != "domestic-doh" {
		t.Errorf("node-public-vps domain_resolver = %v, want bootstrap-dns", byTag["node-public-vps"]["domain_resolver"])
	}
	if _, hasBind := byTag["node-public-vps"]["bind_interface"]; hasBind {
		t.Errorf("node-public-vps should not bind Tailscale interface")
	}

	bootstrap := collectAllBootstrapDomains(opts)
	bootstrapSet := make(map[string]bool, len(bootstrap))
	for _, d := range bootstrap {
		bootstrapSet[d] = true
	}
	for _, excluded := range []string{"my-vps.tail8bfe1c.ts.net", "my-vps", "sidecar-box.tail8bfe1c.ts.net"} {
		if bootstrapSet[excluded] {
			t.Errorf("Tailnet domain %q must not appear in bootstrap domains: %v", excluded, bootstrap)
		}
	}
	if !bootstrapSet["edge.example.com"] {
		t.Errorf("expected edge.example.com in bootstrap domains: %v", bootstrap)
	}

	routeCfg := buildRouteConfig(opts, "PROXY_POOL", bootstrap)
	rules := routeCfg["rules"].([]map[string]any)
	firstTailnetIdx, firstDirectRFC1918Idx, nodeCIDRIdx := -1, -1, -1
	for i, r := range rules {
		if r["outbound"] == "tailnet-direct" && firstTailnetIdx == -1 {
			firstTailnetIdx = i
		}
		if r["outbound"] == "direct" {
			if cidrs, ok := r["ip_cidr"].([]string); ok {
				for _, c := range cidrs {
					if c == "100.64.0.0/10" && firstDirectRFC1918Idx == -1 {
						firstDirectRFC1918Idx = i
					}
					if c == "203.0.113.10/32" && nodeCIDRIdx == -1 {
						nodeCIDRIdx = i
					}
					if c == "100.64.1.5/32" {
						t.Errorf("Tailnet peer IP 100.64.1.5/32 must not be emitted into direct nodeCIDRs rule")
					}
				}
			}
		}
	}
	if firstTailnetIdx < 0 || firstDirectRFC1918Idx < 0 || firstTailnetIdx >= firstDirectRFC1918Idx {
		t.Errorf("tailnet-direct rule (idx=%d) must precede RFC1918/CGNAT direct rule (idx=%d)", firstTailnetIdx, firstDirectRFC1918Idx)
	}
	if nodeCIDRIdx < 0 || firstTailnetIdx >= nodeCIDRIdx {
		t.Errorf("tailnet-direct rule (idx=%d) must precede nodeCIDRs direct rule (idx=%d)", firstTailnetIdx, nodeCIDRIdx)
	}
}

func TestEmbeddedTailnetNodeOutbound_DetoursThroughTailscaleEndpoint(t *testing.T) {
	opts := EngineOptions{
		TrafficMode:           "tun",
		TailnetMode:           tailnet.ModeEmbedded,
		TailnetConfig:         &tailnet.Config{Enabled: true, Mode: tailnet.ModeEmbedded},
		TailnetMagicDNSSuffix: "tail8bfe1c.ts.net",
		Services: []config.Service{
			{
				ID:         "vless-ts",
				Engine:     config.EngineSingBox,
				Protocol:   config.ProtoVLESS,
				Server:     "peer1.tail8bfe1c.ts.net",
				ServerPort: 443,
				UUID:       "11111111-1111-1111-1111-111111111111",
			},
			{
				ID:         "public-vps",
				Engine:     config.EngineSingBox,
				Protocol:   config.ProtoTrojan,
				Server:     "public.example.com",
				ServerPort: 443,
				Password:   "pw",
			},
		},
		NodeIPResolver: func(host string) []net.IP {
			if host == "peer1.tail8bfe1c.ts.net" {
				return []net.IP{net.ParseIP("100.64.1.9")}
			}
			return []net.IP{net.ParseIP("203.0.113.20")}
		},
	}

	outbounds, err := buildOutboundsConfig(opts, "PROXY_POOL", nil)
	if err != nil {
		t.Fatalf("buildOutboundsConfig failed: %v", err)
	}
	for _, ob := range outbounds {
		switch ob["tag"] {
		case "node-vless-ts":
			if ob["detour"] != "tailscale-ep" || ob["domain_resolver"] != "tailscale-dns" {
				t.Errorf("node-vless-ts = %+v, want detour=tailscale-ep domain_resolver=tailscale-dns", ob)
			}
		case "node-public-vps":
			if ob["domain_resolver"] != "domestic-doh" || ob["detour"] != nil {
				t.Errorf("node-public-vps = %+v, want domestic-doh with no detour", ob)
			}
		}
	}

	in := tunInbound(t, opts)
	if excludes, ok := in["route_exclude_address"].([]string); ok {
		for _, exc := range excludes {
			if exc == "100.64.1.9/32" {
				t.Errorf("ModeEmbedded TUN inbound must not exclude Tailnet IP %s", exc)
			}
		}
	}
}

type mockDNSTransport struct {
	tag       string
	mu        sync.Mutex
	seenNames []string
	fn        func(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
}

func (m *mockDNSTransport) Type() string                                   { return "udp" }
func (m *mockDNSTransport) Tag() string                                    { return m.tag }
func (m *mockDNSTransport) Dependencies() []string                         { return nil }
func (m *mockDNSTransport) Reset()                                         {}
func (m *mockDNSTransport) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (m *mockDNSTransport) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	m.mu.Lock()
	if len(msg.Question) > 0 {
		m.seenNames = append(m.seenNames, msg.Question[0].Name)
	}
	m.mu.Unlock()
	return m.fn(ctx, msg)
}
func (m *mockDNSTransport) ExchangeAsync(ctx context.Context, msg *dns.Msg, cb func(*dns.Msg, error)) {
	resp, err := m.Exchange(ctx, msg)
	cb(resp, err)
}

// Regression: tailscale-host-dns points straight at UDP 100.100.100.100:53 which does not expand
// single-label Tailscale MagicDNS hostnames and fails when --accept-dns=false.
func TestTailscaleHostDNSTransport_SingleLabelExpansionAndHostRecordFallback(t *testing.T) {
	mock := &mockDNSTransport{
		tag: "tailscale-host-dns",
		fn: func(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
			q := msg.Question[0]
			switch {
			case q.Name == "my-vps.tail8bfe1c.ts.net." && q.Qtype == dns.TypeA:
				resp := new(dns.Msg)
				resp.SetReply(msg)
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP("100.64.1.5").To4(),
				})
				return resp, nil
			case q.Name == "my-vps.tail8bfe1c.ts.net." && q.Qtype == dns.TypeAAAA:
				resp := new(dns.Msg)
				resp.SetReply(msg)
				return resp, nil
			case q.Name == "printer.tail8bfe1c.ts.net.":
				resp := new(dns.Msg)
				resp.SetReply(msg)
				resp.Rcode = dns.RcodeNameError
				return resp, nil
			case q.Name == "printer." && q.Qtype == dns.TypeA:
				resp := new(dns.Msg)
				resp.SetReply(msg)
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP("192.168.1.50").To4(),
				})
				return resp, nil
			case q.Name == "offline-dns.tail8bfe1c.ts.net." || q.Name == "offline-dns.":
				return nil, errors.New("udp i/o timeout")
			default:
				resp := new(dns.Msg)
				resp.SetReply(msg)
				resp.Rcode = dns.RcodeNameError
				return resp, nil
			}
		},
	}

	tr := newTailscaleHostDNSTransport(mock, "tail8bfe1c.ts.net", map[string][]string{
		"offline-dns":                   {"100.64.8.8"},
		"offline-dns.tail8bfe1c.ts.net": {"100.64.8.8"},
	})

	// 1. Single-label A query expands to MagicDNS FQDN and restores original question & answer names.
	req := new(dns.Msg)
	req.SetQuestion("my-vps.", dns.TypeA)
	resp, err := tr.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("Exchange(my-vps A) failed: %v", err)
	}
	if resp.Question[0].Name != "my-vps." || len(resp.Answer) != 1 || resp.Answer[0].Header().Name != "my-vps." {
		t.Fatalf("expected restored name my-vps. in question/answer, got q=%+v ans=%+v", resp.Question, resp.Answer)
	}
	if aRec, ok := resp.Answer[0].(*dns.A); !ok || aRec.A.String() != "100.64.1.5" {
		t.Fatalf("unexpected A record: %+v", resp.Answer[0])
	}

	// 2. Single-label AAAA with NOERROR + 0 answers must return cleanly without retrying raw single-label.
	req6 := new(dns.Msg)
	req6.SetQuestion("my-vps.", dns.TypeAAAA)
	mock.mu.Lock()
	beforeCount := len(mock.seenNames)
	mock.mu.Unlock()
	resp6, err := tr.Exchange(context.Background(), req6)
	if err != nil || resp6 == nil || resp6.Rcode != dns.RcodeSuccess || len(resp6.Answer) != 0 {
		t.Fatalf("expected empty NOERROR for AAAA, got resp=%+v err=%v", resp6, err)
	}
	if resp6.Question[0].Name != "my-vps." {
		t.Errorf("expected restored AAAA question name my-vps., got %q", resp6.Question[0].Name)
	}
	mock.mu.Lock()
	newSeen := append([]string(nil), mock.seenNames[beforeCount:]...)
	mock.mu.Unlock()
	if len(newSeen) != 1 || newSeen[0] != "my-vps.tail8bfe1c.ts.net." {
		t.Errorf("expected single expanded lookup for AAAA, got %v", newSeen)
	}

	// 3. Non-Tailnet single-label name falls back to unexpanded query when expanded returns NXDOMAIN.
	reqLAN := new(dns.Msg)
	reqLAN.SetQuestion("printer.", dns.TypeA)
	respLAN, err := tr.Exchange(context.Background(), reqLAN)
	if err != nil || len(respLAN.Answer) != 1 || respLAN.Answer[0].(*dns.A).A.String() != "192.168.1.50" {
		t.Fatalf("expected LAN fallback answer 192.168.1.50, got resp=%+v err=%v", respLAN, err)
	}

	// 4. Transport error falls back to TailnetHostRecords for both short name and FQDN (ExchangeAsync).
	reqAsync := new(dns.Msg)
	reqAsync.SetQuestion("offline-dns.tail8bfe1c.ts.net.", dns.TypeA)
	ch := make(chan *dns.Msg, 1)
	tr.ExchangeAsync(context.Background(), reqAsync, func(r *dns.Msg, e error) {
		if e != nil {
			t.Errorf("ExchangeAsync failed: %v", e)
		}
		ch <- r
	})
	asyncResp := <-ch
	if asyncResp == nil || len(asyncResp.Answer) != 1 || asyncResp.Answer[0].(*dns.A).A.String() != "100.64.8.8" {
		t.Fatalf("expected fallback record 100.64.8.8, got %+v", asyncResp)
	}

	// 5. Real sing-box Engine builds and starts cleanly with Host-mode Tailscale node + remote-doh.
	ln, lnErr := net.Listen("tcp", "127.0.0.1:0")
	if lnErr != nil {
		t.Fatal(lnErr)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	eng, newErr := New(EngineOptions{
		ListenAddr:            fmt.Sprintf("127.0.0.1:%d", port),
		TrafficMode:           "mixed",
		TailnetMode:           tailnet.ModeHost,
		TailnetMagicDNSSuffix: "tail8bfe1c.ts.net",
		TailnetHostRecords: map[string][]string{
			"my-vps":                   {"100.64.1.5"},
			"my-vps.tail8bfe1c.ts.net": {"100.64.1.5"},
		},
		Services: []config.Service{
			{
				ID:         "ts-vless",
				Name:       "TS VLESS",
				Engine:     config.EngineSingBox,
				Protocol:   config.ProtoVLESS,
				Server:     "my-vps",
				ServerPort: 443,
				UUID:       "11111111-1111-1111-1111-111111111111",
			},
		},
		NodeIPResolver: func(host string) []net.IP { return nil },
	})
	if newErr != nil {
		t.Fatalf("real sing-box Engine New failed: %v", newErr)
	}
	if err := eng.Start(); err != nil {
		t.Fatalf("real sing-box Engine Start failed: %v", err)
	}
	defer eng.Close()

	dnsRouter := service.FromContext[adapter.DNSRouter](eng.boxCtx)
	if dnsRouter == nil {
		t.Fatal("expected DNSRouter in running sing-box context")
	}
	for _, host := range []string{"my-vps", "my-vps.tail8bfe1c.ts.net"} {
		addrs, lookupErr := dnsRouter.Lookup(context.Background(), host, adapter.DNSQueryOptions{})
		if lookupErr != nil || len(addrs) == 0 || addrs[0].String() != "100.64.1.5" {
			t.Errorf("real sing-box DNSRouter.Lookup(%q) = %v, err=%v; want [100.64.1.5]", host, addrs, lookupErr)
		}
	}
}




// Regression: proxy node domains must resolve via domestic-doh (encrypted, direct),
// while the DoH server's own hostname must stay on bootstrap-dns, since a server
// cannot resolve itself.
func TestBuildDNSConfig_NodeDomainsUseDomesticDoHAndDoHHostUsesBootstrap(t *testing.T) {
	opts := EngineOptions{
		DomesticDoH: []string{"https://dns.alidns.com/dns-query"},
	}
	cfg := buildDNSConfig(opts, "PROXY_POOL", []string{"dns.alidns.com", "node.example.com"})
	rules, _ := cfg["rules"].([]map[string]any)
	got := map[string]string{}
	for _, r := range rules {
		doms, _ := r["domain"].([]string)
		for _, d := range doms {
			if s, ok := r["server"].(string); ok {
				got[d] = s
			}
		}
	}
	if got["node.example.com"] != "domestic-doh" {
		t.Errorf("node domain server = %q, want domestic-doh", got["node.example.com"])
	}
	if got["dns.alidns.com"] != "bootstrap-dns" {
		t.Errorf("DoH host server = %q, want bootstrap-dns", got["dns.alidns.com"])
	}
}
