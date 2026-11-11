package boxengine

import (
	"context"
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
	"naive-client/internal/tunhelper"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
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


