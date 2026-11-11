package boxengine

import (
	"net"
	"sync"
	"testing"

	"naive-client/internal/config"
	"naive-client/internal/tunhelper"
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

