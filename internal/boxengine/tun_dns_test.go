package boxengine

import (
	"net/netip"
	"testing"

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
// By leaving dns_address unset in tun inbound, sing-box automatically derives
// the peer address from the TUN subnet (172.19.0.1/30 -> 172.19.0.2) and populates
// dnsHijackAddress so both UDP and TCP DNS are hijacked.
func TestTunDNSAddressMatchesHelperAndIsHijacked(t *testing.T) {
	opts := EngineOptions{TrafficMode: "tun"}
	in := tunInbound(t, opts)

	if dnsAddrs, ok := in["dns_address"].([]string); ok && len(dnsAddrs) > 0 {
		t.Fatalf("dns_address should remain unset for sing-box auto derivation, got %v", dnsAddrs)
	}
	addrs, _ := in["address"].([]string)
	prefix := netip.MustParsePrefix(addrs[0])
	derivedDNS := prefix.Addr().Next()
	if derivedDNS.String() != tunhelper.DNSAddress {
		t.Errorf("derived DNS address %s does not match tunhelper.DNSAddress %s", derivedDNS, tunhelper.DNSAddress)
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
