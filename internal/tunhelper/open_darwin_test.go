//go:build darwin

package tunhelper

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Regression guard for stale-DNS cleanup: if the key parser stops recognizing scutil's list
// format, entries left by a killed helper are never removed and system DNS stays broken.
func TestParseScutilKeys(t *testing.T) {
	out := "subKeys [0] = {\n  0 : x\n}\n  subKey [0] = State:/Network/Service/utun5/DNS\n  subKey [1] = State:/Network/Service/utun9/DNS\n"
	want := []string{"State:/Network/Service/utun5/DNS", "State:/Network/Service/utun9/DNS"}
	if got := parseScutilKeys(out); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if got := parseScutilKeys("  No keys found\n"); len(got) != 0 {
		t.Errorf("expected none, got %v", got)
	}
}

// Regression: macOS TUN DNS setup previously only read the first token of /etc/resolv.conf
// search lines and ignored /etc/resolver/* Split DNS files created by Tailscale.
func TestCollectDarwinSearchDomains_IncludesAllSearchTokensAndSplitDNSResolver(t *testing.T) {
	tmp := t.TempDir()
	resolvPath := filepath.Join(tmp, "resolv.conf")
	resolverDir := filepath.Join(tmp, "resolver")
	if err := os.MkdirAll(resolverDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(resolvPath, []byte("nameserver 192.168.1.1\nsearch office.local tail8bfe1c.ts.net.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(resolverDir, "tail9abc.ts.net"), []byte("# Added by tailscaled\nnameserver 100.100.100.100\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(resolverDir, "corp.internal"), []byte("nameserver 10.0.0.2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := collectDarwinSearchDomains(resolvPath, resolverDir)
	want := []string{"office.local", "tail8bfe1c.ts.net", "tail9abc.ts.net"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("collectDarwinSearchDomains() = %v, want %v", got, want)
	}

	cmds := buildDarwinDNSCommands("utun5", got)
	if !strings.Contains(cmds, "d.add ServerAddresses * "+DNSAddress+" "+DNSAddressV6+"\n") {
		t.Errorf("missing dual-stack ServerAddresses line in:\n%s", cmds)
	}
	if !strings.Contains(cmds, "d.add SearchDomains * office.local tail8bfe1c.ts.net tail9abc.ts.net\n") {
		t.Errorf("missing SearchDomains line in:\n%s", cmds)
	}
	if !strings.Contains(cmds, `d.add SupplementalMatchDomains * "" office.local. tail8bfe1c.ts.net. tail9abc.ts.net.`+"\n") {
		t.Errorf("missing SupplementalMatchDomains line in:\n%s", cmds)
	}
	if !strings.Contains(cmds, "d.add SupplementalMatchOrders * # 100000 100000 100000 100000\n") {
		t.Errorf("missing SupplementalMatchOrders line in:\n%s", cmds)
	}
}

// Tests that macOS exclude and default route builders handle pure-IPv6 hosts and forced IPv6-over-IPv4 routes.
func TestBuildDarwinIPv6Routes(t *testing.T) {
	// 1. Pure-IPv6 host (no gw4/iface4) uses gw6 for IPv6 node bypass routes.
	cmds := buildDarwinExcludeRouteCommands([]string{"[2001:db8::1]", "2606:4700:d0::/48", "1.2.3.4"}, "", "", "fe80::1%en0", "en0")
	if len(cmds) != 2 {
		t.Fatalf("expected 2 IPv6 exclude route commands on IPv6-only host, got %v", cmds)
	}
	want0 := []string{"route", "-q", "-n", "add", "-inet6", "2001:db8::1/128", "fe80::1%en0"}
	want1 := []string{"route", "-q", "-n", "add", "-inet6", "2606:4700:d0::/48", "fe80::1%en0"}
	if !reflect.DeepEqual(cmds[0], want0) || !reflect.DeepEqual(cmds[1], want1) {
		t.Fatalf("unexpected IPv6 exclude commands: %v", cmds)
	}

	// 2. Default route builder installs IPv6 half-default routes when installIPv6 is true.
	defRoutes := buildDarwinDefaultRouteCommands("utun9", true)
	if len(defRoutes) != 4 {
		t.Fatalf("expected 4 default routes (v4+v6), got %v", defRoutes)
	}
	if !reflect.DeepEqual(defRoutes[2], []string{"route", "-q", "-n", "add", "-inet6", "::/1", "-interface", "utun9"}) {
		t.Fatalf("unexpected ::/1 route command: %v", defRoutes[2])
	}
}

// Regression: parseDarwinRouteOutput previously discarded virtual interfaces from iface
// while still returning gw (e.g. fd7a:115c:a1e0::), routing exclude routes into Tailscale utun.
func TestParseDarwinRouteOutput_IgnoresVirtualGatewayAndV6DNS(t *testing.T) {
	tailscaleV6Route := "   route to: default\n" +
		"destination: default\n" +
		"       mask: default\n" +
		"    gateway: fd7a:115c:a1e0::\n" +
		"  interface: utun12\n" +
		"      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n"
	gw, iface := parseDarwinRouteOutput(tailscaleV6Route)
	if gw != "" || iface != "" {
		t.Fatalf("expected empty gw and iface for virtual utun route, got (%q, %q)", gw, iface)
	}

	physV6Route := "   route to: default\n" +
		"    gateway: fe80::1%en0\n" +
		"  interface: en0\n"
	gw, iface = parseDarwinRouteOutput(physV6Route)
	if gw != "fe80::1%en0" || iface != "en0" {
		t.Fatalf("expected physical gateway (fe80::1%%en0, en0), got (%q, %q)", gw, iface)
	}

	// Verify fd7a:115c:a1e0::53 in /etc/resolver is recognized and includeIPv6=false omits DNSAddressV6.
	tmp := t.TempDir()
	resolverDir := filepath.Join(tmp, "resolver")
	if err := os.MkdirAll(resolverDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(resolverDir, "tail9abc.ts.net"), []byte("nameserver fd7a:115c:a1e0::53\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gotDomains := collectDarwinSearchDomains("", resolverDir)
	if !reflect.DeepEqual(gotDomains, []string{"tail9abc.ts.net"}) {
		t.Fatalf("expected [tail9abc.ts.net] from IPv6 MagicDNS resolver, got %v", gotDomains)
	}
	cmdsV4Only := buildDarwinDNSCommands("utun5", gotDomains, false)
	if !strings.Contains(cmdsV4Only, "d.add ServerAddresses * "+DNSAddress+"\n") || strings.Contains(cmdsV4Only, DNSAddressV6) {
		t.Fatalf("expected IPv4-only ServerAddresses when includeIPv6=false, got:\n%s", cmdsV4Only)
	}
}
