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
