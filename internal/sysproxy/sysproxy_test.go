package sysproxy

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// Tests that Sysproxy creates a dirty recovery snapshot before modifying state
// and recovers cleanly when RecoverIfDirty is called.
func TestSysproxy_RecoveryIfDirty(t *testing.T) {
	tmpDir := t.TempDir()
	recoveryPath := filepath.Join(tmpDir, "network-recovery.json")

	var executedCommands []string
	execMock := func(cmd string, args ...string) ([]byte, error) {
		full := cmd
		for _, a := range args {
			full += " " + a
		}
		executedCommands = append(executedCommands, full)
		return []byte("ok"), nil
	}

	sp := NewWithExecutor(execMock, recoveryPath)

	// 1. Initially recovery file does not exist, RecoverIfDirty should be a no-op
	if err := sp.RecoverIfDirty(); err != nil {
		t.Fatalf("unexpected error on clean RecoverIfDirty: %v", err)
	}
	if len(executedCommands) != 0 {
		t.Fatalf("expected 0 commands executed on clean recovery, got %d", len(executedCommands))
	}

	// 2. Set system proxy to 127.0.0.1:10808
	bypass := []string{"localhost", "127.0.0.1", "*.local"}
	if err := sp.Set("127.0.0.1:10808", bypass); err != nil {
		t.Fatalf("failed to set system proxy: %v", err)
	}

	// Verify recovery file is marked dirty
	data, err := os.ReadFile(recoveryPath)
	if err != nil {
		t.Fatalf("failed to read recovery file: %v", err)
	}
	if len(data) == 0 {
		t.Fatalf("recovery file is empty")
	}

	// 3. Simulate crash & restart: Create a new Sysproxy instance and run RecoverIfDirty
	executedCommands = nil
	sp2 := NewWithExecutor(execMock, recoveryPath)
	if err := sp2.RecoverIfDirty(); err != nil {
		t.Fatalf("failed to recover dirty proxy: %v", err)
	}

	// Verify unset commands were executed during recovery
	if len(executedCommands) == 0 {
		t.Fatalf("expected unset commands executed on dirty recovery")
	}

	// Second RecoverIfDirty should now be a no-op
	executedCommands = nil
	if err := sp2.RecoverIfDirty(); err != nil {
		t.Fatalf("second recover failed: %v", err)
	}
	if len(executedCommands) != 0 {
		t.Fatalf("expected 0 commands after recovery cleaned dirty flag, got %d", len(executedCommands))
	}
}

// Tests that Sysproxy properly marks TUN mode as dirty and cleans it up upon RecoverIfDirty.
func TestSysproxy_TunRecoveryIfDirty(t *testing.T) {
	tmpDir := t.TempDir()
	recoveryPath := filepath.Join(tmpDir, "network-recovery.json")

	var executedCommands []string
	execMock := func(cmd string, args ...string) ([]byte, error) {
		full := cmd
		for _, a := range args {
			full += " " + a
		}
		executedCommands = append(executedCommands, full)
		return []byte("ok"), nil
	}

	sp := NewWithExecutor(execMock, recoveryPath)
	if err := sp.MarkDirtyTun("utun8"); err != nil {
		t.Fatalf("failed to mark dirty tun: %v", err)
	}

	// Verify state file
	sp2 := NewWithExecutor(execMock, recoveryPath)
	if err := sp2.RecoverIfDirty(); err != nil {
		t.Fatalf("RecoverIfDirty on tun state failed: %v", err)
	}

	// Verify dirty flag is cleared
	executedCommands = nil
	if err := sp2.RecoverIfDirty(); err != nil {
		t.Fatalf("subsequent RecoverIfDirty failed: %v", err)
	}
	if len(executedCommands) != 0 {
		t.Errorf("expected 0 commands after tun recovery, got %d", len(executedCommands))
	}
}

func TestSysproxy_DefaultBypassReservedSubnets(t *testing.T) {
	type cmdCall struct {
		name string
		args []string
	}
	var calls []cmdCall
	execMock := func(name string, args ...string) ([]byte, error) {
		cp := append([]string(nil), args...)
		calls = append(calls, cmdCall{name: name, args: cp})
		if name == "networksetup" && len(args) > 0 && args[0] == "-listallnetworkservices" {
			return []byte("Wi-Fi\n"), nil
		}
		return []byte("ok"), nil
	}

	wantBypass := []string{
		"127.0.0.1",
		"127.0.0.0/8",
		"::1",
		"::1/128",
		"localhost",
		"*.local",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"fc00::/7",
		"fe80::/10",
	}

	sp := NewWithExecutor(execMock, "")
	if err := sp.Set("127.0.0.1:10808", nil); err != nil {
		t.Fatalf("Set with nil bypass failed: %v", err)
	}

	switch runtime.GOOS {
	case "darwin":
		var gotBypass []string
		for _, c := range calls {
			if c.name == "networksetup" && len(c.args) >= 2 && c.args[0] == "-setproxybypassdomains" && c.args[1] == "Wi-Fi" {
				gotBypass = c.args[2:]
			}
		}
		if !reflect.DeepEqual(gotBypass, wantBypass) {
			t.Fatalf("darwin bypass domains mismatch:\n got: %v\nwant: %v", gotBypass, wantBypass)
		}
	case "windows":
		var gotOverride string
		for _, c := range calls {
			if c.name == "reg" && len(c.args) >= 7 && c.args[3] == "ProxyOverride" {
				gotOverride = c.args[7]
			}
		}
		wantOverride := formatWindowsProxyOverride(wantBypass)
		if gotOverride != wantOverride {
			t.Fatalf("windows ProxyOverride mismatch:\n got: %q\nwant: %q", gotOverride, wantOverride)
		}
	default:
		var gotIgnoreHosts string
		for _, c := range calls {
			if c.name == "gsettings" && len(c.args) == 4 && c.args[2] == "ignore-hosts" {
				gotIgnoreHosts = c.args[3]
			}
		}
		wantIgnoreHosts := formatGSettingsStringArray(wantBypass)
		if gotIgnoreHosts != wantIgnoreHosts {
			t.Fatalf("linux ignore-hosts mismatch:\n got: %q\nwant: %q", gotIgnoreHosts, wantIgnoreHosts)
		}
	}

	// Verify Linux gsettings ignore-hosts behavior regardless of host OS.
	calls = nil
	if err := sp.setLinux("127.0.0.1", "10808", wantBypass); err != nil {
		t.Fatalf("setLinux failed: %v", err)
	}
	wantIgnoreHosts := "['127.0.0.1', '127.0.0.0/8', '::1', '::1/128', 'localhost', '*.local', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', 'fc00::/7', 'fe80::/10']"
	var gotIgnoreHosts string
	for _, c := range calls {
		if c.name == "gsettings" && len(c.args) == 4 && c.args[1] == "org.gnome.system.proxy" && c.args[2] == "ignore-hosts" {
			gotIgnoreHosts = c.args[3]
		}
	}
	if gotIgnoreHosts != wantIgnoreHosts {
		t.Fatalf("setLinux ignore-hosts mismatch:\n got: %q\nwant: %q", gotIgnoreHosts, wantIgnoreHosts)
	}
}

// Tests that Windows ProxyServer formats IPv6 proxy hosts with brackets.
func TestSysproxy_WindowsIPv6ProxyServerFormatting(t *testing.T) {
	var proxyServer string
	sp := NewWithExecutor(func(name string, args ...string) ([]byte, error) {
		if name == "reg" && len(args) >= 8 && args[3] == "ProxyServer" {
			proxyServer = args[7]
		}
		return []byte("ok"), nil
	}, "")
	if err := sp.setWindows("::1", "10808", []string{"::1/128"}); err != nil {
		t.Fatalf("setWindows failed: %v", err)
	}
	if proxyServer != "[::1]:10808" {
		t.Fatalf("expected Windows ProxyServer [::1]:10808, got %q", proxyServer)
	}
}

// Tests that wildcard proxy listen addresses (0.0.0.0, ::, empty host) normalize to 127.0.0.1 in sysproxy Set and recovery state.
func TestSysproxy_WildcardNormalizedToLoopback(t *testing.T) {
	recPath := filepath.Join(t.TempDir(), "recovery.json")
	for _, input := range []string{"0.0.0.0:10809", "[::]:10809", ":10809"} {
		var sawCalls []string
		sp := NewWithExecutor(func(name string, args ...string) ([]byte, error) {
			sawCalls = append(sawCalls, name+" "+strings.Join(args, " "))
			if name == "networksetup" && len(args) > 0 && args[0] == "-listallnetworkservices" {
				return []byte("An asterisk (*)\nWi-Fi\n"), nil
			}
			return []byte("ok"), nil
		}, recPath)

		if err := sp.Set(input, []string{"127.0.0.1"}); err != nil {
			t.Fatalf("Set(%q) failed: %v", input, err)
		}
		joined := strings.Join(sawCalls, "\n")
		if strings.Contains(joined, "0.0.0.0") || strings.Contains(joined, " :: ") || strings.Contains(joined, "[::]") {
			t.Fatalf("expected wildcard normalized to 127.0.0.1 for %q, got calls:\n%s", input, joined)
		}
		if !strings.Contains(joined, "127.0.0.1") {
			t.Fatalf("expected 127.0.0.1 in sysproxy command calls for %q, got:\n%s", input, joined)
		}

		raw, err := os.ReadFile(recPath)
		if err != nil {
			t.Fatalf("read recovery state: %v", err)
		}
		if !strings.Contains(string(raw), `"addr": "127.0.0.1:10809"`) {
			t.Fatalf("expected normalized recovery addr 127.0.0.1:10809 for %q, got:\n%s", input, string(raw))
		}
	}
}

// Tests that custom bypass lists preserve user rules while retaining dual-stack loopback guards without duplicates.
func TestSysproxy_CustomBypassPreservesDualStackLoopback(t *testing.T) {
	var calls []string
	sp := NewWithExecutor(func(name string, args ...string) ([]byte, error) {
		if name == "networksetup" && len(args) > 0 && args[0] == "-listallnetworkservices" {
			return []byte("Wi-Fi\n"), nil
		}
		calls = append(calls, name+" "+strings.Join(args, " "))
		return []byte("ok"), nil
	}, "")

	if err := sp.Set("127.0.0.1:10809", []string{"*.corp.internal", "127.0.0.1", " *.corp.internal "}); err != nil {
		t.Fatalf("Set with custom bypass failed: %v", err)
	}
	joined := strings.Join(calls, "\n")
	for _, want := range []string{"*.corp.internal", "127.0.0.1", "::1", "localhost"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected %q in sysproxy bypass calls, got:\n%s", want, joined)
		}
	}
	if got := normalizeBypass([]string{"*.corp.internal", "127.0.0.1", " *.corp.internal "}); !reflect.DeepEqual(got, []string{"*.corp.internal", "127.0.0.1", "::1", "localhost"}) {
		t.Fatalf("unexpected normalizeBypass output: %v", got)
	}
}

// Tests that Windows ProxyOverride keeps dual-stack CIDR rules, adds WinINET wildcards/bracketed loopback, and avoids duplicate <local>.
func TestSysproxy_WindowsProxyOverrideCompatibility(t *testing.T) {
	var proxyOverride string
	sp := NewWithExecutor(func(name string, args ...string) ([]byte, error) {
		if name == "reg" && len(args) >= 8 && args[3] == "ProxyOverride" {
			proxyOverride = args[7]
		}
		return []byte("ok"), nil
	}, "")

	if err := sp.setWindows("127.0.0.1", "10809", defaultBypass); err != nil {
		t.Fatalf("setWindows failed: %v", err)
	}
	parts := strings.Split(proxyOverride, ";")
	for _, want := range []string{"127.*", "10.*", "192.168.*", "169.254.*", "[::1]", "fc00::/7", "fe80::/10", "<local>"} {
		found := false
		for _, p := range parts {
			if p == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected %q in Windows ProxyOverride %q", want, proxyOverride)
		}
	}
	localCount := 0
	for _, p := range parts {
		if strings.EqualFold(p, "<local>") {
			localCount++
		}
	}
	if localCount != 1 {
		t.Fatalf("expected exactly one <local> in ProxyOverride %q, got %d", proxyOverride, localCount)
	}

	deduped := formatWindowsProxyOverride([]string{"127.0.0.1", "<local>", "<LOCAL>"})
	if deduped != "127.0.0.1;<local>" {
		t.Fatalf("expected no duplicate <local>, got %q", deduped)
	}
}

