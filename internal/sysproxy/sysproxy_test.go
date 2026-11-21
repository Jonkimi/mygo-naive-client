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
		"localhost",
		"*.local",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
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
		wantOverride := strings.Join(wantBypass, ";") + ";<local>"
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
	wantIgnoreHosts := "['127.0.0.1', '127.0.0.0/8', '::1', 'localhost', '*.local', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16']"
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

