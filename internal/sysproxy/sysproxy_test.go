package sysproxy

import (
	"os"
	"path/filepath"
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

