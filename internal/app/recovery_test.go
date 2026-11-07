package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"naive-client/internal/config"
)

// Regression: premature saveState during early geodata detection overwrote state.json with an uninitialized empty service list, and state.json corruption left valid config.json files unrecovered.
func TestStateLoad_RecoversServicesFromConfigsWhenStateEmpty(t *testing.T) {
	tmp := t.TempDir()
	cfgDir := filepath.Join(tmp, "configs")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatalf("mkdir configs: %v", err)
	}

	naiveCfg := map[string]any{
		"listen": "socks://127.0.0.1:1083",
		"proxy":  "https://user:pass@example.com:443",
		"log":    "",
	}
	cfgRaw, _ := json.Marshal(naiveCfg)
	cfgPath := filepath.Join(cfgDir, "service-svc-recovered-1.json")
	if err := os.WriteFile(cfgPath, cfgRaw, 0o600); err != nil {
		t.Fatalf("write mock config: %v", err)
	}

	// Write an empty state.json to simulate wipeout
	emptyState := PersistedState{
		Services: []config.Service{},
	}
	stRaw, _ := json.Marshal(emptyState)
	if err := os.WriteFile(filepath.Join(tmp, "state.json"), stRaw, 0o600); err != nil {
		t.Fatalf("write empty state: %v", err)
	}

	a := &app{
		dataDir: tmp,
	}
	a.loadState()

	if len(a.state.Services) != 1 {
		t.Fatalf("expected 1 recovered service, got %d", len(a.state.Services))
	}
	svc := a.state.Services[0]
	if svc.ID != "svc-recovered-1" {
		t.Errorf("expected ID svc-recovered-1, got %s", svc.ID)
	}
	if len(svc.Listens) == 0 || svc.Listens[0] != "socks://127.0.0.1:1083" {
		t.Errorf("expected listen socks://127.0.0.1:1083, got %v", svc.Listens)
	}
	if len(svc.Proxies) == 0 || svc.Proxies[0] != "https://user:pass@example.com:443" {
		t.Errorf("expected proxy https://user:pass@example.com:443, got %v", svc.Proxies)
	}
}

// Premature saveState before loadState completes must be ignored to prevent wiping out persisted user data.
func TestApp_PrematureSaveStateBeforeLoadedBlocked(t *testing.T) {
	tmp := t.TempDir()
	existingState := PersistedState{
		Services: []config.Service{
			{ID: "keep-me", Name: "Existing Service"},
		},
	}
	raw, _ := json.Marshal(existingState)
	statePath := filepath.Join(tmp, "state.json")
	if err := os.WriteFile(statePath, raw, 0o600); err != nil {
		t.Fatalf("write existing state: %v", err)
	}

	// a is initialized as in Run() with empty state and stateLoaded = false
	a := &app{
		dataDir:     tmp,
		stateLoaded: false,
	}

	// Attempt premature save
	a.saveState()

	// Verify disk file was untouched
	diskRaw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	var loaded PersistedState
	if err := json.Unmarshal(diskRaw, &loaded); err != nil {
		t.Fatalf("unmarshal state file: %v", err)
	}
	if len(loaded.Services) != 1 || loaded.Services[0].ID != "keep-me" {
		t.Fatalf("state on disk was unexpectedly mutated by premature saveState: %+v", loaded)
	}
}
