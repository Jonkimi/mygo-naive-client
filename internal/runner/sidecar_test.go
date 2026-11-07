package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"naive-client/internal/config"
)

func writeFakeScript(t *testing.T, path, echoMsg string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell script test on unix")
	}
	body := "#!/bin/sh\necho \"" + echoMsg + " $1\"\ntrap 'exit 0' INT TERM\nwhile true; do sleep 0.1; done\n"
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("failed to write fake script %s: %v", path, err)
	}
}

func TestToXrayConfigJSON(t *testing.T) {
	vlessSvc := config.Service{
		ID:         "vless-node",
		Name:       "VLESS Reality Node",
		Protocol:   config.ProtoVLESS,
		Engine:     config.EngineSidecar,
		Server:     "example.com",
		ServerPort: 443,
		UUID:       "12345678-1234-1234-1234-123456789abc",
		Flow:       "xtls-rprx-vision",
		Security:   "reality",
		SNI:        "yahoo.com",
		Fingerprint: "chrome",
		PublicKey:  "test-pubkey",
		ShortID:    "test-shortid",
		Network:    "tcp",
	}

	cfgBytes, err := GenerateXrayConfig(vlessSvc, 12345)
	if err != nil {
		t.Fatalf("GenerateXrayConfig failed: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(cfgBytes, &m); err != nil {
		t.Fatalf("invalid json generated: %v", err)
	}

	inbounds, ok := m["inbounds"].([]any)
	if !ok || len(inbounds) == 0 {
		t.Fatalf("expected inbounds in xray config: %v", m)
	}
	firstInbound := inbounds[0].(map[string]any)
	if int(firstInbound["port"].(float64)) != 12345 {
		t.Errorf("inbound port = %v, want 12345", firstInbound["port"])
	}
	if firstInbound["protocol"] != "socks" {
		t.Errorf("inbound protocol = %v, want socks", firstInbound["protocol"])
	}

	outbounds, ok := m["outbounds"].([]any)
	if !ok || len(outbounds) == 0 {
		t.Fatalf("expected outbounds in xray config: %v", m)
	}
	firstOutbound := outbounds[0].(map[string]any)
	if firstOutbound["protocol"] != "vless" {
		t.Errorf("outbound protocol = %v, want vless", firstOutbound["protocol"])
	}
}

func TestManagerDynamicPortAllocation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix only")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "naive")
	writeFakeScript(t, bin, "naive started")

	mgr := NewManager(bin, dir, nil)
	svc := config.Service{
		ID:       "dynamic-node",
		Name:     "Dynamic Port Node",
		Protocol: config.ProtoNaive,
		Engine:   config.EngineSidecar,
		Listens:  []string{"socks://127.0.0.1:0"},
		Proxies:  []string{"https://user:pass@example.com"},
	}

	if err := mgr.Start(svc); err != nil {
		t.Fatalf("Start dynamic port service failed: %v", err)
	}
	defer mgr.Stop(svc.ID)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if mgr.StatusOf(svc.ID).State == StateRunning {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	st := mgr.StatusOf(svc.ID)
	if st.State != StateRunning {
		t.Fatalf("expected service running, got %+v", st)
	}
	if st.AllocatedPort <= 0 {
		t.Errorf("expected AllocatedPort > 0, got %d", st.AllocatedPort)
	}
}

func TestManagerDualSidecarSelection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix only")
	}
	dir := t.TempDir()
	naiveBin := filepath.Join(dir, "naive")
	writeFakeScript(t, naiveBin, "naive started")
	xrayBin := filepath.Join(dir, "xray")
	writeFakeScript(t, xrayBin, "xray started")

	mgr := NewManager(naiveBin, dir, nil)
	mgr.SetXrayBinaryPath(xrayBin)

	// Sidecar with VLESS protocol should use xray binary
	vlessSvc := config.Service{
		ID:         "vless-sidecar",
		Name:       "VLESS Sidecar",
		Protocol:   config.ProtoVLESS,
		Engine:     config.EngineSidecar,
		Server:     "vless.example.com",
		ServerPort: 443,
		UUID:       "12345678-1234-1234-1234-123456789abc",
		Listens:    []string{"socks://127.0.0.1:0"},
	}

	if err := mgr.Start(vlessSvc); err != nil {
		t.Fatalf("Start VLESS sidecar failed: %v", err)
	}
	defer mgr.Stop(vlessSvc.ID)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if mgr.StatusOf(vlessSvc.ID).State == StateRunning {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	st := mgr.StatusOf(vlessSvc.ID)
	if st.State != StateRunning {
		t.Fatalf("expected VLESS sidecar running, got %+v", st)
	}

	deadline = time.Now().Add(2 * time.Second)
	hasXray := false
	var logs []string
	for time.Now().Before(deadline) {
		logs = mgr.LogsOf(vlessSvc.ID).Lines()
		for _, l := range logs {
			if strings.Contains(l, "xray started") {
				hasXray = true
				break
			}
		}
		if hasXray {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !hasXray {
		t.Errorf("expected logs to contain 'xray started', got: %v", logs)
	}
}
