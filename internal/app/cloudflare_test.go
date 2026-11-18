package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"

	"time"

	"naive-client/internal/blocker"
	"naive-client/internal/config"
	"naive-client/internal/routing"
	"naive-client/internal/runner"
	"naive-client/internal/warp"
)

func TestCloudflarePage_NavigationAndSubtabs(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)

	// 1. Navigate via Cmd+5
	tt.Key(ui.Cmd, ui.Key5)
	tt.Frame()

	if a.activeTab != TabCloudflare {
		t.Fatalf("expected activeTab = TabCloudflare, got %v", a.activeTab)
	}

	// Default subtab is 0 (WARP)
	if a.cloudflareSubTab != 0 {
		t.Fatalf("expected default cloudflareSubTab = 0, got %d", a.cloudflareSubTab)
	}

	// 2. Switch to Tunnel subtab (index 1)
	a.cloudflareSubTab = 1
	tt.Frame()

	// Enable Tunnel and set token
	a.state.Cloudflare.Tunnel.Enabled = true
	a.state.Cloudflare.Tunnel.Token = "test-token-zero-trust-123"
	a.saveState()

	if !a.state.Cloudflare.Tunnel.Enabled || a.state.Cloudflare.Tunnel.Token != "test-token-zero-trust-123" {
		t.Errorf("failed to persist Tunnel config")
	}
}

func TestCloudflarePage_TriggerWarpRegister(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/reg") {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":    "device-mock-123",
				"type":  "PC",
				"token": "tok-456",
				"account": map[string]any{
					"id":           "acc-789",
					"account_type": "free",
				},
				"config": map[string]any{
					"client_id": "AQID",
					"interface": map[string]any{
						"addresses": map[string]any{
							"v4": "172.16.0.2/32",
							"v6": "2606:4700:110:8a36::2/128",
						},
					},
				},
			})
			return
		}
		if strings.Contains(r.URL.Path, "/v0a4471/reg") {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "device-mock-123",
			})
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	a, tt, _ := newTestApp(t, nil)

	// Use mock server by testing client directly and verifying state update
	cli := warp.NewClient(ts.Client())
	cli.BaseURL = ts.URL

	acc, err := cli.ProvisionAll(context.Background(), warp.Account{}, "")
	if err != nil {
		t.Fatalf("ProvisionAll failed: %v", err)
	}

	a.state.Cloudflare.Account = acc
	a.saveState()

	if a.state.Cloudflare.Account.DeviceID != "device-mock-123" {
		t.Errorf("unexpected device ID: %s", a.state.Cloudflare.Account.DeviceID)
	}
	if a.state.Cloudflare.Account.IPv4 != "172.16.0.2/32" {
		t.Errorf("unexpected IPv4: %s", a.state.Cloudflare.Account.IPv4)
	}

	tt.Frame()
}

func TestNodeEditor_CreateDirectWARPNode(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)

	a.openCreateServiceDialog()
	tt.Frame()

	// Select Cloudflare WARP protocol (index 9 in editorProtocols)
	warpProtoIndex := -1
	for i, p := range editorProtocols {
		if p == config.ProtoWARP {
			warpProtoIndex = i
			break
		}
	}
	if warpProtoIndex < 0 {
		t.Fatalf("ProtoWARP not found in editorProtocols")
	}

	a.editor.name = "My Direct WARP"
	a.editor.protoIndex = warpProtoIndex
	a.editor.warpModeIndex = 0 // MASQUE (index 0 for direct WARP)
	a.editor.warpEndpoint = "162.159.198.2:443"

	svc, err := a.buildServiceFromEditor()
	if err != nil {
		t.Fatalf("buildServiceFromEditor failed: %v", err)
	}

	if svc.EffectiveProtocol() != config.ProtoWARP {
		t.Errorf("expected ProtoWARP, got %s", svc.EffectiveProtocol())
	}
	if svc.WARPConfig == nil || svc.WARPConfig.Transport != config.WarpTransportMasque {
		t.Errorf("expected WarpTransportMasque, got %+v", svc.WARPConfig)
	}
}

func TestNodeEditor_EnableWARPOnProxyNode(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)

	svc := config.Service{
		ID:         "vless-01",
		Name:       "VLESS Node",
		Protocol:   config.ProtoVLESS,
		Server:     "node.example.com",
		ServerPort: 443,
		UUID:       "00000000-0000-0000-0000-000000000001",
	}

	a.openEditServiceDialog(svc)
	tt.Frame()

	a.editor.enableWARP = true
	a.editor.warpModeIndex = 1 // WireGuard (default for chained proxy+WARP)
	a.editor.warpEndpoint = "162.159.192.1:2408"

	updated, err := a.buildServiceFromEditor()
	if err != nil {
		t.Fatalf("buildServiceFromEditor failed: %v", err)
	}

	if !updated.EnableWARP {
		t.Errorf("expected EnableWARP to be true")
	}
	if updated.WARPConfig == nil || updated.WARPConfig.Transport != config.WarpTransportWireGuard {
		t.Errorf("expected WarpTransportWireGuard, got %+v", updated.WARPConfig)
	}
}

func TestGatewayConfigSignature_TracksWARPAndTunnelChanges(t *testing.T) {
	a, _, _ := newTestApp(t, nil)

	sig1 := a.gatewayConfigSignature()

	// Toggle Cloudflare Tunnel
	a.state.Cloudflare.Tunnel.Enabled = true
	sig2 := a.gatewayConfigSignature()
	if sig1 == sig2 {
		t.Errorf("expected signature to change when Cloudflare Tunnel is toggled")
	}

	// Change Tunnel Token
	a.state.Cloudflare.Tunnel.Token = "new-token-456"
	sig3 := a.gatewayConfigSignature()
	if sig2 == sig3 {
		t.Errorf("expected signature to change when Tunnel Token is modified")
	}

	// Add service with EnableWARP
	a.state.Services = append(a.state.Services, config.Service{
		ID:         "svc-warp-test",
		Name:       "Test WARP Node",
		Protocol:   config.ProtoVLESS,
		Server:     "test.example.com",
		ServerPort: 443,
		UUID:       "11111111-1111-1111-1111-111111111111",
		EnableWARP: true,
	})
	sig4 := a.gatewayConfigSignature()
	if sig3 == sig4 {
		t.Errorf("expected signature to change when node with EnableWARP is added")
	}
}

func TestBuiltinWarp_LifecycleAndRuleSync(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)
	a.warpRegistering = true // Prevent background live Cloudflare API calls during unit test.
	gwPort := freeLocalPort(t)
	a.state.GatewayPort = gwPort
	a.state.GatewayEnabled = true
	if err := a.startGateway(); err != nil {
		t.Fatalf("startGateway failed: %v", err)
	}
	defer a.stopGateway()

	// Initially, builtin-warp should not exist
	for _, s := range a.state.Services {
		if s.IsBuiltinWarp() {
			t.Fatalf("expected no builtin-warp initially")
		}
	}

	// 1. Set preset-cn-direct to target builtin-warp and saveState
	a.setCnDirectWarpEnabled(true)
	tt.Frame()

	// Verify builtin-warp now exists in services
	var foundBuiltin *config.Service
	for i := range a.state.Services {
		if a.state.Services[i].IsBuiltinWarp() {
			foundBuiltin = &a.state.Services[i]
			break
		}
	}
	if foundBuiltin == nil {
		t.Fatalf("expected builtin-warp to be injected into Services")
	}
	if foundBuiltin.Protocol != config.ProtoWARP {
		t.Errorf("expected ProtoWARP, got %s", foundBuiltin.Protocol)
	}
	if a.mgr.StatusOf(config.BuiltinWarpServiceID).State != runner.StateRunning {
		t.Errorf("expected builtin-warp to be running")
	}

	// 2. Switch preset-cn-direct back to ActionDirect and saveState
	a.setCnDirectWarpEnabled(false)
	tt.Frame()

	// Verify builtin-warp is stopped and removed
	for _, s := range a.state.Services {
		if s.IsBuiltinWarp() {
			t.Fatalf("expected builtin-warp to be removed from Services")
		}
	}
	if a.mgr.StatusOf(config.BuiltinWarpServiceID).State == runner.StateRunning {
		t.Errorf("expected builtin-warp to be stopped")
	}

	// 3. Re-enable via Cloudflare Direct -> WARP toggle helper (single source of truth on preset-cn-direct)
	a.setCnDirectWarpEnabled(true)
	tt.Frame()

	var foundAgain bool
	for _, s := range a.state.Services {
		if s.IsBuiltinWarp() {
			foundAgain = true
			break
		}
	}
	if !foundAgain {
		t.Fatalf("expected builtin-warp to re-appear when preset-cn-direct targets builtin-warp")
	}
}

func TestDirectWARP_DefaultProbeURL(t *testing.T) {
	a, _, _ := newTestApp(t, nil)

	warpSvc := config.Service{
		ID:       "warp-node",
		Name:     "WARP Direct",
		Protocol: config.ProtoWARP,
	}

	proxySvc := config.Service{
		ID:       "vless-node",
		Name:     "VLESS Proxy",
		Protocol: config.ProtoVLESS,
	}

	// 1. Direct WARP node defaults to MIUI 204
	warpProbe := a.probeURLForService(warpSvc)
	if warpProbe != "http://connect.rom.miui.com/generate_204" {
		t.Errorf("expected http://connect.rom.miui.com/generate_204, got %s", warpProbe)
	}

	// 2. Normal proxy node defaults to Cloudflare 204
	proxyProbe := a.probeURLForService(proxySvc)
	if proxyProbe != defaultProbeURL {
		t.Errorf("expected defaultProbeURL %s, got %s", defaultProbeURL, proxyProbe)
	}

	// 3. Cloudflare custom probe URL override
	a.state.Cloudflare.ProbeURL = "http://www.qualcomm.cn/generate_204"
	warpCustomProbe := a.probeURLForService(warpSvc)
	if warpCustomProbe != "http://www.qualcomm.cn/generate_204" {
		t.Errorf("expected custom probe URL, got %s", warpCustomProbe)
	}
}

func TestBuiltinWarp_NodeNameAndDisabledDelete(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)
	a.warpRegistering = true
	a.setCnDirectWarpEnabled(true)
	tt.Frame()

	var found *config.Service
	for i := range a.state.Services {
		if a.state.Services[i].IsBuiltinWarp() {
			found = &a.state.Services[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected builtin-warp in services")
	}

	// 1. Name must be clean "Cloudflare WARP", not containing "(内置直连)"
	if found.Name != "Cloudflare WARP" {
		t.Errorf("expected node name to be 'Cloudflare WARP', got %q", found.Name)
	}

	// 2. Migration: if an older state had "(内置直连)", saveState migrates it cleanly
	found.Name = "Cloudflare WARP (内置直连)"
	a.saveState()
	tt.Frame()
	if a.state.Services[0].Name != "Cloudflare WARP" {
		t.Errorf("expected migration to restore 'Cloudflare WARP', got %q", a.state.Services[0].Name)
	}

	// 3. Render card and verify delete dialog is NOT opened
	tt.Frame()
	if a.deleteDlg.open {
		t.Errorf("delete dialog should not be open")
	}
}

func TestInsights_WarpChainDisplay(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)
	a.activeTab = TabInsights
	tt.Frame()

	now := time.Now()
	// Record gateway entry with Cloudflare WARP chain
	a.blocker.Logger().RecordAtWithChain("api.cloudflare.com", blocker.SourceGateway, blocker.VerdictAllowed, "geosite-cn", "rule_set(geosite-cn) -> Cloudflare WARP", now)
	tt.Frame()

	entries := a.blocker.Logger().GetEntries(10)
	if len(entries) == 0 {
		t.Fatalf("expected recorded entry")
	}
	if entries[0].Chain != "rule_set(geosite-cn) -> Cloudflare WARP" {
		t.Errorf("unexpected chain: %s", entries[0].Chain)
	}
	if entries[0].Error != "" {
		t.Errorf("unexpected error in entry: %s", entries[0].Error)
	}
}

func TestBuiltinWarp_DirectLatencyProbe(t *testing.T) {
	if testing.Short() || os.Getenv("RUN_LIVE_WARP_TESTS") == "" {
		t.Skip("live Cloudflare WARP network test skipped; set RUN_LIVE_WARP_TESTS=1 to run")
	}
	a, tt, _ := newTestApp(t, nil)
	freePort, err := runner.AllocateFreePort()
	if err != nil {
		t.Fatalf("failed to allocate free port: %v", err)
	}
	a.state.GatewayPort = freePort
	a.state.LogLevel = "debug"
	a.warpRegistering = true
	a.setCnDirectWarpEnabled(true)
	tt.Frame()

	var warpSvc *config.Service
	for i := range a.state.Services {
		if a.state.Services[i].IsBuiltinWarp() {
			warpSvc = &a.state.Services[i]
			break
		}
	}
	if warpSvc == nil {
		t.Fatalf("expected builtin-warp in services")
	}

	a.warpRegistering = true
	cli := warp.NewClient(nil)
	regCtx, regCancel := context.WithTimeout(context.Background(), 10*time.Second)
	acc, regErr := cli.ProvisionAll(regCtx, a.state.Cloudflare.Account, "")
	regCancel()
	t.Logf("ProvisionAll: devID=%s, err=%v", acc.DeviceID, regErr)
	if regErr != nil {
		if strings.Contains(regErr.Error(), "429") {
			t.Skipf("Cloudflare API rate-limited (HTTP 429): %v", regErr)
		}
		t.Fatalf("ProvisionAll failed: %v", regErr)
	}
	if !acc.IsRegistered() {
		t.Skipf("WARP account is not registered, skipping live probe test")
	}
	a.state.Cloudflare.Account = acc
	a.warpRegistering = false
	a.saveState()
	tt.Frame()

	probeURL := a.probeURLForService(*warpSvc)
	t.Logf("Probing URL: %s", probeURL)
	t.Logf("Status of warpSvc: %+v", a.mgr.StatusOf(warpSvc.ID))

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	rtt, err := a.mgr.ProbeServiceCtx(ctx, *warpSvc, probeURL)
	t.Logf("Probe 1 result: rtt=%v, err=%v", rtt, err)
	if err != nil {
		t.Fatalf("first probe failed: %v", err)
	}

	// Second probe should hit the cached endpoint / circuit breaker quickly
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	rtt2, err2 := a.mgr.ProbeServiceCtx(ctx2, *warpSvc, probeURL)
	t.Logf("Probe 2 (circuit breaker) result: rtt=%v, err=%v", rtt2, err2)
	if err2 != nil {
		t.Fatalf("second probe failed: %v", err2)
	}

	dlCtx, dlCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer dlCancel()
	bps, dlErr := a.mgr.DownloadTestServiceCtx(dlCtx, *warpSvc, "https://speed.cloudflare.com/__down?bytes=1000000")
	t.Logf("Download test result: speed=%.2f MB/s, err=%v", bps/(1024*1024), dlErr)
	if dlErr != nil {
		t.Fatalf("download test failed: %v", dlErr)
	}
	if a.gatewayLogs != nil {
		for _, l := range a.gatewayLogs.Lines() {
			t.Logf("gateway log: %s", l)
		}
	}
}

func TestDirectWARP_UnhealthyStatusAndDiagnostics(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)
	a.warpRegistering = true
	a.setCnDirectWarpEnabled(true)
	tt.Frame()

	var warpSvc *config.Service
	for i := range a.state.Services {
		if a.state.Services[i].IsBuiltinWarp() {
			warpSvc = &a.state.Services[i]
			break
		}
	}
	if warpSvc == nil {
		t.Fatalf("expected builtin-warp in services")
	}

	// 1. When running normally without error, it is healthy
	stNormal := runner.Status{
		State:   runner.StateRunning,
		Latency: 80 * time.Millisecond,
	}
	a.mgr.SetStatusForTest(warpSvc.ID, stNormal)
	if a.isNodeUnhealthy(*warpSvc, stNormal) {
		t.Errorf("expected normal node to be healthy")
	}

	// 2. When probe fails with WARP server dial failure, mark unhealthy
	stUnhealthy := runner.Status{
		State:      runner.StateRunning,
		ProbeError: "warp server (162.159.198.2:443) connection failed: dial tcp 162.159.198.2:443: i/o timeout",
	}
	a.mgr.SetStatusForTest(warpSvc.ID, stUnhealthy)
	if !a.isNodeUnhealthy(*warpSvc, stUnhealthy) {
		t.Fatalf("expected node to be marked unhealthy on probe failure")
	}

	// 2a. When account is not registered yet, diagnosis guides user to register credentials
	diagUnreg, isWarpUnreg, isUnreg := a.diagnoseNodeUnhealthy(*warpSvc, stUnhealthy)
	if !isWarpUnreg || !isUnreg {
		t.Errorf("expected isWarp and isUnregistered to be true")
	}
	if !strings.Contains(diagUnreg, "注册") && !strings.Contains(diagUnreg, "register") {
		t.Errorf("expected unregistered hint, got: %s", diagUnreg)
	}

	// 2b. Once account is registered, diagnosis targets WARP server Anycast network block
	a.state.Cloudflare.Account.DeviceID = "test-device-id"
	a.state.Cloudflare.Account.WGPrivateKey = "test-wg-key"
	a.saveState()

	diag, isWarp, _ := a.diagnoseNodeUnhealthy(*warpSvc, stUnhealthy)
	if !isWarp {
		t.Errorf("expected isWarp to be true")
	}
	if !strings.Contains(diag, "162.159.198.2:443") {
		t.Errorf("expected diagnostic message to mention WARP endpoint, got: %s", diag)
	}
	if !strings.Contains(diag, "并非") && !strings.Contains(diag, "not") {
		t.Errorf("expected diagnostic message to clarify it's not a user config error, got: %s", diag)
	}

	// 3. Render UI frame: should find "不健康" status badge and diagnostic banner
	tt.Frame()
	cat := a.catalog()
	if _, ok := tt.Find(cat.StatusUnhealthy()); !ok {
		t.Errorf("expected '%s' status badge on card", cat.StatusUnhealthy())
	}
	if _, ok := tt.Find(cat.NodeUnhealthyDiagnosticTitle()); !ok {
		t.Errorf("expected '%s' diagnostic title in banner", cat.NodeUnhealthyDiagnosticTitle())
	}

	// 4. Click "前往 Cloudflare 设置" button to switch to TabCloudflare
	if err := tt.Click(cat.ActionGoToCloudflare()); err != nil {
		t.Fatalf("failed to click '%s': %v", cat.ActionGoToCloudflare(), err)
	}
	tt.Frame()
	if a.activeTab != TabCloudflare {
		t.Errorf("expected activeTab to switch to TabCloudflare, got %v", a.activeTab)
	}
}

func TestNodeDrawer_UnhealthyReflected(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)
	a.warpRegistering = true
	a.setCnDirectWarpEnabled(true)
	tt.Frame()

	var warpSvc *config.Service
	for i := range a.state.Services {
		if a.state.Services[i].IsBuiltinWarp() {
			warpSvc = &a.state.Services[i]
			break
		}
	}
	if warpSvc == nil {
		t.Fatalf("expected builtin-warp in services")
	}

	// Set status to unhealthy
	stUnhealthy := runner.Status{
		State:      runner.StateRunning,
		ProbeError: "warp server (162.159.198.2:443) connection failed: connection refused",
	}
	a.mgr.SetStatusForTest(warpSvc.ID, stUnhealthy)

	// Open node drawer
	a.activeNodeDrawerID = warpSvc.ID
	tt.Frame()

	cat := a.catalog()
	if _, ok := tt.Find(cat.NodeDrawerTitle()); !ok {
		t.Fatalf("expected node drawer to be open")
	}

	// Should show StatusUnhealthy in drawer
	if _, ok := tt.Find(cat.StatusUnhealthy()); !ok {
		t.Errorf("expected drawer to display StatusUnhealthy")
	}
	// Should show diagnostic banner in drawer
	if _, ok := tt.Find(cat.NodeUnhealthyDiagnosticTitle()); !ok {
		t.Errorf("expected drawer to display diagnostic banner")
	}
}

func TestDownloadSpeedFailure_TriggersUnhealthy(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)
	svc := config.Service{
		ID:       "test-vless-node",
		Name:     "Test VLESS",
		Protocol: config.ProtoVLESS,
	}
	a.state.Services = append(a.state.Services, svc)
	a.saveState()
	tt.Frame()

	// Download test error causes unhealthy status
	stSpeedErr := runner.Status{
		State:      runner.StateRunning,
		SpeedError: "download test failed: context deadline exceeded",
	}
	a.mgr.SetStatusForTest(svc.ID, stSpeedErr)

	if !a.isNodeUnhealthy(svc, stSpeedErr) {
		t.Errorf("expected service to be unhealthy when SpeedError is present")
	}

	tt.Frame()
	cat := a.catalog()
	if _, ok := tt.Find(cat.StatusUnhealthy()); !ok {
		t.Errorf("expected StatusUnhealthy badge on card for speed test failure")
	}
}

func TestCloudflarePage_AttachedNodesHealth(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)
	a.warpRegistering = true
	a.setCnDirectWarpEnabled(true)
	tt.Frame()

	var warpSvc *config.Service
	for i := range a.state.Services {
		if a.state.Services[i].IsBuiltinWarp() {
			warpSvc = &a.state.Services[i]
			break
		}
	}
	if warpSvc == nil {
		t.Fatalf("expected builtin-warp in services")
	}

	// Mark WARP node unhealthy
	stUnhealthy := runner.Status{
		State:      runner.StateRunning,
		ProbeError: "warp server (162.159.198.2:443) connection failed: timeout",
	}
	a.mgr.SetStatusForTest(warpSvc.ID, stUnhealthy)

	// Switch to Cloudflare tab
	a.activeTab = TabCloudflare
	tt.Frame()

	cat := a.catalog()
	if _, ok := tt.Find(cat.CloudflareWarpAttachedNodes()); !ok {
		t.Fatalf("expected attached nodes card on Cloudflare tab")
	}
	if _, ok := tt.Find(cat.StatusUnhealthy()); !ok {
		t.Errorf("expected StatusUnhealthy badge in attached nodes list")
	}
}

// Regression: a Naive sidecar with auto loopback (:0) and EnableWARP must:
// 1. Not prevent the gateway from building while stopped.
// 2. Be rejected by PreStartChecker if GatewayEnabled is false.
// 3. Dynamically sync its allocated port into sing-box outbounds (node-<id> + raw-node-<id>) when started.
func TestNaiveWarp_DynamicPortSyncAndPreStartCheck(t *testing.T) {
	naiveSvc := config.Service{
		ID:         "naive-warp-01",
		Name:       "Naive + WARP",
		Protocol:   config.ProtoNaive,
		Engine:     config.EngineSidecar,
		Listens:    []string{"socks://127.0.0.1:0"},
		Proxies:    []string{"https://user:pass@example.com:443"},
		EnableWARP: true,
	}

	a, tt, _ := newTestApp(t, []config.Service{naiveSvc})
	a.state.GatewayPort = freeLocalPort(t)
	a.state.GatewayEnabled = false
	a.saveState()
	tt.Frame()

	// 1. With GatewayEnabled == false, starting an EnableWARP sidecar must fail PreStartChecker
	if err := a.mgr.Start(naiveSvc); err == nil {
		t.Fatalf("expected Start to fail when GatewayEnabled is false for EnableWARP sidecar")
	}

	// 2. Enable gateway and start gateway BEFORE starting the :0 sidecar — must succeed
	a.state.GatewayEnabled = true
	a.saveState()
	if err := a.startGateway(); err != nil {
		t.Fatalf("startGateway with stopped :0 sidecar failed: %v", err)
	}
	if a.getGateway() == nil {
		t.Fatalf("expected gateway to be running")
	}

	// 3. Start the Naive sidecar -> allocates dynamic port -> sync gateway -> node outbound ready
	if err := a.mgr.Start(naiveSvc); err != nil {
		t.Fatalf("mgr.Start failed: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a.mgr.StatusOf(naiveSvc.ID).State == runner.StateRunning {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	allocPort := a.mgr.AllocatedPorts()[naiveSvc.ID]
	if allocPort <= 0 {
		t.Fatalf("expected non-zero allocated port for started naive sidecar, got %d", allocPort)
	}

	if err := a.ensureGatewaySynced(); err != nil {
		t.Fatalf("ensureGatewaySynced failed: %v", err)
	}
	gw := a.getGateway()
	if gw == nil {
		t.Fatalf("expected gateway after ensureGatewaySynced")
	}
	if _, ok := gw.GetOutbound("raw-node-" + naiveSvc.ID); !ok {
		t.Errorf("expected raw-node-%s outbound in gateway after sidecar start", naiveSvc.ID)
	}
	if _, ok := gw.GetOutbound("node-" + naiveSvc.ID); !ok {
		t.Errorf("expected node-%s masque outbound in gateway after sidecar start", naiveSvc.ID)
	}
}

// Regression: for WARP-enabled nodes (direct WARP and chained proxy+WARP),
// transient probe/speed-test request failures (e.g. packet loss or target timeout)
// must NOT mark the node as unhealthy unless the WARP tunnel itself failed or
// consecutive failures tripped the circuit breaker.
func TestWARPNode_TransientProbeFailureStaysHealthy(t *testing.T) {
	chainedSvc := config.Service{
		ID:         "vless-warp-health",
		Name:       "VLESS + WARP",
		Protocol:   config.ProtoVLESS,
		EnableWARP: true,
	}
	directWarp := config.Service{
		ID:       config.BuiltinWarpServiceID,
		Name:     "Cloudflare WARP",
		Protocol: config.ProtoWARP,
	}

	a, tt, _ := newTestApp(t, []config.Service{chainedSvc, directWarp})
	a.warpRegistering = true
	a.setCnDirectWarpEnabled(true)
	tt.Frame()

	// 1. Single probe timeout on target URL -> must stay healthy
	stTransientProbe := runner.Status{
		State:      runner.StateRunning,
		ProbeError: "Get \"https://www.gstatic.com/generate_204\": context deadline exceeded",
	}
	a.mgr.SetStatusForTest(chainedSvc.ID, stTransientProbe)
	if a.isNodeUnhealthy(chainedSvc, stTransientProbe) {
		t.Errorf("expected chained WARP node to remain healthy on transient probe timeout")
	}
	a.mgr.SetStatusForTest(directWarp.ID, stTransientProbe)
	if a.isNodeUnhealthy(directWarp, stTransientProbe) {
		t.Errorf("expected direct WARP node to remain healthy on transient probe timeout")
	}

	// 2. Single download speed test timeout -> must stay healthy for WARP nodes
	stTransientSpeed := runner.Status{
		State:      runner.StateRunning,
		SpeedError: "download test failed: unexpected EOF",
	}
	if a.isNodeUnhealthy(chainedSvc, stTransientSpeed) {
		t.Errorf("expected chained WARP node to remain healthy on transient speed test failure")
	}

	// 3. WARP tunnel / registration failure -> must be marked unhealthy
	stWarpErr := runner.Status{
		State:      runner.StateRunning,
		ProbeError: "warp server (162.159.198.2:443) connection failed: i/o timeout",
	}
	if !a.isNodeUnhealthy(chainedSvc, stWarpErr) {
		t.Errorf("expected chained WARP node to be unhealthy on WARP server tunnel error")
	}
	if !a.isNodeUnhealthy(directWarp, stWarpErr) {
		t.Errorf("expected direct WARP node to be unhealthy on WARP server tunnel error")
	}

	// 4. Circuit breaker tripped on node itself -> must be marked unhealthy
	a.tracker.RecordProbeFailure(chainedSvc.ID)
	a.tracker.RecordProbeFailure(chainedSvc.ID)
	a.tracker.RecordProbeFailure(chainedSvc.ID)
	if !a.isNodeUnhealthy(chainedSvc, stTransientProbe) {
		t.Errorf("expected chained WARP node to be unhealthy when circuit breaker is tripped")
	}
}

func TestCloudflareWarpTransport_ModeSelectionUpdatesState(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)
	a.activeTab = TabCloudflare
	tt.Frame()

	cat := a.catalog()
	if err := tt.Click(cat.CloudflareWarpTransportMasque()); err != nil {
		t.Fatalf("click MASQUE mode: %v", err)
	}
	tt.Frame()
	if a.state.Cloudflare.DefaultMode != warp.ModeMASQUE {
		t.Fatalf("expected DefaultMode = %q, got %q", warp.ModeMASQUE, a.state.Cloudflare.DefaultMode)
	}

	if err := tt.Click(cat.CloudflareWarpTransportWireGuard()); err != nil {
		t.Fatalf("click WireGuard mode: %v", err)
	}
	tt.Frame()
	if a.state.Cloudflare.DefaultMode != warp.ModeWireGuard {
		t.Fatalf("expected DefaultMode = %q, got %q", warp.ModeWireGuard, a.state.Cloudflare.DefaultMode)
	}
}

func TestCloudflareWarpPreferH2_ToggleAndNodeEditorAndSignature(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)
	a.activeTab = TabCloudflare
	tt.Frame()

	sigBefore := a.gatewayConfigSignature()
	cat := a.catalog()

	// Toggle Prefer H2 on Cloudflare page
	if err := tt.Click(cat.CloudflareWarpPreferH2()); err != nil {
		t.Fatalf("click CloudflareWarpPreferH2: %v", err)
	}
	tt.Frame()
	if !a.state.Cloudflare.MasquePreferH2 {
		t.Fatalf("expected Cloudflare.MasquePreferH2 to become true")
	}
	sigAfter := a.gatewayConfigSignature()
	if sigBefore == sigAfter {
		t.Fatalf("expected gatewayConfigSignature to change when MasquePreferH2 is toggled")
	}

	// Node editor inherits global MasquePreferH2 for new WARP nodes and persists per-node setting
	a.openCreateServiceDialog()
	tt.Frame()
	for i, p := range editorProtocols {
		if p == config.ProtoWARP {
			a.editor.protoIndex = i
			break
		}
	}
	a.editor.name = "WARP H2 First"
	svc, err := a.buildServiceFromEditor()
	if err != nil {
		t.Fatalf("buildServiceFromEditor failed: %v", err)
	}
	if svc.WARPConfig == nil || svc.WARPConfig.MasquePreferH2 == nil || !*svc.WARPConfig.MasquePreferH2 {
		t.Fatalf("expected built WARP node to inherit MasquePreferH2=true, got %+v", svc.WARPConfig)
	}

	// Per-node toggle back to false overrides global setting and changes gatewayConfigSignature
	falseVal := false
	svc.WARPConfig.MasquePreferH2 = &falseVal
	a.state.Services = append(a.state.Services, svc)
	sigNodeFalse := a.gatewayConfigSignature()
	trueVal := true
	a.state.Services[len(a.state.Services)-1].WARPConfig.MasquePreferH2 = &trueVal
	sigNodeTrue := a.gatewayConfigSignature()
	if sigNodeFalse == sigNodeTrue {
		t.Fatalf("expected gatewayConfigSignature to distinguish per-node MasquePreferH2 false vs true")
	}

	// Regression: changing WARPConfig struct pointer with identical field values must not change signature
	// (otherwise syncBuiltinWarpService allocating a new WarpNodeConfig restarts the gateway and resets circuit breakers).
	copyVal := true
	a.state.Services[len(a.state.Services)-1].WARPConfig = &config.WarpNodeConfig{
		Transport:      svc.WARPConfig.Transport,
		MasquePreferH2: &copyVal,
	}
	sigCopy := a.gatewayConfigSignature()
	if sigNodeTrue != sigCopy {
		t.Fatalf("expected identical WARPConfig values under new pointer to keep gatewayConfigSignature stable")
	}
}

func TestCloudflareWarpEndpointScan_OneClickAndCandidateSwitchAndReset(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)
	a.activeTab = TabCloudflare

	// Install mock scanner returning deterministic Anycast candidates with loss rate
	a.warpEndpointScanner = func(ctx context.Context, opts warp.ScanOptions) ([]warp.EndpointCandidateResult, error) {
		return []warp.EndpointCandidateResult{
			{Endpoint: "162.159.198.5:443", Protocol: "h3", RTT: 14 * time.Millisecond, LossRate: 0},
			{Endpoint: "162.159.198.2:8443", Protocol: "h2", RTT: 28 * time.Millisecond, LossRate: 0.33},
		}, nil
	}

	tt.Frame()
	cat := a.catalog()

	// Scroll Cloudflare page so the Clean Endpoint & Scan section is inside the test viewport
	a.cloudflareScroll.Y = 350
	tt.Frame()

	// 1. Click One-Click Scan button
	if err := tt.Click(cat.CloudflareWarpScanBtn()); err != nil {
		t.Fatalf("click scan button: %v", err)
	}

	// Wait for background scan goroutine to dispatch UI update
	waitForUI(t, a, tt, 2*time.Second, func() bool {
		return !a.warpScanning && len(a.warpScanResults) == 2
	})
	if a.warpScanning {
		t.Fatalf("expected scan to finish")
	}
	if a.state.Cloudflare.CleanIP != "162.159.198.5" || a.state.Cloudflare.CleanPort != 443 {
		t.Fatalf("expected fastest endpoint 162.159.198.5:443 to be auto-filled, got %s:%d", a.state.Cloudflare.CleanIP, a.state.Cloudflare.CleanPort)
	}
	if a.warpCleanEndpointInput != "162.159.198.5:443" {
		t.Fatalf("expected input field updated to 162.159.198.5:443, got %q", a.warpCleanEndpointInput)
	}

	// 2. Click second candidate pill to switch CleanIP:CleanPort
	tt.Frame()
	secondLabel := "162.159.198.2:8443 (28ms · 33% loss · h2)"
	if err := tt.Click(secondLabel); err != nil {
		t.Fatalf("click candidate pill %q: %v", secondLabel, err)
	}
	tt.Frame()
	if a.state.Cloudflare.CleanIP != "162.159.198.2" || a.state.Cloudflare.CleanPort != 8443 {
		t.Fatalf("expected switched endpoint 162.159.198.2:8443, got %s:%d", a.state.Cloudflare.CleanIP, a.state.Cloudflare.CleanPort)
	}

	// 3. Click Reset Auto button to clear CleanIP/CleanPort back to automatic per-network selection
	if err := tt.Click(cat.CloudflareWarpResetAutoBtn()); err != nil {
		t.Fatalf("click reset auto button: %v", err)
	}
	tt.Frame()
	if a.state.Cloudflare.CleanIP != "" || a.state.Cloudflare.CleanPort != 0 {
		t.Fatalf("expected CleanIP/CleanPort cleared after reset, got %s:%d", a.state.Cloudflare.CleanIP, a.state.Cloudflare.CleanPort)
	}
}

func TestCollectNodeServerIPs_IncludesWARPAnycastCIDRs(t *testing.T) {
	a, _, _ := newTestApp(t, nil)
	ips := a.collectNodeServerIPs()
	wantCIDRs := []string{"162.159.192.0/24", "162.159.198.0/24", "188.114.96.0/22"}
	for _, want := range wantCIDRs {
		found := false
		for _, got := range ips {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %s in collectNodeServerIPs(), got %v", want, ips)
		}
	}
}

func TestCloudflarePage_ProgressiveDisclosureAndAttachedNodeDrawer(t *testing.T) {
	chainedSvc := config.Service{
		ID:         "vless-warp-drawer",
		Name:       "JP-VLESS-WARP",
		Protocol:   config.ProtoVLESS,
		Server:     "jp.example.com",
		ServerPort: 443,
		UUID:       "11111111-2222-3333-4444-555555555555",
		EnableWARP: true,
	}
	a, tt, _ := newTestApp(t, []config.Service{chainedSvc})
	a.activeTab = TabCloudflare
	tt.SetSize(960, 900)
	tt.Frame()

	cat := a.catalog()

	// 1. License form and Advanced settings are collapsed by default
	if _, ok := tt.Find(cat.CloudflareWarpLicenseBindBtn()); ok {
		t.Fatalf("expected license bind form to be collapsed initially")
	}
	if _, ok := tt.Find(cat.CloudflareWarpProbeURL()); ok {
		t.Fatalf("expected advanced probe URL input to be collapsed initially")
	}

	// 2. Toggle WARP+ License form open
	if err := tt.Click(cat.CloudflareWarpLicenseToggleBtn()); err != nil {
		t.Fatalf("click license toggle: %v", err)
	}
	tt.Frame()
	if !a.warpShowLicenseForm {
		t.Fatalf("expected warpShowLicenseForm to be true")
	}
	if _, ok := tt.Find(cat.CloudflareWarpLicenseBindBtn()); !ok {
		t.Fatalf("expected license bind button after expanding form")
	}
	// Collapse it again so below-the-fold layout stays reachable
	if err := tt.Click(cat.CloudflareWarpLicenseToggleBtn()); err != nil {
		t.Fatalf("collapse license toggle: %v", err)
	}
	tt.Frame()

	// 3. Chained default protocol switches summary dynamically
	if !tt.HasText(cat.CloudflareWarpTransportWireGuardSummary()) {
		t.Fatalf("expected WireGuard chained summary initially")
	}
	if err := tt.Click("MASQUE"); err != nil {
		t.Fatalf("click chained MASQUE segment: %v", err)
	}
	tt.Frame()
	if a.state.Cloudflare.ChainedMode != warp.ModeMASQUE {
		t.Fatalf("expected ChainedMode = %q, got %q", warp.ModeMASQUE, a.state.Cloudflare.ChainedMode)
	}
	if !tt.HasText(cat.CloudflareWarpTransportMasqueSummary()) {
		t.Fatalf("expected MASQUE chained summary after switching segment")
	}

	// 4. Scroll down to attached nodes and Advanced settings
	a.cloudflareScroll.Y = 450
	tt.Frame()

	// Click attached node row -> opens NodeDrawer for that service
	if err := tt.Click("JP-VLESS-WARP"); err != nil {
		t.Fatalf("click attached node row: %v", err)
	}
	tt.Frame()
	if a.activeNodeDrawerID != chainedSvc.ID {
		t.Fatalf("expected activeNodeDrawerID = %q, got %q", chainedSvc.ID, a.activeNodeDrawerID)
	}
	a.activeNodeDrawerID = ""
	tt.Frame()

	// 5. Expand Advanced Network Settings and verify ProbeURL persistence + reset
	if err := tt.Click(cat.CloudflareWarpAdvancedTitle()); err != nil {
		t.Fatalf("click advanced settings header: %v", err)
	}
	tt.Frame()
	if !a.warpShowAdvanced {
		t.Fatalf("expected warpShowAdvanced = true")
	}
	a.cloudflareScroll.Y = 550
	tt.Frame()

	probeRect, ok := tt.Find(cat.CloudflareWarpProbeURL())
	if !ok {
		t.Fatalf("expected probe URL label after expanding advanced settings")
	}
	// Click inside the TextInput directly below the Probe URL label
	tt.ClickAt(probeRect.X+60, probeRect.Y+probeRect.H+16)
	tt.Type("http://example.com/204")
	tt.Frame()
	if a.state.Cloudflare.ProbeURL != "http://example.com/204" {
		t.Fatalf("expected ProbeURL persisted, got %q", a.state.Cloudflare.ProbeURL)
	}
	if err := tt.Click(cat.CloudflareWarpResetDefaultBtn()); err != nil {
		t.Fatalf("click reset probe URL: %v", err)
	}
	tt.Frame()
	if a.state.Cloudflare.ProbeURL != "" {
		t.Fatalf("expected ProbeURL cleared after reset, got %q", a.state.Cloudflare.ProbeURL)
	}
}

func TestCloudflareTunnelView_GatewayHintPasteAndIdleBudget(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)
	a.activeTab = TabCloudflare
	a.cloudflareSubTab = 1
	a.state.GatewayEnabled = false
	a.saveState()
	tt.Frame()

	cat := a.catalog()

	// 1. Enable Tunnel while Gateway is off -> shows need-gateway banner
	if err := tt.Click(cat.CloudflareTunnelEnable()); err != nil {
		t.Fatalf("click tunnel enable: %v", err)
	}
	tt.Frame()
	if !a.state.Cloudflare.Tunnel.Enabled {
		t.Fatalf("expected Tunnel.Enabled = true")
	}
	if !tt.HasText(cat.CloudflareTunnelNeedGatewayHint()) {
		t.Fatalf("expected gateway dependency hint when GatewayEnabled is false")
	}

	// 2. Paste Tunnel Token from clipboard
	a.clipboardMem = "tok-paste-987654"
	if err := tt.Click(cat.CloudflareTunnelPasteToken()); err != nil {
		t.Fatalf("click paste tunnel token: %v", err)
	}
	tt.Frame()
	if a.state.Cloudflare.Tunnel.Token != "tok-paste-987654" {
		t.Fatalf("expected pasted token, got %q", a.state.Cloudflare.Tunnel.Token)
	}

	// 3. Toggle token visibility
	if err := tt.Click(cat.CloudflareTunnelShowToken()); err != nil {
		t.Fatalf("click show token: %v", err)
	}
	tt.Frame()
	if !a.tunnelTokenVisible {
		t.Fatalf("expected tunnelTokenVisible = true")
	}

	// 4. Verify idle frame budget on both Cloudflare subtabs
	tt.Advance(500 * time.Millisecond)
	tt.Frame()
	if tt.FramePending() {
		t.Fatalf("idle Cloudflare Tunnel view should not continuously request animation frames")
	}
	a.cloudflareSubTab = 0
	tt.Advance(500 * time.Millisecond)
	tt.Frame()
	if tt.FramePending() {
		t.Fatalf("idle Cloudflare WARP view should not continuously request animation frames")
	}
}

func TestCloudflare_PresetSplitMigrationAndSingleSourceToggle(t *testing.T) {
	a, tt, _ := newTestApp(t, nil)

	// 1. Simulate legacy state.json where preset-lan-direct had ActionWarp + DirectWarpEnabled=true and preset-cn-direct was absent.
	legacyState := PersistedState{
		Language:    "zh-Hans",
		GatewayPort: freeLocalPort(t),
		Cloudflare: warp.Config{
			DirectWarpEnabled: true,
		},
		RoutingRules: []routing.Rule{
			{
				ID:      "preset-block-ads",
				Name:    "广告拦截",
				Enabled: true,
				GeoSite: []string{"category-ads-all"},
				Action:  routing.RouteAction{Type: routing.ActionBlock},
			},
			{
				ID:           "preset-lan-direct",
				Name:         "直连",
				Enabled:      true,
				GeoSite:      []string{"cn"},
				GeoIP:        []string{"cn", "private"},
				IPCidr:       []string{"192.168.0.0/16"},
				DomainSuffix: []string{"local"},
				Action:       routing.RouteAction{Type: routing.ActionWarp},
			},
		},
	}
	rawLegacy, err := json.Marshal(legacyState)
	if err != nil {
		t.Fatalf("marshal legacyState: %v", err)
	}
	if err := os.WriteFile(a.stateFilePath(), rawLegacy, 0o600); err != nil {
		t.Fatalf("write legacy state: %v", err)
	}

	// Reload from disk to exercise loadState() migration
	a.warpRegistering = true
	a.loadState()
	tt.Frame()

	if a.state.Cloudflare.DirectWarpEnabled {
		t.Fatalf("expected legacy DirectWarpEnabled to be cleared after migration")
	}

	var lanRule, cnRule *routing.Rule
	for i := range a.state.RoutingRules {
		switch a.state.RoutingRules[i].ID {
		case "preset-lan-direct":
			lanRule = &a.state.RoutingRules[i]
		case "preset-cn-direct":
			cnRule = &a.state.RoutingRules[i]
		}
	}
	if lanRule == nil || cnRule == nil {
		t.Fatalf("expected both preset-lan-direct and preset-cn-direct after migration")
	}
	if lanRule.Action.Type != routing.ActionDirect {
		t.Fatalf("expected preset-lan-direct restored to ActionDirect, got %+v", lanRule.Action)
	}
	if len(lanRule.GeoSite) != 0 || len(lanRule.GeoIP) != 1 || lanRule.GeoIP[0] != "private" {
		t.Fatalf("expected preset-lan-direct split to LAN-only criteria, got GeoSite=%v GeoIP=%v", lanRule.GeoSite, lanRule.GeoIP)
	}
	if !cnRule.Action.TargetsNode(config.BuiltinWarpServiceID) {
		t.Fatalf("expected preset-cn-direct migrated to target builtin-warp, got %+v", cnRule.Action)
	}
	if !a.isCnDirectWarpEnabled() || !a.isBuiltinWarpNeeded() {
		t.Fatalf("expected isCnDirectWarpEnabled and isBuiltinWarpNeeded to reflect migrated preset-cn-direct")
	}

	// 2. Toggle Direct -> WARP switch on Cloudflare tab and verify preset-cn-direct updates directly.
	a.activeTab = TabCloudflare
	a.cloudflareSubTab = 0
	tt.Frame()
	if err := tt.Click("toggle-direct-warp-takeover"); err != nil {
		t.Fatalf("click toggle-direct-warp-takeover: %v", err)
	}
	tt.Frame()

	if a.isCnDirectWarpEnabled() || a.isBuiltinWarpNeeded() {
		t.Fatalf("expected Direct -> WARP toggle off to clear builtin-warp from preset-cn-direct")
	}
	for _, r := range a.state.RoutingRules {
		if r.ID == "preset-cn-direct" && r.Action.Type != routing.ActionDirect {
			t.Fatalf("expected preset-cn-direct to revert to ActionDirect, got %+v", r.Action)
		}
		if r.ID == "preset-lan-direct" && r.Action.Type != routing.ActionDirect {
			t.Fatalf("expected preset-lan-direct to remain ActionDirect, got %+v", r.Action)
		}
	}
}

// Regression test: auto-enrolling WARP credentials from a running gateway must
// persist the account without restarting the active gateway (which previously
// deadlocked headless mode on eng.Close() and interrupted live GUI dials).
func TestCloudflareAccountUpdate_DoesNotRestartOrDeadlockGateway(t *testing.T) {
	a, _, _ := newTestApp(t, nil)
	a.win = nil // Exercise headless synchronous dispatchUI path.
	a.setUIQueueEnabled(false)
	a.state.GatewayPort = freeLocalPort(t)
	a.state.GatewayEnabled = true
	if err := a.startGateway(); err != nil {
		t.Fatalf("startGateway failed: %v", err)
	}
	defer a.stopGateway()

	origGw := a.getGateway()
	if origGw == nil {
		t.Fatalf("expected running gateway")
	}

	updated := warp.Account{
		DeviceID:         "auto-wg-dev",
		WGPrivateKey:     "wg-priv-secret",
		MASQUEDeviceID:   "auto-masque-dev",
		MASQUEPrivateKey: "masque-priv-secret",
		Reserved:         []uint8{1, 2, 3},
	}
	a.handleGatewayCloudflareAccountUpdate(origGw, updated)

	if a.getGateway() != origGw {
		t.Fatalf("expected gateway instance to remain running without restart")
	}
	if a.state.Cloudflare.Account.DeviceID != "auto-wg-dev" || a.state.Cloudflare.Account.MASQUEDeviceID != "auto-masque-dev" {
		t.Fatalf("expected state Cloudflare account updated, got %+v", a.state.Cloudflare.Account)
	}

	// Subsequent saveState/ensureGatewaySynced must keep the same gateway alive.
	a.saveState()
	if err := a.ensureGatewaySynced(); err != nil {
		t.Fatalf("ensureGatewaySynced failed: %v", err)
	}
	if a.getGateway() != origGw {
		t.Fatalf("expected saveState + ensureGatewaySynced not to restart gateway")
	}

	// Verify secrets were written without dropping keys.
	var reloaded warp.Config
	a.readCloudflareSecrets(&reloaded)
	if reloaded.Account.WGPrivateKey != "wg-priv-secret" || reloaded.Account.MASQUEPrivateKey != "masque-priv-secret" {
		t.Fatalf("expected Cloudflare secrets persisted, got %+v", reloaded.Account)
	}

	// Stale persistence snapshots (older stateRev) must not overwrite newer credentials on disk.
	staleSnap := a.state
	staleSnap.Cloudflare.Account = warp.Account{DeviceID: "stale-dev", WGPrivateKey: "stale-priv"}
	a.persistStateFiles(staleSnap, 1)
	var afterStale warp.Config
	a.readCloudflareSecrets(&afterStale)
	if afterStale.Account.WGPrivateKey != "wg-priv-secret" {
		t.Fatalf("expected stale snapshot rev=1 not to overwrite newer secrets, got %+v", afterStale.Account)
	}

	// Concurrent MASQUE enrollment on cur must be preserved when WG registration finishes.
	merged := mergeRegisteredWarpAccount(
		warp.Account{MASQUEDeviceID: "live-masque-dev", MASQUEPrivateKey: "live-masque-priv"},
		warp.Account{},
		warp.Account{DeviceID: "new-wg-dev", WGPrivateKey: "new-wg-priv", MASQUEDeviceID: "reg-masque", MASQUEPrivateKey: "reg-priv"},
	)
	if merged.DeviceID != "new-wg-dev" || merged.MASQUEPrivateKey != "live-masque-priv" {
		t.Fatalf("expected merged account to keep live MASQUE key while updating WG, got %+v", merged)
	}

	// Concurrent account update + stopGateway must never ABBA-deadlock or race.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 10; i++ {
			a.handleGatewayCloudflareAccountUpdate(origGw, updated)
		}
	}()
	a.stopGateway()
	<-done
}

// Regression: enabling WARP on a Naive sidecar node previously inherited global ChainedMode
// (WireGuard) in the node editor, saving WARPConfig.Transport="wireguard" and rendering
// "➔ WARP · WG" on the node card even though boxengine always forces MASQUE over HTTP/2.
func TestNaiveWarp_EditorSavesMasqueH2AndNormalizesCardBadge(t *testing.T) {
	naiveSvc := config.Service{
		ID:       "naive-warp-ui-01",
		Name:     "Naive Sidecar",
		Protocol: config.ProtoNaive,
		Engine:   config.EngineSidecar,
		Listens:  []string{"socks://127.0.0.1:1080"},
		Proxies:  []string{"https://user:pass@example.com:443"},
	}
	a, tt, _ := newTestApp(t, []config.Service{naiveSvc})
	a.state.Cloudflare.ChainedMode = warp.ModeWireGuard
	a.saveState()

	// 1. Toggle EnableWARP in node editor -> must persist MASQUE + PreferH2=true, never WireGuard.
	tt.SetSize(960, 900)
	a.openEditServiceDialog(naiveSvc)
	tt.Frame()
	a.editor.scroll.Y = 400
	tt.Frame()
	if err := tt.Click(a.catalog().NodeEditorEnableWarp()); err != nil {
		t.Fatalf("toggle enable warp: %v", err)
	}
	tt.Frame()
	if !a.editor.enableWARP {
		t.Fatalf("expected editor.enableWARP to become true")
	}

	built, err := a.buildServiceFromEditor()
	if err != nil {
		t.Fatalf("buildServiceFromEditor failed: %v", err)
	}
	if built.WARPConfig == nil || built.WARPConfig.Transport != config.WarpTransportMasque {
		t.Fatalf("expected Naive+WARP to save WarpTransportMasque, got %+v", built.WARPConfig)
	}
	if built.WARPConfig.MasquePreferH2 == nil || !*built.WARPConfig.MasquePreferH2 {
		t.Fatalf("expected Naive+WARP to save MasquePreferH2=true, got %+v", built.WARPConfig)
	}

	// 2. Legacy persisted state with Transport="wireguard" on Naive+WARP must normalize on load
	// and render "➔ WARP · MASQUE H2" (not "WARP · WG") on the node card.
	a.editor.open = false
	legacy := naiveSvc
	legacy.EnableWARP = true
	legacy.WARPConfig = &config.WarpNodeConfig{Transport: config.WarpTransportWireGuard}
	a.state.Services = []config.Service{legacy}
	a.saveState()

	a.loadState()
	tt.Frame()

	reloaded := a.state.Services[0]
	if reloaded.WARPConfig == nil || reloaded.WARPConfig.Transport != config.WarpTransportMasque {
		t.Fatalf("expected loadState to normalize Naive+WARP transport to masque, got %+v", reloaded.WARPConfig)
	}
	if reloaded.WARPConfig.MasquePreferH2 == nil || !*reloaded.WARPConfig.MasquePreferH2 {
		t.Fatalf("expected loadState to normalize Naive+WARP MasquePreferH2=true, got %+v", reloaded.WARPConfig)
	}
	if !tt.HasText("➔ WARP · MASQUE H2") {
		t.Fatalf("expected node card to show '➔ WARP · MASQUE H2'")
	}
	if tt.HasText("WARP · WG") {
		t.Fatalf("node card must not show 'WARP · WG' for Naive sidecar node")
	}
}

// Regression: the Cloudflare page's Attached Nodes section previously rendered a generic
// "<PROTO> ➔ WARP" pill without the actual WARP transport protocol (and omitted the protocol
// badge for direct WARP nodes), diverging from the main node cards and drawer.
func TestCloudflarePage_AttachedNodesShowsActualWarpTransportBadges(t *testing.T) {
	naiveSvc := config.Service{
		ID:         "cf-naive-warp",
		Name:       "CF-Naive-WARP",
		Protocol:   config.ProtoNaive,
		Engine:     config.EngineSidecar,
		Listens:    []string{"socks://127.0.0.1:1080"},
		Proxies:    []string{"https://user:pass@example.com:443"},
		EnableWARP: true,
		WARPConfig: &config.WarpNodeConfig{Transport: config.WarpTransportWireGuard},
	}
	vlessSvc := config.Service{
		ID:         "cf-vless-warp",
		Name:       "CF-VLESS-WARP",
		Protocol:   config.ProtoVLESS,
		Server:     "vless.example.com",
		ServerPort: 443,
		UUID:       "11111111-1111-1111-1111-111111111111",
		EnableWARP: true,
	}
	directSvc := config.Service{
		ID:       "cf-direct-warp",
		Name:     "CF-Direct-WARP",
		Protocol: config.ProtoWARP,
	}

	a, tt, _ := newTestApp(t, []config.Service{naiveSvc, vlessSvc, directSvc})
	a.activeTab = TabCloudflare
	tt.SetSize(960, 900)
	tt.Frame()
	a.cloudflareScroll.Y = 450
	tt.Frame()

	if !tt.HasText("NAIVE · SIDECAR") || !tt.HasText("➔ WARP · MASQUE H2") {
		t.Fatalf("expected Naive+WARP row to show 'NAIVE · SIDECAR' and '➔ WARP · MASQUE H2'")
	}
	if !tt.HasText("VLESS · SING-BOX") || !tt.HasText("➔ WARP · WG") {
		t.Fatalf("expected VLESS+WARP row to show 'VLESS · SING-BOX' and '➔ WARP · WG'")
	}
	if !tt.HasText(a.catalog().CloudflareWarpDirectBadge()) || !tt.HasText("WARP · MASQUE") {
		t.Fatalf("expected direct WARP row to show direct badge and 'WARP · MASQUE'")
	}
}




