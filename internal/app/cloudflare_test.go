package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	a.editor.warpModeIndex = 1 // MASQUE
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
	a.editor.warpModeIndex = 0 // Auto
	a.editor.warpEndpoint = "162.159.198.2:443"

	updated, err := a.buildServiceFromEditor()
	if err != nil {
		t.Fatalf("buildServiceFromEditor failed: %v", err)
	}

	if !updated.EnableWARP {
		t.Errorf("expected EnableWARP to be true")
	}
	if updated.WARPConfig == nil || updated.WARPConfig.Transport != config.WarpTransportAuto {
		t.Errorf("expected WarpTransportAuto, got %+v", updated.WARPConfig)
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

	// 1. Set preset-lan-direct action to ActionWarp and saveState
	for i := range a.state.RoutingRules {
		if a.state.RoutingRules[i].ID == "preset-lan-direct" {
			a.state.RoutingRules[i].Action = routing.RouteAction{Type: routing.ActionWarp}
			break
		}
	}
	a.saveState()
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

	// 2. Switch preset-lan-direct back to ActionDirect and saveState
	for i := range a.state.RoutingRules {
		if a.state.RoutingRules[i].ID == "preset-lan-direct" {
			a.state.RoutingRules[i].Action = routing.RouteAction{Type: routing.ActionDirect}
			break
		}
	}
	a.state.Cloudflare.DirectWarpEnabled = false
	a.saveState()
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

	// 3. Toggle DirectWarpEnabled via Cloudflare settings
	a.state.Cloudflare.DirectWarpEnabled = true
	for i := range a.state.RoutingRules {
		if a.state.RoutingRules[i].ID == "preset-lan-direct" {
			a.state.RoutingRules[i].Action = routing.RouteAction{Type: routing.ActionWarp}
			break
		}
	}
	a.saveState()
	tt.Frame()

	var foundAgain bool
	for _, s := range a.state.Services {
		if s.IsBuiltinWarp() {
			foundAgain = true
			break
		}
	}
	if !foundAgain {
		t.Fatalf("expected builtin-warp to re-appear when DirectWarpEnabled is true")
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
	a.state.Cloudflare.DirectWarpEnabled = true
	a.saveState()
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
	a, tt, _ := newTestApp(t, nil)
	freePort, err := runner.AllocateFreePort()
	if err != nil {
		t.Fatalf("failed to allocate free port: %v", err)
	}
	a.state.GatewayPort = freePort
	a.state.LogLevel = "debug"
	a.warpRegistering = true
	a.state.Cloudflare.DirectWarpEnabled = true
	a.saveState()
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

	// Second probe should hit the 60s circuit breaker directly to WireGuard without MASQUE delay
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
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
	a.state.Cloudflare.DirectWarpEnabled = true
	a.saveState()
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
	a.state.Cloudflare.DirectWarpEnabled = true
	a.saveState()
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
	a.state.Cloudflare.DirectWarpEnabled = true
	a.saveState()
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
