package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"

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
