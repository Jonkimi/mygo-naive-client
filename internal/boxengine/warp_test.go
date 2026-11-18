package boxengine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"naive-client/internal/blocker"
	"naive-client/internal/config"
	"naive-client/internal/routing"
	"naive-client/internal/warp"

	"github.com/sagernet/sing-box/adapter"
	boxLog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
)

func TestBuildInboundsConfig_CloudflareTunnel(t *testing.T) {
	opts := EngineOptions{
		TrafficMode: "port",
		CloudflareConfig: &warp.Config{
			Tunnel: warp.TunnelConfig{
				Enabled:       true,
				Token:         "test-tunnel-token-12345",
				Protocol:      "quic",
				HAConnections: 4,
				PostQuantum:   true,
			},
		},
	}

	inbounds := buildInboundsConfig(opts, "127.0.0.1", 10809)
	var foundTunnel bool
	for _, in := range inbounds {
		if in["type"] == "cloudflared" && in["tag"] == "cloudflare-tunnel-in" {
			foundTunnel = true
			if in["token"] != "test-tunnel-token-12345" {
				t.Errorf("unexpected token: %v", in["token"])
			}
			if in["protocol"] != "quic" {
				t.Errorf("unexpected protocol: %v", in["protocol"])
			}
			if in["ha_connections"] != 4 {
				t.Errorf("unexpected ha_connections: %v", in["ha_connections"])
			}
			if in["post_quantum"] != true {
				t.Errorf("unexpected post_quantum: %v", in["post_quantum"])
			}
		}
	}
	if !foundTunnel {
		t.Errorf("expected cloudflared inbound in generated inbounds")
	}
}

func TestBuildOutboundsConfig_StandaloneWARP_MASQUE(t *testing.T) {
	svc := config.Service{
		ID:       "warp-direct",
		Name:     "Cloudflare WARP Direct",
		Protocol: config.ProtoWARP,
		WARPConfig: &config.WarpNodeConfig{
			Transport: config.WarpTransportMasque,
			Endpoint:  "162.159.198.2:443",
		},
	}
	opts := EngineOptions{
		Services: []config.Service{svc},
	}

	outbounds, err := buildOutboundsConfig(opts, "PROXY_POOL", nil)
	if err != nil {
		t.Fatalf("buildOutboundsConfig failed: %v", err)
	}

	var foundMasque bool
	for _, ob := range outbounds {
		if ob["tag"] == "node-warp-direct" {
			foundMasque = true
			if ob["type"] != "masque" {
				t.Errorf("expected type masque, got %v", ob["type"])
			}
			if ob["detour"] != nil {
				t.Errorf("expected no detour for standalone node, got %v", ob["detour"])
			}
		}
	}
	if !foundMasque {
		t.Errorf("expected node-warp-direct outbound")
	}
}

func TestBuildOutboundsConfig_MASQUEPreferH2(t *testing.T) {
	globalOn := &warp.Config{
		DefaultMode:    warp.ModeAuto,
		MasquePreferH2: true,
	}
	boolFalse := false
	svcInherit := config.Service{
		ID:       "warp-inherit",
		Name:     "Inherit Global",
		Protocol: config.ProtoWARP,
	}
	svcOverrideOff := config.Service{
		ID:       "warp-override-off",
		Name:     "Override Off",
		Protocol: config.ProtoWARP,
		WARPConfig: &config.WarpNodeConfig{
			Transport:      config.WarpTransportMasque,
			MasquePreferH2: &boolFalse,
		},
	}
	naiveSvc := config.Service{
		ID:         "naive-warp",
		Name:       "Naive + WARP",
		Protocol:   config.ProtoNaive,
		Listens:    []string{"socks://127.0.0.1:1080"},
		Proxies:    []string{"https://user:pass@naive.example.com"},
		EnableWARP: true,
	}

	outbounds, err := buildOutboundsConfig(EngineOptions{
		Services:         []config.Service{svcInherit, svcOverrideOff, naiveSvc},
		AllocatedPorts:   map[string]int{"naive-warp": 1080},
		CloudflareConfig: globalOn,
	}, "PROXY_POOL", map[string]int{"naive-warp": 1080})
	if err != nil {
		t.Fatalf("buildOutboundsConfig failed: %v", err)
	}

	byTag := make(map[string]map[string]any)
	for _, ob := range outbounds {
		if tag, ok := ob["tag"].(string); ok {
			byTag[tag] = ob
		}
	}

	if byTag["node-warp-inherit"]["prefer_h2"] != true {
		t.Fatalf("expected inherited prefer_h2=true, got %+v", byTag["node-warp-inherit"])
	}
	if _, has := byTag["node-warp-override-off"]["prefer_h2"]; has {
		t.Fatalf("expected explicit false override to omit prefer_h2, got %+v", byTag["node-warp-override-off"])
	}
	if _, has := byTag["node-naive-warp"]["prefer_h2"]; has || byTag["node-naive-warp"]["tcp_only_detour"] != true {
		t.Fatalf("expected tcp_only_detour without prefer_h2 on naive node, got %+v", byTag["node-naive-warp"])
	}
}

func TestBuildOutboundsAndEndpoints_StandaloneWARP_WireGuard(t *testing.T) {
	svc := config.Service{
		ID:       "warp-wg",
		Name:     "Cloudflare WARP WG",
		Protocol: config.ProtoWARP,
		WARPConfig: &config.WarpNodeConfig{
			Transport:   config.WarpTransportWireGuard,
			Endpoint:    "162.159.192.1:2408",
			PrivateKey:  "dGVzdC1wcml2YXRlLWtleS0xMjM0NQ==",
			AddressIPv4: "172.16.0.2/32",
			AddressIPv6: "2606:4700:110:8a36::2/128",
			Reserved:    []uint8{1, 2, 3},
		},
	}
	opts := EngineOptions{
		Services: []config.Service{svc},
	}

	endpoints := buildEndpointsConfig(opts)
	var foundWG bool
	for _, ep := range endpoints {
		if ep["tag"] == "node-warp-wg" {
			foundWG = true
			if ep["type"] != "wireguard" {
				t.Errorf("expected type wireguard, got %v", ep["type"])
			}
			if ep["detour"] != nil {
				t.Errorf("expected no detour, got %v", ep["detour"])
			}
			peers, _ := ep["peers"].([]map[string]any)
			if len(peers) == 0 || peers[0]["address"] != "162.159.192.1" {
				t.Errorf("unexpected peers: %v", peers)
			}
		}
	}
	if !foundWG {
		t.Errorf("expected node-warp-wg endpoint")
	}
}

func TestBuildOutboundsConfig_ChainedProxy_EnableWARP(t *testing.T) {
	vlessSvc := config.Service{
		ID:         "vless-node",
		Name:       "My VLESS Server",
		Protocol:   config.ProtoVLESS,
		Server:     "vless.example.com",
		ServerPort: 443,
		UUID:       "12345678-1234-1234-1234-123456789abc",
		EnableWARP: true,
	}

	naiveSvc := config.Service{
		ID:         "naive-node",
		Name:       "My Naive Node",
		Protocol:   config.ProtoNaive,
		Listens:    []string{"socks://127.0.0.1:1080"},
		Proxies:    []string{"https://user:pass@naive.example.com"},
		EnableWARP: true,
	}

	opts := EngineOptions{
		Services: []config.Service{vlessSvc, naiveSvc},
		AllocatedPorts: map[string]int{
			"naive-node": 1080,
		},
		CloudflareConfig: &warp.Config{
			DefaultMode: warp.ModeMASQUE,
			ChainedMode: warp.ModeWireGuard,
		},
	}

	outbounds, err := buildOutboundsConfig(opts, "PROXY_POOL", opts.AllocatedPorts)
	if err != nil {
		t.Fatalf("buildOutboundsConfig failed: %v", err)
	}

	outboundByTag := make(map[string]map[string]any)
	for _, ob := range outbounds {
		if tag, ok := ob["tag"].(string); ok {
			outboundByTag[tag] = ob
		}
	}

	// Verify VLESS chaining: raw-node-vless-node -> node-vless-node (defaults to WireGuard via warp-wg-auto)
	rawVless, ok := outboundByTag["raw-node-vless-node"]
	if !ok || rawVless["type"] != "vless" {
		t.Errorf("expected raw-node-vless-node of type vless, got %+v", rawVless)
	}

	warpVless, ok := outboundByTag["node-vless-node"]
	if !ok || warpVless["type"] != "warp-wg-auto" || warpVless["detour"] != "raw-node-vless-node" {
		t.Errorf("expected node-vless-node to default to warp-wg-auto detouring to raw-node-vless-node, got %+v", warpVless)
	}

	// Verify Naive Sidecar chaining: raw-node-naive-node -> node-naive-node with MASQUE tcp_only_detour: true
	rawNaive, ok := outboundByTag["raw-node-naive-node"]
	if !ok || rawNaive["type"] != "socks" {
		t.Errorf("expected raw-node-naive-node of type socks, got %+v", rawNaive)
	}

	warpNaive, ok := outboundByTag["node-naive-node"]
	if !ok || warpNaive["type"] != "masque" || warpNaive["detour"] != "raw-node-naive-node" {
		t.Errorf("expected node-naive-node detouring to raw-node-naive-node via masque, got %+v", warpNaive)
	}
	if warpNaive["tcp_only_detour"] != true {
		t.Errorf("expected tcp_only_detour: true for Naive TCP sidecar node, got %+v", warpNaive["tcp_only_detour"])
	}
}

func TestBuildRouteConfig_SplitPresetsWarpAndLANDirectProtection(t *testing.T) {
	ruleLan := routing.Rule{
		ID:           "preset-lan-direct",
		Name:         "局域网直连",
		Enabled:      true,
		GeoIP:        []string{"private"},
		IPCidr:       []string{"192.168.1.0/24"},
		DomainSuffix: []string{"local", "lan"},
		Action:       routing.RouteAction{Type: routing.ActionDirect},
	}
	ruleCnWarp := routing.Rule{
		ID:      "preset-cn-direct",
		Name:    "大陆直连",
		Enabled: true,
		GeoSite: []string{"cn"},
		GeoIP:   []string{"cn"},
		IPCidr:  []string{"114.114.114.114/32"},
		Action:  routing.NewWarpTargetAction(),
	}

	opts := EngineOptions{
		Rules:      []routing.Rule{ruleLan, ruleCnWarp},
		FinalRoute: routing.NewWarpTargetAction(),
	}

	// 1. Check resolveRouteOutbound & resolveFinalOutbound route builtin-warp through PoolOutbound
	wantWarpPool := resolveRouteOutbound(routing.NewWarpTargetAction(), "")
	if !strings.HasPrefix(wantWarpPool, "POOL:") {
		t.Fatalf("expected PoolOutbound tag for builtin-warp, got %s", wantWarpPool)
	}
	if legacyWarpPool := resolveRouteOutbound(routing.RouteAction{Type: routing.ActionWarp}, ""); legacyWarpPool != wantWarpPool {
		t.Errorf("expected legacy ActionWarp to normalize to %s, got %s", wantWarpPool, legacyWarpPool)
	}
	finalOutbound := resolveFinalOutbound(opts)
	if finalOutbound != wantWarpPool {
		t.Errorf("expected %s for final outbound, got %s", wantWarpPool, finalOutbound)
	}

	// 2. Check route config
	routeMap := buildRouteConfig(opts, finalOutbound, nil)
	rules, ok := routeMap["rules"].([]map[string]any)
	if !ok || len(rules) == 0 {
		t.Fatalf("expected generated sing-box rules, got %v", routeMap["rules"])
	}

	// Ensure Rule 0.25 (RFC1918 CIDRs) and preset-lan-direct route to direct
	var foundLANDirect bool
	for _, r := range rules {
		if r["outbound"] == "direct" {
			if cidrs, ok := r["ip_cidr"].([]string); ok {
				for _, c := range cidrs {
					if c == "192.168.0.0/16" || c == "10.0.0.0/8" {
						foundLANDirect = true
						break
					}
				}
			}
		}
	}
	if !foundLANDirect {
		t.Errorf("expected RFC1918 LAN direct protection rule in sing-box route config")
	}

	// Ensure preset-cn-direct routes to builtin-warp PoolOutbound
	var foundWarpRuleSet bool
	var foundWarpCIDR bool
	for _, r := range rules {
		if r["outbound"] == wantWarpPool {
			if _, ok := r["rule_set"].([]string); ok {
				foundWarpRuleSet = true
			}
			if _, ok := r["ip_cidr"].([]string); ok {
				foundWarpCIDR = true
			}
		}
	}
	if !foundWarpRuleSet || !foundWarpCIDR {
		t.Errorf("expected builtin-warp PoolOutbound rules in route config (ruleSet=%v, cidr=%v)", foundWarpRuleSet, foundWarpCIDR)
	}

	// 3. Check DNS config:
	// - preset-cn-direct targeting builtin-warp is a domestic rule -> domestic-doh
	// - FinalRoute targeting builtin-warp -> remote-doh detours via wantWarpPool (WARP-only setup)
	dnsMap := buildDNSConfig(opts, finalOutbound, nil)
	if dnsMap["final"] != "remote-doh" {
		t.Errorf("expected dns final remote-doh when FinalRoute targets builtin-warp, got %v", dnsMap["final"])
	}
	servers := dnsMap["servers"].([]map[string]any)
	var remoteDetour any
	for _, s := range servers {
		if s["tag"] == "remote-doh" {
			remoteDetour = s["detour"]
		}
	}
	if remoteDetour != wantWarpPool {
		t.Errorf("expected remote-doh detour %s in WARP-only setup, got %v", wantWarpPool, remoteDetour)
	}
	dnsRules, ok := dnsMap["rules"].([]map[string]any)
	if !ok {
		t.Fatalf("expected dns rules, got %v", dnsMap["rules"])
	}
	var foundDomesticRule bool
	for _, dr := range dnsRules {
		if dr["server"] == "domestic-doh" {
			if rsets, ok := dr["rule_set"].([]string); ok {
				for _, rs := range rsets {
					if rs == "geosite-cn" {
						foundDomesticRule = true
					}
				}
			}
		}
	}
	if !foundDomesticRule {
		t.Errorf("expected preset-cn-direct targeting builtin-warp to route geosite-cn DNS lookups to domestic-doh")
	}
}

func TestBuildOutboundsConfig_StandardProxy_NoWARP(t *testing.T) {
	vlessSvc := config.Service{
		ID:         "vless-plain",
		Name:       "Plain VLESS",
		Protocol:   config.ProtoVLESS,
		Server:     "plain.example.com",
		ServerPort: 443,
		UUID:       "11111111-2222-3333-4444-555555555555",
		EnableWARP: false,
	}

	builtinWarp := config.Service{
		ID:        config.BuiltinWarpServiceID,
		Name:      "Cloudflare WARP",
		Protocol:  config.ProtoWARP,
		Engine:    config.EngineSingBox,
		AutoStart: true,
	}

	opts := EngineOptions{
		Services: []config.Service{vlessSvc, builtinWarp},
		CloudflareConfig: &warp.Config{
			DefaultMode: warp.ModeAuto,
		},
	}

	outbounds, err := buildOutboundsConfig(opts, "PROXY_POOL", nil)
	if err != nil {
		t.Fatalf("buildOutboundsConfig failed: %v", err)
	}

	outboundByTag := make(map[string]map[string]any)
	for _, ob := range outbounds {
		if tag, ok := ob["tag"].(string); ok {
			outboundByTag[tag] = ob
		}
	}

	// 1. Plain VLESS must have tag "node-vless-plain", type "vless", and NO detour
	ob, ok := outboundByTag["node-vless-plain"]
	if !ok {
		t.Fatalf("expected node-vless-plain in outbounds, got tags: %v", outboundByTag)
	}
	if ob["type"] != "vless" {
		t.Errorf("expected type vless, got %v", ob["type"])
	}
	if detour, hasDetour := ob["detour"]; hasDetour && detour != "" {
		t.Errorf("expected no detour on plain proxy node, got %v", detour)
	}

	// 2. Must NOT create raw-node-vless-plain
	if _, hasRaw := outboundByTag["raw-node-vless-plain"]; hasRaw {
		t.Errorf("expected no raw-node-vless-plain when EnableWARP is false")
	}

	// 3. Endpoints must NOT contain vless-plain
	endpoints := buildEndpointsConfig(opts)
	for _, ep := range endpoints {
		if ep["tag"] == "node-vless-plain" || ep["tag"] == "wg-node-vless-plain" {
			t.Errorf("plain proxy node must not be in endpoints, found: %+v", ep)
		}
	}
}

// Regression: an unstarted sidecar node with auto loopback listen (socks://127.0.0.1:0)
// must not fail buildOutboundsConfig; once started with an allocated port, both raw-node
// and chained masque node must be built with tcp_only_detour: true.
func TestBuildOutboundsConfig_StoppedAutoZeroSidecar_EnableWARP(t *testing.T) {
	naiveSvc := config.Service{
		ID:         "naive-auto",
		Name:       "Naive Auto",
		Protocol:   config.ProtoNaive,
		Engine:     config.EngineSidecar,
		Listens:    []string{"socks://127.0.0.1:0"},
		Proxies:    []string{"https://user:pass@naive.example.com"},
		EnableWARP: true,
	}

	// 1. Before starting (no allocated port): must succeed and skip naive-auto
	optsStopped := EngineOptions{
		Services: []config.Service{naiveSvc},
	}
	outboundsStopped, err := buildOutboundsConfig(optsStopped, "PROXY_POOL", nil)
	if err != nil {
		t.Fatalf("expected stopped :0 sidecar not to fail buildOutboundsConfig, got: %v", err)
	}
	for _, ob := range outboundsStopped {
		if ob["tag"] == "node-naive-auto" || ob["tag"] == "raw-node-naive-auto" {
			t.Fatalf("expected unstarted :0 sidecar outbound to be skipped, found %+v", ob)
		}
	}

	// 2. After starting with an allocated port: raw-node-naive-auto + node-naive-auto (masque H2)
	optsRunning := EngineOptions{
		Services:       []config.Service{naiveSvc},
		AllocatedPorts: map[string]int{"naive-auto": 15432},
	}
	outboundsRunning, err := buildOutboundsConfig(optsRunning, "PROXY_POOL", optsRunning.AllocatedPorts)
	if err != nil {
		t.Fatalf("buildOutboundsConfig with allocated port failed: %v", err)
	}
	byTag := make(map[string]map[string]any)
	for _, ob := range outboundsRunning {
		if tag, ok := ob["tag"].(string); ok {
			byTag[tag] = ob
		}
	}
	if raw, ok := byTag["raw-node-naive-auto"]; !ok || raw["server_port"] != 15432 {
		t.Fatalf("expected raw-node-naive-auto on port 15432, got %+v", raw)
	}
	if mq, ok := byTag["node-naive-auto"]; !ok || mq["type"] != "masque" || mq["detour"] != "raw-node-naive-auto" || mq["tcp_only_detour"] != true {
		t.Fatalf("expected masque outbound with tcp_only_detour=true, got %+v", mq)
	}
}

// Regression: chained proxy nodes with EnableWARP must append " -> WARP" in Insights gateway chains,
// while plain proxy nodes keep "... -> nodeName" and builtin-warp stays "... -> Cloudflare WARP".
func TestInsightsChain_ChainedProxyWarpSuffix(t *testing.T) {
	services := []config.Service{
		{
			ID:         "svc-warp-proxy",
			Name:       "HK-Proxy",
			Protocol:   config.ProtoVLESS,
			Server:     "hk.example.com",
			ServerPort: 443,
			UUID:       "11111111-2222-3333-4444-555555555555",
			EnableWARP: true,
		},
		{
			ID:         "svc-plain-proxy",
			Name:       "US-Plain",
			Protocol:   config.ProtoVLESS,
			Server:     "us.example.com",
			ServerPort: 443,
			UUID:       "11111111-2222-3333-4444-555555555556",
			EnableWARP: false,
		},
		{
			ID:       config.BuiltinWarpServiceID,
			Name:     "Cloudflare WARP",
			Protocol: config.ProtoWARP,
		},
	}

	eng := &Engine{
		services:  services,
		activeIDs: map[string]bool{"svc-warp-proxy": true},
	}
	bl := blocker.NewEngine(blocker.Options{})
	bl.Logger().SetDedupWindow(0)

	tracker := &BlockerConnectionTracker{
		blocker:            bl,
		nodeNameResolver:   eng.GetNodeName,
		chainedWarpChecker: eng.IsChainedWarp,
	}

	// 1. Pool outbound selecting chained WARP proxy node
	poolOb := NewPoolOutbound(PoolOutboundOptions{
		Tag:          "PROXY_POOL",
		NodeProvider: eng,
	})
	tracker.recordConnection("api.ipify.org", nil, poolOb)

	// 2. Direct-node outbound targeting chained WARP proxy node
	tracker.recordConnection("example.com", nil, &mockOutbound{tag: "node-svc-warp-proxy"})

	// 3. Plain proxy node without EnableWARP
	tracker.recordConnection("example.org", nil, &mockOutbound{tag: "node-svc-plain-proxy"})

	// 4. Builtin direct WARP node (should NOT double-append "-> WARP")
	tracker.recordConnection("cloudflare.com", nil, &mockOutbound{tag: "node-" + config.BuiltinWarpServiceID})

	entries := bl.Logger().GetEntries(10)
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(entries))
	}
	byDomain := make(map[string]string)
	for _, e := range entries {
		byDomain[e.Domain] = e.Chain
	}
	if got := byDomain["api.ipify.org"]; got != "final -> PROXY_POOL -> HK-Proxy -> WARP" {
		t.Errorf("unexpected pool chained WARP chain: %q", got)
	}
	if got := byDomain["example.com"]; got != "final -> HK-Proxy -> WARP" {
		t.Errorf("unexpected single-node chained WARP chain: %q", got)
	}
	if got := byDomain["example.org"]; got != "final -> US-Plain" {
		t.Errorf("unexpected plain proxy chain: %q", got)
	}
	if got := byDomain["cloudflare.com"]; got != "final -> Cloudflare WARP" {
		t.Errorf("unexpected builtin WARP chain: %q", got)
	}
}

// Regression: warpMasqueOutbound must return destination errors raw when the MASQUE tunnel
// itself is alive (not wrap them as "warp server (...) connection failed"), and Engine.IsChainedWarp
// distinguishes chained proxy+WARP nodes from builtin WARP.
func TestDialNode_WarpErrorClassification(t *testing.T) {
	eng := &Engine{
		services: []config.Service{
			{
				ID:       config.BuiltinWarpServiceID,
				Name:     "Cloudflare WARP",
				Protocol: config.ProtoWARP,
			},
			{
				ID:         "svc-chained",
				Name:       "Chained Node",
				Protocol:   config.ProtoVLESS,
				EnableWARP: true,
			},
		},
	}
	if eng.IsChainedWarp(config.BuiltinWarpServiceID) {
		t.Errorf("builtin-warp should not be classified as chained WARP")
	}
	if !eng.IsChainedWarp("svc-chained") {
		t.Errorf("svc-chained should be classified as chained WARP")
	}

	// Simulate warpMasqueOutbound with an active Netstack tunnel where dialing an unreachable
	// destination times out while the tunnel itself stays alive.
	ns, err := warp.NewNetstack(warp.DefaultIPv4, warp.DefaultIPv6)
	if err != nil {
		t.Fatalf("NewNetstack failed: %v", err)
	}
	defer ns.Close()
	fb := &mockOutbound{tag: "wg-node-builtin-warp"}
	ob := &warpMasqueOutbound{
		tag: "node-builtin-warp",
		tun: &warp.MASQUETunnel{
			Netstack: ns,
		},
		opts: warpMasqueOptions{
			Endpoint:          "162.159.198.2:443",
			WireGuardFallback: "wg-node-builtin-warp",
		},
		outboundMgr: &testOutboundManager{
			outbounds: map[string]adapter.Outbound{
				"wg-node-builtin-warp": fb,
			},
		},
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, dialErr := ob.DialContext(dialCtx, "tcp", M.ParseSocksaddr("1.1.1.1:443"))
	if dialErr == nil {
		t.Fatalf("expected destination dial timeout error, got nil")
	}
	if strings.Contains(dialErr.Error(), "warp server") {
		t.Errorf("expected raw destination error without 'warp server' wrapper, got: %v", dialErr)
	}
	if fb.dialed != 0 {
		t.Errorf("expected WireGuard fallback NOT to trigger when MASQUE tunnel is alive, dialed=%d", fb.dialed)
	}
	_ = errors.Is
}

func TestBuildOutboundsConfig_CleanIPScopeIsolation(t *testing.T) {
	globalCfg := &warp.Config{
		CleanIP:     "162.159.198.9",
		CleanPort:   8443,
		DefaultMode: warp.ModeMASQUE,
		ChainedMode: warp.ModeMASQUE,
	}

	directWarpWG := config.Service{
		ID:       config.BuiltinWarpServiceID,
		Name:     "Cloudflare WARP",
		Protocol: config.ProtoWARP,
		WARPConfig: &config.WarpNodeConfig{
			Transport: config.WarpTransportWireGuard,
		},
	}
	chainedUS := config.Service{
		ID:         "us-node",
		Name:       "US VLESS + WARP",
		Protocol:   config.ProtoVLESS,
		Server:     "us.example.com:443",
		EnableWARP: true,
	}
	chainedUSWG := config.Service{
		ID:         "us-wg-node",
		Name:       "US VLESS + WARP WG",
		Protocol:   config.ProtoVLESS,
		Server:     "us-wg.example.com:443",
		EnableWARP: true,
		WARPConfig: &config.WarpNodeConfig{
			Transport: config.WarpTransportWireGuard,
		},
	}
	chainedJPExplicit := config.Service{
		ID:         "jp-node",
		Name:       "JP VLESS + WARP",
		Protocol:   config.ProtoVLESS,
		Server:     "jp.example.com:443",
		EnableWARP: true,
		WARPConfig: &config.WarpNodeConfig{
			Endpoint: "162.159.198.12:443",
		},
	}

	opts := EngineOptions{
		Services:         []config.Service{directWarpWG, chainedUS, chainedUSWG, chainedJPExplicit},
		CloudflareConfig: globalCfg,
	}

	outbounds, err := buildOutboundsConfig(opts, "direct", nil)
	if err != nil {
		t.Fatalf("buildOutboundsConfig failed: %v", err)
	}

	byTag := map[string]map[string]any{}
	for _, ob := range outbounds {
		if tag, ok := ob["tag"].(string); ok {
			byTag[tag] = ob
		}
	}

	// 1. Direct WARP WG with CleanIP builds static WireGuard endpoint (no warp-wg-auto outbound)
	if byTag["node-"+config.BuiltinWarpServiceID] != nil {
		t.Errorf("expected direct WARP WG with CleanIP to use static endpoint instead of outbound, got %+v", byTag["node-"+config.BuiltinWarpServiceID])
	}

	// 2. Chained proxy+WARP without explicit endpoint must NOT inherit global CleanIP (stays empty for runtime per-egress auto-selection)
	if ep := byTag["node-us-node"]["endpoint"]; ep != "" {
		t.Errorf("expected chained node-us-node endpoint to be empty (auto-select), got %v", ep)
	}
	if wgAuto := byTag["node-us-wg-node"]; wgAuto == nil || wgAuto["type"] != "warp-wg-auto" {
		t.Errorf("expected node-us-wg-node to use warp-wg-auto outbound, got %+v", wgAuto)
	}

	// 3. Chained proxy+WARP with explicit node-level endpoint keeps its explicit endpoint
	if ep := byTag["node-jp-node"]["endpoint"]; ep != "162.159.198.12:443" {
		t.Errorf("expected explicit chained node-jp-node endpoint 162.159.198.12:443, got %v", ep)
	}

	// 4. Verify endpoints slice only contains static WireGuard endpoints for nodes with explicit endpoints
	endpoints := buildEndpointsConfig(opts)
	epTags := map[string]bool{}
	for _, ep := range endpoints {
		if tag, ok := ep["tag"].(string); ok {
			epTags[tag] = true
		}
	}
	if !epTags["node-"+config.BuiltinWarpServiceID] {
		t.Errorf("expected static WG endpoint node-%s for direct WARP WG with CleanIP, got %v", config.BuiltinWarpServiceID, epTags)
	}
	if epTags["node-us-wg-node"] || epTags["wg-node-us-wg-node"] {
		t.Errorf("expected NO static WG endpoint for auto-select chained us-wg-node")
	}
}

// Regression: warpAutoWireGuardOutbound previously omitted adapter.Lifecycle.Start and was
// also wrapped by blockerOutbound which hid Lifecycle.Start. As a result, Engine.Close()
// canceled the box context without ever closing the WireGuard endpoint, leaving sing-box's
// ClientBind.receive loop spamming "outbound/warp-wg-auto[...]: connect to server: ...: operation was canceled"
// every second even after WARP was removed from all nodes.
func TestWarpAutoWireGuardOutbound_CloseStopsClientBindLoop(t *testing.T) {
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer upstreamLn.Close()

	go func() {
		for {
			conn, aErr := upstreamLn.Accept()
			if aErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	privKey, _, err := warp.GenerateWireGuardKeypair()
	if err != nil {
		t.Fatalf("GenerateWireGuardKeypair: %v", err)
	}

	sel := warp.NewEndpointSelector()
	sel.SetCached(warp.EndpointCacheKey{
		ScopeKey: "node-svc-wg-test",
		Mode:     warp.ModeWireGuard,
	}, "127.0.0.1:2408", "wireguard", 10*time.Millisecond)

	var logMu sync.Mutex
	var postCloseLogs []string
	var closedAfter bool

	bl := blocker.NewEngine(blocker.Options{})
	svc := config.Service{
		ID:          "svc-wg-test",
		Name:        "WG Test",
		Kind:        config.KindExternalProxy,
		Protocol:    config.ProtoSOCKS5,
		Engine:      config.EngineSingBox,
		ExternalURI: fmt.Sprintf("socks5://%s", upstreamLn.Addr().String()),
		EnableWARP:  true,
		WARPConfig: &config.WarpNodeConfig{
			Transport:  config.WarpTransportWireGuard,
			PrivateKey: privKey,
		},
	}

	eng, err := New(EngineOptions{
		ListenAddr:       "127.0.0.1:0",
		TrafficMode:      "port",
		Services:         []config.Service{svc},
		ActiveIDs:        map[string]bool{"svc-wg-test": true},
		Blocker:          bl,
		EndpointSelector: sel,
		LogLevel:         "warn",
		OnLog: func(level, message string) {
			logMu.Lock()
			if closedAfter {
				postCloseLogs = append(postCloseLogs, level+": "+message)
			}
			logMu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("New engine failed: %v", err)
	}
	if err := eng.Start(); err != nil {
		_ = eng.Close()
		t.Fatalf("Start engine failed: %v", err)
	}

	// Trigger lazy WireGuard endpoint creation and ClientBind receive loop.
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	_, _ = eng.DialNode(dialCtx, "svc-wg-test", "tcp", "127.0.0.1:80")
	dialCancel()

	ob, ok := eng.GetOutbound("svc-wg-test")
	if !ok {
		_ = eng.Close()
		t.Fatalf("expected node-svc-wg-test outbound to exist")
	}
	wgOb, ok := common.Cast[*warpAutoWireGuardOutbound](ob)
	if !ok {
		_ = eng.Close()
		t.Fatalf("expected outbound to unwrap to *warpAutoWireGuardOutbound, got %T", ob)
	}
	wgOb.mu.Lock()
	hadEP := wgOb.ep != nil
	wgOb.mu.Unlock()
	if !hadEP {
		_ = eng.Close()
		t.Fatalf("expected DialNode to start WireGuard endpoint before Close")
	}

	if err := eng.Close(); err != nil {
		t.Fatalf("Close engine failed: %v", err)
	}

	logMu.Lock()
	closedAfter = true
	logMu.Unlock()

	wgOb.mu.Lock()
	isClosed := wgOb.closed
	epAfter := wgOb.ep
	wgOb.mu.Unlock()
	if !isClosed || epAfter != nil {
		t.Fatalf("expected warpAutoWireGuardOutbound to be closed with ep=nil after Engine.Close(), closed=%v ep=%v", isClosed, epAfter)
	}

	// Wait past ClientBind.receive()'s 1-second retry backoff to prove no zombie loop remains.
	time.Sleep(1200 * time.Millisecond)

	logMu.Lock()
	leaked := append([]string(nil), postCloseLogs...)
	logMu.Unlock()
	if len(leaked) > 0 {
		t.Fatalf("expected no sing-box logs after Engine.Close(), got leaked logs: %v", leaked)
	}
}

type lifecycleTrackingOutbound struct {
	*mockOutbound
	startedStages     []adapter.StartStage
	scopeAddCount     int
	interfaceUpdated  int
	keepIdle          bool
	closeIdleCount    int
	activeEndpointVal string
}

func (l *lifecycleTrackingOutbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	l.startedStages = append(l.startedStages, stage)
	if stage == adapter.StartStateInitialize && scope != nil {
		scope.Add(func() error {
			l.scopeAddCount++
			return nil
		})
	}
	return nil
}

func (l *lifecycleTrackingOutbound) InterfaceUpdated(ctx context.Context) {
	l.interfaceUpdated++
}

func (l *lifecycleTrackingOutbound) SetKeepIdleConnections(keep bool) {
	l.keepIdle = keep
}

func (l *lifecycleTrackingOutbound) CloseIdleConnections() {
	l.closeIdleCount++
}

func (l *lifecycleTrackingOutbound) ActiveEndpoint() string {
	return l.activeEndpointVal
}

// Regression: blockerOutbound must forward adapter.Lifecycle and InterfaceUpdateListener,
// blockerOutboundRegistry must only wrap direct/block outbounds, and ReferenceManager must
// still trace pooled and fallback proxy outbounds via adapter.Referrer.
func TestBlockerOutbound_ForwardsLifecycleAndInterfaceHooks(t *testing.T) {
	inner := &lifecycleTrackingOutbound{
		mockOutbound:      &mockOutbound{tag: "direct"},
		activeEndpointVal: "162.159.198.2:443",
	}
	wrapped := &blockerOutbound{Outbound: inner}

	if unwrapped, ok := common.Cast[*lifecycleTrackingOutbound](wrapped); !ok || unwrapped != inner {
		t.Fatalf("expected common.Cast to unwrap blockerOutbound via Upstream()")
	}
	if _, isKeeper := any(wrapped).(adapter.IdleConnectionKeeper); isKeeper {
		t.Fatalf("expected blockerOutbound NOT to expose adapter.IdleConnectionKeeper directly")
	}

	scope := adapter.NewScope(context.Background(), boxLog.NewNOPFactory().Logger())
	var lc adapter.Lifecycle = wrapped
	if err := lc.Start(adapter.StartStateInitialize, scope); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if len(inner.startedStages) != 1 || inner.startedStages[0] != adapter.StartStateInitialize {
		t.Fatalf("expected Start to forward StartStateInitialize, got %v", inner.startedStages)
	}
	if err := scope.Close(); err != nil {
		t.Fatalf("scope.Close failed: %v", err)
	}
	if inner.scopeAddCount != 1 {
		t.Fatalf("expected forwarded scope cleanup to run once on Close, got %d", inner.scopeAddCount)
	}

	var iul adapter.InterfaceUpdateListener = wrapped
	iul.InterfaceUpdated(context.Background())
	if inner.interfaceUpdated != 1 {
		t.Fatalf("expected InterfaceUpdated to forward once, got %d", inner.interfaceUpdated)
	}

	// Verify blockerOutboundRegistry only wraps direct/block and leaves proxy/WARP/pool unwrapped,
	// and ReferenceManager keeps pooled/chained proxy outbounds referenced (no unreferenced log).
	bl := blocker.NewEngine(blocker.Options{Denylist: []string{"blocked.example"}})
	svc := config.Service{
		ID:          "svc-socks",
		Name:        "SOCKS",
		Kind:        config.KindExternalProxy,
		Protocol:    config.ProtoSOCKS5,
		Engine:      config.EngineSingBox,
		ExternalURI: "socks5://127.0.0.1:1080",
	}
	trojanSvc := config.Service{
		ID:         "svc-trojan",
		Name:       "Trojan",
		Protocol:   config.ProtoTrojan,
		Engine:     config.EngineSingBox,
		Server:     "127.0.0.1",
		ServerPort: 443,
		Password:   "secret",
		EnableWARP: true,
	}
	warpSvc := config.Service{
		ID:       config.BuiltinWarpServiceID,
		Name:     "Cloudflare WARP",
		Protocol: config.ProtoWARP,
		WARPConfig: &config.WarpNodeConfig{
			Transport: config.WarpTransportMasque,
			Endpoint:  "162.159.198.2:443",
		},
	}

	var logMu sync.Mutex
	var unrefLogs []string
	eng, err := New(EngineOptions{
		ListenAddr:  "127.0.0.1:0",
		TrafficMode: "port",
		Services:    []config.Service{svc, trojanSvc, warpSvc},
		ActiveIDs:   map[string]bool{"svc-socks": true, "svc-trojan": true, config.BuiltinWarpServiceID: true},
		FinalAction: "proxy",
		Blocker:     bl,
		LogLevel:    "debug",
		OnLog: func(level, message string) {
			if strings.Contains(message, "is unreferenced") {
				logMu.Lock()
				unrefLogs = append(unrefLogs, message)
				logMu.Unlock()
			}
		},
	})
	if err != nil {
		t.Fatalf("New engine failed: %v", err)
	}
	if err := eng.Start(); err != nil {
		_ = eng.Close()
		t.Fatalf("Start engine failed: %v", err)
	}
	defer eng.Close()

	logMu.Lock()
	gotUnref := append([]string(nil), unrefLogs...)
	logMu.Unlock()
	for _, msg := range gotUnref {
		if strings.Contains(msg, "raw-node-svc-trojan") || strings.Contains(msg, "node-svc-trojan") {
			t.Fatalf("expected ReferenceManager to keep pooled/chained trojan outbound referenced, got log: %v", gotUnref)
		}
	}

	directOb, ok := eng.box.Outbound().Outbound("direct")
	if !ok {
		t.Fatalf("expected direct outbound")
	}
	if _, isBlocker := directOb.(*blockerOutbound); !isBlocker {
		t.Fatalf("expected direct outbound to be wrapped by *blockerOutbound, got %T", directOb)
	}
	blockOb, ok := eng.box.Outbound().Outbound("block")
	if !ok {
		t.Fatalf("expected block outbound")
	}
	if _, isReject := blockOb.(*rejectOutbound); !isReject {
		t.Fatalf("expected block outbound to be wrapped by *rejectOutbound, got %T", blockOb)
	}
	if socksOb, ok := eng.GetOutbound("svc-socks"); !ok {
		t.Fatalf("expected svc-socks outbound")
	} else if _, isBlocker := socksOb.(*blockerOutbound); isBlocker {
		t.Fatalf("expected proxy outbound NOT to be wrapped by *blockerOutbound")
	}
	if trojanOb, ok := eng.GetOutbound("raw-node-svc-trojan"); !ok {
		t.Fatalf("expected raw-node-svc-trojan outbound")
	} else if _, isKeeper := trojanOb.(adapter.IdleConnectionKeeper); !isKeeper {
		t.Fatalf("expected unwrapped trojan outbound to preserve adapter.IdleConnectionKeeper directly, got %T", trojanOb)
	}
	if mqOb, ok := eng.GetOutbound(config.BuiltinWarpServiceID); !ok {
		t.Fatalf("expected builtin-warp outbound")
	} else if _, isDirectType := mqOb.(*warpMasqueOutbound); !isDirectType {
		t.Fatalf("expected MASQUE outbound to be unwrapped *warpMasqueOutbound, got %T", mqOb)
	}
	if poolOb, ok := eng.box.Outbound().Outbound("PROXY_POOL"); !ok {
		t.Fatalf("expected PROXY_POOL outbound")
	} else if ref, ok := poolOb.(adapter.Referrer); !ok {
		t.Fatalf("expected PoolOutbound to implement adapter.Referrer")
	} else {
		refs := ref.References()
		hasTrojan := false
		for _, r := range refs {
			if r == "node-svc-trojan" {
				hasTrojan = true
				break
			}
		}
		if !hasTrojan {
			t.Fatalf("expected PoolOutbound.References() to include node-svc-trojan, got %v", refs)
		}
	}
	if _, dialErr := eng.DialNode(context.Background(), "svc-socks", "tcp", "blocked.example:443"); !errors.Is(dialErr, syscall.EPERM) {
		t.Fatalf("expected DialNode to enforce Blocker with EPERM, got %v", dialErr)
	}
}

// Regression: warpMasqueOutbound must implement adapter.Lifecycle so Engine.Close tears down
// MASQUE outbounds cleanly.
func TestWarpMasqueOutbound_CloseRunsOnEngineClose(t *testing.T) {
	bl := blocker.NewEngine(blocker.Options{})
	svc := config.Service{
		ID:       config.BuiltinWarpServiceID,
		Name:     "Cloudflare WARP",
		Protocol: config.ProtoWARP,
		WARPConfig: &config.WarpNodeConfig{
			Transport: config.WarpTransportMasque,
			Endpoint:  "162.159.198.2:443",
		},
	}

	eng, err := New(EngineOptions{
		ListenAddr:  "127.0.0.1:0",
		TrafficMode: "port",
		Services:    []config.Service{svc},
		Blocker:     bl,
	})
	if err != nil {
		t.Fatalf("New engine failed: %v", err)
	}
	if err := eng.Start(); err != nil {
		_ = eng.Close()
		t.Fatalf("Start engine failed: %v", err)
	}

	ob, ok := eng.GetOutbound(config.BuiltinWarpServiceID)
	if !ok {
		_ = eng.Close()
		t.Fatalf("expected builtin-warp outbound")
	}
	mqOb, ok := common.Cast[*warpMasqueOutbound](ob)
	if !ok {
		_ = eng.Close()
		t.Fatalf("expected *warpMasqueOutbound, got %T", ob)
	}

	if err := eng.Close(); err != nil {
		t.Fatalf("Close engine failed: %v", err)
	}

	mqOb.mu.Lock()
	closed := mqOb.closed
	mqOb.mu.Unlock()
	if !closed {
		t.Fatalf("expected warpMasqueOutbound to be closed after Engine.Close()")
	}
}

// Regression: invalidateTunnel previously called wg.Add(1) unconditionally outside w.tun == tun
// and without checking w.closed, racing with Close()'s wg.Wait() when tun.Close() woke up
// concurrent DialContext callers via <-tun.Done().
func TestWarpMasqueOutbound_ConcurrentInvalidateAndCloseNoRace(t *testing.T) {
	for i := 0; i < 10; i++ {
		ns, err := warp.NewNetstack(warp.DefaultIPv4, warp.DefaultIPv6)
		if err != nil {
			t.Fatalf("NewNetstack: %v", err)
		}
		tun := &warp.MASQUETunnel{
			Netstack: ns,
		}
		ob := &warpMasqueOutbound{
			tag:                   "node-builtin-warp",
			eng:                   &Engine{endpointSelector: warp.NewEndpointSelector()},
			warpOutboundLifecycle: newWarpOutboundLifecycle(context.Background()),
			tun:                   tun,
			activeEndpoint:        "162.159.198.2:443",
		}

		var workers sync.WaitGroup
		startCh := make(chan struct{})
		for g := 0; g < 4; g++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				<-startCh
				ob.invalidateTunnel(tun)
			}()
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-startCh
			_ = ob.Close()
		}()
		close(startCh)
		workers.Wait()
	}
}

// Regression: Engine.Close() previously held e.mu while calling w.Close(), while ensureEndpoint
// held w.mu across network I/O and called e.mu (via GetOutbound / cloudflareConfig), causing an
// ABBA deadlock and long shutdown stalls.
func TestWarpAutoWireGuardOutbound_CloseDuringInflightDialNoDeadlock(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Accept upstream SOCKS5 connections and stall them so SelectWireGuardEndpoint stays
	// in-flight until Engine.Close() cancels closeCtx.
	connsMu := sync.Mutex{}
	var accepted []net.Conn
	acceptedCh := make(chan struct{}, 1)
	defer func() {
		connsMu.Lock()
		for _, c := range accepted {
			_ = c.Close()
		}
		connsMu.Unlock()
	}()
	go func() {
		for {
			c, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			connsMu.Lock()
			accepted = append(accepted, c)
			connsMu.Unlock()
			select {
			case acceptedCh <- struct{}{}:
			default:
			}
		}
	}()

	privKey, _, err := warp.GenerateWireGuardKeypair()
	if err != nil {
		t.Fatalf("GenerateWireGuardKeypair: %v", err)
	}

	sel := warp.NewEndpointSelector()
	svc := config.Service{
		ID:          "svc-wg-inflight",
		Name:        "WG Inflight",
		Kind:        config.KindExternalProxy,
		Protocol:    config.ProtoSOCKS5,
		Engine:      config.EngineSingBox,
		ExternalURI: fmt.Sprintf("socks5://%s", ln.Addr().String()),
		EnableWARP:  true,
		WARPConfig: &config.WarpNodeConfig{
			Transport:  config.WarpTransportWireGuard,
			PrivateKey: privKey,
		},
	}

	eng, err := New(EngineOptions{
		ListenAddr:       "127.0.0.1:0",
		TrafficMode:      "port",
		Services:         []config.Service{svc},
		ActiveIDs:        map[string]bool{"svc-wg-inflight": true},
		EndpointSelector: sel,
		CloudflareConfig: &warp.Config{},
	})
	if err != nil {
		t.Fatalf("New engine failed: %v", err)
	}
	if err := eng.Start(); err != nil {
		_ = eng.Close()
		t.Fatalf("Start engine failed: %v", err)
	}

	dialDone := make(chan error, 1)
	go func() {
		_, dErr := eng.DialNode(context.Background(), "svc-wg-inflight", "tcp", "1.1.1.1:80")
		dialDone <- dErr
	}()

	select {
	case <-acceptedCh:
	case <-time.After(1500 * time.Millisecond):
		t.Fatalf("timed out waiting for in-flight WARP probe to reach upstream listener")
	}

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- eng.Close()
	}()

	select {
	case cErr := <-closeDone:
		if cErr != nil {
			t.Fatalf("Engine.Close returned error: %v", cErr)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatalf("Engine.Close timed out / deadlocked against in-flight WARP dial")
	}

	select {
	case <-dialDone:
	case <-time.After(1500 * time.Millisecond):
		t.Fatalf("in-flight DialNode did not abort promptly on Engine.Close")
	}
}

// Regression: deriveLifecycleContext previously relied solely on context.AfterFunc, which
// schedules cancel asynchronously when lifeCtx is already done, leaving subCtx.Err() == nil
// immediately after return.
func TestWarpLifecycle_DeriveContextCanceledSynchronouslyWhenLifeCtxClosed(t *testing.T) {
	for i := 0; i < 200; i++ {
		lifeCtx, lifeCancel := context.WithCancel(context.Background())
		lifeCancel()

		subCtx, subCancel := deriveLifecycleContext(context.Background(), lifeCtx, 5*time.Second)
		err := subCtx.Err()
		subCancel()
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("iteration %d: expected derived context to be synchronously canceled when lifeCtx is already done, got %v", i, err)
		}
	}
}

// Regression: invalidateTunnel checked w.closed instead of w.isClosedLocked(), and
// getOrCreateTunnel recorded masqueFailedAt even when caller ctx was canceled, which
// could mark healthy endpoints failed during shutdown or force 60s WireGuard fallback.
func TestWarpMasqueOutbound_CanceledInvalidateAndDialDoNotMarkFailed(t *testing.T) {
	t.Run("invalidateTunnel after closeCancel does not mark endpoint failed", func(t *testing.T) {
		sel := warp.NewEndpointSelector()
		key := warp.EndpointCacheKey{
			ScopeKey: "direct",
			Mode:     warp.ModeMASQUE,
		}
		const ep = "162.159.198.2:443"
		sel.SetCached(key, ep, "h3", 10*time.Millisecond)

		ns, err := warp.NewNetstack(warp.DefaultIPv4, warp.DefaultIPv6)
		if err != nil {
			t.Fatalf("NewNetstack: %v", err)
		}
		defer ns.Close()

		tun := &warp.MASQUETunnel{Netstack: ns}
		ob := &warpMasqueOutbound{
			tag:                   "node-builtin-warp",
			eng:                   &Engine{endpointSelector: sel},
			warpOutboundLifecycle: newWarpOutboundLifecycle(context.Background()),
			tun:                   tun,
			activeEndpoint:        ep,
		}

		// Simulate the shutdown window after closeCancel() fires and before Close() sets closed=true.
		ob.closeCancel()
		ob.invalidateTunnel(tun)

		if cached, ok := sel.GetCached(key); !ok || cached != ep {
			t.Fatalf("expected cached endpoint %q to stay intact after closeCancel, got %q (ok=%v)", ep, cached, ok)
		}
		ob.mu.Lock()
		failedAt := ob.masqueFailedAt
		ob.mu.Unlock()
		if !failedAt.IsZero() {
			t.Fatalf("expected masqueFailedAt to remain zero after closeCancel, got %v", failedAt)
		}
	})

	t.Run("caller context cancellation during getOrCreateTunnel does not set fallback cooldown", func(t *testing.T) {
		priv, _, certPEM, err := warp.GenerateMASQUEKeypair()
		if err != nil {
			t.Fatalf("GenerateMASQUEKeypair: %v", err)
		}
		ob := &warpMasqueOutbound{
			tag: "node-builtin-warp",
			opts: warpMasqueOptions{
				Endpoint:          "127.0.0.1:1",
				PrivateKey:        priv,
				CertPEM:           certPEM,
				WireGuardFallback: "wg-node-builtin-warp",
			},
			eng:                   &Engine{},
			warpOutboundLifecycle: newWarpOutboundLifecycle(context.Background()),
		}
		defer ob.Close()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		if _, err := ob.getOrCreateTunnel(ctx); err == nil {
			t.Fatalf("expected getOrCreateTunnel to fail for canceled caller ctx")
		}
		ob.mu.Lock()
		failedAt := ob.masqueFailedAt
		ob.mu.Unlock()
		if !failedAt.IsZero() {
			t.Fatalf("expected masqueFailedAt to remain zero on caller cancellation, got %v", failedAt)
		}
	})
}

// Regression: warpAutoWireGuardOutbound.recordDialResult previously counted context.Canceled
// dial errors toward consecFails (rotating healthy endpoints after 3 canceled dials) and checked
// w.closed instead of w.isClosedLocked().
func TestWarpAutoWireGuardOutbound_CanceledDialsDoNotRotateOrMarkFailed(t *testing.T) {
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer upstreamLn.Close()

	go func() {
		for {
			c, aErr := upstreamLn.Accept()
			if aErr != nil {
				return
			}
			_ = c.Close()
		}
	}()

	privKey, _, err := warp.GenerateWireGuardKeypair()
	if err != nil {
		t.Fatalf("GenerateWireGuardKeypair: %v", err)
	}

	sel := warp.NewEndpointSelector()
	key := warp.EndpointCacheKey{
		ScopeKey: "node-svc-wg-cancel",
		Mode:     warp.ModeWireGuard,
	}
	const cachedEP = "127.0.0.1:2408"
	sel.SetCached(key, cachedEP, "wireguard", 10*time.Millisecond)

	svc := config.Service{
		ID:          "svc-wg-cancel",
		Name:        "WG Cancel",
		Kind:        config.KindExternalProxy,
		Protocol:    config.ProtoSOCKS5,
		Engine:      config.EngineSingBox,
		ExternalURI: fmt.Sprintf("socks5://%s", upstreamLn.Addr().String()),
		EnableWARP:  true,
		WARPConfig: &config.WarpNodeConfig{
			Transport:  config.WarpTransportWireGuard,
			PrivateKey: privKey,
		},
	}

	eng, err := New(EngineOptions{
		ListenAddr:       "127.0.0.1:0",
		TrafficMode:      "port",
		Services:         []config.Service{svc},
		ActiveIDs:        map[string]bool{"svc-wg-cancel": true},
		EndpointSelector: sel,
	})
	if err != nil {
		t.Fatalf("New engine failed: %v", err)
	}
	if err := eng.Start(); err != nil {
		_ = eng.Close()
		t.Fatalf("Start engine failed: %v", err)
	}
	defer eng.Close()

	// Establish the initial WireGuard endpoint cleanly.
	initCtx, initCancel := context.WithTimeout(context.Background(), 2*time.Second)
	_, _ = eng.DialNode(initCtx, "svc-wg-cancel", "tcp", "127.0.0.1:80")
	initCancel()

	ob, ok := eng.GetOutbound("svc-wg-cancel")
	if !ok {
		t.Fatalf("expected node-svc-wg-cancel outbound")
	}
	wgOb, ok := common.Cast[*warpAutoWireGuardOutbound](ob)
	if !ok {
		t.Fatalf("expected *warpAutoWireGuardOutbound, got %T", ob)
	}
	wgOb.mu.Lock()
	initialEP := wgOb.ep
	wgOb.consecFails = 0
	wgOb.mu.Unlock()
	if initialEP == nil {
		t.Fatalf("expected initial WireGuard endpoint to be created")
	}

	// 3+ caller-canceled dials must not increment consecFails, rotate ep, or MarkFailed.
	for i := 0; i < 4; i++ {
		cCtx, cCancel := context.WithCancel(context.Background())
		cCancel()
		_, dErr := wgOb.DialContext(cCtx, "tcp", M.ParseSocksaddr("127.0.0.1:80"))
		if dErr == nil {
			t.Fatalf("expected DialContext with canceled context to fail")
		}
		if strings.Contains(strings.ToLower(dErr.Error()), "warp server") {
			t.Fatalf("expected canceled DialContext not to wrap error as warp server failure, got %v", dErr)
		}
	}

	wgOb.mu.Lock()
	epAfterCancels := wgOb.ep
	failsAfterCancels := wgOb.consecFails
	wgOb.mu.Unlock()
	if epAfterCancels != initialEP || failsAfterCancels != 0 {
		t.Fatalf("expected canceled dials not to rotate ep or increment consecFails, epChanged=%v consecFails=%d", epAfterCancels != initialEP, failsAfterCancels)
	}
	if got, ok := sel.GetCached(key); !ok || got != cachedEP {
		t.Fatalf("expected cached endpoint %q to stay intact after canceled dials, got %q (ok=%v)", cachedEP, got, ok)
	}

	// Stale endpoint failures must not increment consecFails or rotate a newer endpoint.
	wgOb.mu.Lock()
	wgOb.consecFails = 2
	wgOb.mu.Unlock()
	wgOb.recordDialResult(context.Background(), nil, errors.New("stale ep failure"))
	wgOb.mu.Lock()
	epAfterStale := wgOb.ep
	failsAfterStale := wgOb.consecFails
	wgOb.mu.Unlock()
	if epAfterStale != initialEP || failsAfterStale != 2 {
		t.Fatalf("expected stale ep failure not to rotate or mutate consecFails, epChanged=%v consecFails=%d", epAfterStale != initialEP, failsAfterStale)
	}

	// InterfaceUpdated should run safely without racing Close().
	wgOb.InterfaceUpdated(context.Background())

	// Shutdown cancellation (closeCancel before closed=true) must also prevent recordDialResult rotation.
	wgOb.closeCancel()
	wgOb.recordDialResult(context.Background(), initialEP, errors.New("shutdown failure"))

	wgOb.mu.Lock()
	epAfterShutdown := wgOb.ep
	wgOb.mu.Unlock()
	if epAfterShutdown != initialEP {
		t.Fatalf("expected recordDialResult after closeCancel not to rotate ep")
	}
	if got, ok := sel.GetCached(key); !ok || got != cachedEP {
		t.Fatalf("expected cached endpoint %q to stay intact after closeCancel, got %q (ok=%v)", cachedEP, got, ok)
	}
}

// Regression: concurrent callers waiting on warpOutboundLifecycle.acquireInit must unblock
// immediately when their own ctx is canceled instead of blocking until the initializer finishes.
func TestWarpLifecycle_AcquireInitRespectsWaiterContext(t *testing.T) {
	l := newWarpOutboundLifecycle(context.Background())
	defer l.close(nil)

	release, ready, err := l.acquireInit(context.Background(), nil)
	if err != nil || ready || release == nil {
		t.Fatalf("expected initial acquireInit to succeed, ready=%v err=%v", ready, err)
	}
	defer release()

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer waitCancel()
	start := time.Now()
	_, _, waitErr := l.acquireInit(waitCtx, nil)
	if !errors.Is(waitErr, context.DeadlineExceeded) {
		t.Fatalf("expected waiter to fail with DeadlineExceeded, got %v", waitErr)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("expected waiter to abort promptly on ctx.Done, took %v", elapsed)
	}
}

// Regression: chained warpAutoWireGuardOutbound previously queried dnsRouter.Lookup instead of
// in-tunnel DNS and bypassed recordDialResult/wrapDialError when resolveDestination failed, while
// Engine.New left eng.cloudflareConfig nil when opts.CloudflareConfig was nil.
func TestWarpAutoWireGuardOutbound_TunnelDNSFailureRotatesAndDefaultsCloudflareConfig(t *testing.T) {
	eng, err := New(EngineOptions{
		ListenAddr:  "127.0.0.1:0",
		TrafficMode: "port",
	})
	if err != nil {
		t.Fatalf("New engine: %v", err)
	}
	if eng.cloudflareConfig == nil {
		t.Fatalf("expected non-nil internal cloudflareConfig when opts.CloudflareConfig is nil")
	}
	saveGlobalWarpAccount(eng, warp.Account{
		DeviceID:     "dev-1",
		WGPrivateKey: "priv-1",
	})
	if loaded := loadGlobalWarpAccount(eng); loaded.DeviceID != "dev-1" {
		t.Fatalf("expected saveGlobalWarpAccount to persist into initialized cloudflareConfig, got %+v", loaded)
	}
	_ = eng.Close()

	// Exercise resolveDestination -> recordDialResult -> wrapDialError when tunnel DNS fails.
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer upstreamLn.Close()
	go func() {
		for {
			c, aErr := upstreamLn.Accept()
			if aErr != nil {
				return
			}
			_ = c.Close()
		}
	}()

	privKey, _, err := warp.GenerateWireGuardKeypair()
	if err != nil {
		t.Fatalf("GenerateWireGuardKeypair: %v", err)
	}
	sel := warp.NewEndpointSelector()
	const cachedEP = "127.0.0.1:2408"
	key := warp.EndpointCacheKey{ScopeKey: "node-svc-wg-dns", Mode: warp.ModeWireGuard}
	sel.SetCached(key, cachedEP, "wireguard", 10*time.Millisecond)

	svc := config.Service{
		ID:          "svc-wg-dns",
		Name:        "WG DNS",
		Kind:        config.KindExternalProxy,
		Protocol:    config.ProtoSOCKS5,
		Engine:      config.EngineSingBox,
		ExternalURI: fmt.Sprintf("socks5://%s", upstreamLn.Addr().String()),
		EnableWARP:  true,
		WARPConfig: &config.WarpNodeConfig{
			Transport:  config.WarpTransportWireGuard,
			PrivateKey: privKey,
		},
	}

	eng2, err := New(EngineOptions{
		ListenAddr:       "127.0.0.1:0",
		TrafficMode:      "port",
		Services:         []config.Service{svc},
		ActiveIDs:        map[string]bool{"svc-wg-dns": true},
		EndpointSelector: sel,
	})
	if err != nil {
		t.Fatalf("New engine2: %v", err)
	}
	if err := eng2.Start(); err != nil {
		_ = eng2.Close()
		t.Fatalf("Start engine2: %v", err)
	}
	defer eng2.Close()

	ob, ok := eng2.GetOutbound("svc-wg-dns")
	if !ok {
		t.Fatalf("expected node-svc-wg-dns outbound")
	}
	wgOb, ok := common.Cast[*warpAutoWireGuardOutbound](ob)
	if !ok {
		t.Fatalf("expected *warpAutoWireGuardOutbound, got %T", ob)
	}

	// Ensure endpoint is established first via an IP dial.
	initCtx, initCancel := context.WithTimeout(context.Background(), 2*time.Second)
	_, _ = wgOb.DialContext(initCtx, "tcp", M.ParseSocksaddr("127.0.0.1:80"))
	initCancel()

	// Genuine ErrNoDNSRecords must NOT increment consecFails or wrap as warp server failure.
	epAddr := wgOb.ActiveEndpoint()
	wgOb.mu.Lock()
	wgOb.consecFails = 0
	ep := wgOb.ep
	wgOb.mu.Unlock()
	if ep == nil {
		t.Fatalf("expected WireGuard endpoint to be initialized")
	}
	wgOb.recordDialResult(context.Background(), ep, warp.ErrNoDNSRecords)
	if wrapped := wgOb.wrapDialError(context.Background(), epAddr, warp.ErrNoDNSRecords); !errors.Is(wrapped, warp.ErrNoDNSRecords) || strings.Contains(strings.ToLower(wrapped.Error()), "warp server") {
		t.Fatalf("expected ErrNoDNSRecords not to wrap as warp server failure, got %v", wrapped)
	}
	wgOb.mu.Lock()
	failsAfterNX := wgOb.consecFails
	wgOb.mu.Unlock()
	if failsAfterNX != 0 {
		t.Fatalf("expected ErrNoDNSRecords not to increment consecFails, got %d", failsAfterNX)
	}

	// Simulate 3 tunnel-level DNS resolution failures over a broken tunnel -> wraps & rotates ep.
	wgOb.mu.Lock()
	wgOb.consecFails = 0
	wgOb.mu.Unlock()
	for i := 0; i < 3; i++ {
		dCtx, dCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		// Force ensureEndpoint on the same ep until 3rd failure rotates it.
		_, dErr := wgOb.DialContext(dCtx, "tcp", M.ParseSocksaddr("blocked-or-unreachable.example:443"))
		dCancel()
		if dErr == nil {
			t.Fatalf("expected domain dial over unreachable tunnel to fail")
		}
		if !strings.Contains(strings.ToLower(dErr.Error()), "warp server (") {
			t.Fatalf("expected tunnel DNS transport failure to wrap with warp server error, got %v", dErr)
		}
	}

	wgOb.mu.Lock()
	rotated := wgOb.ep == nil
	wgOb.mu.Unlock()
	if !rotated {
		t.Fatalf("expected 3 tunnel DNS failures to rotate WireGuard endpoint")
	}
}

// Regression: buildDNSConfig must preserve PROXY_POOL detour for remote-doh when a custom
// ProtoWARP node is configured, DialNode must not wrap context.Canceled into a warp server
// error, and PoolOutbound must route static explicit-endpoint WireGuard WARP domain dials
// through ResolveWarpDomain rather than forwarding unresolved domains to sing-box's dnsRouter.
func TestWarpDNSLeakAndCancelClassification_Regressions(t *testing.T) {
	// 1. Custom non-builtin ProtoWARP node in PROXY_POOL keeps remote-doh detour = PROXY_POOL.
	customWarp := config.Service{
		ID:       "custom-warp-1",
		Name:     "Custom WARP",
		Protocol: config.ProtoWARP,
		WARPConfig: &config.WarpNodeConfig{
			Transport: config.WarpTransportWireGuard,
			Endpoint:  "162.159.192.1:2408",
		},
	}
	dnsMap := buildDNSConfig(EngineOptions{
		Services: []config.Service{customWarp},
	}, "PROXY_POOL", nil)
	servers := dnsMap["servers"].([]map[string]any)
	var remoteDetour any
	for _, s := range servers {
		if s["tag"] == "remote-doh" {
			remoteDetour = s["detour"]
		}
	}
	if remoteDetour != "PROXY_POOL" {
		t.Fatalf("expected remote-doh detour PROXY_POOL when custom ProtoWARP service exists, got %v", remoteDetour)
	}

	// 2. DialNode must return context.Canceled directly instead of wrapping with "warp server (...)".
	priv, _, certPEM, err := warp.GenerateMASQUEKeypair()
	if err != nil {
		t.Fatalf("GenerateMASQUEKeypair: %v", err)
	}
	customWarpMasque := config.Service{
		ID:       "custom-warp-cancel",
		Name:     "Custom WARP Cancel",
		Protocol: config.ProtoWARP,
		WARPConfig: &config.WarpNodeConfig{
			Transport: config.WarpTransportMasque,
			Endpoint:  "127.0.0.1:1",
		},
	}
	eng, err := New(EngineOptions{
		ListenAddr:  "127.0.0.1:0",
		TrafficMode: "port",
		Services:    []config.Service{customWarpMasque, customWarp},
		CloudflareConfig: &warp.Config{
			Account: warp.Account{
				MASQUEPrivateKey: priv,
				MASQUECertPEM:    certPEM,
			},
		},
	})
	if err != nil {
		t.Fatalf("New engine: %v", err)
	}
	if err := eng.Start(); err != nil {
		_ = eng.Close()
		t.Fatalf("Start engine: %v", err)
	}
	defer eng.Close()

	cCtx, cCancel := context.WithCancel(context.Background())
	cCancel()
	_, dialErr := eng.DialNode(cCtx, customWarpMasque.ID, "tcp", "1.1.1.1:443")
	if !errors.Is(dialErr, context.Canceled) {
		t.Fatalf("expected context.Canceled from DialNode, got %v", dialErr)
	}
	if strings.Contains(strings.ToLower(dialErr.Error()), "warp server") {
		t.Fatalf("expected canceled DialNode not to wrap error as warp server failure, got %v", dialErr)
	}

	// 3. PoolOutbound dialing a static explicit-endpoint WireGuard WARP candidate must invoke
	// ResolveWarpDomain (failing canceled DNS resolution before forwarding domain to endpoint).
	wgOnlyEng, err := New(EngineOptions{
		ListenAddr:  "127.0.0.1:0",
		TrafficMode: "port",
		Services:    []config.Service{customWarp},
	})
	if err != nil {
		t.Fatalf("New wgOnlyEng: %v", err)
	}
	if err := wgOnlyEng.Start(); err != nil {
		_ = wgOnlyEng.Close()
		t.Fatalf("Start wgOnlyEng: %v", err)
	}
	defer wgOnlyEng.Close()

	pool := NewPoolOutbound(PoolOutboundOptions{
		Tag:          "PROXY_POOL",
		PoolTag:      "PROXY_POOL",
		NodeProvider: wgOnlyEng,
	})
	_, poolErr := pool.DialContext(cCtx, "tcp", M.ParseSocksaddr("domain-must-not-leak.example:443"))
	if !errors.Is(poolErr, context.Canceled) {
		t.Fatalf("expected PoolOutbound domain dial over static WG WARP with canceled ctx to fail via ResolveWarpDomain, got %v", poolErr)
	}
}
