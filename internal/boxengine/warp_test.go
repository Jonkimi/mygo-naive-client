package boxengine

import (
	"testing"

	"naive-client/internal/config"
	"naive-client/internal/routing"
	"naive-client/internal/warp"
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
			DefaultMode: warp.ModeAuto,
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

	// Verify VLESS chaining: raw-node-vless-node -> node-vless-node
	rawVless, ok := outboundByTag["raw-node-vless-node"]
	if !ok || rawVless["type"] != "vless" {
		t.Errorf("expected raw-node-vless-node of type vless, got %+v", rawVless)
	}

	warpVless, ok := outboundByTag["node-vless-node"]
	if !ok || warpVless["type"] != "masque" || warpVless["detour"] != "raw-node-vless-node" {
		t.Errorf("expected node-vless-node detouring to raw-node-vless-node, got %+v", warpVless)
	}

	// Verify Naive Sidecar chaining: raw-node-naive-node -> node-naive-node with tcp_only_detour: true
	rawNaive, ok := outboundByTag["raw-node-naive-node"]
	if !ok || rawNaive["type"] != "socks" {
		t.Errorf("expected raw-node-naive-node of type socks, got %+v", rawNaive)
	}

	warpNaive, ok := outboundByTag["node-naive-node"]
	if !ok || warpNaive["type"] != "masque" || warpNaive["detour"] != "raw-node-naive-node" {
		t.Errorf("expected node-naive-node detouring to raw-node-naive-node, got %+v", warpNaive)
	}
	if warpNaive["tcp_only_detour"] != true {
		t.Errorf("expected tcp_only_detour: true for Naive TCP sidecar node, got %+v", warpNaive["tcp_only_detour"])
	}
}

func TestBuildRouteConfig_ActionWarpAndLANDirectProtection(t *testing.T) {
	ruleWarp := routing.Rule{
		ID:       "preset-lan-direct",
		Name:     "直连",
		Enabled:  true,
		GeoSite:  []string{"cn"},
		GeoIP:    []string{"cn", "private"},
		IPCidr:   []string{"192.168.1.0/24", "114.114.114.114/32"},
		Action:   routing.RouteAction{Type: routing.ActionWarp},
	}

	opts := EngineOptions{
		Rules:       []routing.Rule{ruleWarp},
		FinalAction: string(routing.ActionWarp),
	}

	// 1. Check resolveRouteOutbound & resolveFinalOutbound
	outbound := resolveRouteOutbound(routing.RouteAction{Type: routing.ActionWarp}, "")
	if outbound != "node-builtin-warp" {
		t.Errorf("expected node-builtin-warp, got %s", outbound)
	}
	finalOutbound := resolveFinalOutbound(opts)
	if finalOutbound != "node-builtin-warp" {
		t.Errorf("expected node-builtin-warp for final outbound, got %s", finalOutbound)
	}

	// 2. Check route config
	routeMap := buildRouteConfig(opts, finalOutbound, nil)
	rules, ok := routeMap["rules"].([]map[string]any)
	if !ok || len(rules) == 0 {
		t.Fatalf("expected generated sing-box rules, got %v", routeMap["rules"])
	}

	// Ensure Rule 0.25 (RFC1918 CIDRs) is present and routes to direct
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

	// Ensure user rule with ActionWarp routes to node-builtin-warp, but excludes geoip-private and 192.168.1.0/24
	var foundWarpRuleSet bool
	var foundWarpCIDR bool
	for _, r := range rules {
		if r["outbound"] == "node-builtin-warp" {
			if rsets, ok := r["rule_set"].([]string); ok {
				foundWarpRuleSet = true
				for _, rs := range rsets {
					if rs == "geoip-private" {
						t.Errorf("geoip-private should NOT be in node-builtin-warp rule_set: %v", rsets)
					}
				}
			}
			if cidrs, ok := r["ip_cidr"].([]string); ok {
				foundWarpCIDR = true
				for _, c := range cidrs {
					if c == "192.168.1.0/24" {
						t.Errorf("private CIDR 192.168.1.0/24 should NOT be in node-builtin-warp ip_cidr: %v", cidrs)
					}
				}
			}
		}
	}
	if !foundWarpRuleSet {
		t.Errorf("expected node-builtin-warp rule_set rule in route config")
	}
	if !foundWarpCIDR {
		t.Errorf("expected node-builtin-warp ip_cidr rule in route config")
	}

	// 3. Check DNS config: ActionWarp routes to domestic-doh
	dnsMap := buildDNSConfig(opts, finalOutbound, nil)
	dnsRules, ok := dnsMap["rules"].([]map[string]any)
	if !ok {
		t.Fatalf("expected dns rules, got %v", dnsMap["rules"])
	}
	var foundDomesticRule bool
	for _, dr := range dnsRules {
		if dr["server"] == "domestic-doh" {
			foundDomesticRule = true
			break
		}
	}
	if !foundDomesticRule {
		t.Errorf("expected ActionWarp to route domain DNS lookups to domestic-doh")
	}
}
