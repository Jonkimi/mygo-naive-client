package routing

import (
	"testing"
)

// Tests that the Router matches domains, suffixes, CIDRs, and keywords in priority order,
// falling back to FinalAction when no rule matches.
func TestRouter_MatchRulesAndFinalAction(t *testing.T) {
	rules := []Rule{
		{
			Name:    "Ads Blocker",
			Enabled: true,
			DomainSuffix: []string{
				"doubleclick.net",
				"adservice.google.com",
			},
			Action: RouteAction{Type: ActionBlock},
		},
		{
			Name:    "AI Services",
			Enabled: true,
			DomainSuffix: []string{
				"openai.com",
				"chatgpt.com",
				"anthropic.com",
				"claude.ai",
			},
			Action: RouteAction{Type: ActionProxyTag, Tag: "AI"},
		},
		{
			Name:    "Streaming Media",
			Enabled: true,
			DomainKeyword: []string{
				"netflix",
				"spotify",
			},
			Action: RouteAction{Type: ActionProxyTag, Tag: "Media"},
		},
		{
			Name:    "Direct LAN",
			Enabled: true,
			IPCidr: []string{
				"127.0.0.0/8",
				"10.0.0.0/8",
				"192.168.0.0/16",
			},
			Action: RouteAction{Type: ActionDirect},
		},
	}

	r := NewRouter(rules, RouteAction{Type: ActionProxyPool})

	// 1. Match Ads Blocker -> ActionBlock
	act1, rule1 := r.Match("pagead2.doubleclick.net:443")
	if act1.Type != ActionBlock || rule1 != "Ads Blocker" {
		t.Fatalf("expected ActionBlock from 'Ads Blocker', got %+v, rule %s", act1, rule1)
	}

	// 2. Match AI Services -> ActionProxyTag "AI"
	act2, rule2 := r.Match("api.openai.com:443")
	if act2.Type != ActionProxyTag || act2.Tag != "AI" || rule2 != "AI Services" {
		t.Fatalf("expected ActionProxyTag 'AI' from 'AI Services', got %+v, rule %s", act2, rule2)
	}

	// 3. Match Streaming Media by Keyword -> ActionProxyTag "Media"
	act3, rule3 := r.Match("custom-netflix-cdn.com:80")
	if act3.Type != ActionProxyTag || act3.Tag != "Media" || rule3 != "Streaming Media" {
		t.Fatalf("expected ActionProxyTag 'Media' from 'Streaming Media', got %+v, rule %s", act3, rule3)
	}

	// 4. Match LAN IP -> ActionDirect
	act4, rule4 := r.Match("192.168.1.100:8080")
	if act4.Type != ActionDirect || rule4 != "Direct LAN" {
		t.Fatalf("expected ActionDirect from 'Direct LAN', got %+v, rule %s", act4, rule4)
	}

	// 5. Unmatched host -> FinalAction (ActionProxyPool)
	act5, rule5 := r.Match("github.com:443")
	if act5.Type != ActionProxyPool || rule5 != "Final" {
		t.Fatalf("expected FinalAction ActionProxyPool for unmatched host, got %+v, rule %s", act5, rule5)
	}

	// 6. Disabled rule is skipped
	rules[1].Enabled = false // disable AI Services
	r2 := NewRouter(rules, RouteAction{Type: ActionProxyPool})
	act6, rule6 := r2.Match("api.openai.com:443")
	if act6.Type != ActionProxyPool || rule6 != "Final" {
		t.Fatalf("expected disabled rule to be skipped, got %+v, rule %s", act6, rule6)
	}
}

// Tests that DefaultPresets returns the 6 preset rule groups (including split LAN Direct and CN Direct) and direct LAN matches.
func TestRouter_DefaultPresets(t *testing.T) {
	presets := DefaultPresets()
	if len(presets) != 6 {
		t.Fatalf("expected 6 default preset rules, got %d", len(presets))
	}

	var lanRule, cnRule *Rule
	for i := range presets {
		if presets[i].ID == "preset-lan-direct" {
			lanRule = &presets[i]
		} else if presets[i].ID == "preset-cn-direct" {
			cnRule = &presets[i]
		}
	}
	if lanRule == nil || cnRule == nil {
		t.Fatalf("expected both preset-lan-direct and preset-cn-direct in DefaultPresets")
	}
	if len(lanRule.GeoSite) != 0 {
		t.Fatalf("expected preset-lan-direct to have no GeoSite, got %v", lanRule.GeoSite)
	}
	if len(lanRule.GeoIP) != 1 || lanRule.GeoIP[0] != "private" {
		t.Fatalf("expected preset-lan-direct GeoIP ['private'], got %v", lanRule.GeoIP)
	}
	if len(cnRule.GeoSite) != 1 || cnRule.GeoSite[0] != "cn" {
		t.Fatalf("expected preset-cn-direct GeoSite ['cn'], got %v", cnRule.GeoSite)
	}
	if len(cnRule.GeoIP) != 1 || cnRule.GeoIP[0] != "cn" {
		t.Fatalf("expected preset-cn-direct GeoIP ['cn'], got %v", cnRule.GeoIP)
	}

	r := NewRouter(presets, RouteAction{Type: ActionProxyPool})

	// Private and loopback IPs should directly match preset-lan-direct without geodata
	testTargets := []string{
		"192.168.1.1:80",
		"10.0.0.2:443",
		"127.0.0.1:8080",
		"172.16.10.5:22",
		"169.254.1.1:80",
		"::1",
		"nas.local:5000",
		"server.lan:80",
	}
	for _, target := range testTargets {
		act, ruleName := r.Match(target)
		if act.Type != ActionDirect || ruleName != "局域网直连" {
			t.Fatalf("target %s should match '局域网直连' ActionDirect, got %+v from rule %s", target, act, ruleName)
		}
	}
}

func TestRouteAction_NormalizedTargetsAndLegacyCompat(t *testing.T) {
	// 1. Legacy ActionWarp normalizes to builtin-warp node target
	warpAct := RouteAction{Type: ActionWarp}
	if !warpAct.TargetsNode(BuiltinWarpTargetID) {
		t.Fatalf("expected legacy ActionWarp to target %s", BuiltinWarpTargetID)
	}

	// 2. Legacy ActionProxyService normalizes to single node target
	svcAct := RouteAction{Type: ActionProxyService, ServiceID: "svc-us-1"}
	nt := svcAct.NormalizedTargets()
	if len(nt) != 1 || nt[0].Kind != TargetNode || nt[0].Value != "svc-us-1" {
		t.Fatalf("expected single node target svc-us-1, got %+v", nt)
	}

	// 3. Legacy ActionProxyTag normalizes to deduplicated tag targets
	tagAct := RouteAction{Type: ActionProxyTag, Tag: "AI", Tags: []string{"#AI", "ai", "US"}}
	ntTag := tagAct.NormalizedTargets()
	if len(ntTag) != 2 || ntTag[0] != (TargetRef{Kind: TargetTag, Value: "AI"}) || ntTag[1] != (TargetRef{Kind: TargetTag, Value: "US"}) {
		t.Fatalf("expected deduplicated tags [AI, US], got %+v", ntTag)
	}

	// 4. Unified NewProxyAction preserves mixed node+tag order, policy, and fallback
	mixed := NewProxyAction([]TargetRef{
		{Kind: TargetNode, Value: "svc-us-1"},
		{Kind: TargetTag, Value: "#AI"},
		{Kind: TargetNode, Value: "svc-us-1"},
	}, DispatchOrder, true)
	if mixed.Type != ActionProxyPool || mixed.EffectiveDispatchPolicy() != DispatchOrder || !mixed.FallbackToPool {
		t.Fatalf("unexpected mixed action metadata: %+v", mixed)
	}
	if len(mixed.Targets) != 2 || mixed.Targets[0].Value != "svc-us-1" || mixed.Targets[1].Value != "AI" {
		t.Fatalf("unexpected normalized mixed targets: %+v", mixed.Targets)
	}
	if tags := mixed.GetTags(); len(tags) != 1 || tags[0] != "AI" {
		t.Fatalf("expected GetTags() to return ['AI'], got %v", tags)
	}

	// 5. Empty targets produces global PROXY_POOL without fallback flag
	empty := NewProxyAction(nil, DispatchOrder, true)
	if empty.Type != ActionProxyPool || len(empty.Targets) != 0 || empty.FallbackToPool {
		t.Fatalf("expected clean global PROXY_POOL action, got %+v", empty)
	}
}

func TestRouter_ActionWarpAndLANProtection(t *testing.T) {
	presets := DefaultPresets()
	for i := range presets {
		if presets[i].ID == "preset-lan-direct" {
			presets[i].Action = RouteAction{Type: ActionWarp}
			presets[i].DomainSuffix = append(presets[i].DomainSuffix, "baidu.com")
			presets[i].IPCidr = append(presets[i].IPCidr, "114.114.114.114/32")
			break
		}
	}

	r := NewRouter(presets, RouteAction{Type: ActionProxyPool})

	lanTargets := []string{
		"192.168.1.1:80",
		"10.0.0.1:443",
		"127.0.0.1:8080",
		"172.16.0.1:22",
		"169.254.1.1",
		"nas.local:5000",
		"router.lan",
		"localhost:3000",
	}
	for _, target := range lanTargets {
		act, _ := r.Match(target)
		if act.Type != ActionDirect {
			t.Errorf("expected target %s to be protected as ActionDirect, got %+v", target, act)
		}
	}

	warpTargets := []string{
		"baidu.com:443",
		"news.baidu.com",
		"114.114.114.114:53",
	}
	for _, target := range warpTargets {
		act, _ := r.Match(target)
		if act.Type != ActionWarp {
			t.Errorf("expected target %s to resolve to ActionWarp, got %+v", target, act)
		}
	}
}
