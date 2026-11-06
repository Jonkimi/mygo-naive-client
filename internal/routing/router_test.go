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

// Tests that DefaultPresets returns the standard set of 5 preset rule groups (merged LAN and CN direct) and direct LAN matches.
func TestRouter_DefaultPresets(t *testing.T) {
	presets := DefaultPresets()
	if len(presets) != 5 {
		t.Fatalf("expected 5 default preset rules, got %d", len(presets))
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
		if act.Type != ActionDirect || ruleName != "绕过大陆及局域网" {
			t.Fatalf("target %s should match '绕过大陆及局域网' ActionDirect, got %+v from rule %s", target, act, ruleName)
		}
	}
}
