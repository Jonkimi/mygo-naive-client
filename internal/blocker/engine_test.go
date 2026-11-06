package blocker

import (
	"strings"
	"testing"
)

// Tests that Engine enforces the strict 5-tier matching priority:
// Tailnet -> User Allowlist -> Subscription @@|| -> User Denylist -> Subscriptions/category-ads-all
func TestEngine_StrictPriorityOrder(t *testing.T) {
	subInput := `
||ads.tracking.com^
||analytics.service.com^
@@||exempt.analytics.service.com^
0.0.0.0 hosts-bad.com
`
	rules, err := ParseRuleStream(strings.NewReader(subInput), "sub-test")
	if err != nil {
		t.Fatalf("parse stream: %v", err)
	}

	engine := NewEngine(Options{
		Ruleset: rules,
	})

	// 1. Tailnet bypasses everything (even if it matches a block rule)
	engine.AddDenylist("my-server.ts.net")
	if blocked, rule := engine.Match("my-server.ts.net"); blocked {
		t.Fatalf("expected Tailnet domain to be exempt, got blocked with rule: %s", rule)
	}

	// 2. User Allowlist overrides subscriptions and denylist
	engine.AddDenylist("override.com")
	engine.AddAllowlist("override.com")
	if blocked, _ := engine.Match("override.com"); blocked {
		t.Fatalf("expected User Allowlist to override User Denylist")
	}

	// 3. User Allowlist unblocks subscription ad
	if blocked, _ := engine.Match("ads.tracking.com"); !blocked {
		t.Fatalf("expected ads.tracking.com to be blocked initially")
	}
	engine.AddAllowlist("ads.tracking.com")
	if blocked, _ := engine.Match("ads.tracking.com"); blocked {
		t.Fatalf("expected ads.tracking.com to be allowed after adding to user allowlist")
	}

	// 4. Subscription exemption (@@||) exempts subscription blocks
	if blocked, _ := engine.Match("analytics.service.com"); !blocked {
		t.Fatalf("expected analytics.service.com to be blocked by subscription")
	}
	if blocked, _ := engine.Match("exempt.analytics.service.com"); blocked {
		t.Fatalf("expected exempt.analytics.service.com to be exempt by @@||")
	}

	// 5. User Denylist blocks arbitrary domain not in subscriptions
	if blocked, _ := engine.Match("bad-actor.net"); blocked {
		t.Fatalf("expected bad-actor.net to not be blocked initially")
	}
	engine.AddDenylist("bad-actor.net")
	if blocked, rule := engine.Match("bad-actor.net"); !blocked || rule != RuleUserDenylist {
		t.Fatalf("expected bad-actor.net to be blocked with RuleUserDenylist, got (%v, %q)", blocked, rule)
	}

	// 6. External subscriptions & hosts format
	if blocked, _ := engine.Match("hosts-bad.com"); !blocked {
		t.Fatalf("expected hosts-bad.com to be blocked by hosts rule")
	}
}
