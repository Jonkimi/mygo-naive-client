package blocker_test

import (
	"strings"
	"testing"

	"naive-client/internal/blocker"
)

// Tests that AsDNS and AsGateway adapters evaluate rules, log corresponding sources, and respect dynamic allowlist updates.
func TestDualLayer_DNSAndGatewayAdapters(t *testing.T) {
	rules, err := blocker.ParseRuleStream(strings.NewReader(`
||ad.doubleclick.net^
0.0.0.0 telemetry.tracker.com
`), "test-rule")
	if err != nil {
		t.Fatalf("parse rules: %v", err)
	}

	engine := blocker.NewEngine(blocker.Options{
		Ruleset: rules,
	})

	dnsAdapter := engine.AsDNS()
	gwAdapter := engine.AsGateway()

	// 1. Evaluate via DNS adapter
	blocked, rule := dnsAdapter.Match("ad.doubleclick.net")
	if !blocked || rule == "" {
		t.Fatalf("expected ad.doubleclick.net to be blocked by DNS adapter, got blocked=%v, rule=%s", blocked, rule)
	}

	// 2. Evaluate via Gateway adapter
	blocked, rule = gwAdapter.Match("ad.doubleclick.net")
	if !blocked || rule == "" {
		t.Fatalf("expected ad.doubleclick.net to be blocked by Gateway adapter, got blocked=%v, rule=%s", blocked, rule)
	}

	// 3. Verify Telemetry in QueryLogger
	entries := engine.Logger().GetEntries(10)
	if len(entries) < 2 {
		t.Fatalf("expected at least 2 log entries, got %d", len(entries))
	}

	hasDNSEntry := false
	hasGatewayEntry := false
	for _, entry := range entries {
		if entry.Domain == "ad.doubleclick.net" {
			if entry.Source == blocker.SourceDNS && entry.Verdict == blocker.VerdictBlocked {
				hasDNSEntry = true
			}
			if entry.Source == blocker.SourceGateway && entry.Verdict == blocker.VerdictBlocked {
				hasGatewayEntry = true
			}
		}
	}
	if !hasDNSEntry {
		t.Fatalf("missing DNS blocked entry in QueryLogger")
	}
	if !hasGatewayEntry {
		t.Fatalf("missing Gateway blocked entry in QueryLogger")
	}

	// 4. Hot-whitelist: Add to allowlist and verify immediate unblock
	engine.AddAllowlist("ad.doubleclick.net")
	if blocked, rule := engine.Match("ad.doubleclick.net"); blocked {
		t.Fatalf("expected domain to be allowed after AddAllowlist, got blocked with rule: %s", rule)
	}

	blocked, _ = gwAdapter.Match("ad.doubleclick.net")
	if blocked {
		t.Fatalf("expected gateway adapter to unblock whitelisted domain")
	}

	latestEntries := engine.Logger().GetEntries(1)
	if len(latestEntries) > 0 && latestEntries[0].Verdict != blocker.VerdictWhitelisted {
		t.Fatalf("expected latest entry verdict to be WHITELISTED, got %v", latestEntries[0].Verdict)
	}
}
