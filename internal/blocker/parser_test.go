package blocker

import (
	"strings"
	"testing"
)

// Tests that ParseRuleStream correctly parses hosts, plain domain lists,
// and AdGuard filter rules (|| and @@||).
func TestParseRuleStream(t *testing.T) {
	input := `
# Comment line
127.0.0.1 hosts-blocked.com # inline comment
0.0.0.0 zero-blocked.com
plain-blocked.com
||adguard-suffix.net^
@@||adguard-suffix.net^
@@||whitelist-only.com^
! Another comment
`
	ruleset, err := ParseRuleStream(strings.NewReader(input), "sub-test")
	if err != nil {
		t.Fatalf("unexpected error parsing stream: %v", err)
	}

	// Exact / Hosts
	if m, _ := ruleset.BlockExact.Match("hosts-blocked.com"); !m {
		t.Errorf("expected hosts-blocked.com to match BlockExact")
	}
	if m, _ := ruleset.BlockExact.Match("zero-blocked.com"); !m {
		t.Errorf("expected zero-blocked.com to match BlockExact")
	}

	// Plain domain and ||suffix
	if m, _ := ruleset.BlockTrie.Match("plain-blocked.com"); !m {
		t.Errorf("expected plain-blocked.com to match BlockTrie")
	}
	if m, _ := ruleset.BlockTrie.Match("sub.adguard-suffix.net"); !m {
		t.Errorf("expected sub.adguard-suffix.net to match BlockTrie")
	}

	// @@|| exemptions
	if m, _ := ruleset.ExemptTrie.Match("adguard-suffix.net"); !m {
		t.Errorf("expected adguard-suffix.net to match ExemptTrie")
	}
	if m, _ := ruleset.ExemptTrie.Match("sub.whitelist-only.com"); !m {
		t.Errorf("expected sub.whitelist-only.com to match ExemptTrie")
	}
}
