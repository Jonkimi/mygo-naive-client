package blocker

import (
	"testing"
)

// Tests that SuffixTrie correctly matches exact and subdomain suffixes
// based on reversed dot labels without false positives.
func TestSuffixTrie_Matching(t *testing.T) {
	trie := NewSuffixTrie()
	trie.Insert("doubleclick.net", "ad-rule")
	trie.Insert("adservice.google.com", "google-ads")

	cases := []struct {
		domain   string
		expected bool
		rule     string
	}{
		{"doubleclick.net", true, "ad-rule"},
		{"pagead2.doubleclick.net", true, "ad-rule"},
		{"sub.pagead2.doubleclick.net", true, "ad-rule"},
		{"DOUBLECLICK.NET", true, "ad-rule"},
		{"adservice.google.com", true, "google-ads"},
		{"sub.adservice.google.com", true, "google-ads"},
		// Non-matches
		{"google.com", false, ""},
		{"notdoubleclick.net", false, ""},
		{"net", false, ""},
		{"com", false, ""},
		{"", false, ""},
	}

	for _, tc := range cases {
		matched, rule := trie.Match(tc.domain)
		if matched != tc.expected || rule != tc.rule {
			t.Errorf("domain %q: expected (matched=%v, rule=%q), got (matched=%v, rule=%q)",
				tc.domain, tc.expected, tc.rule, matched, rule)
		}
	}
}

// Tests that ExactMap matches exact hostnames only and does not match subdomains.
func TestExactMap_Matching(t *testing.T) {
	em := NewExactMap()
	em.Set("ads.example.com", "hosts-rule")

	if matched, rule := em.Match("ads.example.com"); !matched || rule != "hosts-rule" {
		t.Errorf("expected ads.example.com to match, got (%v, %q)", matched, rule)
	}
	if matched, rule := em.Match("ADS.EXAMPLE.COM."); !matched || rule != "hosts-rule" {
		t.Errorf("expected ADS.EXAMPLE.COM. to match, got (%v, %q)", matched, rule)
	}
	if matched, _ := em.Match("sub.ads.example.com"); matched {
		t.Errorf("expected sub.ads.example.com to not match ExactMap")
	}
	if matched, _ := em.Match("example.com"); matched {
		t.Errorf("expected example.com to not match ExactMap")
	}
}
