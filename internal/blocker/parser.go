package blocker

import (
	"bufio"
	"io"
	"net"
	"strings"
)

// DomainMatcher matches built-in GeoSite domain rules without duplicating them into a separate trie.
type DomainMatcher interface {
	MatchDomain(tag string, domain string) bool
	TagRuleCount(tag string) int
}

// ParsedRules holds parsed rules from a rule subscription stream.
type ParsedRules struct {
	BlockExact *ExactMap
	BlockTrie  *SuffixTrie
	ExemptTrie *SuffixTrie
	GeoAds     DomainMatcher
}

func NewParsedRules() *ParsedRules {
	return &ParsedRules{
		BlockExact: NewExactMap(),
		BlockTrie:  NewSuffixTrie(),
		ExemptTrie: NewSuffixTrie(),
	}
}

// Merge merges another ParsedRules into this one.
func (r *ParsedRules) Merge(other *ParsedRules) {
	if r == nil || other == nil {
		return
	}
	r.BlockExact.Merge(other.BlockExact)
	r.BlockTrie.Merge(other.BlockTrie)
	r.ExemptTrie.Merge(other.ExemptTrie)
	if other.GeoAds != nil {
		r.GeoAds = other.GeoAds
	}
}

// TotalRules returns the sum of exact and suffix rules.
func (r *ParsedRules) TotalRules() int {
	if r == nil {
		return 0
	}
	c := r.BlockExact.Len() + r.BlockTrie.Count() + r.ExemptTrie.Count()
	if r.GeoAds != nil {
		c += r.GeoAds.TagRuleCount("category-ads-all")
	}
	return c
}

// ParseRuleStream parses rules from an io.Reader stream supporting:
// 1. Hosts syntax (127.0.0.1 domain.com or 0.0.0.0 domain.com)
// 2. AdGuard / EasyList syntax (||domain^ or @@||domain^)
// 3. Plain domain lists (domain.com per line)
func ParseRuleStream(r io.Reader, ruleTag string) (*ParsedRules, error) {
	rules := NewParsedRules()
	scanner := bufio.NewScanner(r)

	// Support larger line buffer if needed
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()

		// Strip inline and whole-line comments
		if idx := strings.IndexAny(line, "#!"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// AdGuard exemption rule: @@||domain^
		if strings.HasPrefix(line, "@@||") {
			dom := strings.TrimPrefix(line, "@@||")
			dom = cleanAdGuardDomain(dom)
			if dom != "" {
				rules.ExemptTrie.Insert(dom, ruleTag)
			}
			continue
		}

		// AdGuard block rule: ||domain^
		if strings.HasPrefix(line, "||") {
			dom := strings.TrimPrefix(line, "||")
			dom = cleanAdGuardDomain(dom)
			if dom != "" {
				rules.BlockTrie.Insert(dom, ruleTag)
			}
			continue
		}

		// Hosts file line: IP [space] domain
		fields := strings.Fields(line)
		if len(fields) >= 2 && net.ParseIP(fields[0]) != nil {
			for _, d := range fields[1:] {
				d = normalizeDomain(d)
				if d != "" && d != "localhost" && d != "broadcasthost" {
					rules.BlockExact.Set(d, ruleTag)
				}
			}
			continue
		}

		// Plain domain entry
		if len(fields) == 1 {
			dom := cleanAdGuardDomain(fields[0])
			if dom != "" && !strings.Contains(dom, "/") {
				rules.BlockTrie.Insert(dom, ruleTag)
			}
		}
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		return rules, err
	}
	return rules, nil
}

func cleanAdGuardDomain(s string) string {
	s = strings.TrimSpace(s)
	// Remove trailing options like ^, ^$third-party, etc.
	if idx := strings.Index(s, "^"); idx >= 0 {
		s = s[:idx]
	}
	if idx := strings.Index(s, "$"); idx >= 0 {
		s = s[:idx]
	}
	if idx := strings.Index(s, "/"); idx >= 0 {
		s = s[:idx]
	}
	return normalizeDomain(s)
}
