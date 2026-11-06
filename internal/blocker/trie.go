package blocker

import (
	"strings"
)

// SuffixTrie stores domain suffix rules and matches domain suffixes efficiently.
// It uses a flat map with uint16 interned rule IDs and scans suffix boundaries (dots)
// from shortest to longest suffix, minimizing bucket size and GC pointer scanning.
type SuffixTrie struct {
	rules    map[string]uint16
	ruleList []string
	ruleIdx  map[string]uint16
}

// NewSuffixTrie creates an empty suffix matcher.
func NewSuffixTrie() *SuffixTrie {
	return &SuffixTrie{
		rules:   make(map[string]uint16),
		ruleIdx: make(map[string]uint16),
	}
}

func (t *SuffixTrie) internRule(rule string) uint16 {
	if id, ok := t.ruleIdx[rule]; ok {
		return id
	}
	t.ruleList = append(t.ruleList, rule)
	id := uint16(len(t.ruleList))
	t.ruleIdx[rule] = id
	return id
}

func (t *SuffixTrie) ruleByID(id uint16) string {
	if id == 0 || int(id) > len(t.ruleList) {
		return ""
	}
	return t.ruleList[id-1]
}

// Insert adds a domain suffix rule.
func (t *SuffixTrie) Insert(domain, rule string) {
	d := normalizeDomain(domain)
	if d == "" {
		return
	}
	t.rules[d] = t.internRule(rule)
}

// Match checks whether domain (or any parent suffix of domain) matches an inserted rule.
// Suffixes are evaluated from shortest (widest) to longest.
func (t *SuffixTrie) Match(domain string) (bool, string) {
	d := normalizeDomain(domain)
	if d == "" {
		return false, ""
	}

	// Check candidate suffixes from shortest to longest (right to left across dots)
	for i := len(d) - 1; i >= 0; i-- {
		if d[i] == '.' {
			sub := d[i+1:]
			if id, ok := t.rules[sub]; ok {
				return true, t.ruleByID(id)
			}
		}
	}
	if id, ok := t.rules[d]; ok {
		return true, t.ruleByID(id)
	}
	return false, ""
}

// Walk traverses all rules in the SuffixTrie and invokes fn for each rule.
func (t *SuffixTrie) Walk(fn func(domain, rule string)) {
	if t == nil {
		return
	}
	for domain, id := range t.rules {
		fn(domain, t.ruleByID(id))
	}
}

// Merge copies all rules from other into t.
func (t *SuffixTrie) Merge(other *SuffixTrie) {
	if other == nil {
		return
	}
	for domain, id := range other.rules {
		t.rules[domain] = t.internRule(other.ruleByID(id))
	}
}

// Count returns the number of rule endpoints in O(1) time.
func (t *SuffixTrie) Count() int {
	if t == nil {
		return 0
	}
	return len(t.rules)
}

func normalizeDomain(domain string) string {
	return strings.Trim(strings.ToLower(strings.TrimSpace(domain)), ".")
}

// ExactMap holds domain rules requiring exact string equality with uint16 interned rule IDs.
type ExactMap struct {
	rules    map[string]uint16
	ruleList []string
	ruleIdx  map[string]uint16
}

// NewExactMap creates an empty exact match map.
func NewExactMap() *ExactMap {
	return &ExactMap{
		rules:   make(map[string]uint16),
		ruleIdx: make(map[string]uint16),
	}
}

func (m *ExactMap) internRule(rule string) uint16 {
	if id, ok := m.ruleIdx[rule]; ok {
		return id
	}
	m.ruleList = append(m.ruleList, rule)
	id := uint16(len(m.ruleList))
	m.ruleIdx[rule] = id
	return id
}

func (m *ExactMap) ruleByID(id uint16) string {
	if id == 0 || int(id) > len(m.ruleList) {
		return ""
	}
	return m.ruleList[id-1]
}

// Set sets a domain exact match rule.
func (m *ExactMap) Set(domain, rule string) {
	d := normalizeDomain(domain)
	if d != "" {
		m.rules[d] = m.internRule(rule)
	}
}

// Match checks whether domain matches any exact rule.
func (m *ExactMap) Match(domain string) (bool, string) {
	d := normalizeDomain(domain)
	if d == "" {
		return false, ""
	}
	id, ok := m.rules[d]
	if !ok {
		return false, ""
	}
	return true, m.ruleByID(id)
}

// Merge copies all rules from other into m.
func (m *ExactMap) Merge(other *ExactMap) {
	if m == nil || other == nil {
		return
	}
	for k, id := range other.rules {
		m.rules[k] = m.internRule(other.ruleByID(id))
	}
}

// Len returns the number of entries in the exact map.
func (m *ExactMap) Len() int {
	if m == nil {
		return 0
	}
	return len(m.rules)
}
