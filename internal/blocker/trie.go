package blocker

import (
	"strings"
)

// trieNode represents a single label node in the reversed-label suffix trie.
type trieNode struct {
	children map[string]*trieNode
	isEnd    bool
	rule     string
}

func newTrieNode() *trieNode {
	return &trieNode{
		children: make(map[string]*trieNode),
	}
}

// SuffixTrie stores domain suffixes with reversed dot-separated labels.
// For example, "doubleclick.net" is stored as "net" -> "doubleclick".
type SuffixTrie struct {
	root  *trieNode
	count int
}

// NewSuffixTrie creates an empty reversed-label suffix trie.
func NewSuffixTrie() *SuffixTrie {
	return &SuffixTrie{
		root: newTrieNode(),
	}
}

// Insert adds a domain suffix rule into the trie.
func (t *SuffixTrie) Insert(domain, rule string) {
	labels := splitDomainReversed(domain)
	if len(labels) == 0 {
		return
	}

	curr := t.root
	for _, label := range labels {
		next, exists := curr.children[label]
		if !exists {
			next = newTrieNode()
			curr.children[label] = next
		}
		curr = next
	}
	if !curr.isEnd {
		curr.isEnd = true
		t.count++
	}
	curr.rule = rule
}

// Match checks whether domain (or any parent suffix of domain) matches an inserted rule.
func (t *SuffixTrie) Match(domain string) (bool, string) {
	labels := splitDomainReversed(domain)
	if len(labels) == 0 {
		return false, ""
	}

	curr := t.root
	for _, label := range labels {
		next, exists := curr.children[label]
		if !exists {
			return false, ""
		}
		curr = next
		if curr.isEnd {
			return true, curr.rule
		}
	}
	return false, ""
}

// Walk traverses all rules in the SuffixTrie and invokes fn for each rule.
func (t *SuffixTrie) Walk(fn func(domain, rule string)) {
	if t == nil || t.root == nil {
		return
	}
	var walk func(n *trieNode, labels []string)
	walk = func(n *trieNode, labels []string) {
		if n.isEnd {
			parts := make([]string, len(labels))
			for i, l := range labels {
				parts[len(labels)-1-i] = l
			}
			fn(strings.Join(parts, "."), n.rule)
		}
		for label, child := range n.children {
			walk(child, append(labels, label))
		}
	}
	walk(t.root, nil)
}

// Merge copies all rules from other into t.
func (t *SuffixTrie) Merge(other *SuffixTrie) {
	if other == nil {
		return
	}
	other.Walk(func(domain, rule string) {
		t.Insert(domain, rule)
	})
}

// splitDomainReversed cleans domain and splits it into labels in reversed order.
// e.g. "pagead2.doubleclick.net." -> ["net", "doubleclick", "pagead2"]
func splitDomainReversed(domain string) []string {
	domain = normalizeDomain(domain)
	if domain == "" {
		return nil
	}
	parts := strings.Split(domain, ".")
	// Reverse parts
	n := len(parts)
	rev := make([]string, n)
	for i, part := range parts {
		if part == "" {
			return nil
		}
		rev[n-1-i] = part
	}
	return rev
}

func normalizeDomain(domain string) string {
	return strings.Trim(strings.ToLower(strings.TrimSpace(domain)), ".")
}

// ExactMap holds domain rules requiring exact string equality.
type ExactMap struct {
	rules map[string]string
}

// NewExactMap creates an empty exact match map.
func NewExactMap() *ExactMap {
	return &ExactMap{
		rules: make(map[string]string),
	}
}

// Set sets a domain exact match rule.
func (m *ExactMap) Set(domain, rule string) {
	d := normalizeDomain(domain)
	if d != "" {
		m.rules[d] = rule
	}
}

// Match checks whether domain matches any exact rule.
func (m *ExactMap) Match(domain string) (bool, string) {
	d := normalizeDomain(domain)
	if d == "" {
		return false, ""
	}
	rule, ok := m.rules[d]
	return ok, rule
}

// Merge copies all rules from other into m.
func (m *ExactMap) Merge(other *ExactMap) {
	if m == nil || other == nil {
		return
	}
	for k, v := range other.rules {
		m.rules[k] = v
	}
}

// Len returns the number of entries in the exact map.
func (m *ExactMap) Len() int {
	if m == nil {
		return 0
	}
	return len(m.rules)
}

// Count returns the number of rule endpoints in the suffix trie in O(1) time.
func (t *SuffixTrie) Count() int {
	if t == nil {
		return 0
	}
	return t.count
}
