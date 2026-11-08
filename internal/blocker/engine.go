package blocker

import (
	"strings"
	"sync"
	"sync/atomic"
)

const (
	RuleTailnetBypass      = "tailnet-bypass"
	RuleUserAllowlist      = "user-allowlist"
	RuleSubscriptionExempt = "subscription-exempt"
	RuleUserDenylist       = "user-denylist"
)

// CompiledRuleset contains immutable compiled rules for atomic hot-swapping.
type CompiledRuleset struct {
	BlockExact *ExactMap
	BlockTrie  *SuffixTrie
	ExemptTrie *SuffixTrie
	GeoAds     DomainMatcher
}

func NewCompiledRuleset(parsed *ParsedRules) *CompiledRuleset {
	if parsed == nil {
		parsed = NewParsedRules()
	}
	return &CompiledRuleset{
		BlockExact: parsed.BlockExact,
		BlockTrie:  parsed.BlockTrie,
		ExemptTrie: parsed.ExemptTrie,
		GeoAds:     parsed.GeoAds,
	}
}

// Options configures the blocker Engine.
type Options struct {
	Ruleset   *ParsedRules
	Allowlist []string
	Denylist  []string
	Disabled  bool
}

// Engine implements high-performance domain matching with atomic ruleset updates.
type Engine struct {
	ruleset   atomic.Pointer[CompiledRuleset]
	allowMu   sync.RWMutex
	userAllow map[string]bool
	denyMu    sync.RWMutex
	userDeny  map[string]bool
	enabled   atomic.Bool

	onUpdateMu sync.RWMutex
	onUpdate   func()

	// Query telemetry hooks (configured in Seam 3)
	logger *QueryLogger
}

// NewEngine initializes a blocker Engine.
func NewEngine(opts Options) *Engine {
	e := &Engine{
		userAllow: make(map[string]bool),
		userDeny:  make(map[string]bool),
		logger:    NewQueryLogger(2000),
	}
	e.enabled.Store(!opts.Disabled)

	rs := NewCompiledRuleset(opts.Ruleset)
	e.ruleset.Store(rs)

	for _, d := range opts.Allowlist {
		e.AddAllowlist(d)
	}
	for _, d := range opts.Denylist {
		e.AddDenylist(d)
	}

	return e
}

// RuleCount returns the total number of compiled blocking rules.
func (e *Engine) RuleCount() int {
	rs := e.ruleset.Load()
	if rs == nil {
		return 0
	}
	c := 0
	if rs.BlockExact != nil {
		c += rs.BlockExact.Len()
	}
	if rs.BlockTrie != nil {
		c += rs.BlockTrie.Count()
	}
	if rs.GeoAds != nil {
		c += rs.GeoAds.TagRuleCount("category-ads-all")
	}
	return c
}

// sourceAdapter adapts Engine to a specific QuerySource while implementing Blocker.
type sourceAdapter struct {
	engine *Engine
	source QuerySource
}

func (a *sourceAdapter) Match(domain string) (bool, string) {
	return a.engine.EvaluateAndLog(domain, a.source)
}

// AsDNS returns a Blocker adapter that logs queries with SourceDNS.
func (e *Engine) AsDNS() Blocker {
	return &sourceAdapter{engine: e, source: SourceDNS}
}

// AsGateway returns a Blocker adapter that logs queries with SourceGateway.
func (e *Engine) AsGateway() Blocker {
	return &sourceAdapter{engine: e, source: SourceGateway}
}

// Logger returns the query telemetry logger.
func (e *Engine) Logger() *QueryLogger {
	return e.logger
}

// EvaluateAndLog evaluates domain against rules and records telemetry into logger.
func (e *Engine) EvaluateAndLog(domain string, source QuerySource) (bool, string) {
	return e.EvaluateAndLogWithChain(domain, source, "")
}

// EvaluateAndLogWithChain evaluates domain against rules and records telemetry with chain into logger.
func (e *Engine) EvaluateAndLogWithChain(domain string, source QuerySource, chain string) (bool, string) {
	blocked, rule, verdict := e.Evaluate(domain)
	if e.logger != nil {
		e.logger.RecordWithChain(domain, source, verdict, rule, chain)
	}
	return blocked, rule
}

// SetOnUpdate registers a callback that is notified whenever rules, allowlists, or denylists change.
func (e *Engine) SetOnUpdate(fn func()) {
	e.onUpdateMu.Lock()
	e.onUpdate = fn
	e.onUpdateMu.Unlock()
}

func (e *Engine) notifyUpdate() {
	e.onUpdateMu.RLock()
	fn := e.onUpdate
	e.onUpdateMu.RUnlock()
	if fn != nil {
		fn()
	}
}

// SetEnabled enables or disables domain blocking.
func (e *Engine) SetEnabled(enabled bool) {
	e.enabled.Store(enabled)
	e.notifyUpdate()
}

// IsEnabled reports whether blocking is active.
func (e *Engine) IsEnabled() bool {
	return e.enabled.Load()
}

// SwapRuleset atomically hot-replaces the compiled subscription ruleset.
func (e *Engine) SwapRuleset(parsed *ParsedRules) {
	e.ruleset.Store(NewCompiledRuleset(parsed))
	e.notifyUpdate()
}

// AddAllowlist adds a domain to the user allowlist.
func (e *Engine) AddAllowlist(domain string) {
	d := normalizeDomain(domain)
	if d == "" {
		return
	}
	e.allowMu.Lock()
	e.userAllow[d] = true
	e.allowMu.Unlock()
	e.notifyUpdate()
}

// RemoveAllowlist removes a domain from the user allowlist.
func (e *Engine) RemoveAllowlist(domain string) {
	d := normalizeDomain(domain)
	if d == "" {
		return
	}
	e.allowMu.Lock()
	delete(e.userAllow, d)
	e.allowMu.Unlock()
	e.notifyUpdate()
}

// GetAllowlist returns a copy of current user allowlist domains.
func (e *Engine) GetAllowlist() []string {
	e.allowMu.RLock()
	defer e.allowMu.RUnlock()
	res := make([]string, 0, len(e.userAllow))
	for d := range e.userAllow {
		res = append(res, d)
	}
	return res
}

// AddDenylist adds a domain to the user denylist.
func (e *Engine) AddDenylist(domain string) {
	d := normalizeDomain(domain)
	if d == "" {
		return
	}
	e.denyMu.Lock()
	e.userDeny[d] = true
	e.denyMu.Unlock()
	e.notifyUpdate()
}

// RemoveDenylist removes a domain from the user denylist.
func (e *Engine) RemoveDenylist(domain string) {
	d := normalizeDomain(domain)
	if d == "" {
		return
	}
	e.denyMu.Lock()
	delete(e.userDeny, d)
	e.denyMu.Unlock()
	e.notifyUpdate()
}

// GetDenylist returns a copy of current user denylist domains.
func (e *Engine) GetDenylist() []string {
	e.denyMu.RLock()
	defer e.denyMu.RUnlock()
	res := make([]string, 0, len(e.userDeny))
	for d := range e.userDeny {
		res = append(res, d)
	}
	return res
}

func (e *Engine) matchesUserMap(m map[string]bool, domain string) bool {
	if m[domain] {
		return true
	}
	// Check parent suffix: e.g. "sub.example.com" matches "example.com"
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		if m[parent] {
			return true
		}
	}
	return false
}

// Match evaluates a domain against the 5-tier strict priority:
// 1. Tailnet (*.ts.net)
// 2. User Allowlist
// 3. Subscription Exemptions (@@||)
// 4. User Denylist
// 5. External Subscriptions & Built-in Rules
func (e *Engine) Match(domain string) (blocked bool, rule string) {
	blocked, rule, _ = e.Evaluate(domain)
	return blocked, rule
}

// ShouldBlock reports whether the domain matches any blocking rule.
func (e *Engine) ShouldBlock(domain string) bool {
	if e == nil {
		return false
	}
	blocked, _ := e.Match(domain)
	return blocked
}

// Evaluate evaluates a domain and returns (blocked, rule, verdict).
func (e *Engine) Evaluate(domain string) (blocked bool, rule string, verdict Verdict) {
	d := normalizeDomain(domain)
	if d == "" {
		return false, "", VerdictAllowed
	}

	if !e.enabled.Load() {
		return false, "", VerdictAllowed
	}

	// 1. Tailnet bypass
	if strings.HasSuffix(d, ".ts.net") || d == "ts.net" {
		return false, RuleTailnetBypass, VerdictAllowed
	}

	// 2. User Allowlist
	e.allowMu.RLock()
	inAllow := e.matchesUserMap(e.userAllow, d)
	e.allowMu.RUnlock()
	if inAllow {
		return false, RuleUserAllowlist, VerdictWhitelisted
	}

	rs := e.ruleset.Load()

	// 3. Subscription Exemption (@@||)
	if rs != nil && rs.ExemptTrie != nil {
		if matched, r := rs.ExemptTrie.Match(d); matched {
			if r == "" {
				r = RuleSubscriptionExempt
			}
			return false, r, VerdictWhitelisted
		}
	}

	// 4. User Denylist
	e.denyMu.RLock()
	inDeny := e.matchesUserMap(e.userDeny, d)
	e.denyMu.RUnlock()
	if inDeny {
		return true, RuleUserDenylist, VerdictBlocked
	}

	// 5. External Subscriptions & Built-in Rules
	if rs != nil {
		if rs.GeoAds != nil && rs.GeoAds.MatchDomain("category-ads-all", d) {
			return true, "category-ads-all", VerdictBlocked
		}
		if rs.BlockExact != nil {
			if matched, r := rs.BlockExact.Match(d); matched {
				return true, r, VerdictBlocked
			}
		}
		if rs.BlockTrie != nil {
			if matched, r := rs.BlockTrie.Match(d); matched {
				return true, r, VerdictBlocked
			}
		}
	}

	return false, "", VerdictAllowed
}
