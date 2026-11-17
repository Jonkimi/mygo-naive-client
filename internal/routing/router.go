package routing

import (
	"net"
	"strings"

	"naive-client/internal/geodata"
)

type ActionType string

const (
	ActionDirect       ActionType = "DIRECT"
	ActionProxyPool    ActionType = "PROXY_POOL"
	ActionProxyTag     ActionType = "PROXY_TAG"
	ActionProxyService ActionType = "PROXY_SERVICE"
	ActionBlock        ActionType = "BLOCK"
	ActionTailnet      ActionType = "TAILNET"
	ActionTailnetExit  ActionType = "TAILNET_EXIT"
	ActionWarp         ActionType = "WARP"
)

var privateLANSubnets []*net.IPNet

func init() {
	cidrs := []string{
		"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"169.254.0.0/16", "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10",
	}
	for _, c := range cidrs {
		if _, ipNet, err := net.ParseCIDR(c); err == nil {
			privateLANSubnets = append(privateLANSubnets, ipNet)
		}
	}
}

func isPrivateLANIP(ip net.IP) bool {
	for _, n := range privateLANSubnets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func isLocalDomain(host string) bool {
	for _, s := range []string{"local", "localhost", "internal", "lan", "home.arpa"} {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

type TargetKind string

const (
	TargetNode TargetKind = "node"
	TargetTag  TargetKind = "tag"
)

type TargetRef struct {
	Kind  TargetKind `json:"kind"`
	Value string     `json:"value"`
}

const (
	DispatchSmart       = "smart"
	DispatchOrder       = "order"
	BuiltinWarpTargetID = "builtin-warp"
)

type RouteAction struct {
	Type           ActionType  `json:"type"`
	Tag            string      `json:"tag,omitempty"`
	Tags           []string    `json:"tags,omitempty"`
	ServiceID      string      `json:"serviceId,omitempty"`
	ExitNode       string      `json:"exitNode,omitempty"`
	Targets        []TargetRef `json:"targets,omitempty"`
	DispatchPolicy string      `json:"dispatchPolicy,omitempty"`
	FallbackToPool bool        `json:"fallbackToPool,omitempty"`
}

// NormalizeTargets cleans and deduplicates target refs while preserving declaration order.
func NormalizeTargets(targets []TargetRef) []TargetRef {
	if len(targets) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(targets))
	out := make([]TargetRef, 0, len(targets))
	for _, t := range targets {
		kind := TargetKind(strings.ToLower(strings.TrimSpace(string(t.Kind))))
		val := strings.TrimSpace(t.Value)
		if kind == TargetTag {
			val = strings.TrimSpace(strings.TrimPrefix(val, "#"))
		}
		if val == "" || (kind != TargetNode && kind != TargetTag) {
			continue
		}
		dedupKey := string(kind) + ":" + val
		if kind == TargetTag {
			dedupKey = string(kind) + ":" + strings.ToLower(val)
		}
		if seen[dedupKey] {
			continue
		}
		seen[dedupKey] = true
		out = append(out, TargetRef{Kind: kind, Value: val})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// NormalizedTargets returns the ordered list of node/tag targets for this action,
// seamlessly normalizing legacy ActionProxyTag, ActionProxyService, and ActionWarp fields.
func (a RouteAction) NormalizedTargets() []TargetRef {
	if len(a.Targets) > 0 {
		return NormalizeTargets(a.Targets)
	}
	switch a.Type {
	case ActionWarp:
		return []TargetRef{{Kind: TargetNode, Value: BuiltinWarpTargetID}}
	case ActionProxyService:
		if svcID := strings.TrimSpace(a.ServiceID); svcID != "" {
			return []TargetRef{{Kind: TargetNode, Value: svcID}}
		}
	case ActionProxyTag:
		var out []TargetRef
		for _, t := range a.legacyTags() {
			out = append(out, TargetRef{Kind: TargetTag, Value: t})
		}
		return NormalizeTargets(out)
	}
	return nil
}

// EffectiveDispatchPolicy returns "order" if explicitly set, otherwise "smart".
func (a RouteAction) EffectiveDispatchPolicy() string {
	if strings.EqualFold(strings.TrimSpace(a.DispatchPolicy), DispatchOrder) {
		return DispatchOrder
	}
	return DispatchSmart
}

// IsProxyAction reports whether this action routes traffic through proxy/WARP outbounds.
func (a RouteAction) IsProxyAction() bool {
	switch a.Type {
	case ActionProxyPool, ActionProxyTag, ActionProxyService, ActionWarp:
		return true
	case ActionDirect, ActionBlock, ActionTailnet, ActionTailnetExit:
		return false
	default:
		return len(a.Targets) > 0
	}
}

// TargetsNode reports whether the normalized target list explicitly includes nodeID.
func (a RouteAction) TargetsNode(nodeID string) bool {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return false
	}
	for _, t := range a.NormalizedTargets() {
		if t.Kind == TargetNode && t.Value == nodeID {
			return true
		}
	}
	return false
}

// NewProxyAction constructs a unified proxy RouteAction from ordered targets, dispatch policy, and fallback setting.
func NewProxyAction(targets []TargetRef, policy string, fallbackToPool bool) RouteAction {
	clean := NormalizeTargets(targets)
	if len(clean) == 0 {
		return RouteAction{Type: ActionProxyPool}
	}
	act := RouteAction{
		Type:           ActionProxyPool,
		Targets:        clean,
		FallbackToPool: fallbackToPool,
	}
	if strings.EqualFold(strings.TrimSpace(policy), DispatchOrder) {
		act.DispatchPolicy = DispatchOrder
	}
	return act
}

// NewWarpTargetAction constructs a RouteAction targeting the built-in Cloudflare WARP node.
func NewWarpTargetAction() RouteAction {
	return NewProxyAction([]TargetRef{{Kind: TargetNode, Value: BuiltinWarpTargetID}}, DispatchSmart, false)
}

func (a RouteAction) legacyTags() []string {
	if len(a.Tags) > 0 {
		return a.Tags
	}
	if a.Tag != "" {
		return []string{a.Tag}
	}
	return nil
}

func (a RouteAction) GetTags() []string {
	if len(a.Targets) > 0 {
		var tags []string
		for _, t := range a.NormalizedTargets() {
			if t.Kind == TargetTag {
				tags = append(tags, t.Value)
			}
		}
		return tags
	}
	return a.legacyTags()
}

type Rule struct {
	ID            string      `json:"id"`
	Name          string      `json:"name"`
	Description   string      `json:"description,omitempty"`
	Enabled       bool        `json:"enabled"`
	DomainSuffix  []string    `json:"domainSuffix,omitempty"`
	DomainKeyword []string    `json:"domainKeyword,omitempty"`
	DomainFull    []string    `json:"domainFull,omitempty"`
	IPCidr        []string    `json:"ipCidr,omitempty"`
	GeoSite       []string    `json:"geoSite,omitempty"`
	GeoIP         []string    `json:"geoIP,omitempty"`
	Action        RouteAction `json:"action"`
}

type parsedCIDRRule struct {
	ipNet  *net.IPNet
	rule   *Rule
}

type Router struct {
	rules       []Rule
	finalAction RouteAction
	parsedNets  []parsedCIDRRule
	geoIP       *geodata.GeoIPDB
	geoSite     *geodata.GeoSiteDB
}

func (r *Router) SetGeoData(ipDB *geodata.GeoIPDB, siteDB *geodata.GeoSiteDB) {
	r.geoIP = ipDB
	r.geoSite = siteDB
}

// PrioritizedRules returns a slice of rules where custom rules (non-preset) are ordered
// before preset rules, ensuring custom rules evaluate with higher priority across all engines.
func PrioritizedRules(rules []Rule) []Rule {
	var ordered []Rule
	for _, r := range rules {
		if !strings.HasPrefix(r.ID, "preset-") {
			ordered = append(ordered, r)
		}
	}
	for _, r := range rules {
		if strings.HasPrefix(r.ID, "preset-") {
			ordered = append(ordered, r)
		}
	}
	return ordered
}

func NewRouter(rules []Rule, finalAction RouteAction) *Router {
	if finalAction.Type == "" {
		finalAction = RouteAction{Type: ActionProxyPool}
	}
	ordered := PrioritizedRules(rules)
	r := &Router{
		rules:       ordered,
		finalAction: finalAction,
	}
	r.compile()
	return r
}

func (r *Router) compile() {
	r.parsedNets = nil
	for i := range r.rules {
		rule := &r.rules[i]
		if !rule.Enabled {
			continue
		}
		for _, cidr := range rule.IPCidr {
			cidr = strings.TrimSpace(cidr)
			if cidr == "" {
				continue
			}
			if !strings.Contains(cidr, "/") {
				if ip := net.ParseIP(cidr); ip != nil {
					if ip.To4() != nil {
						cidr += "/32"
					} else {
						cidr += "/128"
					}
				}
			}
			if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
				r.parsedNets = append(r.parsedNets, parsedCIDRRule{
					ipNet: ipNet,
					rule:  rule,
				})
			}
		}
	}
}

func (r *Router) Match(target string) (RouteAction, string) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	host = strings.TrimSpace(strings.ToLower(host))

	resolveAction := func(act RouteAction, ip net.IP, host string) RouteAction {
		if act.Type == ActionWarp {
			if ip != nil && isPrivateLANIP(ip) {
				return RouteAction{Type: ActionDirect}
			}
			if isLocalDomain(host) {
				return RouteAction{Type: ActionDirect}
			}
		}
		return act
	}

	// Check if host is an IP
	if ip := net.ParseIP(host); ip != nil {
		for _, item := range r.parsedNets {
			if item.ipNet.Contains(ip) {
				return resolveAction(item.rule.Action, ip, host), item.rule.Name
			}
		}
		if r.geoIP != nil {
			for i := range r.rules {
				rule := &r.rules[i]
				if !rule.Enabled {
					continue
				}
				for _, tag := range rule.GeoIP {
					if r.geoIP.MatchIP(tag, ip) {
						return resolveAction(rule.Action, ip, host), rule.Name
					}
				}
			}
		}
		return resolveAction(r.finalAction, ip, host), "Final"
	}

	// Host is a domain name
	for i := range r.rules {
		rule := &r.rules[i]
		if !rule.Enabled {
			continue
		}

		// 1. Full domain match
		for _, d := range rule.DomainFull {
			if strings.EqualFold(host, strings.TrimSpace(d)) {
				return resolveAction(rule.Action, nil, host), rule.Name
			}
		}

		// 2. Domain suffix match
		for _, s := range rule.DomainSuffix {
			s = strings.TrimSpace(strings.ToLower(s))
			if s == "" {
				continue
			}
			if host == s || strings.HasSuffix(host, "."+s) {
				return resolveAction(rule.Action, nil, host), rule.Name
			}
		}

		// 3. Domain keyword match
		for _, kw := range rule.DomainKeyword {
			kw = strings.TrimSpace(strings.ToLower(kw))
			if kw != "" && strings.Contains(host, kw) {
				return resolveAction(rule.Action, nil, host), rule.Name
			}
		}

		// 4. GeoSite match
		if r.geoSite != nil {
			for _, tag := range rule.GeoSite {
				if r.geoSite.MatchDomain(tag, host) {
					return resolveAction(rule.Action, nil, host), rule.Name
				}
			}
		}
	}

	return resolveAction(r.finalAction, nil, host), "Final"
}

func DefaultPresets() []Rule {
	return []Rule{
		{
			ID:          "preset-block-ads",
			Name:        "广告拦截",
			Description: "拦截常见广告、追踪统计与恶意分析域名",
			Enabled:     true,
			GeoSite:     []string{"category-ads-all"},
			Action:      RouteAction{Type: ActionBlock},
		},
		{
			ID:          "preset-ai-services",
			Name:        "AI 服务",
			Description: "将 OpenAI、Claude、Copilot 等 AI 流量调度至高速 AI 节点池",
			Enabled:     true,
			GeoSite:     []string{"category-ai-!cn", "openai"},
			Action:      RouteAction{Type: ActionProxyTag, Tag: "AI", Tags: []string{"AI"}},
		},
		{
			ID:          "preset-streaming",
			Name:        "流媒体服务",
			Description: "将 YouTube、Netflix、Spotify、Disney+ 调度至流媒体节点池",
			Enabled:     true,
			GeoSite:     []string{"netflix", "youtube", "spotify"},
			Action:      RouteAction{Type: ActionProxyTag, Tag: "Media", Tags: []string{"Media"}},
		},
		{
			ID:          "preset-gfw",
			Name:        "GFW 专线",
			Description: "加速受 GFW 阻断的境外网站与服务",
			Enabled:     true,
			GeoSite:     []string{"gfw"},
			Action:      RouteAction{Type: ActionProxyTag, Tag: "GFW", Tags: []string{"GFW"}},
		},
		{
			ID:          "preset-lan-direct",
			Name:        "局域网直连",
			Description: "局域网、内网与本地主机域名直连，不走代理",
			Enabled:     true,
			GeoIP:       []string{"private"},
			IPCidr: []string{
				"127.0.0.0/8",
				"10.0.0.0/8",
				"172.16.0.0/12",
				"192.168.0.0/16",
				"169.254.0.0/16",
				"::1/128",
				"fc00::/7",
				"fe80::/10",
			},
			DomainSuffix: []string{
				"local",
				"localhost",
				"internal",
				"lan",
			},
			Action: RouteAction{Type: ActionDirect},
		},
		{
			ID:          "preset-cn-direct",
			Name:        "大陆直连",
			Description: "中国大陆域名与 IP 直连（可编辑为 WARP 或指定节点）",
			Enabled:     true,
			GeoSite:     []string{"cn"},
			GeoIP:       []string{"cn"},
			Action:      RouteAction{Type: ActionDirect},
		},
	}
}
