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
)

type RouteAction struct {
	Type      ActionType `json:"type"`
	Tag       string     `json:"tag,omitempty"`
	Tags      []string   `json:"tags,omitempty"`
	ServiceID string     `json:"serviceId,omitempty"`
	ExitNode  string     `json:"exitNode,omitempty"`
}

func (a RouteAction) GetTags() []string {
	if len(a.Tags) > 0 {
		return a.Tags
	}
	if a.Tag != "" {
		return []string{a.Tag}
	}
	return nil
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

	// Check if host is an IP
	if ip := net.ParseIP(host); ip != nil {
		for _, item := range r.parsedNets {
			if item.ipNet.Contains(ip) {
				return item.rule.Action, item.rule.Name
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
						return rule.Action, rule.Name
					}
				}
			}
		}
		return r.finalAction, "Final"
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
				return rule.Action, rule.Name
			}
		}

		// 2. Domain suffix match
		for _, s := range rule.DomainSuffix {
			s = strings.TrimSpace(strings.ToLower(s))
			if s == "" {
				continue
			}
			if host == s || strings.HasSuffix(host, "."+s) {
				return rule.Action, rule.Name
			}
		}

		// 3. Domain keyword match
		for _, kw := range rule.DomainKeyword {
			kw = strings.TrimSpace(strings.ToLower(kw))
			if kw != "" && strings.Contains(host, kw) {
				return rule.Action, rule.Name
			}
		}

		// 4. GeoSite match
		if r.geoSite != nil {
			for _, tag := range rule.GeoSite {
				if r.geoSite.MatchDomain(tag, host) {
					return rule.Action, rule.Name
				}
			}
		}
	}

	return r.finalAction, "Final"
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
			Name:        "直连",
			Description: "直连，不走代理",
			Enabled:     true,
			GeoSite:     []string{"cn"},
			GeoIP:       []string{"cn", "private"},
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
			Action:      RouteAction{Type: ActionDirect},
		},
	}
}
