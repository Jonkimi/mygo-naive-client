package routing

import (
	"net"
	"strings"
)

type ActionType string

const (
	ActionDirect       ActionType = "DIRECT"
	ActionProxyPool    ActionType = "PROXY_POOL"
	ActionProxyTag     ActionType = "PROXY_TAG"
	ActionProxyService ActionType = "PROXY_SERVICE"
	ActionBlock        ActionType = "BLOCK"
)

type RouteAction struct {
	Type      ActionType `json:"type"`
	Tag       string     `json:"tag,omitempty"`
	ServiceID string     `json:"serviceId,omitempty"`
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
}

func NewRouter(rules []Rule, finalAction RouteAction) *Router {
	if finalAction.Type == "" {
		finalAction = RouteAction{Type: ActionProxyPool}
	}
	r := &Router{
		rules:       rules,
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
	}

	return r.finalAction, "Final"
}

func DefaultPresets() []Rule {
	return []Rule{
		{
			ID:          "preset-block-ads",
			Name:        "广告拦截 (Ad Blocker)",
			Description: "拦截常见广告、追踪统计与恶意分析域名",
			Enabled:     true,
			DomainSuffix: []string{
				"doubleclick.net",
				"googleadservices.com",
				"adservice.google.com",
				"pagead2.googlesyndication.com",
				"unityads.unity3d.com",
			},
			Action: RouteAction{Type: ActionBlock},
		},
		{
			ID:          "preset-ai-services",
			Name:        "AI 与大模型服务",
			Description: "将 OpenAI、Claude、Copilot 等 AI 流量调度至高速 AI 节点池",
			Enabled:     true,
			DomainSuffix: []string{
				"openai.com",
				"chatgpt.com",
				"oaistatic.com",
				"oaiusercontent.com",
				"anthropic.com",
				"claude.ai",
				"meta.ai",
				"copilot.microsoft.com",
				"perplex.ai",
				"perplexity.ai",
			},
			Action: RouteAction{Type: ActionProxyTag, Tag: "AI"},
		},
		{
			ID:          "preset-streaming",
			Name:        "流媒体加速",
			Description: "将 YouTube、Netflix、Spotify、Disney+ 调度至流媒体节点池",
			Enabled:     true,
			DomainSuffix: []string{
				"netflix.com",
				"nflxvideo.net",
				"youtube.com",
				"googlevideo.com",
				"ytimg.com",
				"spotify.com",
				"scdn.co",
				"disneyplus.com",
			},
			Action: RouteAction{Type: ActionProxyTag, Tag: "Media"},
		},
		{
			ID:          "preset-telegram",
			Name:        "Telegram 专线",
			Description: "加速 Telegram 消息与媒体收发",
			Enabled:     true,
			DomainSuffix: []string{
				"telegram.org",
				"t.me",
				"telegra.ph",
				"tdesktop.com",
			},
			Action: RouteAction{Type: ActionProxyTag, Tag: "TG"},
		},
		{
			ID:          "preset-lan-direct",
			Name:        "绕过局域网与私有地址",
			Description: "本地与私有网段直连，不走代理",
			Enabled:     true,
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
	}
}
