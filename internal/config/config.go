package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Service describes a local NaiveProxy instance managed by the client.
// Its fields map directly to klzgrad/naiveproxy's USAGE.txt options.
type Service struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	AutoStart bool   `json:"autoStart,omitempty"`

	// Listen URIs: <LISTEN-PROTO>"://"[<USER>":"<PASS>"@"][<ADDR>][":"<PORT>]
	// LISTEN-PROTO = "socks" | "http" | "redir"
	// At least one listen entry is used; when multiple are specified, they emit
	// a JSON array in config.json.
	Listens []string `json:"listens"`

	// Proxy chains or URIs: <PROXY-PROTO>"://"[<USER>":"<PASS>"@"]<HOSTNAME>[":"<PORT>]
	// PROXY-PROTO = "http" | "https" | "quic" | "socks"
	// When multiple are specified, they must match the number of Listens.
	Proxies []string `json:"proxies"`

	// Advanced options from USAGE.txt
	InsecureConcurrency int    `json:"insecureConcurrency,omitempty"` // --insecure-concurrency=<N> (1..4 recommended)
	TunnelTimeout       int    `json:"tunnelTimeout,omitempty"`       // --tunnel-timeout=<SECONDS>
	IdleTimeout         int    `json:"idleTimeout,omitempty"`         // --idle-timeout=<SECONDS>
	ExtraHeaders        string `json:"extraHeaders,omitempty"`        // --extra-headers=... (CRLF separated)
	HostResolverRules   string `json:"hostResolverRules,omitempty"`   // --host-resolver-rules="MAP proxy.example.com 1.2.3.4"
	ResolverRange       string `json:"resolverRange,omitempty"`       // --resolver-range=CIDR
	EnableLog           bool   `json:"enableLog,omitempty"`           // --log (empty path prints to console for live log capture)
	LogFile             string `json:"logFile,omitempty"`             // --log=<path> (optional file path)
	LogNetLog           string `json:"logNetLog,omitempty"`           // --log-net-log=<path>
	SSLKeyLogFile       string `json:"sslKeyLogFile,omitempty"`       // --ssl-key-log-file=<path>
	NoPostQuantum       bool   `json:"noPostQuantum,omitempty"`       // --no-post-quantum

	// ExtraJSON holds optional raw JSON key-values merged into the generated config.json.
	ExtraJSON string `json:"extraJson,omitempty"`
}

// DefaultService returns a new Service pre-filled with sensible defaults.
func DefaultService(id string, port int) Service {
	if port <= 0 {
		port = 1080
	}
	return Service{
		ID:        id,
		Name:      fmt.Sprintf("Naive-%d", port),
		Listens:   []string{fmt.Sprintf("socks://127.0.0.1:%d", port)},
		Proxies:   []string{"https://user:pass@example.com"},
		EnableLog: true,
	}
}

// PrimaryListen returns the first non-empty listen URI, or the default "socks://127.0.0.1:1080".
func (s Service) PrimaryListen() string {
	for _, l := range s.Listens {
		if trimmed := strings.TrimSpace(l); trimmed != "" {
			return trimmed
		}
	}
	return "socks://127.0.0.1:1080"
}

// PrimaryProxy returns the first non-empty proxy URI.
func (s Service) PrimaryProxy() string {
	for _, p := range s.Proxies {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// RedactedProxy returns a display-safe summary of the primary proxy (hiding password).
func (s Service) RedactedProxy() string {
	raw := s.PrimaryProxy()
	if raw == "" {
		return "直连 (无代理)"
	}
	// If it's a proxy chain (comma-separated), redact each hop.
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		u, err := url.Parse(part)
		if err != nil || u.Scheme == "" || u.Host == "" {
			out = append(out, part)
			continue
		}
		if u.User != nil {
			username := u.User.Username()
			if username != "" {
				u.User = nil
				out = append(out, fmt.Sprintf("%s://%s:***@%s", u.Scheme, username, u.Host))
				continue
			}
		}
		out = append(out, fmt.Sprintf("%s://%s", u.Scheme, u.Host))
	}
	return strings.Join(out, " -> ")
}

// ListenEndpoint parses a listen URI into protocol, host, and port.
// According to USAGE.txt:
// LISTEN-URI = <LISTEN-PROTO>"://"[<USER>":"<PASS>"@"][<ADDR>][":"<PORT>]
// Default proto, addr, port: socks, 0.0.0.0, 1080.
type ListenEndpoint struct {
	Proto string
	User  string
	Pass  string
	Addr  string
	Port  int
}

// DialAddr returns the local address suitable for dialing from this machine
// (converting 0.0.0.0 or empty addr to 127.0.0.1).
func (e ListenEndpoint) DialAddr() string {
	host := e.Addr
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, strconv.Itoa(e.Port))
}

// ListenAddr returns the address suitable for net.Listen pre-check.
func (e ListenEndpoint) ListenAddr() string {
	host := e.Addr
	if host == "" {
		host = "0.0.0.0"
	}
	return net.JoinHostPort(host, strconv.Itoa(e.Port))
}

// ParseListenURI parses a NaiveProxy listen URI according to USAGE.txt.
func ParseListenURI(raw string) (ListenEndpoint, error) {
	raw = strings.TrimSpace(raw)
	ep := ListenEndpoint{
		Proto: "socks",
		Addr:  "0.0.0.0",
		Port:  1080,
	}
	if raw == "" {
		return ep, nil
	}
	idx := strings.Index(raw, "://")
	if idx < 0 {
		return ep, fmt.Errorf("监听地址缺少协议前缀 (例如 socks://127.0.0.1:1080): %q", raw)
	}
	proto := strings.ToLower(raw[:idx])
	switch proto {
	case "socks", "http", "redir":
		ep.Proto = proto
	default:
		return ep, fmt.Errorf("不支持的监听协议 %q (仅支持 socks, http, redir)", proto)
	}
	rest := raw[idx+3:]
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		userinfo := rest[:at]
		rest = rest[at+1:]
		if colon := strings.Index(userinfo, ":"); colon >= 0 {
			ep.User = userinfo[:colon]
			ep.Pass = userinfo[colon+1:]
		} else {
			ep.User = userinfo
		}
	}
	rest = strings.TrimSuffix(rest, "/")
	if rest == "" {
		return ep, nil
	}
	if strings.HasPrefix(rest, ":") {
		port, err := strconv.Atoi(rest[1:])
		if err != nil || port <= 0 || port > 65535 {
			return ep, fmt.Errorf("无效的监听端口: %q", rest[1:])
		}
		ep.Port = port
		return ep, nil
	}
	host, portStr, err := net.SplitHostPort(rest)
	if err == nil {
		if host != "" {
			ep.Addr = host
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			return ep, fmt.Errorf("无效的监听端口: %q", portStr)
		}
		ep.Port = port
		return ep, nil
	}
	// No port specified, treat rest as host.
	ep.Addr = strings.Trim(rest, "[]")
	return ep, nil
}

// Validate checks whether the service configuration satisfies USAGE.txt rules.
func (s Service) Validate() error {
	if strings.TrimSpace(s.Name) == "" {
		return errors.New("服务名称不能为空")
	}
	listens := cleanSlice(s.Listens)
	if len(listens) == 0 {
		return errors.New("至少需要配置一个本地监听地址 (listen)")
	}
	for _, l := range listens {
		if _, err := ParseListenURI(l); err != nil {
			return err
		}
	}
	proxies := cleanSlice(s.Proxies)
	if len(proxies) > 1 && len(proxies) != len(listens) {
		return fmt.Errorf("当配置多个远端代理 (%d 个) 时，数量必须与本地监听地址 (%d 个) 一致", len(proxies), len(listens))
	}
	for _, chain := range proxies {
		if err := ValidateProxyChain(chain); err != nil {
			return err
		}
	}
	if s.InsecureConcurrency < 0 {
		return errors.New("并发连接数 (insecure-concurrency) 不能为负数")
	}
	if s.ExtraJSON != "" {
		var extra map[string]any
		if err := json.Unmarshal([]byte(s.ExtraJSON), &extra); err != nil {
			return fmt.Errorf("额外 JSON 参数格式错误: %w", err)
		}
	}
	return nil
}

// ValidateProxyChain validates a proxy or comma-separated proxy chain according to USAGE.txt.
func ValidateProxyChain(chain string) error {
	chain = strings.TrimSpace(chain)
	if chain == "" {
		return errors.New("远端代理地址不能为空")
	}
	hops := strings.Split(chain, ",")
	seenTCP := false
	for i, hop := range hops {
		hop = strings.TrimSpace(hop)
		u, err := url.Parse(hop)
		if err != nil || u.Scheme == "" || u.Hostname() == "" {
			return fmt.Errorf("无效的代理地址 %q (格式应为 https://user:pass@example.com)", hop)
		}
		scheme := strings.ToLower(u.Scheme)
		switch scheme {
		case "https", "http":
			seenTCP = true
		case "quic":
			if seenTCP {
				return errors.New("代理链限制：QUIC 代理不能排在基于 TCP 的代理 (http/https) 之后")
			}
		case "socks":
			if len(hops) > 1 {
				return errors.New("代理链限制：SOCKS 远端代理不支持代理链")
			}
			if u.User != nil {
				return errors.New("代理限制：SOCKS 远端代理不支持账号密码认证")
			}
		default:
			return fmt.Errorf("不支持的远端代理协议 %q (仅支持 https, quic, http, socks)", u.Scheme)
		}
		if portStr := u.Port(); portStr != "" {
			if p, err := strconv.Atoi(portStr); err != nil || p <= 0 || p > 65535 {
				return fmt.Errorf("第 %d 跳代理端口无效: %q", i+1, portStr)
			}
		}
	}
	return nil
}

// ToConfigJSON generates the JSON bytes expected by `naive config.json`.
func (s Service) ToConfigJSON() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	m := make(map[string]any)
	if strings.TrimSpace(s.ExtraJSON) != "" {
		if err := json.Unmarshal([]byte(s.ExtraJSON), &m); err != nil {
			return nil, err
		}
	}

	listens := cleanSlice(s.Listens)
	if len(listens) == 1 {
		m["listen"] = listens[0]
	} else if len(listens) > 1 {
		m["listen"] = listens
	}

	proxies := cleanSlice(s.Proxies)
	if len(proxies) == 1 {
		m["proxy"] = proxies[0]
	} else if len(proxies) > 1 {
		m["proxy"] = proxies
	}

	if s.InsecureConcurrency > 0 {
		m["insecure-concurrency"] = s.InsecureConcurrency
	}
	if s.TunnelTimeout > 0 {
		m["tunnel-timeout"] = s.TunnelTimeout
	}
	if s.IdleTimeout > 0 {
		m["idle-timeout"] = s.IdleTimeout
	}
	if hdr := strings.TrimSpace(s.ExtraHeaders); hdr != "" {
		// Normalize LF to CRLF as required by USAGE.txt:
		// "Multiple headers are separated by CRLF."
		lines := strings.Split(strings.ReplaceAll(hdr, "\r\n", "\n"), "\n")
		var cleanLines []string
		for _, line := range lines {
			if t := strings.TrimSpace(line); t != "" {
				cleanLines = append(cleanLines, t)
			}
		}
		if len(cleanLines) > 0 {
			m["extra-headers"] = strings.Join(cleanLines, "\r\n")
		}
	}
	if rules := strings.TrimSpace(s.HostResolverRules); rules != "" {
		m["host-resolver-rules"] = rules
	}
	if cidr := strings.TrimSpace(s.ResolverRange); cidr != "" {
		m["resolver-range"] = cidr
	}
	if s.LogFile != "" {
		m["log"] = strings.TrimSpace(s.LogFile)
	} else if s.EnableLog {
		m["log"] = ""
	}
	if netLog := strings.TrimSpace(s.LogNetLog); netLog != "" {
		m["log-net-log"] = netLog
	}
	if sslLog := strings.TrimSpace(s.SSLKeyLogFile); sslLog != "" {
		m["ssl-key-log-file"] = sslLog
	}
	if s.NoPostQuantum {
		m["no-post-quantum"] = true
	}

	return json.MarshalIndent(m, "", "  ")
}

func cleanSlice(in []string) []string {
	var out []string
	for _, v := range in {
		if t := strings.TrimSpace(v); t != "" {
			out = append(out, t)
		}
	}
	return out
}
