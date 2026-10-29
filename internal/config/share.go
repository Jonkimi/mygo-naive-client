package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// V2rayNSocksURI formats the service's local listen endpoint into a V2rayN-compatible
// pasteable SOCKS link: socks://address:port#alias
// If the listen address is 0.0.0.0 or empty, it normalizes to 127.0.0.1.
func (s Service) V2rayNSocksURI() string {
	ep, err := ParseListenURI(s.PrimaryListen())
	host := "127.0.0.1"
	port := 1080
	if err == nil {
		if ep.Addr != "" && ep.Addr != "0.0.0.0" && ep.Addr != "::" {
			host = ep.Addr
		}
		if ep.Port > 0 {
			port = ep.Port
		}
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	alias := strings.TrimSpace(s.Name)
	if alias == "" {
		return "socks://" + addr
	}
	return fmt.Sprintf("socks://%s#%s", addr, url.PathEscape(alias))
}

// NaiveShareURI exports the service as a standard `naive+https://...` or `naive+quic://...` URI.
func (s Service) NaiveShareURI() string {
	proxy := s.PrimaryProxy()
	if proxy == "" {
		return ""
	}
	u, err := url.Parse(proxy)
	if err != nil || u.Scheme == "" {
		return ""
	}
	u.Scheme = "naive+" + strings.ToLower(u.Scheme)
	q := u.Query()
	if s.ExtraHeaders != "" {
		q.Set("extra-headers", s.ExtraHeaders)
	}
	if s.InsecureConcurrency > 0 {
		q.Set("insecure-concurrency", strconv.Itoa(s.InsecureConcurrency))
	}
	if len(q) > 0 {
		u.RawQuery = q.Encode()
	}
	if name := strings.TrimSpace(s.Name); name != "" {
		u.Fragment = name
	}
	return u.String()
}

// ParseImports parses single or multi-line import text into one or more Services.
// Supported formats:
// 1. Complete JSON config (`config.json`)
// 2. One or more lines of `https://user:pass@example.com` or `naive+https://user:pass@example.com` (or `quic://` / `naive+quic://`)
func ParseImports(raw string, allocPort func() int) ([]Service, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("导入内容为空")
	}
	if allocPort == nil {
		port := 1080
		allocPort = func() int {
			p := port
			port++
			return p
		}
	}

	// 1. Complete JSON config (can span multiple lines)
	if strings.HasPrefix(raw, "{") {
		svc, err := parseJSONImport(raw, allocPort())
		if err != nil {
			return nil, err
		}
		return []Service{svc}, nil
	}

	// 2. Multi-line URI import (one URI per non-empty line)
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(normalized, "\n")
	var out []Service
	for idx, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		svc, err := ParseImport(line, allocPort())
		if err != nil {
			return nil, fmt.Errorf("第 %d 行导入失败: %w", idx+1, err)
		}
		out = append(out, svc)
	}
	if len(out) == 0 {
		return nil, errors.New("未识别到有效的导入内容")
	}
	return out, nil
}

// ParseImport parses a single URI or JSON config into a Service.
// Supported formats:
// 1. JSON object (`config.json` from naiveproxy or Service JSON)
// 2. `https://user:pass@example.com` or `naive+https://user:pass@example.com` (also `quic://` / `naive+quic://`)
func ParseImport(raw string, nextPort int) (Service, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Service{}, errors.New("导入内容为空")
	}
	if nextPort <= 0 {
		nextPort = 1080
	}

	// 1. JSON config
	if strings.HasPrefix(raw, "{") {
		return parseJSONImport(raw, nextPort)
	}

	// 2. URI format
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return Service{}, fmt.Errorf("格式错误，仅支持 https://user:pass@example.com、naive+https://user:pass@example.com 或完整的 config.json")
	}

	scheme := strings.ToLower(u.Scheme)
	name := ""
	if u.Fragment != "" {
		if decoded, err := url.PathUnescape(u.Fragment); err == nil {
			name = strings.TrimSpace(decoded)
		} else {
			name = strings.TrimSpace(u.Fragment)
		}
	}

	switch scheme {
	case "naive+https", "naive+quic", "https", "quic":
		proxyScheme := strings.TrimPrefix(scheme, "naive+")
		q := u.Query()
		sni := strings.TrimSpace(q.Get("sni"))

		host := u.Host
		hostname := u.Hostname()
		if sni != "" {
			hostname = sni
			if strings.Contains(sni, ":") {
				host = sni
			} else if p := u.Port(); p != "" {
				host = net.JoinHostPort(sni, p)
			} else {
				host = sni
			}
		}
		if hostname == "" {
			return Service{}, errors.New("代理链接缺少服务器域名或地址")
		}
		if name == "" {
			name = hostname
		}
		svc := DefaultService("", nextPort)
		svc.Name = name

		if eh := q.Get("extra-headers"); eh != "" {
			svc.ExtraHeaders = eh
		}
		if ic := q.Get("insecure-concurrency"); ic != "" {
			if n, err := strconv.Atoi(ic); err == nil && n > 0 {
				svc.InsecureConcurrency = n
			}
		}

		cleanURL := &url.URL{
			Scheme: proxyScheme,
			User:   normalizeUserInfo(u.User),
			Host:   host,
		}
		svc.Proxies = []string{cleanURL.String()}
		return svc, nil

	default:
		return Service{}, fmt.Errorf("不支持的链接协议 %q，仅支持 https://user:pass@example.com、naive+https://user:pass@example.com 或完整的 config.json", u.Scheme)
	}
}

func normalizeUserInfo(ui *url.Userinfo) *url.Userinfo {
	if ui == nil {
		return nil
	}
	if _, hasPass := ui.Password(); hasPass {
		return ui
	}
	rawUser := ui.Username()
	if rawUser == "" || strings.EqualFold(rawUser, "null") {
		return nil
	}
	if decoded, err := decodeBase64(rawUser); err == nil && strings.Contains(decoded, ":") {
		parts := strings.SplitN(decoded, ":", 2)
		return url.UserPassword(parts[0], parts[1])
	}
	return ui
}

func parseJSONImport(raw string, nextPort int) (Service, error) {
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &rawMap); err != nil {
		return Service{}, fmt.Errorf("JSON 解析失败: %w", err)
	}

	// Check if it's already a serialized Service struct
	if _, hasListens := rawMap["listens"]; hasListens {
		var svc Service
		if err := json.Unmarshal([]byte(raw), &svc); err != nil {
			return Service{}, err
		}
		if len(svc.Listens) == 0 {
			svc.Listens = []string{fmt.Sprintf("socks://127.0.0.1:%d", nextPort)}
		}
		if svc.Name == "" {
			svc.Name = fmt.Sprintf("Naive-%d", nextPort)
		}
		return svc, nil
	}

	// Parse standard naiveproxy config.json
	svc := DefaultService("", nextPort)
	if v, ok := rawMap["listen"]; ok {
		listens, err := parseStringOrArray(v)
		if err != nil {
			return Service{}, fmt.Errorf("解析 listen 字段失败: %w", err)
		}
		if len(listens) > 0 {
			svc.Listens = listens
		}
		delete(rawMap, "listen")
	}
	if v, ok := rawMap["proxy"]; ok {
		proxies, err := parseStringOrArray(v)
		if err != nil {
			return Service{}, fmt.Errorf("解析 proxy 字段失败: %w", err)
		}
		if len(proxies) > 0 {
			svc.Proxies = proxies
			if u, err := url.Parse(proxies[0]); err == nil && u.Hostname() != "" {
				svc.Name = u.Hostname()
			}
		}
		delete(rawMap, "proxy")
	}
	if v, ok := rawMap["insecure-concurrency"]; ok {
		_ = json.Unmarshal(v, &svc.InsecureConcurrency)
		delete(rawMap, "insecure-concurrency")
	}
	if v, ok := rawMap["tunnel-timeout"]; ok {
		_ = json.Unmarshal(v, &svc.TunnelTimeout)
		delete(rawMap, "tunnel-timeout")
	}
	if v, ok := rawMap["idle-timeout"]; ok {
		_ = json.Unmarshal(v, &svc.IdleTimeout)
		delete(rawMap, "idle-timeout")
	}
	if v, ok := rawMap["extra-headers"]; ok {
		_ = json.Unmarshal(v, &svc.ExtraHeaders)
		delete(rawMap, "extra-headers")
	}
	if v, ok := rawMap["host-resolver-rules"]; ok {
		_ = json.Unmarshal(v, &svc.HostResolverRules)
		delete(rawMap, "host-resolver-rules")
	}
	if v, ok := rawMap["resolver-range"]; ok {
		_ = json.Unmarshal(v, &svc.ResolverRange)
		delete(rawMap, "resolver-range")
	}
	if v, ok := rawMap["log"]; ok {
		var logPath string
		if err := json.Unmarshal(v, &logPath); err == nil {
			svc.EnableLog = true
			svc.LogFile = logPath
		}
		delete(rawMap, "log")
	}
	if v, ok := rawMap["log-net-log"]; ok {
		_ = json.Unmarshal(v, &svc.LogNetLog)
		delete(rawMap, "log-net-log")
	}
	if v, ok := rawMap["ssl-key-log-file"]; ok {
		_ = json.Unmarshal(v, &svc.SSLKeyLogFile)
		delete(rawMap, "ssl-key-log-file")
	}
	if v, ok := rawMap["no-post-quantum"]; ok {
		_ = json.Unmarshal(v, &svc.NoPostQuantum)
		delete(rawMap, "no-post-quantum")
	}

	if len(rawMap) > 0 {
		if extraBytes, err := json.MarshalIndent(rawMap, "", "  "); err == nil {
			svc.ExtraJSON = string(extraBytes)
		}
	}
	return svc, nil
}

func parseStringOrArray(raw json.RawMessage) ([]string, error) {
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		if strings.TrimSpace(single) == "" {
			return nil, nil
		}
		return []string{strings.TrimSpace(single)}, nil
	}
	var multi []string
	if err := json.Unmarshal(raw, &multi); err == nil {
		return cleanSlice(multi), nil
	}
	return nil, errors.New("必须是字符串或字符串数组")
}

func decodeBase64(s string) (string, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return string(b), nil
		}
	}
	return "", errors.New("invalid base64")
}
