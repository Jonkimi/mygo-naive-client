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

// ShareURI exports the service as a standard share link based on its EffectiveProtocol().
func (s Service) ShareURI() string {
	switch s.EffectiveProtocol() {
	case ProtoVLESS:
		return s.vlessShareURI()
	case ProtoVMess:
		return s.vmessShareURI()
	case ProtoTrojan:
		return s.trojanShareURI()
	case ProtoShadowsocks:
		return s.shadowsocksShareURI()
	case ProtoHysteria2:
		return s.hysteria2ShareURI()
	case ProtoTUIC:
		return s.tuicShareURI()
	case ProtoSOCKS5:
		return s.socks5ShareURI()
	case ProtoHTTP:
		return s.httpShareURI()
	default:
		return s.NaiveShareURI()
	}
}

func (s Service) vlessShareURI() string {
	server := s.Server
	port := s.ServerPort
	if port <= 0 {
		port = 443
	}
	u := &url.URL{
		Scheme: "vless",
		User:   url.User(s.UUID),
		Host:   net.JoinHostPort(server, strconv.Itoa(port)),
	}
	q := make(url.Values)
	if s.Security != "" {
		q.Set("security", s.Security)
	}
	if s.SNI != "" {
		q.Set("sni", s.SNI)
	}
	if s.Fingerprint != "" {
		q.Set("fp", s.Fingerprint)
	}
	if s.PublicKey != "" {
		q.Set("pbk", s.PublicKey)
	}
	if s.ShortID != "" {
		q.Set("sid", s.ShortID)
	}
	if s.SpiderX != "" {
		q.Set("spx", s.SpiderX)
	}
	if s.Flow != "" {
		q.Set("flow", s.Flow)
	}
	if s.Network != "" {
		q.Set("type", s.Network)
	}
	if s.Path != "" {
		q.Set("path", s.Path)
	}
	if s.Host != "" {
		q.Set("host", s.Host)
	}
	if s.ServiceName != "" {
		q.Set("serviceName", s.ServiceName)
	}
	if len(s.ALPN) > 0 {
		q.Set("alpn", strings.Join(s.ALPN, ","))
	}
	if len(q) > 0 {
		u.RawQuery = q.Encode()
	}
	if s.Name != "" {
		u.Fragment = s.Name
	}
	return u.String()
}

func (s Service) vmessShareURI() string {
	portVal := any(s.ServerPort)
	if s.ServerPort <= 0 {
		portVal = 443
	}
	m := map[string]any{
		"v":    "2",
		"ps":   s.Name,
		"add":  s.Server,
		"port": portVal,
		"id":   s.UUID,
		"aid":  0,
		"scy":  "auto",
		"net":  s.Network,
		"type": "none",
		"host": s.Host,
		"path": s.Path,
		"tls":  s.Security,
		"sni":  s.SNI,
	}
	if s.Network == "" {
		m["net"] = "tcp"
	}
	b, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

func (s Service) trojanShareURI() string {
	server := s.Server
	port := s.ServerPort
	if port <= 0 {
		port = 443
	}
	u := &url.URL{
		Scheme: "trojan",
		User:   url.User(s.Password),
		Host:   net.JoinHostPort(server, strconv.Itoa(port)),
	}
	q := make(url.Values)
	if s.Security != "" {
		q.Set("security", s.Security)
	} else {
		q.Set("security", "tls")
	}
	if s.SNI != "" {
		q.Set("sni", s.SNI)
	}
	if len(s.ALPN) > 0 {
		q.Set("alpn", strings.Join(s.ALPN, ","))
	}
	if s.Network != "" {
		q.Set("type", s.Network)
	}
	if len(q) > 0 {
		u.RawQuery = q.Encode()
	}
	if s.Name != "" {
		u.Fragment = s.Name
	}
	return u.String()
}

func (s Service) shadowsocksShareURI() string {
	server := s.Server
	port := s.ServerPort
	if port <= 0 {
		port = 8388
	}
	method := s.Method
	if method == "" {
		method = "aes-128-gcm"
	}
	userInfo := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", method, s.Password)))
	u := &url.URL{
		Scheme: "ss",
		User:   url.User(userInfo),
		Host:   net.JoinHostPort(server, strconv.Itoa(port)),
	}
	if s.Name != "" {
		u.Fragment = s.Name
	}
	return u.String()
}

func (s Service) hysteria2ShareURI() string {
	server := s.Server
	port := s.ServerPort
	if port <= 0 {
		port = 443
	}
	u := &url.URL{
		Scheme: "hysteria2",
		User:   url.User(s.Password),
		Host:   net.JoinHostPort(server, strconv.Itoa(port)),
	}
	q := make(url.Values)
	if s.SNI != "" {
		q.Set("sni", s.SNI)
	}
	if len(q) > 0 {
		u.RawQuery = q.Encode()
	}
	if s.Name != "" {
		u.Fragment = s.Name
	}
	return u.String()
}

func (s Service) tuicShareURI() string {
	server := s.Server
	port := s.ServerPort
	if port <= 0 {
		port = 8443
	}
	var user *url.Userinfo
	if s.Password != "" {
		user = url.UserPassword(s.UUID, s.Password)
	} else {
		user = url.User(s.UUID)
	}
	u := &url.URL{
		Scheme: "tuic",
		User:   user,
		Host:   net.JoinHostPort(server, strconv.Itoa(port)),
	}
	q := make(url.Values)
	if s.SNI != "" {
		q.Set("sni", s.SNI)
	}
	if s.CongestionController != "" {
		q.Set("congestion_control", s.CongestionController)
	}
	if len(s.ALPN) > 0 {
		q.Set("alpn", strings.Join(s.ALPN, ","))
	}
	if len(q) > 0 {
		u.RawQuery = q.Encode()
	}
	if s.Name != "" {
		u.Fragment = s.Name
	}
	return u.String()
}

func (s Service) socks5ShareURI() string {
	if s.ExternalURI != "" {
		return s.ExternalURI
	}
	host := s.Server
	if host == "" {
		host = "127.0.0.1"
	}
	port := s.ServerPort
	if port <= 0 {
		port = 1080
	}
	var user *url.Userinfo
	if s.Password != "" {
		user = url.UserPassword(s.UUID, s.Password)
	}
	u := &url.URL{
		Scheme: "socks5",
		User:   user,
		Host:   net.JoinHostPort(host, strconv.Itoa(port)),
	}
	if s.Name != "" {
		u.Fragment = s.Name
	}
	return u.String()
}

func (s Service) httpShareURI() string {
	if s.ExternalURI != "" {
		return s.ExternalURI
	}
	host := s.Server
	if host == "" {
		host = "127.0.0.1"
	}
	port := s.ServerPort
	if port <= 0 {
		port = 8080
	}
	var user *url.Userinfo
	if s.Password != "" {
		user = url.UserPassword(s.UUID, s.Password)
	}
	u := &url.URL{
		Scheme: "http",
		User:   user,
		Host:   net.JoinHostPort(host, strconv.Itoa(port)),
	}
	if s.Name != "" {
		u.Fragment = s.Name
	}
	return u.String()
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

	// 1.5. VMess format
	if strings.HasPrefix(strings.ToLower(raw), "vmess://") {
		return parseVMessImport(raw, nextPort)
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
	case "vless":
		if u.Hostname() == "" {
			return Service{}, errors.New("VLESS 链接缺少服务器地址")
		}
		if name == "" {
			name = u.Hostname()
		}
		port := 443
		if p, err := strconv.Atoi(u.Port()); err == nil && p > 0 {
			port = p
		}
		uuid := ""
		if u.User != nil {
			uuid = u.User.Username()
		}
		q := u.Query()
		svc := DefaultService("", nextPort)
		svc.Name = name
		svc.Protocol = ProtoVLESS
		svc.Engine = EngineSingBox
		svc.Server = u.Hostname()
		svc.ServerPort = port
		svc.UUID = uuid
		svc.Security = q.Get("security")
		svc.SNI = q.Get("sni")
		svc.Fingerprint = q.Get("fp")
		svc.PublicKey = q.Get("pbk")
		svc.ShortID = q.Get("sid")
		svc.SpiderX = q.Get("spx")
		svc.Flow = q.Get("flow")
		svc.Network = q.Get("type")
		svc.Path = q.Get("path")
		svc.Host = q.Get("host")
		svc.ServiceName = q.Get("serviceName")
		if alpn := q.Get("alpn"); alpn != "" {
			svc.ALPN = strings.Split(alpn, ",")
		}
		return svc, nil

	case "trojan":
		if u.Hostname() == "" {
			return Service{}, errors.New("Trojan 链接缺少服务器地址")
		}
		if name == "" {
			name = u.Hostname()
		}
		port := 443
		if p, err := strconv.Atoi(u.Port()); err == nil && p > 0 {
			port = p
		}
		pass := ""
		if u.User != nil {
			pass = u.User.Username()
		}
		q := u.Query()
		svc := DefaultService("", nextPort)
		svc.Name = name
		svc.Protocol = ProtoTrojan
		svc.Engine = EngineSingBox
		svc.Server = u.Hostname()
		svc.ServerPort = port
		svc.Password = pass
		svc.Security = q.Get("security")
		if svc.Security == "" {
			svc.Security = "tls"
		}
		svc.SNI = q.Get("sni")
		svc.Network = q.Get("type")
		if alpn := q.Get("alpn"); alpn != "" {
			svc.ALPN = strings.Split(alpn, ",")
		}
		return svc, nil

	case "ss":
		if u.Hostname() == "" {
			return Service{}, errors.New("Shadowsocks 链接缺少服务器地址")
		}
		if name == "" {
			name = u.Hostname()
		}
		port := 8388
		if p, err := strconv.Atoi(u.Port()); err == nil && p > 0 {
			port = p
		}
		method := "aes-128-gcm"
		pass := ""
		if u.User != nil {
			userRaw := u.User.Username()
			if p, hasP := u.User.Password(); hasP {
				method = userRaw
				pass = p
			} else if decoded, err := decodeBase64(userRaw); err == nil && strings.Contains(decoded, ":") {
				parts := strings.SplitN(decoded, ":", 2)
				method = parts[0]
				pass = parts[1]
			} else {
				pass = userRaw
			}
		}
		svc := DefaultService("", nextPort)
		svc.Name = name
		svc.Protocol = ProtoShadowsocks
		svc.Engine = EngineSingBox
		svc.Server = u.Hostname()
		svc.ServerPort = port
		svc.Method = method
		svc.Password = pass
		return svc, nil

	case "hysteria2", "hy2":
		if u.Hostname() == "" {
			return Service{}, errors.New("Hysteria2 链接缺少服务器地址")
		}
		if name == "" {
			name = u.Hostname()
		}
		port := 443
		if p, err := strconv.Atoi(u.Port()); err == nil && p > 0 {
			port = p
		}
		pass := ""
		if u.User != nil {
			pass = u.User.Username()
		}
		q := u.Query()
		svc := DefaultService("", nextPort)
		svc.Name = name
		svc.Protocol = ProtoHysteria2
		svc.Engine = EngineSingBox
		svc.Server = u.Hostname()
		svc.ServerPort = port
		svc.Password = pass
		svc.SNI = q.Get("sni")
		svc.CongestionController = "bbr"
		return svc, nil

	case "tuic":
		if u.Hostname() == "" {
			return Service{}, errors.New("TUIC 链接缺少服务器地址")
		}
		if name == "" {
			name = u.Hostname()
		}
		port := 8443
		if p, err := strconv.Atoi(u.Port()); err == nil && p > 0 {
			port = p
		}
		uuid := ""
		pass := ""
		if u.User != nil {
			uuid = u.User.Username()
			pass, _ = u.User.Password()
		}
		q := u.Query()
		svc := DefaultService("", nextPort)
		svc.Name = name
		svc.Protocol = ProtoTUIC
		svc.Engine = EngineSingBox
		svc.Server = u.Hostname()
		svc.ServerPort = port
		svc.UUID = uuid
		svc.Password = pass
		svc.SNI = q.Get("sni")
		svc.CongestionController = q.Get("congestion_control")
		if svc.CongestionController == "" {
			svc.CongestionController = "bbr"
		}
		svc.UDPRelayMode = q.Get("udp_relay_mode")
		if alpn := q.Get("alpn"); alpn != "" {
			svc.ALPN = strings.Split(alpn, ",")
		}
		return svc, nil

	case "socks", "socks5", "socks5h", "http":
		cleanURL := &url.URL{
			Scheme: scheme,
			User:   u.User,
			Host:   u.Host,
			Path:   u.Path,
		}
		if name == "" {
			name = u.Host
		}
		svc := Service{
			Name:        name,
			Kind:        KindExternalProxy,
			ExternalURI: cleanURL.String(),
		}
		return svc, nil

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

type vmessRaw struct {
	V    any    `json:"v"`
	Ps   string `json:"ps"`
	Add  string `json:"add"`
	Port any    `json:"port"`
	Id   string `json:"id"`
	Aid  any    `json:"aid"`
	Scy  string `json:"scy"`
	Net  string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
	Tls  string `json:"tls"`
	Sni  string `json:"sni"`
	Alpn string `json:"alpn"`
}

func parseVMessImport(raw string, nextPort int) (Service, error) {
	encoded := strings.TrimPrefix(raw, "vmess://")
	encoded = strings.TrimPrefix(encoded, "VMESS://")
	decoded, err := decodeBase64(encoded)
	if err != nil {
		return Service{}, fmt.Errorf("VMess base64 解码失败: %w", err)
	}
	var data vmessRaw
	if err := json.Unmarshal([]byte(decoded), &data); err != nil {
		return Service{}, fmt.Errorf("VMess JSON 解析失败: %w", err)
	}

	name := strings.TrimSpace(data.Ps)
	if name == "" {
		name = data.Add
	}
	port := 443
	switch p := data.Port.(type) {
	case float64:
		port = int(p)
	case string:
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			port = parsed
		}
	}

	svc := DefaultService("", nextPort)
	svc.Name = name
	svc.Protocol = ProtoVMess
	svc.Engine = EngineSingBox
	svc.Server = data.Add
	svc.ServerPort = port
	svc.UUID = data.Id
	svc.Network = data.Net
	svc.Path = data.Path
	svc.Host = data.Host
	svc.Security = data.Tls
	svc.SNI = data.Sni
	if data.Alpn != "" {
		svc.ALPN = strings.Split(data.Alpn, ",")
	}
	return svc, nil
}
