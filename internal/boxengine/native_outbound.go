package boxengine

import (
	"net"
	"net/url"
	"runtime"
	"strconv"
	"strings"

	"naive-client/internal/config"
	"naive-client/internal/tailnet"
)

var buildNativeOutbound = BuildNativeOutbound

// BuildNativeOutbound converts a config.Service into sing-box native outbound options.
func BuildNativeOutbound(svc config.Service) map[string]any {
	ob := buildNativeOutboundInner(svc)
	if srv, ok := ob["server"].(string); ok && srv != "" {
		cleanSrv := strings.Trim(strings.TrimSpace(srv), "[]")
		if cleanSrv != srv {
			ob["server"] = cleanSrv
		}
		if net.ParseIP(cleanSrv) == nil {
			ob["domain_resolver"] = "domestic-doh"
		}
	}
	return ob
}

// ConfigureNativeOutboundTailnet overrides domain_resolver and outbound binding/detour on ob
// when the node's server targets a Tailnet host or IP under active Tailnet cooperation.
func ConfigureNativeOutboundTailnet(ob map[string]any, opts EngineOptions, hostInterface string) {
	if len(ob) == 0 {
		return
	}
	if opts.TailnetMode != tailnet.ModeHost && (opts.TailnetMode != tailnet.ModeEmbedded || opts.TailnetConfig == nil) {
		return
	}
	srv, _ := ob["server"].(string)
	srv = strings.TrimSpace(srv)
	if srv == "" {
		return
	}
	cleanIP := strings.TrimSuffix(strings.TrimPrefix(srv, "["), "]")
	isDomain := net.ParseIP(cleanIP) == nil
	isTailnetHost := isDomain && tailnet.IsTailnetHostname(opts.TailnetMode, srv, opts.TailnetMagicDNSSuffix)
	isTailnetDest := tailnet.IsTailnetTarget(opts.TailnetMode, srv, opts.TailnetMagicDNSSuffix, opts.TailnetHostRecords)

	switch opts.TailnetMode {
	case tailnet.ModeHost:
		if isTailnetHost {
			ob["domain_resolver"] = "tailscale-host-dns"
		}
		if isTailnetDest && hostInterface != "" && ob["detour"] == nil {
			ob["bind_interface"] = hostInterface
		}
	case tailnet.ModeEmbedded:
		if isTailnetHost && isTailnetDest {
			ob["domain_resolver"] = "tailscale-dns"
		}
		if isTailnetDest && ob["detour"] == nil {
			ob["detour"] = "tailscale-ep"
		}
	}
}

func buildNativeOutboundInner(svc config.Service) map[string]any {
	tag := "node-" + svc.ID

	// Handle ExternalURI (e.g. socks5://user:pass@host:port or http://host:port)
	if svc.EffectiveKind() == config.KindExternalProxy && svc.ExternalURI != "" {
		if u, err := url.Parse(svc.ExternalURI); err == nil {
			scheme := strings.ToLower(u.Scheme)
			port := 1080
			if p, err := strconv.Atoi(u.Port()); err == nil && p > 0 {
				port = p
			}
			host := u.Hostname()
			username := u.User.Username()
			password, _ := u.User.Password()

			switch scheme {
			case "http", "https":
				ob := map[string]any{
					"type":        "http",
					"tag":         tag,
					"server":      host,
					"server_port": port,
				}
				if username != "" {
					ob["username"] = username
					ob["password"] = password
				}
				if scheme == "https" {
					ob["tls"] = map[string]any{"enabled": true}
				}
				return ob
			default:
				// SOCKS5 default
				ob := map[string]any{
					"type":        "socks",
					"tag":         tag,
					"server":      host,
					"server_port": port,
					"version":     "5",
				}
				if host == "127.0.0.1" || host == "localhost" || host == "::1" {
					if ifName := loopbackInterfaceName(); ifName != "" {
						ob["bind_interface"] = ifName
					}
				}
				if username != "" {
					ob["username"] = username
					ob["password"] = password
				}
				return ob
			}
		}
	}

	proto := svc.EffectiveProtocol()
	switch proto {
	case config.ProtoVLESS:
		ob := map[string]any{
			"type":        "vless",
			"tag":         tag,
			"server":      svc.Server,
			"server_port": svc.ServerPort,
			"uuid":        svc.UUID,
		}
		if svc.Flow != "" {
			ob["flow"] = svc.Flow
		}
		if tlsMap := buildNativeTLS(svc, false); tlsMap != nil {
			ob["tls"] = tlsMap
		}
		if transport := buildNativeTransport(svc); transport != nil {
			ob["transport"] = transport
		}
		return ob

	case config.ProtoVMess:
		tlsMap := buildNativeTLS(svc, false)
		ob := map[string]any{
			"type":        "vmess",
			"tag":         tag,
			"server":      svc.Server,
			"server_port": svc.ServerPort,
			"uuid":        svc.UUID,
			"security":    effectiveNativeVMessSecurity(svc.Method, tlsMap != nil),
		}
		if tlsMap != nil {
			ob["tls"] = tlsMap
		}
		if transport := buildNativeTransport(svc); transport != nil {
			ob["transport"] = transport
		}
		return ob

	case config.ProtoTrojan:
		ob := map[string]any{
			"type":        "trojan",
			"tag":         tag,
			"server":      svc.Server,
			"server_port": svc.ServerPort,
			"password":    svc.Password,
		}
		if tlsMap := buildNativeTLS(svc, !strings.EqualFold(strings.TrimSpace(svc.Security), "none")); tlsMap != nil {
			ob["tls"] = tlsMap
		}
		if transport := buildNativeTransport(svc); transport != nil {
			ob["transport"] = transport
		}
		return ob

	case config.ProtoShadowsocks:
		method := svc.Method
		if method == "" {
			method = "2022-blake3-aes-128-gcm"
		}
		return map[string]any{
			"type":        "shadowsocks",
			"tag":         tag,
			"server":      svc.Server,
			"server_port": svc.ServerPort,
			"method":      method,
			"password":    svc.Password,
		}

	case config.ProtoHysteria2:
		ob := map[string]any{
			"type":        "hysteria2",
			"tag":         tag,
			"server":      svc.Server,
			"server_port": svc.ServerPort,
			"password":    svc.Password,
			"tls": map[string]any{
				"enabled": true,
			},
		}
		if svc.UpMbps > 0 {
			ob["up_mbps"] = svc.UpMbps
		}
		if svc.DownMbps > 0 {
			ob["down_mbps"] = svc.DownMbps
		}
		if svc.SNI != "" {
			ob["tls"].(map[string]any)["server_name"] = svc.SNI
		}
		return ob

	case config.ProtoTUIC:
		ob := map[string]any{
			"type":        "tuic",
			"tag":         tag,
			"server":      svc.Server,
			"server_port": svc.ServerPort,
			"uuid":        svc.UUID,
			"password":    svc.Password,
			"tls": map[string]any{
				"enabled": true,
			},
		}
		if svc.SNI != "" {
			ob["tls"].(map[string]any)["server_name"] = svc.SNI
		}
		return ob

	case config.ProtoNaive:
		// In pure-Go builds without CGO cronet (with_naive_outbound), sing-box does not include a
		// native naive outbound. ProtoNaive nodes are supervised as sidecars. If built directly here,
		// fallback to direct placeholder so sing-box core does not crash on initialization.
		return map[string]any{
			"type": "direct",
			"tag":  tag,
		}

	default:
		// Fallback to direct placeholder
		return map[string]any{
			"type": "direct",
			"tag":  tag,
		}
	}
}

func buildNativeTLS(svc config.Service, forceEnabled bool) map[string]any {
	sec := strings.ToLower(strings.TrimSpace(svc.Security))
	if !forceEnabled && sec != "tls" && sec != "reality" {
		return nil
	}
	tlsMap := map[string]any{
		"enabled": true,
	}
	if serverName := svc.EffectiveTLSServerName(); serverName != "" {
		tlsMap["server_name"] = serverName
	}
	if alpn := effectiveNativeALPN(svc); len(alpn) > 0 {
		tlsMap["alpn"] = alpn
	}
	if fp := strings.TrimSpace(svc.Fingerprint); fp != "" {
		tlsMap["utls"] = map[string]any{
			"enabled":     true,
			"fingerprint": fp,
		}
	}
	if sec == "reality" {
		realityMap := map[string]any{
			"enabled": true,
		}
		if svc.PublicKey != "" {
			realityMap["public_key"] = svc.PublicKey
		}
		if svc.ShortID != "" {
			realityMap["short_id"] = svc.ShortID
		}
		tlsMap["reality"] = realityMap
	}
	return tlsMap
}

// effectiveNativeALPN filters out ALPN entries incompatible with HTTP/1.1-only
// upgrade transports in sing-box (ws, httpupgrade). Links exported from v2rayN
// commonly carry alpn=h2 or alpn=h2,http/1.1, which Xray ignores on WebSocket
// but causes sing-box to negotiate HTTP/2 and fail the upgrade with EOF.
func effectiveNativeALPN(svc config.Service) []string {
	if len(svc.ALPN) == 0 {
		return nil
	}
	netName := strings.ToLower(strings.TrimSpace(svc.Network))
	if netName != "ws" && netName != "httpupgrade" {
		return svc.ALPN
	}
	var filtered []string
	for _, proto := range svc.ALPN {
		p := strings.TrimSpace(proto)
		lower := strings.ToLower(p)
		if p == "" || lower == "h2" || lower == "h2c" || lower == "h3" || strings.HasPrefix(lower, "h3-") {
			continue
		}
		filtered = append(filtered, p)
	}
	return filtered
}

func buildNativeTransport(svc config.Service) map[string]any {
	switch strings.ToLower(strings.TrimSpace(svc.Network)) {
	case "ws":
		transport := map[string]any{"type": "ws"}
		path, maxED := splitWSEarlyDataPath(svc.Path)
		if path != "" {
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			transport["path"] = path
		}
		if maxED > 0 {
			transport["max_early_data"] = maxED
			transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
		}
		if host := effectiveWSHostHeader(svc); host != "" {
			transport["headers"] = map[string]string{"Host": host}
		}
		return transport

	case "grpc":
		transport := map[string]any{"type": "grpc"}
		if sn := svc.EffectiveGRPCServiceName(); sn != "" {
			transport["service_name"] = sn
		}
		return transport

	case "http", "h2":
		transport := map[string]any{"type": "http"}
		if p := strings.TrimSpace(svc.Path); p != "" {
			transport["path"] = p
		}
		if hosts := config.SplitHostList(svc.Host); len(hosts) > 0 {
			transport["host"] = hosts
		}
		return transport

	case "httpupgrade":
		transport := map[string]any{"type": "httpupgrade"}
		if p := strings.TrimSpace(svc.Path); p != "" {
			transport["path"] = p
		}
		if host := strings.TrimSpace(svc.Host); host != "" {
			transport["host"] = host
		}
		return transport

	default:
		return nil
	}
}

// effectiveWSHostHeader returns the WebSocket Host header, defaulting on standard ports (443/80)
// to SNI or domain server without the port suffix so sagernet/ws does not emit "Host: domain:443".
func effectiveWSHostHeader(svc config.Service) string {
	if host := strings.TrimSpace(svc.Host); host != "" {
		return host
	}
	if sni := strings.TrimSpace(svc.SNI); sni != "" {
		return sni
	}
	srv := strings.TrimSpace(svc.Server)
	if srv == "" || net.ParseIP(strings.Trim(srv, "[]")) != nil {
		return ""
	}
	sec := strings.ToLower(strings.TrimSpace(svc.Security))
	isTLS := sec == "tls" || sec == "reality"
	if (isTLS && (svc.ServerPort == 443 || svc.ServerPort == 0)) || (!isTLS && svc.ServerPort == 80) {
		return srv
	}
	return ""
}

func splitWSEarlyDataPath(rawPath string) (string, uint32) {
	rawPath = strings.TrimSpace(rawPath)
	if rawPath == "" || !strings.Contains(rawPath, "?") {
		return rawPath, 0
	}
	// Collapse repeated leading slashes so url.Parse doesn't treat "//ws?ed=..." as a host.
	parseTarget := rawPath
	if strings.HasPrefix(parseTarget, "//") {
		parseTarget = "/" + strings.TrimLeft(parseTarget, "/")
	}
	u, err := url.Parse(parseTarget)
	if err != nil {
		return rawPath, 0
	}
	q := u.Query()
	edStr := q.Get("ed")
	if edStr == "" {
		return rawPath, 0
	}
	ed, err := strconv.ParseUint(edStr, 10, 32)
	if err != nil || ed == 0 {
		return rawPath, 0
	}
	q.Del("ed")
	u.RawQuery = q.Encode()
	clean := u.RequestURI()
	if clean == "" {
		clean = "/"
	}
	return clean, uint32(ed)
}

// effectiveNativeVMessSecurity resolves the VMess payload cipher for sing-box.
// sing-box silently downgrades "auto" to "zero" whenever TLS is configured, which
// Xray servers with disableInsecureEncryption reject. Mapping "auto"+TLS to the
// architecture's AEAD cipher keeps "auto" compatible with Xray while preserving
// explicit "zero"/"none" selections.
func effectiveNativeVMessSecurity(method string, hasTLS bool) string {
	sec := config.VMessSecurityOrAuto(method)
	if sec == "auto" && hasTLS {
		if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" || runtime.GOARCH == "s390x" {
			return "aes-128-gcm"
		}
		return "chacha20-poly1305"
	}
	return sec
}
