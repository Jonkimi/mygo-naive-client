package boxengine

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	"naive-client/internal/config"
)

var buildNativeOutbound = BuildNativeOutbound

// BuildNativeOutbound converts a config.Service into sing-box native outbound options.
func BuildNativeOutbound(svc config.Service) map[string]any {
	ob := buildNativeOutboundInner(svc)
	if srv, ok := ob["server"].(string); ok && srv != "" && net.ParseIP(srv) == nil {
		ob["domain_resolver"] = "bootstrap-dns"
	}
	return ob
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
		if svc.Security == "tls" || svc.Security == "reality" {
			tlsMap := map[string]any{
				"enabled": true,
			}
			if svc.SNI != "" {
				tlsMap["server_name"] = svc.SNI
			}
			if len(svc.ALPN) > 0 {
				tlsMap["alpn"] = svc.ALPN
			}
			if svc.Fingerprint != "" {
				tlsMap["utls"] = map[string]any{
					"enabled":     true,
					"fingerprint": svc.Fingerprint,
				}
			}
			if svc.Security == "reality" {
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
			ob["tls"] = tlsMap
		}
		if svc.Network == "ws" {
			transport := map[string]any{"type": "ws"}
			if svc.Path != "" {
				transport["path"] = svc.Path
			}
			if svc.Host != "" {
				transport["headers"] = map[string]string{"Host": svc.Host}
			}
			ob["transport"] = transport
		} else if svc.Network == "grpc" {
			transport := map[string]any{"type": "grpc"}
			if svc.ServiceName != "" {
				transport["service_name"] = svc.ServiceName
			}
			ob["transport"] = transport
		}
		return ob

	case config.ProtoVMess:
		ob := map[string]any{
			"type":        "vmess",
			"tag":         tag,
			"server":      svc.Server,
			"server_port": svc.ServerPort,
			"uuid":        svc.UUID,
			"security":    "auto",
		}
		if svc.Security == "tls" {
			tlsMap := map[string]any{"enabled": true}
			if svc.SNI != "" {
				tlsMap["server_name"] = svc.SNI
			}
			ob["tls"] = tlsMap
		}
		return ob

	case config.ProtoTrojan:
		ob := map[string]any{
			"type":        "trojan",
			"tag":         tag,
			"server":      svc.Server,
			"server_port": svc.ServerPort,
			"password":    svc.Password,
			"tls": map[string]any{
				"enabled": true,
			},
		}
		if svc.SNI != "" {
			ob["tls"].(map[string]any)["server_name"] = svc.SNI
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
		// sing-box native naive outbound
		server := svc.Server
		port := svc.ServerPort
		user := ""
		pass := ""
		if len(svc.Proxies) > 0 {
			if u, err := url.Parse(svc.Proxies[0]); err == nil {
				server = u.Hostname()
				if p, err := strconv.Atoi(u.Port()); err == nil && p > 0 {
					port = p
				}
				user = u.User.Username()
				pass, _ = u.User.Password()
			}
		}
		return map[string]any{
			"type":        "naive",
			"tag":         tag,
			"server":      server,
			"server_port": port,
			"username":    user,
			"password":    pass,
		}

	default:
		// Fallback to direct placeholder
		return map[string]any{
			"type": "direct",
			"tag":  tag,
		}
	}
}
