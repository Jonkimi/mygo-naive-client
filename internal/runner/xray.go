package runner

import (
	"encoding/json"
	"fmt"
	"strings"

	"naive-client/internal/config"
)

// GenerateXrayConfig builds a complete Xray JSON configuration for sidecar execution.
func GenerateXrayConfig(svc config.Service, listenPort int) ([]byte, error) {
	return GenerateXrayConfigWithLogLevel(svc, listenPort, "warning")
}

func normalizeXrayLogLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return "debug"
	case "info":
		return "info"
	case "warn", "warning", "":
		return "warning"
	case "error":
		return "error"
	default:
		return "warning"
	}
}

// GenerateXrayConfigWithLogLevel builds a complete Xray JSON configuration with a specified log level.
func GenerateXrayConfigWithLogLevel(svc config.Service, listenPort int, logLevel string) ([]byte, error) {
	if listenPort <= 0 {
		listenPort = 1080
	}

	inbound := map[string]any{
		"tag":      "socks-in",
		"port":     listenPort,
		"listen":   "127.0.0.1",
		"protocol": "socks",
		"settings": map[string]any{
			"auth": "noauth",
			"udp":  true,
		},
	}

	outbound, err := buildXrayOutbound(svc)
	if err != nil {
		return nil, err
	}

	cfg := map[string]any{
		"log": map[string]any{
			"loglevel": normalizeXrayLogLevel(logLevel),
		},
		"inbounds":  []any{inbound},
		"outbounds": []any{outbound},
	}

	return json.MarshalIndent(cfg, "", "  ")
}

func buildXrayOutbound(svc config.Service) (map[string]any, error) {
	proto := svc.EffectiveProtocol()
	serverPort := svc.ServerPort
	if serverPort <= 0 {
		serverPort = 443
	}

	switch proto {
	case config.ProtoVLESS:
		streamSettings := buildXrayStreamSettings(svc)
		user := map[string]any{
			"id":         svc.UUID,
			"encryption": "none",
		}
		if svc.Flow != "" {
			user["flow"] = svc.Flow
		}
		return map[string]any{
			"protocol": "vless",
			"settings": map[string]any{
				"vnext": []any{
					map[string]any{
						"address": svc.Server,
						"port":    serverPort,
						"users":   []any{user},
					},
				},
			},
			"streamSettings": streamSettings,
		}, nil

	case config.ProtoVMess:
		streamSettings := buildXrayStreamSettings(svc)
		return map[string]any{
			"protocol": "vmess",
			"settings": map[string]any{
				"vnext": []any{
					map[string]any{
						"address": svc.Server,
						"port":    serverPort,
						"users": []any{
							map[string]any{
								"id":       svc.UUID,
								"alterId":  0,
								"security": "auto",
							},
						},
					},
				},
			},
			"streamSettings": streamSettings,
		}, nil

	case config.ProtoTrojan:
		streamSettings := buildXrayStreamSettings(svc)
		return map[string]any{
			"protocol": "trojan",
			"settings": map[string]any{
				"servers": []any{
					map[string]any{
						"address":  svc.Server,
						"port":     serverPort,
						"password": svc.Password,
					},
				},
			},
			"streamSettings": streamSettings,
		}, nil

	case config.ProtoShadowsocks:
		method := svc.Method
		if method == "" {
			method = "aes-128-gcm"
		}
		return map[string]any{
			"protocol": "shadowsocks",
			"settings": map[string]any{
				"servers": []any{
					map[string]any{
						"address":  svc.Server,
						"port":     serverPort,
						"method":   method,
						"password": svc.Password,
					},
				},
			},
		}, nil

	default:
		return nil, fmt.Errorf("Xray sidecar 不支持协议: %s", proto)
	}
}

func buildXrayStreamSettings(svc config.Service) map[string]any {
	network := svc.Network
	if network == "" {
		network = "tcp"
	}
	st := map[string]any{
		"network": network,
	}
	sec := strings.ToLower(svc.Security)
	if sec != "" {
		st["security"] = sec
	}
	if sec == "reality" {
		realitySettings := map[string]any{
			"show":        false,
			"fingerprint": svc.Fingerprint,
			"serverName":  svc.SNI,
			"publicKey":   svc.PublicKey,
			"shortId":     svc.ShortID,
			"spiderX":     svc.SpiderX,
		}
		if realitySettings["fingerprint"] == "" {
			realitySettings["fingerprint"] = "chrome"
		}
		st["realitySettings"] = realitySettings
	} else if sec == "tls" {
		tlsSettings := map[string]any{
			"serverName": svc.SNI,
		}
		if svc.Fingerprint != "" {
			tlsSettings["fingerprint"] = svc.Fingerprint
		}
		if len(svc.ALPN) > 0 {
			tlsSettings["alpn"] = svc.ALPN
		}
		st["tlsSettings"] = tlsSettings
	}

	if network == "ws" {
		wsSettings := make(map[string]any)
		if svc.Path != "" {
			wsSettings["path"] = svc.Path
		}
		if svc.Host != "" {
			wsSettings["headers"] = map[string]string{"Host": svc.Host}
		}
		st["wsSettings"] = wsSettings
	} else if network == "grpc" {
		grpcSettings := make(map[string]any)
		if svc.ServiceName != "" {
			grpcSettings["serviceName"] = svc.ServiceName
		}
		st["grpcSettings"] = grpcSettings
	}

	return st
}
