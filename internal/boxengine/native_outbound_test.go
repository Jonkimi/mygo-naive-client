package boxengine

import (
	"testing"

	"naive-client/internal/config"
)

// Tests that buildNativeOutbound properly translates config.Service protocols to sing-box outbound specifications.
func TestBuildNativeOutbound(t *testing.T) {
	// 1. VLESS REALITY
	vlessSvc := config.Service{
		ID:          "vless-1",
		Protocol:    config.ProtoVLESS,
		Engine:      config.EngineSingBox,
		Server:      "example.org",
		ServerPort:  443,
		UUID:        "12345678-1234-1234-1234-123456789abc",
		Security:    "reality",
		SNI:         "gateway.example.org",
		Fingerprint: "chrome",
		PublicKey:   "pub-key-123",
		ShortID:     "short-id-456",
		Flow:        "xtls-rprx-vision",
	}

	ob := buildNativeOutbound(vlessSvc)
	if ob["type"] != "vless" {
		t.Errorf("expected vless, got %v", ob["type"])
	}
	if ob["server"] != "example.org" || ob["server_port"] != 443 {
		t.Errorf("unexpected server/port: %v:%v", ob["server"], ob["server_port"])
	}
	tlsMap, ok := ob["tls"].(map[string]any)
	if !ok || tlsMap["server_name"] != "gateway.example.org" {
		t.Errorf("unexpected tlsMap: %v", tlsMap)
	}
	realityMap, ok := tlsMap["reality"].(map[string]any)
	if !ok || realityMap["public_key"] != "pub-key-123" {
		t.Errorf("unexpected realityMap: %v", realityMap)
	}

	// 2. Shadowsocks
	ssSvc := config.Service{
		ID:         "ss-1",
		Protocol:   config.ProtoShadowsocks,
		Engine:     config.EngineSingBox,
		Server:     "1.2.3.4",
		ServerPort: 8388,
		Method:     "2022-blake3-aes-128-gcm",
		Password:   "secret-pass",
	}

	ob = buildNativeOutbound(ssSvc)
	if ob["type"] != "shadowsocks" {
		t.Errorf("expected shadowsocks, got %v", ob["type"])
	}
	if ob["method"] != "2022-blake3-aes-128-gcm" || ob["password"] != "secret-pass" {
		t.Errorf("unexpected ss method/password")
	}

	// 3. External SOCKS5 URI
	socksSvc := config.Service{
		ID:          "socks-ext",
		Kind:        config.KindExternalProxy,
		ExternalURI: "socks5://user:pass@127.0.0.1:1080",
	}
	ob = buildNativeOutbound(socksSvc)
	if ob["type"] != "socks" {
		t.Errorf("expected socks, got %v", ob["type"])
	}
	if ob["server"] != "127.0.0.1" || ob["server_port"] != 1080 {
		t.Errorf("unexpected server/port: %v:%v", ob["server"], ob["server_port"])
	}
	if ob["username"] != "user" || ob["password"] != "pass" {
		t.Errorf("unexpected user/pass: %v:%v", ob["username"], ob["password"])
	}

	// 4. NaiveProxy outbound fallbacks to direct in native builder (handled as sidecar in gateway)
	naiveSvc := config.Service{
		ID:       "naive-node-1",
		Protocol: config.ProtoNaive,
		Engine:   config.EngineSingBox,
		SNI:      "sni.example.com",
		Proxies:  []string{"https://user1:pass1@naive.example.com:443"},
	}
	ob = buildNativeOutbound(naiveSvc)
	if ob["type"] != "direct" {
		t.Errorf("expected direct fallback for naive in pure Go build, got %v", ob["type"])
	}
}
