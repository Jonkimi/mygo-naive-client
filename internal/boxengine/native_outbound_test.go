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

func TestBuildNativeOutbound_VMessWebSocketTLS(t *testing.T) {
	// Regression: VMess previously omitted transport and uTLS/ALPN options in buildNativeOutbound,
	// causing wss + WebSocket + VMess nodes to send raw VMess over TLS and fail with
	// "cipher: message authentication failed".
	svc := config.Service{
		ID:          "vmess-wss-1",
		Protocol:    config.ProtoVMess,
		Engine:      config.EngineSingBox,
		Server:      "edge.example.com",
		ServerPort:  443,
		UUID:        "12345678-1234-1234-1234-123456789abc",
		Security:    "tls",
		SNI:         "sni.example.com",
		ALPN:        []string{"http/1.1"},
		Fingerprint: "chrome",
		Network:     "ws",
		Path:        "/ws?ed=2048",
		Host:        "cdn.example.com",
		Method:      "2022-blake3-aes-128-gcm", // invalid for VMess; must fall back to "auto"
	}

	ob := buildNativeOutbound(svc)
	if ob["type"] != "vmess" {
		t.Fatalf("expected type=vmess, got %v", ob["type"])
	}
	if ob["security"] != "auto" {
		t.Errorf("expected security=auto fallback, got %v", ob["security"])
	}

	tlsMap, ok := ob["tls"].(map[string]any)
	if !ok {
		t.Fatalf("expected tls map, got %T", ob["tls"])
	}
	if tlsMap["enabled"] != true || tlsMap["server_name"] != "sni.example.com" {
		t.Errorf("unexpected tls map: %#v", tlsMap)
	}
	utlsMap, ok := tlsMap["utls"].(map[string]any)
	if !ok || utlsMap["enabled"] != true || utlsMap["fingerprint"] != "chrome" {
		t.Errorf("unexpected utls map: %#v", tlsMap["utls"])
	}
	alpn, ok := tlsMap["alpn"].([]string)
	if !ok || len(alpn) != 1 || alpn[0] != "http/1.1" {
		t.Errorf("unexpected alpn: %#v", tlsMap["alpn"])
	}

	trMap, ok := ob["transport"].(map[string]any)
	if !ok {
		t.Fatalf("expected transport map, got %T", ob["transport"])
	}
	if trMap["type"] != "ws" || trMap["path"] != "/ws" {
		t.Errorf("unexpected ws transport: %#v", trMap)
	}
	if trMap["max_early_data"] != uint32(2048) || trMap["early_data_header_name"] != "Sec-WebSocket-Protocol" {
		t.Errorf("unexpected ws early data options: %#v", trMap)
	}
	headers, ok := trMap["headers"].(map[string]string)
	if !ok || headers["Host"] != "cdn.example.com" {
		t.Errorf("unexpected ws headers: %#v", trMap["headers"])
	}
}

func TestBuildNativeOutbound_VMessVariants(t *testing.T) {
	// IP or CDN CNAME server + empty SNI + WS Host (with optional port) fallback
	ipSvc := config.Service{
		ID:         "vmess-ip-ws",
		Protocol:   config.ProtoVMess,
		Server:     "104.16.1.1",
		ServerPort: 443,
		UUID:       "12345678-1234-1234-1234-123456789abc",
		Security:   "tls",
		Network:    "ws",
		Path:       "/vmess",
		Host:       "ws.example.com",
		Method:     "aes-128-gcm",
	}
	ob := buildNativeOutbound(ipSvc)
	if ob["security"] != "aes-128-gcm" {
		t.Errorf("expected security=aes-128-gcm, got %v", ob["security"])
	}
	tlsMap := ob["tls"].(map[string]any)
	if tlsMap["server_name"] != "ws.example.com" {
		t.Errorf("expected server_name fallback to Host ws.example.com, got %v", tlsMap["server_name"])
	}

	cnameSvc := config.Service{
		ID:         "vmess-cname-ws",
		Protocol:   config.ProtoVMess,
		Server:     "cf.cdn-edge.net",
		ServerPort: 443,
		UUID:       "12345678-1234-1234-1234-123456789abc",
		Security:   "tls",
		Network:    "ws",
		Path:       "/vmess",
		Host:       "origin.example.com:443",
	}
	ob = buildNativeOutbound(cnameSvc)
	tlsMap = ob["tls"].(map[string]any)
	if tlsMap["server_name"] != "origin.example.com" {
		t.Errorf("expected server_name fallback to stripped Host origin.example.com, got %v", tlsMap["server_name"])
	}

	// Plain gRPC without TLS (also verify legacy Path-only gRPC service_name fallback)
	grpcSvc := config.Service{
		ID:          "vmess-grpc",
		Protocol:    config.ProtoVMess,
		Server:      "grpc.example.com",
		ServerPort:  80,
		UUID:        "12345678-1234-1234-1234-123456789abc",
		Security:    "none",
		Network:     "grpc",
		ServiceName: "GunService",
	}
	ob = buildNativeOutbound(grpcSvc)
	if _, hasTLS := ob["tls"]; hasTLS {
		t.Errorf("expected no tls when security=none, got %#v", ob["tls"])
	}
	trMap, ok := ob["transport"].(map[string]any)
	if !ok || trMap["type"] != "grpc" || trMap["service_name"] != "GunService" {
		t.Errorf("unexpected grpc transport: %#v", ob["transport"])
	}

	legacyGrpcSvc := config.Service{
		ID:         "vmess-grpc-legacy",
		Protocol:   config.ProtoVMess,
		Server:     "grpc.example.com",
		ServerPort: 80,
		UUID:       "12345678-1234-1234-1234-123456789abc",
		Security:   "none",
		Network:    "grpc",
		Path:       "LegacyGun",
	}
	ob = buildNativeOutbound(legacyGrpcSvc)
	trMap, ok = ob["transport"].(map[string]any)
	if !ok || trMap["service_name"] != "LegacyGun" {
		t.Errorf("expected legacy Path fallback for grpc service_name, got %#v", ob["transport"])
	}

	// Regression: "//ws?ed=2048" must not be misparsed as URL host by url.Parse
	doubleSlashWS := config.Service{
		ID:         "vmess-double-slash",
		Protocol:   config.ProtoVMess,
		Server:     "ws.example.com",
		ServerPort: 80,
		UUID:       "12345678-1234-1234-1234-123456789abc",
		Security:   "none",
		Network:    "ws",
		Path:       " //ws?ed=2048 ",
	}
	ob = buildNativeOutbound(doubleSlashWS)
	trMap = ob["transport"].(map[string]any)
	if trMap["path"] != "/ws" || trMap["max_early_data"] != uint32(2048) {
		t.Errorf("unexpected transport for //ws?ed=2048: %#v", trMap)
	}

	// HTTP/2 multi-host & HTTPUpgrade transports + Trojan Security="none" / WS
	h2Svc := config.Service{
		ID:         "vmess-h2",
		Protocol:   config.ProtoVMess,
		Server:     "104.16.1.2",
		ServerPort: 443,
		UUID:       "12345678-1234-1234-1234-123456789abc",
		Security:   "tls",
		Network:    "h2",
		Path:       "/h2",
		Host:       "cdn1.example.com, cdn2.example.com",
	}
	ob = buildNativeOutbound(h2Svc)
	tlsMap = ob["tls"].(map[string]any)
	if tlsMap["server_name"] != "cdn1.example.com" {
		t.Errorf("expected h2 server_name fallback to first host, got %v", tlsMap["server_name"])
	}
	trMap = ob["transport"].(map[string]any)
	hosts, ok := trMap["host"].([]string)
	if !ok || trMap["type"] != "http" || len(hosts) != 2 || hosts[0] != "cdn1.example.com" || hosts[1] != "cdn2.example.com" {
		t.Errorf("unexpected h2 transport: %#v", trMap)
	}

	trojanPlain := config.Service{
		ID:         "trojan-plain",
		Protocol:   config.ProtoTrojan,
		Server:     "trojan.example.com",
		ServerPort: 80,
		Password:   "pw",
		Security:   "none",
		Network:    "httpupgrade",
		Path:       "/up",
		Host:       "up.example.com",
	}
	ob = buildNativeOutbound(trojanPlain)
	if _, hasTLS := ob["tls"]; hasTLS {
		t.Errorf("expected Trojan with Security=none to omit tls, got %#v", ob["tls"])
	}
	trMap = ob["transport"].(map[string]any)
	if trMap["type"] != "httpupgrade" || trMap["path"] != "/up" || trMap["host"] != "up.example.com" {
		t.Errorf("unexpected httpupgrade transport: %#v", trMap)
	}

	// Regression: v2rayN-exported WS/HTTPUpgrade nodes often carry ALPN=["h2"] or ["h2","http/1.1"].
	// sing-box must not negotiate h2 over HTTP/1.1 upgrade transports (which causes immediate EOF).
	wsH2Only := config.Service{
		ID:         "vmess-ws-h2-alpn",
		Protocol:   config.ProtoVMess,
		Server:     "ws.example.com",
		ServerPort: 443,
		UUID:       "12345678-1234-1234-1234-123456789abc",
		Security:   "tls",
		ALPN:       []string{"h2"},
		Network:    "ws",
		Path:       "/ws",
	}
	ob = buildNativeOutbound(wsH2Only)
	tlsMap = ob["tls"].(map[string]any)
	if _, hasALPN := tlsMap["alpn"]; hasALPN {
		t.Errorf("expected h2 ALPN to be omitted for ws so sing-box defaults to http/1.1, got %#v", tlsMap["alpn"])
	}

	wsMixedALPN := wsH2Only
	wsMixedALPN.ALPN = []string{"h2", "http/1.1", "h3"}
	ob = buildNativeOutbound(wsMixedALPN)
	tlsMap = ob["tls"].(map[string]any)
	alpn, ok := tlsMap["alpn"].([]string)
	if !ok || len(alpn) != 1 || alpn[0] != "http/1.1" {
		t.Errorf("expected ws ALPN to filter out h2/h3 leaving [http/1.1], got %#v", tlsMap["alpn"])
	}

	upgradeH2Only := wsH2Only
	upgradeH2Only.Protocol = config.ProtoVLESS
	upgradeH2Only.Network = "httpupgrade"
	ob = buildNativeOutbound(upgradeH2Only)
	tlsMap = ob["tls"].(map[string]any)
	if _, hasALPN := tlsMap["alpn"]; hasALPN {
		t.Errorf("expected h2 ALPN to be omitted for httpupgrade, got %#v", tlsMap["alpn"])
	}

	grpcH2 := wsH2Only
	grpcH2.Network = "grpc"
	grpcH2.ServiceName = "GunService"
	ob = buildNativeOutbound(grpcH2)
	tlsMap = ob["tls"].(map[string]any)
	alpn, ok = tlsMap["alpn"].([]string)
	if !ok || len(alpn) != 1 || alpn[0] != "h2" {
		t.Errorf("expected grpc to preserve h2 ALPN, got %#v", tlsMap["alpn"])
	}
}
