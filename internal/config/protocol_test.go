package config

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestProtocolDefaultEngines(t *testing.T) {
	// Naive should default to EngineSidecar
	naiveSvc := Service{
		Name:     "Naive Node",
		Protocol: ProtoNaive,
	}
	if naiveSvc.EffectiveEngine() != EngineSidecar {
		t.Errorf("naive EffectiveEngine() = %v, want %v", naiveSvc.EffectiveEngine(), EngineSidecar)
	}

	// Legacy service with empty protocol should default to ProtoNaive and EngineSidecar
	legacySvc := Service{
		Name:    "Legacy Node",
		Proxies: []string{"https://u:p@hk.example.com"},
	}
	if legacySvc.EffectiveProtocol() != ProtoNaive {
		t.Errorf("legacy EffectiveProtocol() = %v, want %v", legacySvc.EffectiveProtocol(), ProtoNaive)
	}
	if legacySvc.EffectiveEngine() != EngineSidecar {
		t.Errorf("legacy EffectiveEngine() = %v, want %v", legacySvc.EffectiveEngine(), EngineSidecar)
	}

	// Modern protocols should default to EngineSingBox
	vlessSvc := Service{
		Name:     "VLESS Node",
		Protocol: ProtoVLESS,
	}
	if vlessSvc.EffectiveEngine() != EngineSingBox {
		t.Errorf("vless EffectiveEngine() = %v, want %v", vlessSvc.EffectiveEngine(), EngineSingBox)
	}

	hy2Svc := Service{
		Name:     "Hysteria2 Node",
		Protocol: ProtoHysteria2,
	}
	if hy2Svc.EffectiveEngine() != EngineSingBox {
		t.Errorf("hy2 EffectiveEngine() = %v, want %v", hy2Svc.EffectiveEngine(), EngineSingBox)
	}
}

func TestParseVLESSRealityImportAndExport(t *testing.T) {
	raw := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@hk.reality.com:443?security=reality&sni=yahoo.com&fp=chrome&pbk=q8...pubkey&sid=123456&type=tcp&flow=xtls-rprx-vision#HK-Reality"
	svc, err := ParseImport(raw, 1080)
	if err != nil {
		t.Fatalf("ParseImport VLESS failed: %v", err)
	}

	if svc.EffectiveProtocol() != ProtoVLESS {
		t.Errorf("EffectiveProtocol() = %v, want %v", svc.EffectiveProtocol(), ProtoVLESS)
	}
	if svc.EffectiveEngine() != EngineSingBox {
		t.Errorf("EffectiveEngine() = %v, want %v", svc.EffectiveEngine(), EngineSingBox)
	}
	if svc.Name != "HK-Reality" {
		t.Errorf("Name = %q, want HK-Reality", svc.Name)
	}
	if svc.Server != "hk.reality.com" || svc.ServerPort != 443 {
		t.Errorf("Server:Port = %s:%d, want hk.reality.com:443", svc.Server, svc.ServerPort)
	}
	if svc.UUID != "b831381d-6324-4d53-ad4f-8cda48b30811" {
		t.Errorf("UUID = %q", svc.UUID)
	}
	if svc.Security != "reality" || svc.SNI != "yahoo.com" || svc.Fingerprint != "chrome" || svc.PublicKey != "q8...pubkey" || svc.ShortID != "123456" || svc.Flow != "xtls-rprx-vision" {
		t.Errorf("Reality fields mismatch: %+v", svc)
	}

	exported := svc.ShareURI()
	if !strings.HasPrefix(exported, "vless://") || !strings.Contains(exported, "security=reality") || !strings.Contains(exported, "#HK-Reality") {
		t.Errorf("ShareURI() = %q, invalid VLESS format", exported)
	}
}

func TestParseTrojanImportAndExport(t *testing.T) {
	raw := "trojan://secret-password@jp.trojan.com:443?security=tls&sni=jp.trojan.com&alpn=h2,http/1.1#Tokyo-Trojan"
	svc, err := ParseImport(raw, 1081)
	if err != nil {
		t.Fatalf("ParseImport Trojan failed: %v", err)
	}

	if svc.EffectiveProtocol() != ProtoTrojan {
		t.Errorf("EffectiveProtocol() = %v, want %v", svc.EffectiveProtocol(), ProtoTrojan)
	}
	if svc.EffectiveEngine() != EngineSingBox {
		t.Errorf("EffectiveEngine() = %v, want %v", svc.EffectiveEngine(), EngineSingBox)
	}
	if svc.Password != "secret-password" {
		t.Errorf("Password = %q, want secret-password", svc.Password)
	}
	if svc.Server != "jp.trojan.com" || svc.ServerPort != 443 {
		t.Errorf("Server:Port = %s:%d, want jp.trojan.com:443", svc.Server, svc.ServerPort)
	}

	exported := svc.ShareURI()
	if !strings.HasPrefix(exported, "trojan://secret-password@jp.trojan.com:443") || !strings.Contains(exported, "#Tokyo-Trojan") {
		t.Errorf("ShareURI() = %q", exported)
	}
}

func TestParseShadowsocksImportAndExport(t *testing.T) {
	// ss://<base64(method:password)>@host:port#name
	userinfo := base64.URLEncoding.EncodeToString([]byte("aes-128-gcm:my-secret-pw"))
	raw := "ss://" + userinfo + "@ss.example.com:8388#Shadowsocks-SG"

	svc, err := ParseImport(raw, 1082)
	if err != nil {
		t.Fatalf("ParseImport Shadowsocks failed: %v", err)
	}

	if svc.EffectiveProtocol() != ProtoShadowsocks {
		t.Errorf("EffectiveProtocol() = %v, want %v", svc.EffectiveProtocol(), ProtoShadowsocks)
	}
	if svc.Method != "aes-128-gcm" || svc.Password != "my-secret-pw" {
		t.Errorf("Method/Password = %s / %s", svc.Method, svc.Password)
	}
	if svc.Server != "ss.example.com" || svc.ServerPort != 8388 {
		t.Errorf("Server:Port = %s:%d", svc.Server, svc.ServerPort)
	}

	exported := svc.ShareURI()
	if !strings.HasPrefix(exported, "ss://") || !strings.Contains(exported, "#Shadowsocks-SG") {
		t.Errorf("ShareURI() = %q", exported)
	}
}

func TestParseHysteria2AndTUICImport(t *testing.T) {
	// Hysteria 2
	hy2Raw := "hysteria2://auth-token@hy2.example.com:443?sni=hy2.example.com&insecure=1#Hy2-HK"
	hy2Svc, err := ParseImport(hy2Raw, 1083)
	if err != nil {
		t.Fatalf("ParseImport Hysteria2 failed: %v", err)
	}
	if hy2Svc.EffectiveProtocol() != ProtoHysteria2 {
		t.Errorf("hy2 EffectiveProtocol() = %v, want %v", hy2Svc.EffectiveProtocol(), ProtoHysteria2)
	}
	if hy2Svc.Password != "auth-token" || hy2Svc.SNI != "hy2.example.com" {
		t.Errorf("hy2 fields mismatch: %+v", hy2Svc)
	}

	// TUIC
	tuicRaw := "tuic://my-uuid:my-token@tuic.example.com:8443?congestion_control=bbr&alpn=h3#TUIC-Node"
	tuicSvc, err := ParseImport(tuicRaw, 1084)
	if err != nil {
		t.Fatalf("ParseImport TUIC failed: %v", err)
	}
	if tuicSvc.EffectiveProtocol() != ProtoTUIC {
		t.Errorf("tuic EffectiveProtocol() = %v, want %v", tuicSvc.EffectiveProtocol(), ProtoTUIC)
	}
	if tuicSvc.UUID != "my-uuid" || tuicSvc.Password != "my-token" || tuicSvc.CongestionController != "bbr" {
		t.Errorf("tuic fields mismatch: %+v", tuicSvc)
	}
}

func TestParseVMessImportAndExport(t *testing.T) {
	// vmess://<base64-json>
	vmessJSON := map[string]any{
		"v":    "2",
		"ps":   "VMess-US",
		"add":  "us.vmess.com",
		"port": 443,
		"id":   "23ad6b10-8d1a-40f7-8ad0-e3e35ff382a3",
		"aid":  0,
		"scy":  "auto",
		"net":  "ws",
		"type": "none",
		"host": "us.vmess.com",
		"path": "/websocket",
		"tls":  "tls",
		"sni":  "us.vmess.com",
	}
	b, _ := json.Marshal(vmessJSON)
	raw := "vmess://" + base64.StdEncoding.EncodeToString(b)

	svc, err := ParseImport(raw, 1085)
	if err != nil {
		t.Fatalf("ParseImport VMess failed: %v", err)
	}
	if svc.EffectiveProtocol() != ProtoVMess {
		t.Errorf("EffectiveProtocol() = %v, want %v", svc.EffectiveProtocol(), ProtoVMess)
	}
	if svc.UUID != "23ad6b10-8d1a-40f7-8ad0-e3e35ff382a3" || svc.Server != "us.vmess.com" || svc.ServerPort != 443 {
		t.Errorf("VMess core fields mismatch: %+v", svc)
	}
	if svc.Network != "ws" || svc.Path != "/websocket" || svc.Security != "tls" {
		t.Errorf("VMess transport fields mismatch: %+v", svc)
	}

	exported := svc.ShareURI()
	if !strings.HasPrefix(exported, "vmess://") {
		t.Errorf("ShareURI() = %q, want vmess:// prefix", exported)
	}
}

func TestDynamicPortAndProtocolValidation(t *testing.T) {
	// Parse dynamic port
	ep, err := ParseListenURI("socks://127.0.0.1:0")
	if err != nil {
		t.Fatalf("ParseListenURI dynamic port failed: %v", err)
	}
	if ep.Port != 0 {
		t.Errorf("ep.Port = %d, want 0", ep.Port)
	}

	// Validate VLESS service with dynamic port and no proxies slice (using Server/ServerPort)
	vlessSvc := Service{
		Name:       "VLESS Test",
		Protocol:   ProtoVLESS,
		Server:     "vless.example.com",
		ServerPort: 443,
		UUID:       "12345678-1234-1234-1234-123456789abc",
		Listens:    []string{"socks://127.0.0.1:0"},
	}
	if err := vlessSvc.Validate(); err != nil {
		t.Errorf("vlessSvc.Validate() failed: %v", err)
	}
}
