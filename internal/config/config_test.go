package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestToConfigJSON(t *testing.T) {
	svc := Service{
		ID:                  "1",
		Name:                "HK Node",
		Listens:             []string{"socks://127.0.0.1:1080", "http://127.0.0.1:8080"},
		Proxies:             []string{"https://alice:secret@hk.example.com:443"},
		InsecureConcurrency: 2,
		TunnelTimeout:       1800,
		IdleTimeout:         600,
		ExtraHeaders:        "X-Custom-A: 1\nX-Custom-B: 2",
		HostResolverRules:   "MAP hk.example.com 1.2.3.4",
		ResolverRange:       "100.64.0.0/10",
		EnableLog:           true,
		NoPostQuantum:       true,
		ExtraJSON:           `{"custom-flag": "val"}`,
	}

	data, err := svc.ToConfigJSON()
	if err != nil {
		t.Fatalf("ToConfigJSON failed: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid json: %v", err)
	}

	listens, ok := parsed["listen"].([]any)
	if !ok || len(listens) != 2 || listens[0] != "socks://127.0.0.1:1080" || listens[1] != "http://127.0.0.1:8080" {
		t.Errorf("unexpected listen field: %#v", parsed["listen"])
	}
	if parsed["proxy"] != "https://alice:secret@hk.example.com:443" {
		t.Errorf("unexpected proxy field: %#v", parsed["proxy"])
	}
	if parsed["insecure-concurrency"] != float64(2) {
		t.Errorf("unexpected insecure-concurrency: %#v", parsed["insecure-concurrency"])
	}
	if parsed["extra-headers"] != "X-Custom-A: 1\r\nX-Custom-B: 2" {
		t.Errorf("expected CRLF separated headers, got %q", parsed["extra-headers"])
	}
	if parsed["log"] != "" {
		t.Errorf("expected empty string log field for console logging, got %#v", parsed["log"])
	}
	if parsed["no-post-quantum"] != true {
		t.Errorf("expected no-post-quantum=true, got %#v", parsed["no-post-quantum"])
	}
	if parsed["custom-flag"] != "val" {
		t.Errorf("expected extra json custom-flag=val, got %#v", parsed["custom-flag"])
	}
}

func TestValidateProxyChainRules(t *testing.T) {
	// QUIC cannot follow TCP-based proxies in a proxy chain (from USAGE.txt)
	if err := ValidateProxyChain("https://a.example.com,quic://b.example.com"); err == nil {
		t.Error("expected error when QUIC follows HTTPS in a proxy chain")
	}
	// QUIC followed by HTTPS is valid
	if err := ValidateProxyChain("quic://a.example.com,https://b.example.com"); err != nil {
		t.Errorf("unexpected error for quic->https chain: %v", err)
	}
	// SOCKS does not support chaining or auth
	if err := ValidateProxyChain("socks://user:pass@127.0.0.1:1080"); err == nil {
		t.Error("expected error when SOCKS proxy has authentication")
	}
}

func TestV2rayNSocksURI(t *testing.T) {
	svc := Service{
		Name:    "香港节点 01",
		Listens: []string{"socks://0.0.0.0:10808"},
		Proxies: []string{"https://u:p@hk.example.com"},
	}
	got := svc.V2rayNSocksURI()
	want := "socks://127.0.0.1:10808#%E9%A6%99%E6%B8%AF%E8%8A%82%E7%82%B9%2001"
	if got != want {
		t.Errorf("V2rayNSocksURI() = %q, want %q", got, want)
	}

	// Paste import only supports https://, naive+https:// (or quic) and full config.json, so socks:// is rejected
	if _, err := ParseImport(got, 1080); err == nil {
		t.Errorf("expected error when importing socks:// URI")
	}
}

func TestNaiveShareImportAndExport(t *testing.T) {
	raw := "naive+quic://myuser:mypass@jp.example.com:443?insecure-concurrency=2#Tokyo%20Node"
	svc, err := ParseImport(raw, 1085)
	if err != nil {
		t.Fatalf("ParseImport failed: %v", err)
	}
	if svc.Name != "Tokyo Node" {
		t.Errorf("Name = %q, want Tokyo Node", svc.Name)
	}
	if svc.PrimaryListen() != "socks://127.0.0.1:1085" {
		t.Errorf("PrimaryListen = %q, want socks://127.0.0.1:1085", svc.PrimaryListen())
	}
	if svc.PrimaryProxy() != "quic://myuser:mypass@jp.example.com:443" {
		t.Errorf("PrimaryProxy = %q", svc.PrimaryProxy())
	}
	if svc.InsecureConcurrency != 2 {
		t.Errorf("InsecureConcurrency = %d, want 2", svc.InsecureConcurrency)
	}
	if redacted := svc.RedactedProxy(); redacted != "quic://myuser:***@jp.example.com:443" {
		t.Errorf("RedactedProxy = %q", redacted)
	}
	exported := svc.NaiveShareURI()
	if !strings.HasPrefix(exported, "naive+quic://myuser:mypass@jp.example.com:443") {
		t.Errorf("NaiveShareURI = %q", exported)
	}
}

func TestParseConfigJSONImport(t *testing.T) {
	rawJSON := `{
		"listen": ["socks://127.0.0.1:2080", "http://127.0.0.1:2081"],
		"proxy": "https://user:pass@us.example.com",
		"insecure-concurrency": 3,
		"no-post-quantum": true,
		"log": ""
	}`
	svc, err := ParseImport(rawJSON, 1080)
	if err != nil {
		t.Fatalf("ParseImport JSON failed: %v", err)
	}
	if len(svc.Listens) != 2 || svc.Listens[0] != "socks://127.0.0.1:2080" {
		t.Errorf("unexpected Listens: %v", svc.Listens)
	}
	if svc.PrimaryProxy() != "https://user:pass@us.example.com" {
		t.Errorf("unexpected Proxy: %v", svc.PrimaryProxy())
	}
	if svc.InsecureConcurrency != 3 || !svc.NoPostQuantum || !svc.EnableLog {
		t.Errorf("unexpected flags: concurrency=%d noPQ=%v log=%v", svc.InsecureConcurrency, svc.NoPostQuantum, svc.EnableLog)
	}
}

func TestParseImportsMultiLineAndSNI(t *testing.T) {
	multiRaw := `
https://alice:pw1@hk.example.com#HK-01
naive+https://bob:pw2@1.2.3.4:8443?security=tls&sni=sni.example.com#SNI-Node
`
	port := 1080
	svcs, err := ParseImports(multiRaw, func() int {
		p := port
		port++
		return p
	})
	if err != nil {
		t.Fatalf("ParseImports failed: %v", err)
	}
	if len(svcs) != 2 {
		t.Fatalf("expected 2 services, got %d", len(svcs))
	}
	if svcs[0].Name != "HK-01" || svcs[0].PrimaryProxy() != "https://alice:pw1@hk.example.com" || svcs[0].PrimaryListen() != "socks://127.0.0.1:1080" {
		t.Errorf("unexpected svcs[0]: %+v", svcs[0])
	}
	if svcs[1].Name != "SNI-Node" || svcs[1].PrimaryProxy() != "https://bob:pw2@sni.example.com:8443" || svcs[1].PrimaryListen() != "socks://127.0.0.1:1081" {
		t.Errorf("unexpected svcs[1]: %+v", svcs[1])
	}
}


