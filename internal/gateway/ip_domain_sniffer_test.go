package gateway_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"naive-client/internal/dns/ipcache"
	"naive-client/internal/gateway"
	"naive-client/internal/telemetry"
)

type mockGatewayBlocker struct {
	blocked map[string]bool
}

func (m *mockGatewayBlocker) Match(domain string) (bool, string) {
	if m.blocked[domain] {
		return true, "mock-block"
	}
	return false, ""
}

// Tests that pure IP inbounds are restored to domains via IPCache and Sniffer,
// allowing domain-based blocker and telemetry to work on pure IP connections.
func TestGateway_PureIPDomainReverseAndBlock(t *testing.T) {
	cache := ipcache.New(100)
	cache.Put(net.ParseIP("198.51.100.1"), "api.openai.com")
	cache.Put(net.ParseIP("198.51.100.2"), "ads.tracking.com")

	blocker := &mockGatewayBlocker{
		blocked: map[string]bool{
			"ads.tracking.com": true,
		},
	}

	var dialedTargets []string
	var mu sync.Mutex

	// Echo server simulating target
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen echo: %v", err)
	}
	defer echoListener.Close()
	go func() {
		for {
			c, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	echoAddr := echoListener.Addr().String()

	tr := telemetry.NewTracker()
	gw, err := gateway.New(gateway.Options{
		BindAddr: "127.0.0.1:0",
		Tracker:  tr,
		IPCache:  cache,
		Blocker:  blocker,
		DialTarget: func(ctx context.Context, target string) (net.Conn, string, error) {
			mu.Lock()
			dialedTargets = append(dialedTargets, target)
			mu.Unlock()

			var d net.Dialer
			conn, err := d.DialContext(ctx, "tcp", echoAddr)
			return conn, "node-1", err
		},
	})
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	if err := gw.Start(); err != nil {
		t.Fatalf("failed to start gateway: %v", err)
	}
	defer gw.Stop()

	gwAddr := gw.Addr()

	// 1. SOCKS5 to pure IP 198.51.100.1:443 -> should resolve to api.openai.com:443
	t.Run("SOCKS5_IP_Resolved", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", gwAddr, 2*time.Second)
		if err != nil {
			t.Fatalf("failed to dial gateway: %v", err)
		}
		defer conn.Close()

		// Greeting
		_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
		resp := make([]byte, 2)
		_, _ = io.ReadFull(conn, resp)

		// Request to IPv4 198.51.100.1:443
		req := []byte{0x05, 0x01, 0x00, 0x01, 198, 51, 100, 1, 0x01, 0xBB}
		_, _ = conn.Write(req)

		connResp := make([]byte, 10)
		_, err = io.ReadFull(conn, connResp)
		if err != nil || connResp[1] != 0x00 {
			t.Fatalf("socks5 connect failed: resp=%v, err=%v", connResp, err)
		}

		mu.Lock()
		lastDial := ""
		if len(dialedTargets) > 0 {
			lastDial = dialedTargets[len(dialedTargets)-1]
		}
		mu.Unlock()

		if lastDial != "api.openai.com:443" {
			t.Fatalf("expected dial to resolved domain api.openai.com:443, got %q", lastDial)
		}
	})

	// 2. HTTP CONNECT to pure IP 198.51.100.2:443 -> resolved to ads.tracking.com:443 and blocked!
	t.Run("HTTP_CONNECT_IP_Blocked", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", gwAddr, 2*time.Second)
		if err != nil {
			t.Fatalf("failed to dial gateway: %v", err)
		}
		defer conn.Close()

		req := "CONNECT 198.51.100.2:443 HTTP/1.1\r\nHost: 198.51.100.2:443\r\n\r\n"
		_, _ = conn.Write([]byte(req))

		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("failed to read response: %v", err)
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden for blocked domain, got %d", resp.StatusCode)
		}
	})

	// 3. SOCKS5 to unknown IP with TLS ClientHello -> Sniffer catches SNI and stores in IPCache
	t.Run("SOCKS5_IP_Sniffed_Into_Cache", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", gwAddr, 2*time.Second)
		if err != nil {
			t.Fatalf("failed to dial gateway: %v", err)
		}
		defer conn.Close()

		// SOCKS5 greeting
		_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
		resp := make([]byte, 2)
		_, _ = io.ReadFull(conn, resp)

		// Connect to unknown IP 203.0.113.50:443
		req := []byte{0x05, 0x01, 0x00, 0x01, 203, 0, 113, 50, 0x01, 0xBB}
		_, _ = conn.Write(req)

		connResp := make([]byte, 10)
		_, err = io.ReadFull(conn, connResp)
		if err != nil || connResp[1] != 0x00 {
			t.Fatalf("socks5 connect failed: resp=%v, err=%v", connResp, err)
		}

		// Now send TLS ClientHello with SNI "unregistered.target.org"
		tlsClient := tls.Client(conn, &tls.Config{
			ServerName:         "unregistered.target.org",
			InsecureSkipVerify: true,
		})
		_ = tlsClient.Handshake()

		// Wait briefly for sniffing and caching to occur
		time.Sleep(50 * time.Millisecond)
		domain, ok := cache.Lookup(net.ParseIP("203.0.113.50"))
		if !ok || domain != "unregistered.target.org" {
			t.Fatalf("expected cache to be updated with unregistered.target.org, got %q (ok=%v)", domain, ok)
		}
	})
}
