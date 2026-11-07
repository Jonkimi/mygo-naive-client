package boxengine

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"naive-client/internal/blocker"
	"naive-client/internal/config"
	"naive-client/internal/routing"
	"naive-client/internal/telemetry"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
)

// Tests that Engine starts with Mixed inbound, accepts connections, and routes direct traffic.
func TestEngine_StartAndDirectRouting(t *testing.T) {
	// Start a local HTTP test server to be accessed via DIRECT
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen test server failed: %v", err)
	}
	defer ln.Close()

	testServerPort := ln.Addr().(*net.TCPAddr).Port
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("hello from direct"))
		})
		_ = http.Serve(ln, mux)
	}()

	tracker := telemetry.NewTracker()
	fm := telemetry.NewFailureMonitor(100)
	bl := blocker.NewEngine(blocker.Options{})

	opts := EngineOptions{
		ListenAddr: "127.0.0.1:0", // allocate free port
		Tracker:    tracker,
		FailureMonitor: fm,
		Blocker:    bl,
		Rules: []routing.Rule{
			{
				ID:      "rule-direct-local",
				Enabled: true,
				Action:  routing.RouteAction{Type: routing.ActionDirect},
				IPCidr:  []string{"127.0.0.1/32"},
			},
		},
		FinalAction: "direct",
	}

	eng, err := New(opts)
	if err != nil {
		t.Fatalf("New Engine failed: %v", err)
	}
	if err := eng.Start(); err != nil {
		t.Fatalf("eng.Start failed: %v", err)
	}
	defer func() {
		_ = eng.Close()
	}()

	mixedPort := eng.Port()
	if mixedPort <= 0 {
		t.Fatalf("expected valid allocated mixed port, got %d", mixedPort)
	}

	// Make an HTTP request through the Mixed proxy
	proxyURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", mixedPort))
	if err != nil {
		t.Fatalf("parse proxy url failed: %v", err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 3 * time.Second,
	}

	targetURL := fmt.Sprintf("http://127.0.0.1:%d/hello", testServerPort)
	resp, err := httpClient.Get(targetURL)
	if err != nil {
		t.Fatalf("GET via proxy failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	if string(body) != "hello from direct" {
		t.Errorf("unexpected body: %s", string(body))
	}
}

// Tests that Engine integrates Blocker and blocks blacklisted domains.
func TestEngine_BlockerIntegration(t *testing.T) {
	tracker := telemetry.NewTracker()
	fm := telemetry.NewFailureMonitor(100)
	bl := blocker.NewEngine(blocker.Options{
		Denylist: []string{"ads.example.com"},
	})

	opts := EngineOptions{
		ListenAddr: "127.0.0.1:0",
		Tracker:    tracker,
		FailureMonitor: fm,
		Blocker:    bl,
		FinalAction: "direct",
	}

	eng, err := New(opts)
	if err != nil {
		t.Fatalf("New Engine failed: %v", err)
	}
	if err := eng.Start(); err != nil {
		t.Fatalf("eng.Start failed: %v", err)
	}
	defer func() {
		_ = eng.Close()
	}()

	mixedPort := eng.Port()
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", mixedPort))
	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 2 * time.Second,
	}

	resp, err := httpClient.Get("http://ads.example.com/banner.js")
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode < 400 {
			t.Errorf("expected error or HTTP 4xx/5xx for blocked domain, got status %d", resp.StatusCode)
		}
	}
}

// Tests that Engine routes traffic to sidecar loopback port via PROXY_POOL.
func TestEngine_SidecarRouting(t *testing.T) {
	// 1. Target HTTP server
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target failed: %v", err)
	}
	defer targetLn.Close()
	targetPort := targetLn.Addr().(*net.TCPAddr).Port

	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/proxy-ok", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("served through sidecar"))
		})
		_ = http.Serve(targetLn, mux)
	}()

	// 2. Mock SOCKS5 server representing a sidecar (e.g. naiveproxy or xray loopback)
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks failed: %v", err)
	}
	defer socksLn.Close()
	socksPort := socksLn.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			c, err := socksLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 256)
				// Read version + auth methods
				if _, err := io.ReadFull(conn, buf[:2]); err != nil {
					return
				}
				nAuth := int(buf[1])
				if _, err := io.ReadFull(conn, buf[:nAuth]); err != nil {
					return
				}
				// Reply no auth
				if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
					return
				}
				// Read request
				if _, err := io.ReadFull(conn, buf[:4]); err != nil {
					return
				}
				// addr type: 1 = IPv4, 3 = domain
				var targetHost string
				switch buf[3] {
				case 1:
					if _, err := io.ReadFull(conn, buf[:4]); err != nil {
						return
					}
					targetHost = net.IP(buf[:4]).String()
				case 3:
					if _, err := io.ReadFull(conn, buf[:1]); err != nil {
						return
					}
					dLen := int(buf[0])
					if _, err := io.ReadFull(conn, buf[:dLen]); err != nil {
						return
					}
					targetHost = string(buf[:dLen])
				}
				// port
				if _, err := io.ReadFull(conn, buf[:2]); err != nil {
					return
				}
				p := int(buf[0])<<8 | int(buf[1])

				targetConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", targetHost, p))
				if err != nil {
					_, _ = conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				defer targetConn.Close()

				// Success reply
				_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0})

				// Bidirectional copy
				done := make(chan struct{}, 2)
				go func() {
					_, _ = io.Copy(targetConn, conn)
					done <- struct{}{}
				}()
				go func() {
					_, _ = io.Copy(conn, targetConn)
					done <- struct{}{}
				}()
				<-done
			}(c)
		}
	}()

	// 3. Setup Engine with sidecar node and PROXY_POOL as final action
	tracker := telemetry.NewTracker()
	fm := telemetry.NewFailureMonitor(100)

	opts := EngineOptions{
		ListenAddr: "127.0.0.1:0",
		Tracker:    tracker,
		FailureMonitor: fm,
		Services: []config.Service{
			{
				ID:     "node-1",
				Name:   "Test Sidecar Node",
				Engine: config.EngineSidecar,
			},
		},
		AllocatedPorts: map[string]int{
			"node-1": socksPort,
		},
		FinalAction: "proxy_pool",
	}

	eng, err := New(opts)
	if err != nil {
		t.Fatalf("New Engine failed: %v", err)
	}
	if err := eng.Start(); err != nil {
		t.Fatalf("eng.Start failed: %v", err)
	}
	defer func() {
		_ = eng.Close()
	}()

	mixedPort := eng.Port()
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", mixedPort))
	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 3 * time.Second,
	}

	reqURL := fmt.Sprintf("http://127.0.0.1:%d/proxy-ok", targetPort)
	resp, err := httpClient.Get(reqURL)
	if err != nil {
		t.Fatalf("GET via sidecar pool failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	if string(body) != "served through sidecar" {
		t.Errorf("unexpected body: %s", string(body))
	}
}

// Tests that sidecar nodes remote addresses are extracted as CIDR prefixes for route_exclude_address.
func TestExtractSidecarExcludeAddresses(t *testing.T) {
	services := []config.Service{
		{
			ID:       "naive-1",
			Protocol: config.ProtoNaive,
			Engine:   config.EngineSidecar,
			Proxies:  []string{"https://user:pass@198.51.100.1:443"},
		},
		{
			ID:       "xray-1",
			Protocol: config.ProtoVLESS,
			Engine:   config.EngineSidecar,
			Server:   "203.0.113.5",
		},
		{
			ID:       "naive-ipv6",
			Protocol: config.ProtoNaive,
			Engine:   config.EngineSidecar,
			Proxies:  []string{"https://user:pass@[2001:db8::1]:443"},
		},
		{
			// Native sing-box node should not be in sidecar route exclusion
			ID:       "native-vless",
			Protocol: config.ProtoVLESS,
			Engine:   config.EngineSingBox,
			Server:   "192.0.2.1",
		},
	}

	excludes := extractSidecarExcludeAddresses(services, nil)
	expected := map[string]bool{
		"198.51.100.1/32": true,
		"203.0.113.5/32":  true,
		"2001:db8::1/128": true,
	}

	if len(excludes) != len(expected) {
		t.Fatalf("expected %d exclude addresses, got %d: %v", len(expected), len(excludes), excludes)
	}
	for _, ex := range excludes {
		if !expected[ex] {
			t.Errorf("unexpected exclude address %q", ex)
		}
	}
}

// Tests that TunPlatform injects TunFD and TunName into tun.Options.
func TestTunPlatform_OpenInterface(t *testing.T) {
	var captured tun.Options
	called := false

	tp := &TunPlatform{
		TunFD:   42,
		TunName: "utun7",
		TunCreator: func(opts tun.Options) (tun.Tun, error) {
			called = true
			captured = opts
			return nil, nil
		},
	}

	if !tp.UsePlatformInterface() {
		t.Fatalf("expected UsePlatformInterface to be true when TunFD > 0")
	}

	var opts tun.Options
	_, _ = tp.OpenInterface(&opts, option.TunPlatformOptions{})

	if !called {
		t.Fatalf("expected TunCreator to be called")
	}
	if captured.FileDescriptor != 42 {
		t.Errorf("expected FileDescriptor 42, got %d", captured.FileDescriptor)
	}
	if captured.Name != "utun7" {
		t.Errorf("expected Name utun7, got %q", captured.Name)
	}
}

// Tests that when TrafficMode is "tun", buildConfig includes tun inbound with auto_route and route_exclude_address.
func TestEngine_TUNConfigOptions(t *testing.T) {
	eng := &Engine{}
	ctx := createBoxContext(context.Background(), eng)
	opts := EngineOptions{
		TrafficMode:  "tun",
		TunFD:        55,
		TunInterface: "utun3",
		Services: []config.Service{
			{
				ID:       "sidecar-node",
				Protocol: config.ProtoNaive,
				Engine:   config.EngineSidecar,
				Proxies:  []string{"https://user:pass@198.51.100.99:443"},
			},
		},
	}

	cfg, err := eng.buildConfig(ctx, opts, "127.0.0.1", 10809)
	if err != nil {
		t.Fatalf("buildConfig failed: %v", err)
	}

	if cfg.Route == nil || !cfg.Route.AutoDetectInterface {
		t.Errorf("expected Route.AutoDetectInterface to be true")
	}

	foundTun := false
	for _, in := range cfg.Inbounds {
		if in.Type == "tun" {
			foundTun = true
			tunOpts, ok := in.Options.(*option.TunInboundOptions)
			if !ok || tunOpts == nil {
				t.Fatalf("expected *option.TunInboundOptions, got %T", in.Options)
			}
			if tunOpts.InterfaceName != "utun3" {
				t.Errorf("expected interface_name utun3, got %q", tunOpts.InterfaceName)
			}
			if !tunOpts.AutoRoute {
				t.Errorf("expected auto_route to be true")
			}
			if !tunOpts.StrictRoute {
				t.Errorf("expected strict_route to be true")
			}
			excludes := tunOpts.RouteExcludeAddress
			if len(excludes) == 0 {
				t.Fatalf("expected non-empty route_exclude_address")
			}
			if excludes[0].String() != "198.51.100.99/32" {
				t.Errorf("expected exclude 198.51.100.99/32, got %v", excludes[0])
			}
		}
	}
	if !foundTun {
		t.Errorf("expected tun inbound in configuration")
	}
}



