package gateway

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"naive-client/internal/telemetry"
)

// Tests that the Mixed Gateway handles both SOCKS5 and HTTP CONNECT on a single port.
func TestGateway_MixedSocks5AndHttpConnect(t *testing.T) {
	// 1. Start echo server simulating remote destination
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start echo server: %v", err)
	}
	defer echoListener.Close()

	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	echoAddr := echoListener.Addr().String()

	// 2. Start Gateway on ephemeral port
	tr := telemetry.NewTracker()
	gw, err := New(Options{
		BindAddr: "127.0.0.1:0",
		Tracker:  tr,
		DialTarget: func(ctx context.Context, target string) (net.Conn, string, error) {
			var d net.Dialer
			conn, err := d.DialContext(ctx, "tcp", echoAddr)
			return conn, "mock-node-1", err
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

	// 3. Test SOCKS5 inbound flow
	t.Run("SOCKS5", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", gwAddr, 2*time.Second)
		if err != nil {
			t.Fatalf("failed to dial gateway: %v", err)
		}
		defer conn.Close()

		// SOCKS5 greeting: 0x05 (version), 0x01 (1 method), 0x00 (NO AUTH)
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			t.Fatalf("failed to write socks greeting: %v", err)
		}

		resp := make([]byte, 2)
		if _, err := io.ReadFull(conn, resp); err != nil {
			t.Fatalf("failed to read socks greeting resp: %v", err)
		}
		if resp[0] != 0x05 || resp[1] != 0x00 {
			t.Fatalf("invalid socks greeting resp: %v", resp)
		}

		// SOCKS5 connect request: 0x05, 0x01 (CONNECT), 0x00 (RSV), 0x03 (DOMAIN), "example.internal:80"
		domain := "echo.internal"
		req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
		req = append(req, []byte(domain)...)
		req = append(req, 0x00, 0x50) // port 80
		if _, err := conn.Write(req); err != nil {
			t.Fatalf("failed to write socks connect req: %v", err)
		}

		connResp := make([]byte, 10)
		if _, err := io.ReadFull(conn, connResp); err != nil {
			t.Fatalf("failed to read socks connect resp: %v", err)
		}
		if connResp[0] != 0x05 || connResp[1] != 0x00 {
			t.Fatalf("socks connect failed: %v", connResp)
		}

		// Echo test
		payload := []byte("hello-socks5")
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("write payload failed: %v", err)
		}
		echoBuf := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, echoBuf); err != nil {
			t.Fatalf("read echo failed: %v", err)
		}
		if string(echoBuf) != string(payload) {
			t.Fatalf("expected echo %q, got %q", payload, echoBuf)
		}
	})

	// 4. Test HTTP CONNECT inbound flow
	t.Run("HTTP_CONNECT", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", gwAddr, 2*time.Second)
		if err != nil {
			t.Fatalf("failed to dial gateway: %v", err)
		}
		defer conn.Close()

		reqStr := "CONNECT echo.internal:443 HTTP/1.1\r\nHost: echo.internal:443\r\n\r\n"
		if _, err := conn.Write([]byte(reqStr)); err != nil {
			t.Fatalf("failed to write HTTP CONNECT: %v", err)
		}

		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
		if err != nil {
			t.Fatalf("failed to read CONNECT response: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
		}

		payload := []byte("hello-http-connect")
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("write payload failed: %v", err)
		}
		echoBuf := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, echoBuf); err != nil {
			t.Fatalf("read echo failed: %v", err)
		}
		if string(echoBuf) != string(payload) {
			t.Fatalf("expected echo %q, got %q", payload, echoBuf)
		}
	})

	// 5. Verify telemetry recorded dials for "mock-node-1"
	sc := tr.GetScore("mock-node-1")
	if sc.EWMA == 0 {
		t.Fatalf("expected telemetry EWMA recorded for mock-node-1")
	}
}
