package runner

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"naive-client/internal/config"
)

// DefaultProbeURL is the lightweight HTTP 204 endpoint used to measure end-to-end proxy latency.
const DefaultProbeURL = "https://cp.cloudflare.com/generate_204"

// DefaultDownloadURL is the default payload endpoint used to measure proxy download throughput.
const DefaultDownloadURL = "https://speed.cloudflare.com/__down?bytes=10000000"

// Probe measures the round-trip latency through a local ListenEndpoint (socks or http)
// to targetURL. If targetURL is empty, DefaultProbeURL is used.
func Probe(ctx context.Context, ep config.ListenEndpoint, targetURL string) (time.Duration, error) {
	if targetURL == "" {
		targetURL = DefaultProbeURL
	}
	localAddr := ep.DialAddr()
	start := time.Now()

	transport, err := ProxyTransport(ep)
	if err != nil {
		// For redir protocol, fall back to a TCP handshake check on the local port.
		conn, dialErr := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", localAddr)
		if dialErr != nil {
			return 0, dialErr
		}
		_ = conn.Close()
		return time.Since(start), nil
	}
	defer transport.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, targetURL, nil)
	if err != nil {
		return 0, err
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode >= 500 {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return time.Since(start), nil
}

// MeasureDownloadSpeed downloads payload through the local ListenEndpoint (socks or http)
// and returns the measured throughput in bytes/second.
func MeasureDownloadSpeed(ctx context.Context, ep config.ListenEndpoint, targetURL string, onSample func(bytesPerSec float64)) (float64, error) {
	if targetURL == "" {
		targetURL = DefaultDownloadURL
	}
	transport, err := ProxyTransport(ep)
	if err != nil {
		return 0, err
	}
	defer transport.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Cache-Control", "no-store")

	client := &http.Client{
		Transport: transport,
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	start := time.Now()
	lastSample := start
	var totalBytes int64
	buf := make([]byte, 32*1024)

	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			totalBytes += int64(n)
			now := time.Now()
			if onSample != nil && now.Sub(lastSample) >= 200*time.Millisecond {
				if elapsed := now.Sub(start).Seconds(); elapsed > 0.05 {
					onSample(float64(totalBytes) / elapsed)
				}
				lastSample = now
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			// If context timed out after receiving substantial data, compute speed from downloaded bytes
			if totalBytes > 64*1024 {
				break
			}
			return 0, readErr
		}
	}

	if totalBytes == 0 {
		return 0, errors.New("未接收到测速数据")
	}
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		elapsed = 0.001
	}
	bps := float64(totalBytes) / elapsed
	if onSample != nil {
		onSample(bps)
	}
	return bps, nil
}

// FormatSpeed formats bytes/second into human-readable MB/s or KB/s.
func FormatSpeed(bytesPerSec float64) string {
	if bytesPerSec <= 0 {
		return "0 KB/s"
	}
	const (
		kb = 1024.0
		mb = 1024.0 * 1024.0
	)
	if bytesPerSec >= mb {
		return fmt.Sprintf("%.1f MB/s", bytesPerSec/mb)
	}
	return fmt.Sprintf("%.0f KB/s", max(1.0, bytesPerSec/kb))
}

// ProxyTransport returns an *http.Transport that routes HTTP/HTTPS requests
// through the local NaiveProxy listen endpoint (supports both socks5 and http).
func ProxyTransport(ep config.ListenEndpoint) (*http.Transport, error) {
	localAddr := ep.DialAddr()
	switch ep.Proto {
	case "http":
		u := &url.URL{
			Scheme: "http",
			Host:   localAddr,
		}
		if ep.User != "" {
			u.User = url.UserPassword(ep.User, ep.Pass)
		}
		return &http.Transport{
			Proxy: http.ProxyURL(u),
			DialContext: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout: 6 * time.Second,
		}, nil

	case "socks":
		return &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialSOCKS5(ctx, localAddr, ep.User, ep.Pass, addr)
			},
			TLSHandshakeTimeout: 6 * time.Second,
		}, nil

	default:
		return nil, fmt.Errorf("不支持通过 %s 协议构建 HTTP 传输", ep.Proto)
	}
}

// dialSOCKS5 performs a minimal RFC 1928 / RFC 1929 SOCKS5 CONNECT handshake.
func dialSOCKS5(ctx context.Context, proxyAddr, user, pass, targetAddr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid target port: %q", portStr)
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	}
	defer func() {
		_ = conn.SetDeadline(time.Time{})
	}()

	// 1. Greeting
	if user != "" {
		if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
			_ = conn.Close()
			return nil, err
		}
	} else {
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}

	var methodResp [2]byte
	if _, err := io.ReadFull(conn, methodResp[:]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if methodResp[0] != 0x05 {
		_ = conn.Close()
		return nil, errors.New("invalid SOCKS5 version")
	}

	// 2. Username/Password authentication (RFC 1929) if required
	if methodResp[1] == 0x02 {
		if len(user) > 255 || len(pass) > 255 {
			_ = conn.Close()
			return nil, errors.New("SOCKS5 credentials too long")
		}
		authReq := make([]byte, 0, 3+len(user)+len(pass))
		authReq = append(authReq, 0x01, byte(len(user)))
		authReq = append(authReq, user...)
		authReq = append(authReq, byte(len(pass)))
		authReq = append(authReq, pass...)
		if _, err := conn.Write(authReq); err != nil {
			_ = conn.Close()
			return nil, err
		}
		var authResp [2]byte
		if _, err := io.ReadFull(conn, authResp[:]); err != nil {
			_ = conn.Close()
			return nil, err
		}
		if authResp[1] != 0x00 {
			_ = conn.Close()
			return nil, errors.New("SOCKS5 authentication failed")
		}
	} else if methodResp[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("unsupported SOCKS5 auth method: %d", methodResp[1])
	}

	// 3. CONNECT request
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			_ = conn.Close()
			return nil, errors.New("target host too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		_ = conn.Close()
		return nil, err
	}

	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if hdr[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("SOCKS5 connect failed with code %d", hdr[1])
	}

	// Consume bound address
	var skip int
	switch hdr[3] {
	case 0x01:
		skip = 4 + 2
	case 0x04:
		skip = 16 + 2
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			_ = conn.Close()
			return nil, err
		}
		skip = int(l[0]) + 2
	default:
		_ = conn.Close()
		return nil, fmt.Errorf("unknown SOCKS5 address type %d", hdr[3])
	}
	if _, err := io.CopyN(io.Discard, conn, int64(skip)); err != nil {
		_ = conn.Close()
		return nil, err
	}

	// Suppress unused import warning if base64 isn't needed elsewhere
	_ = base64.StdEncoding
	return conn, nil
}
