package warp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

const (
	DefaultMASQUEConnectURI = "https://cloudflareaccess.com"
	h3Timeout               = 2500 * time.Millisecond
	h2Timeout               = 6000 * time.Millisecond
)

// Dialer abstracts upstream connection dialing (e.g. sing-box Outbound or net.Dialer).
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	ListenPacket(ctx context.Context, network, addr string) (net.PacketConn, error)
}

// defaultDialer uses Go's standard net.Dialer and net.ListenPacket.
type defaultDialer struct {
	d net.Dialer
}

func (d *defaultDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.d.DialContext(ctx, network, addr)
}

func (d *defaultDialer) ListenPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	var lc net.ListenConfig
	return lc.ListenPacket(ctx, network, "0.0.0.0:0")
}

type closerFunc func() error

func (f closerFunc) Close() error {
	return f()
}

// MASQUETunnel manages an active MASQUE tunnel to Cloudflare over HTTP/3 or HTTP/2.
type MASQUETunnel struct {
	Netstack  *Netstack
	protocol  string // "h3" or "h2"
	endpoint  string
	ctx       context.Context
	cancel    context.CancelFunc
	closer    io.Closer
	closeOnce sync.Once
}

func (t *MASQUETunnel) Protocol() string {
	return t.protocol
}

func (t *MASQUETunnel) Done() <-chan struct{} {
	if t.ctx == nil {
		return nil
	}
	return t.ctx.Done()
}

func (t *MASQUETunnel) DialContextTCP(ctx context.Context, dest string) (net.Conn, error) {
	return t.Netstack.DialContextTCP(ctx, dest)
}

func (t *MASQUETunnel) DialUDP(ctx context.Context, dest string) (net.Conn, error) {
	return t.Netstack.DialUDP(ctx, dest)
}

func (t *MASQUETunnel) Close() error {
	var err error
	t.closeOnce.Do(func() {
		t.cancel()
		if t.closer != nil {
			err = t.closer.Close()
		}
		_ = t.Netstack.Close()
	})
	return err
}

// ConnectMASQUE establishes a Cloudflare Consumer MASQUE tunnel.
// When tcpOnly is true or forceH2 is true, it directly connects over HTTP/2 TCP.
// Otherwise, it attempts HTTP/3 QUIC first, falling back to HTTP/2 if QUIC fails.
func ConnectMASQUE(ctx context.Context, dialer Dialer, endpoint string, acc *Account, tcpOnly bool, forceH2 bool) (*MASQUETunnel, error) {
	if dialer == nil {
		dialer = &defaultDialer{}
	}
	if endpoint == "" {
		endpoint = DefaultMASQUEEndpoint
	}
	if acc == nil {
		return nil, errors.New("missing MASQUE account credentials")
	}

	cert, err := ParseMASQUETLSCertificate(acc.MASQUECertPEM, acc.MASQUEPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client certificate: %w", err)
	}

	tlsCfg := &tls.Config{
		ServerName:         DefaultMASQUESNI,
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, // Self-signed / Cloudflare Anycast endpoint verification
	}

	ipv4 := acc.MASQUEIPv4
	if ipv4 == "" {
		ipv4 = acc.IPv4
	}
	ipv6 := acc.MASQUEIPv6
	if ipv6 == "" {
		ipv6 = acc.IPv6
	}

	ns, err := NewNetstack(ipv4, ipv6)
	if err != nil {
		return nil, fmt.Errorf("failed to create netstack: %w", err)
	}

	tunnelCtx, cancel := context.WithCancel(context.Background())

	// If forced to H2 or underlying transport is TCP-only, connect over HTTP/2 directly
	if tcpOnly || forceH2 {
		h2DialCtx, h2Cancel := context.WithTimeout(ctx, h2Timeout)
		tun, err := dialMASQUEH2(h2DialCtx, dialer, endpoint, tlsCfg, ns, tunnelCtx, cancel)
		h2Cancel()
		if err != nil {
			cancel()
			_ = ns.Close()
			return nil, fmt.Errorf("MASQUE HTTP/2 connection failed: %w", err)
		}
		return tun, nil
	}

	// Try HTTP/3 with timeout
	h3Ctx, h3Cancel := context.WithTimeout(ctx, h3Timeout)
	tun, err := dialMASQUEH3(h3Ctx, dialer, endpoint, tlsCfg, ns, tunnelCtx, cancel)
	h3Cancel()
	if err == nil {
		return tun, nil
	}

	// Fallback to HTTP/2
	h2DialCtx, h2Cancel := context.WithTimeout(ctx, h2Timeout)
	tun, err = dialMASQUEH2(h2DialCtx, dialer, endpoint, tlsCfg, ns, tunnelCtx, cancel)
	h2Cancel()
	if err != nil {
		cancel()
		_ = ns.Close()
		return nil, fmt.Errorf("MASQUE fallback to HTTP/2 failed: %w", err)
	}
	return tun, nil
}

func dialMASQUEH3(ctx context.Context, dialer Dialer, endpoint string, baseTLS *tls.Config, ns *Netstack, tunnelCtx context.Context, cancel context.CancelFunc) (*MASQUETunnel, error) {
	tlsCfg := baseTLS.Clone()
	tlsCfg.NextProtos = []string{http3.NextProtoH3}

	// Use tunnelCtx for ListenPacket so cancelling the dial timeout context after handshake
	// does not tear down the underlying proxy packet session.
	pConn, err := dialer.ListenPacket(tunnelCtx, "udp", endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to listen packet for endpoint %s: %w", endpoint, err)
	}

	var dialMu sync.Mutex
	dialSettled := false
	stopListenWatch := context.AfterFunc(ctx, func() {
		dialMu.Lock()
		settled := dialSettled
		dialMu.Unlock()
		if !settled {
			_ = pConn.Close()
		}
	})
	defer func() {
		dialMu.Lock()
		dialSettled = true
		dialMu.Unlock()
		stopListenWatch()
	}()

	rAddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		_ = pConn.Close()
		return nil, fmt.Errorf("failed to resolve UDP address %s: %w", endpoint, err)
	}

	qTransport := &quic.Transport{
		Conn:               pConn,
		ConnectionIDLength: 20,
	}

	qCfg := &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 15 * time.Second,
	}

	qConn, err := qTransport.DialEarly(ctx, rAddr, tlsCfg, qCfg)
	if err != nil {
		_ = qTransport.Close()
		_ = pConn.Close()
		return nil, fmt.Errorf("QUIC dial failed: %w", err)
	}

	h3Tr := &http3.Transport{
		EnableDatagrams:    true,
		DisableCompression: true,
		AdditionalSettings: map[uint64]uint64{
			0x276: 1, // SETTINGS_H3_DATAGRAM_00 required by Cloudflare
		},
	}

	clientConn := h3Tr.NewClientConn(qConn)

	template, err := uritemplate.New(DefaultMASQUEConnectURI)
	if err != nil {
		_ = qConn.CloseWithError(0, "")
		_ = qTransport.Close()
		_ = pConn.Close()
		return nil, err
	}

	additionalHeaders := http.Header{
		"User-Agent": []string{""},
	}

	ipConn, rsp, err := connectip.Dial(ctx, clientConn, template, "cf-connect-ip", additionalHeaders, true)
	if err != nil {
		_ = h3Tr.Close()
		_ = qConn.CloseWithError(0, "")
		_ = qTransport.Close()
		_ = pConn.Close()
		return nil, fmt.Errorf("connect-ip HTTP/3 dial failed: %w", err)
	}
	if rsp.StatusCode < 200 || rsp.StatusCode >= 300 {
		_ = ipConn.Close()
		_ = h3Tr.Close()
		_ = qConn.CloseWithError(0, "")
		_ = qTransport.Close()
		_ = pConn.Close()
		return nil, fmt.Errorf("HTTP/3 CONNECT rejected: %s", rsp.Status)
	}

	_ = ipConn.AdvertiseRoute(ctx, []connectip.IPRoute{
		{
			IPProtocol: 0,
			StartIP:    netip.AddrFrom4([4]byte{}),
			EndIP:      netip.AddrFrom4([4]byte{255, 255, 255, 255}),
		},
		{
			IPProtocol: 0,
			StartIP:    netip.AddrFrom16([16]byte{}),
			EndIP: netip.AddrFrom16([16]byte{
				255, 255, 255, 255,
				255, 255, 255, 255,
				255, 255, 255, 255,
				255, 255, 255, 255,
			}),
		},
	})

	tun := &MASQUETunnel{
		Netstack: ns,
		protocol: "h3",
		endpoint: endpoint,
		ctx:      tunnelCtx,
		cancel:   cancel,
		closer: closerFunc(func() error {
			_ = ipConn.Close()
			_ = h3Tr.Close()
			_ = qConn.CloseWithError(0, "")
			_ = qTransport.Close()
			_ = pConn.Close()
			return nil
		}),
	}

	startTunnelLoops(tun, ipConn)
	return tun, nil
}

func dialMASQUEH2(dialCtx context.Context, dialer Dialer, endpoint string, baseTLS *tls.Config, ns *Netstack, tunnelCtx context.Context, cancel context.CancelFunc) (*MASQUETunnel, error) {
	tlsCfg := baseTLS.Clone()
	tlsCfg.NextProtos = []string{"h2"}

	var connMu sync.Mutex
	var activeConn net.Conn

	h2Tr := &http2.Transport{
		DisableCompression: true,
		ReadIdleTimeout:    30 * time.Second,
		PingTimeout:        10 * time.Second,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			rawConn, err := dialer.DialContext(dialCtx, "tcp", endpoint)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(rawConn, tlsCfg)
			if err := tlsConn.HandshakeContext(dialCtx); err != nil {
				_ = rawConn.Close()
				return nil, err
			}
			connMu.Lock()
			activeConn = tlsConn
			connMu.Unlock()
			return tlsConn, nil
		},
	}
	h2Client := &http.Client{
		Transport: h2Tr,
	}

	template, err := uritemplate.New(DefaultMASQUEConnectURI)
	if err != nil {
		return nil, err
	}

	h2Headers := http.Header{
		"User-Agent":       []string{""},
		"cf-connect-proto": []string{"cf-connect-ip"},
		"pq-enabled":       []string{"false"},
	}

	// reqCtx governs the long-lived HTTP/2 CONNECT stream (tied to tunnelCtx, NOT dialCtx).
	// If dialCtx expires or is canceled before DialH2 finishes, reqCancel aborts the handshake.
	// Once DialH2 succeeds, dialSettled=true ensures h2Cancel() does not kill the active stream.
	reqCtx, reqCancel := context.WithCancel(tunnelCtx)
	var dialMu sync.Mutex
	dialSettled := false
	stopDialWatch := context.AfterFunc(dialCtx, func() {
		dialMu.Lock()
		settled := dialSettled
		dialMu.Unlock()
		if !settled {
			reqCancel()
		}
	})

	ipConn, rsp, err := connectip.DialH2(reqCtx, h2Client, template, h2Headers)
	dialMu.Lock()
	dialSettled = true
	dialMu.Unlock()
	stopDialWatch()

	closeTransport := func() {
		reqCancel()
		h2Tr.CloseIdleConnections()
		connMu.Lock()
		c := activeConn
		activeConn = nil
		connMu.Unlock()
		if c != nil {
			_ = c.Close()
		}
	}

	if err != nil {
		closeTransport()
		return nil, fmt.Errorf("connect-ip HTTP/2 dial failed: %w", err)
	}
	if rsp.StatusCode < 200 || rsp.StatusCode >= 300 {
		_ = ipConn.Close()
		closeTransport()
		return nil, fmt.Errorf("HTTP/2 CONNECT rejected: %s", rsp.Status)
	}

	_ = ipConn.AdvertiseRoute(dialCtx, []connectip.IPRoute{
		{
			IPProtocol: 0,
			StartIP:    netip.AddrFrom4([4]byte{}),
			EndIP:      netip.AddrFrom4([4]byte{255, 255, 255, 255}),
		},
		{
			IPProtocol: 0,
			StartIP:    netip.AddrFrom16([16]byte{}),
			EndIP: netip.AddrFrom16([16]byte{
				255, 255, 255, 255,
				255, 255, 255, 255,
				255, 255, 255, 255,
				255, 255, 255, 255,
			}),
		},
	})

	tun := &MASQUETunnel{
		Netstack: ns,
		protocol: "h2",
		endpoint: endpoint,
		ctx:      tunnelCtx,
		cancel:   cancel,
		closer: closerFunc(func() error {
			_ = ipConn.Close()
			closeTransport()
			return nil
		}),
	}

	startTunnelLoops(tun, ipConn)
	return tun, nil
}

func startTunnelLoops(tun *MASQUETunnel, ipConn *connectip.Conn) {
	// Inbound loop (ipConn -> Netstack)
	go func() {
		defer tun.Close()
		buf := make([]byte, 65535)
		for {
			n, err := ipConn.ReadPacket(buf, true)
			if err != nil {
				return
			}
			if n > 0 {
				_ = tun.Netstack.InjectPacket(buf[:n])
			}
		}
	}()

	// Outbound loop (Netstack -> ipConn)
	go func() {
		defer tun.Close()
		for {
			pkt, err := tun.Netstack.ReadPacket(tun.ctx)
			if err != nil {
				return
			}
			icmp, err := ipConn.WritePacket(pkt)
			if err != nil {
				return
			}
			if len(icmp) > 0 {
				_ = tun.Netstack.InjectPacket(icmp)
			}
		}
	}()
}
