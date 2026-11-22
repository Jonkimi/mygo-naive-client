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
	"strconv"
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
	listenNet, listenAddr := packetListenTarget(network, addr, nil)
	return lc.ListenPacket(ctx, listenNet, listenAddr)
}

type closerFunc func() error

func (f closerFunc) Close() error {
	return f()
}

type domainUDPAddr string

func (a domainUDPAddr) Network() string { return "udp" }
func (a domainUDPAddr) String() string  { return string(a) }

func resolveMASQUEUDPAddr(ctx context.Context, dialer Dialer, pConn net.PacketConn, endpoint string) (net.Addr, error) {
	if ap, err := netip.ParseAddrPort(endpoint); err == nil {
		return net.UDPAddrFromAddrPort(ap), nil
	}
	if _, isDefault := dialer.(*defaultDialer); !isDefault {
		if _, isUDPConn := pConn.(*net.UDPConn); !isUDPConn {
			// Detour packet connections route destination domains remotely; avoid host DNS lookup.
			return domainUDPAddr(endpoint), nil
		}
	}
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port %q", portStr)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses for %q", host)
	}
	selected := ips[0]
	for _, ip := range ips {
		if ip.Is4() {
			selected = ip
			break
		}
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(selected, uint16(port))), nil
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
		if t.cancel != nil {
			t.cancel()
		}
		if t.closer != nil {
			err = t.closer.Close()
		}
		if t.Netstack != nil {
			_ = t.Netstack.Close()
		}
	})
	return err
}

// MASQUEOptions controls how ConnectMASQUEWithOptions establishes the tunnel.
type MASQUEOptions struct {
	TCPOnly  bool // Upstream proxy only supports TCP; skip HTTP/3 and use HTTP/2 only.
	ForceH2  bool // Force HTTP/2 only without falling back to HTTP/3.
	PreferH2 bool // Try HTTP/2 first and fall back to HTTP/3 if HTTP/2 fails.
}

// ConnectMASQUE establishes a Cloudflare Consumer MASQUE tunnel.
// When tcpOnly is true or forceH2 is true, it directly connects over HTTP/2 TCP.
// Otherwise, it attempts HTTP/3 QUIC first, falling back to HTTP/2 if QUIC fails.
func ConnectMASQUE(ctx context.Context, dialer Dialer, endpoint string, acc *Account, tcpOnly bool, forceH2 bool) (*MASQUETunnel, error) {
	return ConnectMASQUEWithOptions(ctx, dialer, endpoint, acc, MASQUEOptions{
		TCPOnly: tcpOnly,
		ForceH2: forceH2,
	})
}

// ConnectMASQUEWithOptions establishes a Cloudflare Consumer MASQUE tunnel with explicit protocol ordering options.
func ConnectMASQUEWithOptions(ctx context.Context, dialer Dialer, endpoint string, acc *Account, opts MASQUEOptions) (*MASQUETunnel, error) {
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

	// If forced to H2, underlying transport is TCP-only, or the endpoint is a known H2-only
	// MASQUE Anycast address (non-::1/::2), connect over HTTP/2 directly without falling back to QUIC.
	if opts.TCPOnly || opts.ForceH2 || isKnownMASQUEH2OnlyEndpoint(endpoint) {
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

	if opts.PreferH2 {
		// Try HTTP/2 first (avoids UDP QoS throttling)
		h2DialCtx, h2Cancel := context.WithTimeout(ctx, h2Timeout)
		tun, h2Err := dialMASQUEH2(h2DialCtx, dialer, endpoint, tlsCfg, ns, tunnelCtx, cancel)
		h2Cancel()
		if h2Err == nil {
			return tun, nil
		}
		if ctx.Err() != nil {
			cancel()
			_ = ns.Close()
			return nil, fmt.Errorf("MASQUE HTTP/2 connection failed: %w", h2Err)
		}

		// Fallback to HTTP/3
		h3Ctx, h3Cancel := context.WithTimeout(ctx, h3Timeout)
		tun, h3Err := dialMASQUEH3(h3Ctx, dialer, endpoint, tlsCfg, ns, tunnelCtx, cancel)
		h3Cancel()
		if h3Err != nil {
			cancel()
			_ = ns.Close()
			return nil, fmt.Errorf("MASQUE HTTP/2 failed (%v) and fallback to HTTP/3 failed: %w", h2Err, h3Err)
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
	if ctx.Err() != nil {
		cancel()
		_ = ns.Close()
		return nil, fmt.Errorf("MASQUE HTTP/3 connection failed: %w", err)
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

	// Tie listenCtx to ctx only while the handshake is settling so cancelling h3Timeout
	// after handshake does not tear down the active proxy packet session, while still
	// aborting blocked ListenPacket calls promptly on timeout or shutdown.
	listenCtx, listenCancel := context.WithCancel(tunnelCtx)
	var dialMu sync.Mutex
	dialSettled := false
	var pConn net.PacketConn
	var pConnCloseOnce sync.Once
	closePacketConn := func(c net.PacketConn) {
		if c == nil {
			return
		}
		pConnCloseOnce.Do(func() {
			_ = c.Close()
		})
	}
	stopListenWatch := context.AfterFunc(ctx, func() {
		dialMu.Lock()
		settled := dialSettled
		c := pConn
		dialMu.Unlock()
		if !settled {
			listenCancel()
			closePacketConn(c)
		}
	})

	rawPConn, err := dialer.ListenPacket(listenCtx, "udp", endpoint)
	if err != nil {
		dialMu.Lock()
		dialSettled = true
		dialMu.Unlock()
		stopListenWatch()
		listenCancel()
		return nil, fmt.Errorf("failed to listen packet for endpoint %s: %w", endpoint, err)
	}
	dialMu.Lock()
	pConn = rawPConn
	aborted := dialSettled || ctx.Err() != nil
	if aborted {
		dialSettled = true
	}
	dialMu.Unlock()
	if aborted {
		stopListenWatch()
		closePacketConn(pConn)
		listenCancel()
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("failed to listen packet for endpoint %s: %w", endpoint, err)
		}
		return nil, fmt.Errorf("failed to listen packet for endpoint %s: dial aborted", endpoint)
	}

	cleanupDial := func() {
		dialMu.Lock()
		dialSettled = true
		dialMu.Unlock()
		stopListenWatch()
		closePacketConn(pConn)
		listenCancel()
	}

	rAddr, err := resolveMASQUEUDPAddr(ctx, dialer, pConn, endpoint)
	if err != nil {
		cleanupDial()
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
		cleanupDial()
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
		_ = h3Tr.Close()
		_ = qConn.CloseWithError(0, "")
		_ = qTransport.Close()
		cleanupDial()
		return nil, err
	}

	additionalHeaders := http.Header{
		"User-Agent": []string{""},
	}

	ipConn, rsp, err := connectip.Dial(ctx, clientConn, template, "cf-connect-ip", additionalHeaders, true)
	dialMu.Lock()
	dialSettled = true
	dialMu.Unlock()
	stopped := stopListenWatch()
	if err == nil && (!stopped || ctx.Err() != nil) {
		err = ctx.Err()
		if err == nil {
			err = context.Canceled
		}
		_ = ipConn.Close()
	}
	if err != nil {
		_ = h3Tr.Close()
		_ = qConn.CloseWithError(0, "")
		_ = qTransport.Close()
		closePacketConn(pConn)
		listenCancel()
		if dialErr := ctx.Err(); dialErr != nil && errors.Is(err, context.Canceled) {
			return nil, fmt.Errorf("connect-ip HTTP/3 dial failed: %w", dialErr)
		}
		return nil, fmt.Errorf("connect-ip HTTP/3 dial failed: %w", err)
	}
	if rsp.StatusCode < 200 || rsp.StatusCode >= 300 {
		_ = ipConn.Close()
		_ = h3Tr.Close()
		_ = qConn.CloseWithError(0, "")
		_ = qTransport.Close()
		closePacketConn(pConn)
		listenCancel()
		return nil, fmt.Errorf("HTTP/3 CONNECT rejected: %s", rsp.Status)
	}

	advCtx, advCancel := context.WithTimeout(tunnelCtx, 2*time.Second)
	_ = ipConn.AdvertiseRoute(advCtx, []connectip.IPRoute{
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
	advCancel()

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
			closePacketConn(pConn)
			listenCancel()
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
	var dialConns []net.Conn
	var transportClosed bool

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
			if transportClosed {
				connMu.Unlock()
				_ = tlsConn.Close()
				return nil, context.Canceled
			}
			dialConns = append(dialConns, tlsConn)
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
	stopped := stopDialWatch()

	closeTransport := func() {
		reqCancel()
		h2Tr.CloseIdleConnections()
		connMu.Lock()
		transportClosed = true
		conns := dialConns
		dialConns = nil
		connMu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	}

	if err == nil && (!stopped || reqCtx.Err() != nil) {
		_ = ipConn.Close()
		closeTransport()
		if dialErr := dialCtx.Err(); dialErr != nil {
			return nil, fmt.Errorf("connect-ip HTTP/2 dial aborted: %w", dialErr)
		}
		if reqErr := reqCtx.Err(); reqErr != nil {
			return nil, fmt.Errorf("connect-ip HTTP/2 dial aborted: %w", reqErr)
		}
		return nil, fmt.Errorf("connect-ip HTTP/2 dial aborted: %w", context.Canceled)
	}

	if err != nil {
		closeTransport()
		if dialErr := dialCtx.Err(); dialErr != nil && errors.Is(err, context.Canceled) {
			return nil, fmt.Errorf("connect-ip HTTP/2 dial failed: %w", dialErr)
		}
		return nil, fmt.Errorf("connect-ip HTTP/2 dial failed: %w", err)
	}
	if rsp.StatusCode < 200 || rsp.StatusCode >= 300 {
		_ = ipConn.Close()
		closeTransport()
		return nil, fmt.Errorf("HTTP/2 CONNECT rejected: %s", rsp.Status)
	}

	advCtx, advCancel := context.WithTimeout(tunnelCtx, 2*time.Second)
	_ = ipConn.AdvertiseRoute(advCtx, []connectip.IPRoute{
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
	advCancel()

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
