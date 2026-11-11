package warp

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"golang.org/x/net/http2"
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
	Netstack    *Netstack
	protocol    string // "h3" or "h2"
	endpoint    string
	ctx         context.Context
	cancel      context.CancelFunc
	closer      io.Closer
	closeOnce   sync.Once
}

func (t *MASQUETunnel) Protocol() string {
	return t.protocol
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
// When tcpOnly is true or forceMode == "h2", it directly connects over HTTP/2 TCP.
// Otherwise, it attempts HTTP/3 QUIC first, falling back to HTTP/2 if QUIC fails within 3 seconds.
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
		InsecureSkipVerify: true, // Pinned endpoint / self-signed certificate handshake
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

	// If forced to H2 or underlying transport is TCP-only, skip QUIC directly
	if tcpOnly || forceH2 {
		tun, err := dialMASQUEH2(tunnelCtx, dialer, endpoint, tlsCfg, ns, cancel)
		if err != nil {
			cancel()
			_ = ns.Close()
			return nil, fmt.Errorf("MASQUE HTTP/2 connection failed: %w", err)
		}
		return tun, nil
	}

	// Try HTTP/3 with 3-second timeout
	h3Ctx, h3Cancel := context.WithTimeout(ctx, 3*time.Second)
	tun, err := dialMASQUEH3(h3Ctx, dialer, endpoint, tlsCfg, ns, tunnelCtx, cancel)
	h3Cancel()
	if err == nil {
		return tun, nil
	}

	// Fallback to HTTP/2
	tun, err = dialMASQUEH2(tunnelCtx, dialer, endpoint, tlsCfg, ns, cancel)
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

	pConn, err := dialer.ListenPacket(ctx, "udp", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}

	rAddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		_ = pConn.Close()
		return nil, err
	}

	qCfg := &quic.Config{
		EnableDatagrams: true,
	}

	qConn, err := quic.DialEarly(ctx, pConn, rAddr, tlsCfg, qCfg)
	if err != nil {
		_ = pConn.Close()
		return nil, err
	}

	h3Tr := &http3.Transport{
		EnableDatagrams: true,
		TLSClientConfig: tlsCfg,
		QUICConfig:      qCfg,
	}

	clientConn := h3Tr.NewClientConn(qConn)

	reqStream, err := clientConn.OpenRequestStream(ctx)
	if err != nil {
		_ = qConn.CloseWithError(0, "")
		_ = pConn.Close()
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "CONNECT", "https://"+DefaultMASQUESNI+"/.well-known/masque/ip/*/*", nil)
	if err != nil {
		_ = qConn.CloseWithError(0, "")
		_ = pConn.Close()
		return nil, err
	}
	req.Header.Set("Capsule-Protocol", "?1")
	req.Header.Set("CF-Connect-Proto", "cf-connect-ip")

	if err := reqStream.SendRequestHeader(req); err != nil {
		_ = qConn.CloseWithError(0, "")
		_ = pConn.Close()
		return nil, err
	}

	resp, err := reqStream.ReadResponse()
	if err != nil {
		_ = qConn.CloseWithError(0, "")
		_ = pConn.Close()
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_ = qConn.CloseWithError(0, "")
		_ = pConn.Close()
		return nil, fmt.Errorf("HTTP/3 CONNECT rejected: %s", resp.Status)
	}

	tun := &MASQUETunnel{
		Netstack: ns,
		protocol: "h3",
		endpoint: endpoint,
		ctx:      tunnelCtx,
		cancel:   cancel,
		closer: closerFunc(func() error {
			return qConn.CloseWithError(0, "")
		}),
	}

	// Inbound datagram loop
	go func() {
		for {
			dg, err := reqStream.ReceiveDatagram(tunnelCtx)
			if err != nil {
				return
			}
			rawIP := dg
			if len(rawIP) > 1 && rawIP[0] == 0 && (rawIP[1]>>4 == 4 || rawIP[1]>>4 == 6) {
				rawIP = rawIP[1:]
			}
			_ = ns.InjectPacket(rawIP)
		}
	}()

	// Outbound datagram loop
	go func() {
		for {
			pkt, err := ns.ReadPacket(tunnelCtx)
			if err != nil {
				return
			}
			var dg []byte
			dg = append(dg, 0x00) // RFC 9297 Context ID 0
			dg = append(dg, pkt...)
			if err := reqStream.SendDatagram(dg); err != nil {
				return
			}
		}
	}()

	return tun, nil
}

func dialMASQUEH2(ctx context.Context, dialer Dialer, endpoint string, baseTLS *tls.Config, ns *Netstack, cancel context.CancelFunc) (*MASQUETunnel, error) {
	tlsCfg := baseTLS.Clone()
	tlsCfg.NextProtos = []string{http2.NextProtoTLS}

	rawConn, err := dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	t2 := &http2.Transport{}
	cc, err := t2.NewClientConn(tlsConn)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}

	pr, pw := io.Pipe()

	req, err := http.NewRequestWithContext(ctx, "CONNECT", "https://"+DefaultMASQUESNI+"/.well-known/masque/ip/*/*", pr)
	if err != nil {
		_ = cc.Close()
		return nil, err
	}
	req.Header.Set("Capsule-Protocol", "?1")
	req.Header.Set("CF-Connect-Proto", "cf-connect-ip")

	resp, err := cc.RoundTrip(req)
	if err != nil {
		_ = cc.Close()
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_ = cc.Close()
		return nil, fmt.Errorf("HTTP/2 CONNECT rejected: %s", resp.Status)
	}

	tun := &MASQUETunnel{
		Netstack: ns,
		protocol: "h2",
		endpoint: endpoint,
		ctx:      ctx,
		cancel:   cancel,
		closer:   cc,
	}

	// Inbound Capsule reader loop
	go func() {
		defer cancel()
		defer resp.Body.Close()
		for {
			capsuleType, err := readVarint(resp.Body)
			if err != nil {
				return
			}
			capsuleLen, err := readVarint(resp.Body)
			if err != nil {
				return
			}
			payload := make([]byte, capsuleLen)
			if _, err := io.ReadFull(resp.Body, payload); err != nil {
				return
			}
			if capsuleType == 0 { // DATAGRAM / IP_PACKET
				rawIP := payload
				if len(rawIP) > 1 && rawIP[0] == 0 && (rawIP[1]>>4 == 4 || rawIP[1]>>4 == 6) {
					rawIP = rawIP[1:]
				}
				_ = ns.InjectPacket(rawIP)
			}
		}
	}()

	// Outbound Capsule writer loop
	go func() {
		defer cancel()
		defer pw.Close()
		var varintBuf bytes.Buffer
		for {
			pkt, err := ns.ReadPacket(ctx)
			if err != nil {
				return
			}
			varintBuf.Reset()
			writeVarint(&varintBuf, 0) // Capsule Type: 0 (DATAGRAM)
			writeVarint(&varintBuf, uint64(len(pkt)+1))
			varintBuf.WriteByte(0x00) // Context ID 0
			varintBuf.Write(pkt)

			if _, err := pw.Write(varintBuf.Bytes()); err != nil {
				return
			}
		}
	}()

	return tun, nil
}

func readVarint(r io.Reader) (uint64, error) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return 0, err
	}
	prefix := first[0] >> 6
	length := 1 << prefix
	val := uint64(first[0] & 0x3f)
	for i := 1; i < length; i++ {
		var next [1]byte
		if _, err := io.ReadFull(r, next[:]); err != nil {
			return 0, err
		}
		val = (val << 8) | uint64(next[0])
	}
	return val, nil
}

func writeVarint(buf *bytes.Buffer, val uint64) {
	if val < 64 {
		buf.WriteByte(byte(val))
	} else if val < 16384 {
		buf.WriteByte(byte((val >> 8) | 0x40))
		buf.WriteByte(byte(val))
	} else if val < 1073741824 {
		buf.WriteByte(byte((val >> 24) | 0x80))
		buf.WriteByte(byte(val >> 16))
		buf.WriteByte(byte(val >> 8))
		buf.WriteByte(byte(val))
	} else {
		buf.WriteByte(byte((val >> 56) | 0xc0))
		buf.WriteByte(byte(val >> 48))
		buf.WriteByte(byte(val >> 40))
		buf.WriteByte(byte(val >> 32))
		buf.WriteByte(byte(val >> 24))
		buf.WriteByte(byte(val >> 16))
		buf.WriteByte(byte(val >> 8))
		buf.WriteByte(byte(val))
	}
}
