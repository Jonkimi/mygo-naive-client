package boxengine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"naive-client/internal/warp"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type warpMasqueOptions struct {
	Detour            string `json:"detour,omitempty"`
	Endpoint          string `json:"endpoint,omitempty"`
	TCPOnlyDetour     bool   `json:"tcp_only_detour,omitempty"`
	ForceH2           bool   `json:"force_h2,omitempty"`
	PrivateKey        string `json:"private_key,omitempty"`
	CertPEM           string `json:"cert_pem,omitempty"`
	IPv4              string `json:"ipv4,omitempty"`
	IPv6              string `json:"ipv6,omitempty"`
	WireGuardFallback string `json:"wireguard_fallback,omitempty"`
}

type warpMasqueOutbound struct {
	tag         string
	router      adapter.Router
	outboundMgr adapter.OutboundManager
	logger      log.ContextLogger
	opts        warpMasqueOptions
	eng         *Engine

	tun            *warp.MASQUETunnel
	masqueFailedAt time.Time
	mu             sync.Mutex
	closed         bool
}

func newWarpMasqueOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, opts warpMasqueOptions, eng *Engine) (adapter.Outbound, error) {
	return &warpMasqueOutbound{
		tag:         tag,
		router:      router,
		outboundMgr: service.FromContext[adapter.OutboundManager](ctx),
		logger:      logger,
		opts:        opts,
		eng:         eng,
	}, nil
}

func (w *warpMasqueOutbound) Type() string {
	return "masque"
}

func (w *warpMasqueOutbound) Tag() string {
	return w.tag
}

func (w *warpMasqueOutbound) Network() []string {
	return []string{N.NetworkTCP, N.NetworkUDP}
}

func (w *warpMasqueOutbound) Dependencies() []string {
	if w.opts.Detour != "" {
		return []string{w.opts.Detour}
	}
	return nil
}

type outboundDialerAdapter struct {
	ob adapter.Outbound
}

func (d *outboundDialerAdapter) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.ob.DialContext(ctx, network, M.ParseSocksaddr(addr))
}

func (d *outboundDialerAdapter) ListenPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	return d.ob.ListenPacket(ctx, M.ParseSocksaddr(addr))
}

func (w *warpMasqueOutbound) getFallbackOutbound() adapter.Outbound {
	if w.opts.WireGuardFallback == "" {
		return nil
	}
	if w.eng != nil {
		if fbOb, ok := w.eng.GetOutbound(w.opts.WireGuardFallback); ok {
			return fbOb
		}
	}
	if w.outboundMgr != nil {
		if fbOb, ok := w.outboundMgr.Outbound(w.opts.WireGuardFallback); ok {
			return fbOb
		}
	}
	return nil
}

func (w *warpMasqueOutbound) getOrCreateTunnel(ctx context.Context) (*warp.MASQUETunnel, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil, errors.New("outbound closed")
	}
	if w.opts.WireGuardFallback != "" && time.Since(w.masqueFailedAt) < 60*time.Second {
		return nil, errors.New("masque recently failed, using wireguard fallback")
	}
	if w.tun != nil {
		select {
		case <-w.tun.Done():
			w.tun = nil
		default:
			return w.tun, nil
		}
	}

	var upstreamDialer warp.Dialer
	if w.opts.Detour != "" {
		var ob adapter.Outbound
		var ok bool
		if w.outboundMgr != nil {
			ob, ok = w.outboundMgr.Outbound(w.opts.Detour)
		}
		if !ok && w.eng != nil {
			ob, ok = w.eng.GetOutbound(w.opts.Detour)
		}
		if !ok {
			return nil, fmt.Errorf("detour outbound %q not found", w.opts.Detour)
		}
		upstreamDialer = &outboundDialerAdapter{ob: ob}
	}

	acc := &warp.Account{
		MASQUEPrivateKey: w.opts.PrivateKey,
		MASQUECertPEM:    w.opts.CertPEM,
		MASQUEIPv4:       w.opts.IPv4,
		MASQUEIPv6:       w.opts.IPv6,
	}

	// Fallback to global Cloudflare account if node credentials not explicitly set
	if acc.MASQUEPrivateKey == "" && w.eng != nil && w.eng.cloudflareConfig != nil {
		gAcc := w.eng.cloudflareConfig.Account
		acc.MASQUEPrivateKey = gAcc.MASQUEPrivateKey
		acc.MASQUECertPEM = gAcc.MASQUECertPEM
		acc.MASQUEIPv4 = gAcc.MASQUEIPv4
		acc.MASQUEIPv6 = gAcc.MASQUEIPv6
		acc.IPv4 = gAcc.IPv4
		acc.IPv6 = gAcc.IPv6
	}

	// If WireGuard fallback is available and MASQUE credentials are not enrolled,
	// bypass MASQUE immediately to avoid a 3s timeout with invalid ephemeral keys.
	if w.opts.WireGuardFallback != "" && (acc.MASQUEPrivateKey == "" || acc.MASQUECertPEM == "") {
		return nil, errors.New("masque key not enrolled, using wireguard fallback")
	}

	// If no WireGuard fallback and account is not registered at all, abort early
	if acc.MASQUEPrivateKey == "" && (w.eng == nil || w.eng.cloudflareConfig == nil || !w.eng.cloudflareConfig.Account.IsRegistered()) {
		return nil, errors.New("warp credentials not registered on Cloudflare")
	}

	// Ephemeral key generation if still unpopulated
	if acc.MASQUEPrivateKey == "" || acc.MASQUECertPEM == "" {
		priv, _, cert, err := warp.GenerateMASQUEKeypair()
		if err == nil {
			acc.MASQUEPrivateKey = priv
			acc.MASQUECertPEM = cert
		}
	}

	tun, err := warp.ConnectMASQUE(ctx, upstreamDialer, w.opts.Endpoint, acc, w.opts.TCPOnlyDetour, w.opts.ForceH2)
	if err != nil {
		w.masqueFailedAt = time.Now()
		return nil, err
	}
	w.masqueFailedAt = time.Time{}
	w.tun = tun
	return tun, nil
}

func resolveHostIP(ctx context.Context, host string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr, nil
	}
	rCtx, rCancel := context.WithTimeout(ctx, 1200*time.Millisecond)
	defer rCancel()
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(c context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 800 * time.Millisecond}
			return d.DialContext(c, "udp", "223.5.5.5:53")
		},
	}
	ips, err := r.LookupIP(rCtx, "ip4", host)
	if err == nil && len(ips) > 0 {
		return netip.ParseAddr(ips[0].String())
	}

	dCtx, dCancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer dCancel()
	ips, err = net.DefaultResolver.LookupIP(dCtx, "ip4", host)
	if err == nil && len(ips) > 0 {
		return netip.ParseAddr(ips[0].String())
	}
	return netip.Addr{}, fmt.Errorf("failed to resolve host %q: %w", host, err)
}

func (w *warpMasqueOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	t0 := time.Now()
	tun, err := w.getOrCreateTunnel(ctx)
	t1 := time.Now()
	if err == nil {
		var conn net.Conn
		if strings.HasPrefix(strings.ToLower(network), "udp") {
			conn, err = tun.DialUDP(ctx, destination.String())
		} else {
			conn, err = tun.DialContextTCP(ctx, destination.String())
		}
		t2 := time.Now()
		if err == nil {
			return conn, nil
		}
		if w.logger != nil {
			w.logger.DebugContext(ctx, fmt.Sprintf("MASQUE dial failed after %v (connect %v, dial %v): %v", t2.Sub(t0), t1.Sub(t0), t2.Sub(t1), err))
		}
	} else if w.logger != nil {
		w.logger.DebugContext(ctx, fmt.Sprintf("MASQUE tunnel create failed after %v: %v", t1.Sub(t0), err))
	}

	ep := w.opts.Endpoint
	if ep == "" {
		ep = warp.DefaultMASQUEEndpoint
	}

	if fbOb := w.getFallbackOutbound(); fbOb != nil {
		tR0 := time.Now()
		if destination.IsDomain() {
			if ip, rErr := resolveHostIP(ctx, destination.Fqdn); rErr == nil {
				destination = M.SocksaddrFrom(ip, destination.Port)
			}
		}
		tR1 := time.Now()
		conn, fbErr := fbOb.DialContext(ctx, network, destination)
		tF := time.Now()
		if w.logger != nil {
			w.logger.DebugContext(ctx, fmt.Sprintf("Fallback dial after %v (resolve %v, dial %v): %v", tF.Sub(tR0), tR1.Sub(tR0), tF.Sub(tR1), fbErr))
		}
		if fbErr != nil {
			return nil, fmt.Errorf("warp server (%s) connection failed: %w", ep, fbErr)
		}
		return conn, nil
	}
	if err != nil {
		return nil, fmt.Errorf("warp server (%s) connection failed: %w", ep, err)
	}
	return nil, fmt.Errorf("warp server (%s) connection failed", ep)
}

func (w *warpMasqueOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	tun, err := w.getOrCreateTunnel(ctx)
	if err == nil {
		conn, err := tun.DialUDP(ctx, destination.String())
		if err == nil {
			return &udpPacketConnAdapter{Conn: conn, raddr: destination.UDPAddr()}, nil
		}
	}

	ep := w.opts.Endpoint
	if ep == "" {
		ep = warp.DefaultMASQUEEndpoint
	}

	if fbOb := w.getFallbackOutbound(); fbOb != nil {
		if destination.IsDomain() {
			if ip, rErr := resolveHostIP(ctx, destination.Fqdn); rErr == nil {
				destination = M.SocksaddrFrom(ip, destination.Port)
			}
		}
		pConn, fbErr := fbOb.ListenPacket(ctx, destination)
		if fbErr != nil {
			return nil, fmt.Errorf("warp server (%s) connection failed: %w", ep, fbErr)
		}
		return pConn, nil
	}
	if err != nil {
		return nil, fmt.Errorf("warp server (%s) connection failed: %w", ep, err)
	}
	return nil, fmt.Errorf("warp server (%s) connection failed", ep)
}

func (w *warpMasqueOutbound) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	if w.tun != nil {
		err := w.tun.Close()
		w.tun = nil
		return err
	}
	return nil
}

type udpPacketConnAdapter struct {
	net.Conn
	raddr net.Addr
}

func (c *udpPacketConnAdapter) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = c.Conn.Read(p)
	return n, c.raddr, err
}

func (c *udpPacketConnAdapter) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return c.Conn.Write(p)
}
