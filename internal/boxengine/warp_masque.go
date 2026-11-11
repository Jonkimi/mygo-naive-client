package boxengine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"naive-client/internal/warp"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type warpMasqueOptions struct {
	Detour        string `json:"detour,omitempty"`
	Endpoint      string `json:"endpoint,omitempty"`
	TCPOnlyDetour bool   `json:"tcp_only_detour,omitempty"`
	ForceH2       bool   `json:"force_h2,omitempty"`
	PrivateKey    string `json:"private_key,omitempty"`
	CertPEM       string `json:"cert_pem,omitempty"`
	IPv4          string `json:"ipv4,omitempty"`
	IPv6          string `json:"ipv6,omitempty"`
}

type warpMasqueOutbound struct {
	tag         string
	router      adapter.Router
	outboundMgr adapter.OutboundManager
	logger      log.ContextLogger
	opts        warpMasqueOptions
	eng         *Engine

	tun    *warp.MASQUETunnel
	mu     sync.Mutex
	closed bool
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

func (w *warpMasqueOutbound) getOrCreateTunnel(ctx context.Context) (*warp.MASQUETunnel, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil, errors.New("outbound closed")
	}
	if w.tun != nil {
		return w.tun, nil
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
		return nil, err
	}
	w.tun = tun
	return tun, nil
}

func (w *warpMasqueOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	tun, err := w.getOrCreateTunnel(ctx)
	if err != nil {
		return nil, err
	}

	if strings.HasPrefix(strings.ToLower(network), "udp") {
		return tun.DialUDP(ctx, destination.String())
	}
	return tun.DialContextTCP(ctx, destination.String())
}

func (w *warpMasqueOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	tun, err := w.getOrCreateTunnel(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := tun.DialUDP(ctx, destination.String())
	if err != nil {
		return nil, err
	}
	return &udpPacketConnAdapter{Conn: conn, raddr: destination.UDPAddr()}, nil
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
