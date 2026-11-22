package boxengine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
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
	PreferH2          bool   `json:"prefer_h2,omitempty"`
	TLSFragment       bool   `json:"tls_fragment,omitempty"`
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
	warpOutboundLifecycle

	tun            *warp.MASQUETunnel
	activeEndpoint string
	masqueFailedAt time.Time
}

var _ adapter.Lifecycle = (*warpMasqueOutbound)(nil)

func newWarpMasqueOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, opts warpMasqueOptions, eng *Engine) (adapter.Outbound, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	return &warpMasqueOutbound{
		tag:                   tag,
		router:                router,
		outboundMgr:           service.FromContext[adapter.OutboundManager](ctx),
		logger:                logger,
		opts:                  opts,
		eng:                   eng,
		warpOutboundLifecycle: newWarpOutboundLifecycle(ctx),
	}, nil
}

// Start registers Close with sing-box's lifecycle scope so Engine.Close tears down active MASQUE tunnels.
func (w *warpMasqueOutbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return w.start(stage, scope, w.Close)
}

func (w *warpMasqueOutbound) scopeKey() string {
	if w.opts.Detour == "" {
		return "direct"
	}
	return w.tag
}

// ActiveEndpoint returns the endpoint currently selected or configured for this MASQUE outbound.
func (w *warpMasqueOutbound) ActiveEndpoint() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.activeEndpoint != "" {
		return w.activeEndpoint
	}
	if strings.TrimSpace(w.opts.Endpoint) != "" {
		return strings.TrimSpace(w.opts.Endpoint)
	}
	return ""
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

var _ adapter.Referrer = (*warpMasqueOutbound)(nil)

// References reports both the upstream detour and any WireGuard fallback outbound
// so ReferenceManager keeps idle connections on underlying transports.
func (w *warpMasqueOutbound) References() []string {
	var refs []string
	if w.opts.Detour != "" {
		refs = append(refs, w.opts.Detour)
	}
	if w.opts.WireGuardFallback != "" {
		refs = append(refs, w.opts.WireGuardFallback)
	}
	return refs
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

type masqueTunnelDialer struct {
	tun *warp.MASQUETunnel
}

func (d *masqueTunnelDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if d == nil || d.tun == nil {
		return nil, errors.New("nil masque tunnel")
	}
	if strings.HasPrefix(strings.ToLower(network), "udp") {
		return d.tun.DialUDP(ctx, destination.String())
	}
	return d.tun.DialContextTCP(ctx, destination.String())
}

func (d *masqueTunnelDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if d == nil || d.tun == nil {
		return nil, errors.New("nil masque tunnel")
	}
	conn, err := d.tun.DialUDP(ctx, destination.String())
	if err != nil {
		return nil, err
	}
	return &udpPacketConnAdapter{Conn: conn, raddr: destination.UDPAddr()}, nil
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

func (w *warpMasqueOutbound) activeTunnelLocked() (*warp.MASQUETunnel, string, error) {
	if w.isClosedLocked() {
		return nil, "", errors.New("outbound closed")
	}
	if w.opts.WireGuardFallback != "" && time.Since(w.masqueFailedAt) < 60*time.Second {
		return nil, "", errors.New("masque recently failed, using wireguard fallback")
	}
	if w.tun != nil {
		select {
		case <-w.tun.Done():
			w.tun = nil
			deadEP := w.activeEndpoint
			w.activeEndpoint = ""
			return nil, deadEP, nil
		default:
			return w.tun, "", nil
		}
	}
	return nil, "", nil
}

func (w *warpMasqueOutbound) recordFailureTime(ctx context.Context, err error) {
	if (ctx != nil && errors.Is(ctx.Err(), context.Canceled)) || errors.Is(err, context.Canceled) {
		return
	}
	w.mu.Lock()
	if !w.isClosedLocked() {
		w.masqueFailedAt = time.Now()
	}
	w.mu.Unlock()
}

func (w *warpMasqueOutbound) markEndpointFailedIfAuto(ep string) {
	if strings.TrimSpace(w.opts.Endpoint) != "" || ep == "" {
		return
	}
	selectEndpointSelector(w.eng).MarkFailed(warp.EndpointCacheKey{
		ScopeKey: w.scopeKey(),
		Mode:     warp.ModeMASQUE,
		TCPOnly:  w.opts.TCPOnlyDetour || w.opts.ForceH2,
	}, ep)
}

func (w *warpMasqueOutbound) getOrCreateTunnel(ctx context.Context) (*warp.MASQUETunnel, error) {
	var activeTun *warp.MASQUETunnel
	var deadEP string
	release, ready, err := w.acquireInit(ctx, func() (bool, error) {
		tun, dead, aErr := w.activeTunnelLocked()
		if dead != "" {
			deadEP = dead
		}
		if aErr != nil {
			return false, aErr
		}
		if tun != nil {
			activeTun = tun
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	if ready {
		return activeTun, nil
	}
	defer release()

	if deadEP != "" {
		w.markEndpointFailedIfAuto(deadEP)
	}
	if ctx != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}

	upstreamDialer, err := resolveDetourDialer(w.opts.Detour, w.outboundMgr, w.eng)
	if err != nil {
		return nil, err
	}

	acc := &warp.Account{
		MASQUEPrivateKey: w.opts.PrivateKey,
		MASQUECertPEM:    w.opts.CertPEM,
		MASQUEIPv4:       w.opts.IPv4,
		MASQUEIPv6:       w.opts.IPv6,
	}

	// Fallback to global Cloudflare account if node credentials not explicitly set
	globalAcc := loadGlobalWarpAccount(w.eng)
	if acc.MASQUEPrivateKey == "" || acc.MASQUECertPEM == "" {
		acc.MASQUEPrivateKey = globalAcc.MASQUEPrivateKey
		acc.MASQUECertPEM = globalAcc.MASQUECertPEM
		acc.MASQUEIPv4 = globalAcc.MASQUEIPv4
		acc.MASQUEIPv6 = globalAcc.MASQUEIPv6
		acc.IPv4 = globalAcc.IPv4
		acc.IPv6 = globalAcc.IPv6
	}

	// Auto-provision enrolled MASQUE credentials if still unpopulated
	if acc.MASQUEPrivateKey == "" || acc.MASQUECertPEM == "" {
		apiHTTPClient := newWarpProvisionHTTPClient(upstreamDialer, 8*time.Second)
		client := warp.NewClient(apiHTTPClient)
		provTimeout := 8 * time.Second
		if w.opts.WireGuardFallback != "" {
			provTimeout = 4 * time.Second
		}
		provCtx, provCancel := w.deriveContext(ctx, provTimeout)
		enrolled, provErr := client.ProvisionAll(provCtx, globalAcc, "")
		provCancel()
		closeHTTPTransportIdle(apiHTTPClient)
		if provErr != nil {
			w.recordFailureTime(ctx, provErr)
			return nil, fmt.Errorf("Cloudflare WARP MASQUE 凭证未注册且自动注册失败: %w", provErr)
		}
		acc.MASQUEPrivateKey = enrolled.MASQUEPrivateKey
		acc.MASQUECertPEM = enrolled.MASQUECertPEM
		acc.MASQUEIPv4 = enrolled.MASQUEIPv4
		acc.MASQUEIPv6 = enrolled.MASQUEIPv6
		acc.IPv4 = enrolled.IPv4
		acc.IPv6 = enrolled.IPv6
		if !w.isClosed() {
			saveGlobalWarpAccount(w.eng, enrolled)
		}
	}

	if w.isClosed() {
		return nil, errors.New("outbound closed")
	}
	if ctx != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}

	var masqueTimeout time.Duration
	if w.opts.WireGuardFallback != "" {
		// Leave headroom inside caller's deadline for WireGuard fallback if MASQUE fails.
		// PreferH2 needs enough time for both H2 (TCP) and H3 (QUIC) attempts.
		masqueTimeout = 5 * time.Second
		if w.opts.PreferH2 && !w.opts.TCPOnlyDetour && !w.opts.ForceH2 {
			masqueTimeout = 9 * time.Second
		}
	}
	connectCtx, connectCancel := w.deriveContext(ctx, masqueTimeout)
	mOpts := warp.MASQUEOptions{
		TCPOnly:     w.opts.TCPOnlyDetour,
		ForceH2:     w.opts.ForceH2,
		PreferH2:    w.opts.PreferH2,
		TLSFragment: w.opts.TLSFragment,
	}
	explicitEP := strings.TrimSpace(w.opts.Endpoint)
	var selectedEP string
	var tun *warp.MASQUETunnel
	if explicitEP != "" {
		tun, err = warp.ConnectMASQUEWithOptions(connectCtx, upstreamDialer, explicitEP, acc, mOpts)
		selectedEP = explicitEP
	} else {
		tun, selectedEP, err = selectEndpointSelector(w.eng).SelectMASQUEAndConnect(connectCtx, w.scopeKey(), upstreamDialer, acc, mOpts)
	}
	connectCancel()
	if err != nil {
		w.recordFailureTime(ctx, err)
		return nil, err
	}

	w.mu.Lock()
	if w.isClosedLocked() {
		w.mu.Unlock()
		_ = tun.Close()
		return nil, errors.New("outbound closed")
	}
	w.masqueFailedAt = time.Time{}
	w.tun = tun
	w.activeEndpoint = selectedEP
	w.mu.Unlock()

	if explicitEP == "" && w.logger != nil && selectedEP != "" {
		w.logger.InfoContext(ctx, fmt.Sprintf("MASQUE auto-selected endpoint %s (%s) for scope %s", selectedEP, tun.Protocol(), w.scopeKey()))
	}
	return tun, nil
}

func (w *warpMasqueOutbound) invalidateTunnel(tun *warp.MASQUETunnel) {
	var failedEP string
	var shouldClose bool
	w.mu.Lock()
	if !w.isClosedLocked() && w.tun == tun {
		w.tun = nil
		failedEP = w.activeEndpoint
		w.activeEndpoint = ""
		w.masqueFailedAt = time.Now()
		if tun != nil {
			shouldClose = true
			w.wg.Add(1)
		}
	}
	w.mu.Unlock()
	if !shouldClose {
		return
	}
	defer w.wg.Done()
	if w.eng != nil {
		w.eng.resetWarpRemoteDoHTransport(w.tag)
	}
	w.markEndpointFailedIfAuto(failedEP)
	_ = tun.Close()
}

func (w *warpMasqueOutbound) resolveDestination(ctx context.Context, tun *warp.MASQUETunnel, destination M.Socksaddr) (M.Socksaddr, error) {
	if !destination.IsDomain() {
		return destination, nil
	}
	allowV4, allowV6 := true, true
	if tun != nil && tun.Netstack != nil {
		allowV4 = tun.Netstack.IPv4.IsValid() || !tun.Netstack.IPv6.IsValid()
		allowV6 = tun.Netstack.IPv6.IsValid()
	}
	rCtx, rCancel := w.deriveContext(ctx, 0)
	defer rCancel()
	ip, err := resolveWarpDomainViaDoH(rCtx, w.eng, w.closeCtx, w.tag, w.opts.Detour != "", &masqueTunnelDialer{tun: tun}, destination.Fqdn, allowV4, allowV6)
	if err != nil {
		return destination, err
	}
	return M.SocksaddrFrom(ip, destination.Port), nil
}

func (w *warpMasqueOutbound) resolveFallbackDestination(ctx context.Context, fbOb adapter.Outbound, destination M.Socksaddr) (M.Socksaddr, error) {
	if !destination.IsDomain() {
		return destination, nil
	}
	if _, isAutoWG := fbOb.(*warpAutoWireGuardOutbound); isAutoWG {
		// warpAutoWireGuardOutbound resolves domains after ensuring its WireGuard endpoint.
		return destination, nil
	}
	rCtx, rCancel := w.deriveContext(ctx, 0)
	defer rCancel()
	ip, err := resolveWarpDomainViaDoH(rCtx, w.eng, w.closeCtx, w.tag, w.opts.Detour != "", fbOb, destination.Fqdn, true, true)
	if err != nil {
		return destination, err
	}
	return M.SocksaddrFrom(ip, destination.Port), nil
}

func (w *warpMasqueOutbound) wrapFallbackOrDialError(ep string, fbErr, dialErr error) error {
	if fbErr != nil {
		if strings.Contains(strings.ToLower(fbErr.Error()), "warp server (") {
			return fbErr
		}
		return fmt.Errorf("warp server (%s) connection failed: %w", ep, fbErr)
	}
	if dialErr != nil {
		if strings.Contains(strings.ToLower(dialErr.Error()), "warp server (") {
			return dialErr
		}
		return fmt.Errorf("warp server (%s) connection failed: %w", ep, dialErr)
	}
	return fmt.Errorf("warp server (%s) connection failed", ep)
}

func (w *warpMasqueOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if d := warpInternalDNSDialer(ctx, w.tag); d != nil && !destination.IsDomain() {
		return d.DialContext(ctx, network, destination)
	}
	t0 := time.Now()
	tun, err := w.getOrCreateTunnel(ctx)
	t1 := time.Now()
	var ep string
	if err == nil {
		ep = w.ActiveEndpoint()
		if destination.IsDomain() {
			destination, err = w.resolveDestination(ctx, tun, destination)
		}
		var conn net.Conn
		if err == nil {
			if strings.HasPrefix(strings.ToLower(network), "udp") {
				conn, err = tun.DialUDP(ctx, destination.String())
			} else {
				conn, err = tun.DialContextTCP(ctx, destination.String())
			}
		}
		t2 := time.Now()
		if err == nil {
			return conn, nil
		}
		if w.logger != nil {
			w.logger.DebugContext(ctx, fmt.Sprintf("MASQUE dial failed after %v (connect %v, dial %v): %v", t2.Sub(t0), t1.Sub(t0), t2.Sub(t1), err))
		}
		select {
		case <-tun.Done():
			w.invalidateTunnel(tun)
		default:
			// WARP tunnel itself is alive; return destination-level error directly
			// without blaming the WARP server or triggering WireGuard fallback.
			return nil, err
		}
	} else if w.logger != nil {
		w.logger.DebugContext(ctx, fmt.Sprintf("MASQUE tunnel create failed after %v: %v", t1.Sub(t0), err))
	}

	if w.isClosed() {
		return nil, errors.New("outbound closed")
	}
	if (ctx != nil && errors.Is(ctx.Err(), context.Canceled)) || errors.Is(err, context.Canceled) {
		if err != nil {
			return nil, err
		}
		return nil, ctx.Err()
	}

	if ep == "" {
		ep = w.ActiveEndpoint()
	}
	if ep == "" {
		ep = "auto"
	}

	if fbOb := w.getFallbackOutbound(); fbOb != nil {
		tR0 := time.Now()
		var resErr error
		destination, resErr = w.resolveFallbackDestination(ctx, fbOb, destination)
		if resErr != nil {
			if errors.Is(resErr, warp.ErrNoDNSRecords) || (ctx != nil && errors.Is(ctx.Err(), context.Canceled)) || errors.Is(resErr, context.Canceled) {
				return nil, resErr
			}
			return nil, w.wrapFallbackOrDialError(ep, resErr, err)
		}
		tR1 := time.Now()
		conn, fbErr := fbOb.DialContext(ctx, network, destination)
		tF := time.Now()
		if w.logger != nil {
			w.logger.DebugContext(ctx, fmt.Sprintf("Fallback dial after %v (resolve %v, dial %v): %v", tF.Sub(tR0), tR1.Sub(tR0), tF.Sub(tR1), fbErr))
		}
		if fbErr != nil {
			return nil, w.wrapFallbackOrDialError(ep, fbErr, err)
		}
		return conn, nil
	}
	return nil, w.wrapFallbackOrDialError(ep, nil, err)
}

func (w *warpMasqueOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if d := warpInternalDNSDialer(ctx, w.tag); d != nil && !destination.IsDomain() {
		return d.ListenPacket(ctx, destination)
	}
	tun, err := w.getOrCreateTunnel(ctx)
	var ep string
	if err == nil {
		ep = w.ActiveEndpoint()
		if destination.IsDomain() {
			destination, err = w.resolveDestination(ctx, tun, destination)
		}
		var conn net.Conn
		if err == nil {
			conn, err = tun.DialUDP(ctx, destination.String())
		}
		if err == nil {
			return &udpPacketConnAdapter{Conn: conn, raddr: destination.UDPAddr()}, nil
		}
		select {
		case <-tun.Done():
			w.invalidateTunnel(tun)
		default:
			// WARP tunnel itself is alive; return destination-level error directly.
			return nil, err
		}
	}

	if w.isClosed() {
		return nil, errors.New("outbound closed")
	}
	if (ctx != nil && errors.Is(ctx.Err(), context.Canceled)) || errors.Is(err, context.Canceled) {
		if err != nil {
			return nil, err
		}
		return nil, ctx.Err()
	}

	if ep == "" {
		ep = w.ActiveEndpoint()
	}
	if ep == "" {
		ep = "auto"
	}

	if fbOb := w.getFallbackOutbound(); fbOb != nil {
		var resErr error
		destination, resErr = w.resolveFallbackDestination(ctx, fbOb, destination)
		if resErr != nil {
			if errors.Is(resErr, warp.ErrNoDNSRecords) || (ctx != nil && errors.Is(ctx.Err(), context.Canceled)) || errors.Is(resErr, context.Canceled) {
				return nil, resErr
			}
			return nil, w.wrapFallbackOrDialError(ep, resErr, err)
		}
		pConn, fbErr := fbOb.ListenPacket(ctx, destination)
		if fbErr != nil {
			return nil, w.wrapFallbackOrDialError(ep, fbErr, err)
		}
		return pConn, nil
	}
	return nil, w.wrapFallbackOrDialError(ep, nil, err)
}

func (w *warpMasqueOutbound) Close() error {
	if w.eng != nil {
		w.eng.resetWarpRemoteDoHTransport(w.tag)
	}
	return w.close(func() func() error {
		tun := w.tun
		w.tun = nil
		if tun == nil {
			return nil
		}
		return tun.Close
	})
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
