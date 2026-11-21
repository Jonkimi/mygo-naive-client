package boxengine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"naive-client/internal/warp"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/wireguard"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type warpAutoWireGuardOptions struct {
	Detour      string  `json:"detour,omitempty"`
	PrivateKey  string  `json:"private_key,omitempty"`
	PeerPubKey  string  `json:"peer_pub_key,omitempty"`
	Reserved    []uint8 `json:"reserved,omitempty"`
	AddressIPv4 string  `json:"address_ipv4,omitempty"`
	AddressIPv6 string  `json:"address_ipv6,omitempty"`
	MTU         uint32  `json:"mtu,omitempty"`
}

// warpAutoWireGuardOutbound lazily selects the lowest-RTT WireGuard Anycast endpoint
// over the node's own egress (direct or detour) via real WireGuard Handshake probing,
// then binds a sing-box wireguard.Endpoint to that selected peer.
//
// Lock ordering: bindMu -> mu (never hold mu while acquiring bindMu).
type warpAutoWireGuardOutbound struct {
	ctx         context.Context
	router      adapter.Router
	outboundMgr adapter.OutboundManager
	logger      log.ContextLogger
	tag         string
	opts        warpAutoWireGuardOptions
	eng         *Engine
	warpOutboundLifecycle

	bindMu         sync.Mutex
	ep             *wireguard.Endpoint
	activeEndpoint string
	consecFails    int
}

var (
	_ adapter.Lifecycle               = (*warpAutoWireGuardOutbound)(nil)
	_ adapter.InterfaceUpdateListener = (*warpAutoWireGuardOutbound)(nil)
)

func newWarpAutoWireGuardOutbound(
	ctx context.Context,
	router adapter.Router,
	logger log.ContextLogger,
	tag string,
	opts warpAutoWireGuardOptions,
	eng *Engine,
) (adapter.Outbound, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	return &warpAutoWireGuardOutbound{
		ctx:                   ctx,
		router:                router,
		outboundMgr:           service.FromContext[adapter.OutboundManager](ctx),
		logger:                logger,
		tag:                   tag,
		opts:                  opts,
		eng:                   eng,
		warpOutboundLifecycle: newWarpOutboundLifecycle(ctx),
	}, nil
}

// Start registers Close with sing-box's lifecycle scope so Engine.Close tears down active WireGuard endpoints.
func (w *warpAutoWireGuardOutbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return w.start(stage, scope, w.Close)
}

func (w *warpAutoWireGuardOutbound) Type() string {
	return "warp-wg-auto"
}

func (w *warpAutoWireGuardOutbound) Tag() string {
	return w.tag
}

func (w *warpAutoWireGuardOutbound) Network() []string {
	return []string{N.NetworkTCP, N.NetworkUDP}
}

func (w *warpAutoWireGuardOutbound) Dependencies() []string {
	if w.opts.Detour != "" {
		return []string{w.opts.Detour}
	}
	return nil
}

func (w *warpAutoWireGuardOutbound) scopeKey() string {
	if w.opts.Detour == "" {
		return "direct"
	}
	// Strip "wg-" prefix when paired as a MASQUE fallback so scope stays per-node.
	return strings.TrimPrefix(w.tag, "wg-")
}

// ActiveEndpoint returns the endpoint selected by the last successful probe/connection.
func (w *warpAutoWireGuardOutbound) ActiveEndpoint() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.activeEndpoint
}

func (w *warpAutoWireGuardOutbound) ensureEndpoint(ctx context.Context) (*wireguard.Endpoint, error) {
	var activeEP *wireguard.Endpoint
	release, ready, err := w.acquireInit(ctx, func() (bool, error) {
		if w.ep != nil {
			activeEP = w.ep
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	if ready {
		return activeEP, nil
	}
	defer release()

	if ctx != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}

	upstreamDialer, err := resolveDetourDialer(w.opts.Detour, w.outboundMgr, w.eng)
	if err != nil {
		return nil, err
	}

	privKey := w.opts.PrivateKey
	peerPubKey := w.opts.PeerPubKey
	reserved := w.opts.Reserved
	ipv4 := w.opts.AddressIPv4
	ipv6 := w.opts.AddressIPv6

	globalAcc := loadGlobalWarpAccount(w.eng)

	if privKey == "" && globalAcc.WGPrivateKey != "" {
		privKey = globalAcc.WGPrivateKey
	}
	if peerPubKey == "" && globalAcc.WGPeerPublicKey != "" {
		peerPubKey = globalAcc.WGPeerPublicKey
	}
	if len(reserved) != 3 && len(globalAcc.Reserved) == 3 {
		reserved = globalAcc.Reserved
	}
	if ipv4 == "" && globalAcc.IPv4 != "" {
		ipv4 = globalAcc.IPv4
	}
	if ipv6 == "" && globalAcc.IPv6 != "" {
		ipv6 = globalAcc.IPv6
	}

	// Auto-provision WireGuard credentials if missing
	if privKey == "" {
		apiHTTPClient := newWarpProvisionHTTPClient(upstreamDialer, 6*time.Second)
		client := warp.NewClient(apiHTTPClient)
		provCtx, provCancel := w.deriveContext(ctx, 6*time.Second)
		enrolled, provErr := client.ProvisionAll(provCtx, globalAcc, "")
		provCancel()
		closeHTTPTransportIdle(apiHTTPClient)
		if provErr != nil {
			return nil, fmt.Errorf("Cloudflare WARP WireGuard 凭证未注册且自动注册失败: %w", provErr)
		}
		privKey = enrolled.WGPrivateKey
		if enrolled.WGPeerPublicKey != "" {
			peerPubKey = enrolled.WGPeerPublicKey
		}
		if len(enrolled.Reserved) == 3 {
			reserved = enrolled.Reserved
		}
		if enrolled.IPv4 != "" {
			ipv4 = enrolled.IPv4
		}
		if enrolled.IPv6 != "" {
			ipv6 = enrolled.IPv6
		}
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

	if peerPubKey == "" {
		peerPubKey = warp.DefaultWireGuardPubKey
	}
	if len(reserved) != 3 {
		reserved = []uint8{0, 0, 0}
	}
	if ipv4 == "" {
		ipv4 = warp.DefaultIPv4
	}
	if ipv6 == "" {
		ipv6 = warp.DefaultIPv6
	}

	probeAcc := &warp.Account{
		WGPrivateKey:    privKey,
		WGPeerPublicKey: peerPubKey,
		Reserved:        reserved,
	}
	selCtx, selCancel := w.deriveContext(ctx, 2500*time.Millisecond)
	selected, selErr := selectEndpointSelector(w.eng).SelectWireGuardEndpoint(selCtx, w.scopeKey(), upstreamDialer, probeAcc)
	selCancel()

	if w.isClosed() {
		return nil, errors.New("outbound closed")
	}
	if selErr != nil && ctx != nil && ctx.Err() != nil {
		return nil, selErr
	}

	targetEndpoint := warp.DefaultWireGuardEndpoint
	if selErr == nil && selected.Endpoint != "" {
		targetEndpoint = selected.Endpoint
		if w.logger != nil {
			w.logger.InfoContext(ctx, fmt.Sprintf("WireGuard auto-selected endpoint %s (%v) for scope %s", targetEndpoint, selected.RTT.Round(time.Millisecond), w.scopeKey()))
		}
	}

	peerHost, peerPortStr, splitErr := net.SplitHostPort(targetEndpoint)
	if splitErr != nil {
		peerHost = "162.159.192.1"
		peerPortStr = "2408"
	}
	peerPortNum, _ := strconv.Atoi(peerPortStr)
	if peerPortNum <= 0 {
		peerPortNum = 2408
	}

	ipv4PrefixStr := ipv4
	if !strings.Contains(ipv4PrefixStr, "/") {
		ipv4PrefixStr += "/32"
	}
	ipv6PrefixStr := ipv6
	if !strings.Contains(ipv6PrefixStr, "/") {
		ipv6PrefixStr += "/128"
	}
	var addrs []netip.Prefix
	if p4, parseErr := netip.ParsePrefix(ipv4PrefixStr); parseErr == nil {
		addrs = append(addrs, p4)
	}
	if p6, parseErr := netip.ParsePrefix(ipv6PrefixStr); parseErr == nil {
		addrs = append(addrs, p6)
	}

	baseCtx := w.ctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}

	dialOpts := option.DialerOptions{}
	if w.opts.Detour != "" {
		dialOpts.Detour = w.opts.Detour
	}
	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:          baseCtx,
		Options:          dialOpts,
		RemoteIsDomain:   net.ParseIP(peerHost) == nil,
		ResolverOnDetour: true,
	})
	if err != nil {
		return nil, fmt.Errorf("create wireguard dialer: %w", err)
	}

	mtu := w.opts.MTU
	if mtu == 0 {
		mtu = warp.DefaultMTU
	}

	networkManager := service.FromContext[adapter.NetworkManager](baseCtx)
	dnsRouter := service.FromContext[adapter.DNSRouter](baseCtx)
	var ifFinder control.InterfaceFinder
	var ifMonitor tun.DefaultInterfaceMonitor
	var autoMark uint32
	if networkManager != nil {
		ifFinder = networkManager.InterfaceFinder()
		ifMonitor = networkManager.InterfaceMonitor()
		autoMark = networkManager.AutoRedirectOutputMark()
	}

	peerAddr, _ := netip.ParseAddr(peerHost)
	var peerSocks M.Socksaddr
	if peerAddr.IsValid() {
		peerSocks = M.SocksaddrFrom(peerAddr, uint16(peerPortNum))
	} else {
		peerSocks = M.ParseSocksaddrHostPort(peerHost, uint16(peerPortNum))
	}

	wgEP, err := wireguard.NewEndpoint(wireguard.EndpointOptions{
		Context:         baseCtx,
		Logger:          w.logger,
		System:          false,
		UDPTimeout:      5 * time.Minute,
		ICMPTimeout:     10 * time.Second,
		InterfaceFinder: ifFinder,
		EgressPoolOptions: tun.UDPEgressPoolOptions{
			Logger:           w.logger,
			InterfaceFinder:  ifFinder,
			InterfaceMonitor: ifMonitor,
			IsExempt: func() bool {
				return autoMark != 0
			},
		},
		Dialer: outboundDialer,
		CreateDialer: func(interfaceName string) N.Dialer {
			return common.Must1(dialer.NewDefault(baseCtx, option.DialerOptions{
				AbstractDialerOptions: option.AbstractDialerOptions{
					BindInterface: interfaceName,
				},
			}))
		},
		Tag:        w.tag,
		MTU:        mtu,
		Address:    addrs,
		PrivateKey: privKey,
		ResolvePeer: func(domain string) ([]netip.Addr, error) {
			if dnsRouter == nil {
				return nil, errors.New("dns router unavailable")
			}
			return dnsRouter.Lookup(baseCtx, domain, outboundDialer.(dialer.ResolveDialer).QueryOptions())
		},
		Peers: []wireguard.PeerOptions{
			{
				Endpoint:   peerSocks,
				PublicKey:  peerPubKey,
				AllowedIPs: badoption.Listable[netip.Prefix]{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
				Reserved:   reserved,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create auto wireguard endpoint: %w", err)
	}
	if err := wgEP.Start(false); err != nil {
		_ = wgEP.Close()
		return nil, err
	}
	if err := wgEP.Start(true); err != nil {
		_ = wgEP.Close()
		return nil, err
	}

	w.mu.Lock()
	if w.isClosedLocked() {
		w.mu.Unlock()
		_ = wgEP.Close()
		return nil, errors.New("outbound closed")
	}
	w.ep = wgEP
	w.activeEndpoint = targetEndpoint
	w.consecFails = 0
	w.mu.Unlock()
	return wgEP, nil
}

func isDestinationLevelWGError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, warp.ErrNoDNSRecords) {
		return true
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "connection refused")
}

func (w *warpAutoWireGuardOutbound) InterfaceUpdated(ctx context.Context) {
	w.mu.Lock()
	if w.isClosedLocked() || w.ep == nil {
		w.mu.Unlock()
		return
	}
	ep := w.ep
	w.wg.Add(1)
	w.mu.Unlock()
	defer w.wg.Done()

	if ctx != nil && ctx.Err() != nil {
		return
	}
	w.bindMu.Lock()
	defer w.bindMu.Unlock()
	w.mu.Lock()
	sameEP := !w.isClosedLocked() && w.ep == ep
	w.mu.Unlock()
	if !sameEP {
		return
	}
	_ = ep.BindUpdate()
}

func (w *warpAutoWireGuardOutbound) recordDialResult(ctx context.Context, ep *wireguard.Endpoint, err error) {
	if err == nil {
		w.mu.Lock()
		if w.ep == ep {
			w.consecFails = 0
		}
		w.mu.Unlock()
		return
	}
	if (ctx != nil && errors.Is(ctx.Err(), context.Canceled)) || errors.Is(err, context.Canceled) || isDestinationLevelWGError(err) {
		return
	}
	w.mu.Lock()
	if w.isClosedLocked() || w.ep != ep || ep == nil {
		w.mu.Unlock()
		return
	}
	w.consecFails++
	shouldRotate := w.consecFails >= 3
	var oldEP *wireguard.Endpoint
	var failedAddr string
	if shouldRotate {
		oldEP = w.ep
		failedAddr = w.activeEndpoint
		w.ep = nil
		w.activeEndpoint = ""
		w.consecFails = 0
		w.wg.Add(1)
	}
	w.mu.Unlock()

	if shouldRotate {
		defer w.wg.Done()
		if w.eng != nil {
			w.eng.resetWarpRemoteDoHTransport(w.tag)
		}
		if failedAddr != "" {
			selectEndpointSelector(w.eng).MarkFailed(warp.EndpointCacheKey{
				ScopeKey: w.scopeKey(),
				Mode:     warp.ModeWireGuard,
			}, failedAddr)
		}
		if oldEP != nil {
			w.bindMu.Lock()
			_ = oldEP.Close()
			w.bindMu.Unlock()
		}
	}
}

func (w *warpAutoWireGuardOutbound) resolveDestination(ctx context.Context, ep *wireguard.Endpoint, destination M.Socksaddr) (M.Socksaddr, error) {
	if !destination.IsDomain() {
		return destination, nil
	}
	rCtx, rCancel := w.deriveContext(ctx, 0)
	defer rCancel()

	// Resolve through sing-box DoH transport (with cache & dedup), routing direct domestic
	// domains via domestic-doh and overseas / chained WARP domains via the node's remote-doh.
	ip, err := resolveWarpDomainViaDoH(rCtx, w.eng, w.ctx, w.tag, w.opts.Detour != "", ep, destination.Fqdn, true, true)
	if err != nil {
		return destination, err
	}
	return M.SocksaddrFrom(ip, destination.Port), nil
}

func (w *warpAutoWireGuardOutbound) wrapDialError(ctx context.Context, epAddr string, err error) error {
	if w.isClosed() {
		return errors.New("outbound closed")
	}
	if (ctx != nil && errors.Is(ctx.Err(), context.Canceled)) || errors.Is(err, context.Canceled) || isDestinationLevelWGError(err) {
		return err
	}
	return fmt.Errorf("warp server (%s) connection failed: %w", epAddr, err)
}

func (w *warpAutoWireGuardOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if d := warpInternalDNSDialer(ctx, w.tag); d != nil && !destination.IsDomain() {
		return d.DialContext(ctx, network, destination)
	}
	ep, err := w.ensureEndpoint(ctx)
	if err != nil {
		return nil, w.wrapDialError(ctx, w.activeOrAuto(), err)
	}
	epAddr := w.activeOrAuto()
	destination, resErr := w.resolveDestination(ctx, ep, destination)
	if resErr != nil {
		w.recordDialResult(ctx, ep, resErr)
		return nil, w.wrapDialError(ctx, epAddr, resErr)
	}
	conn, err := ep.DialContext(ctx, network, destination)
	w.recordDialResult(ctx, ep, err)
	if err != nil {
		return nil, w.wrapDialError(ctx, epAddr, err)
	}
	return conn, nil
}

func (w *warpAutoWireGuardOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if d := warpInternalDNSDialer(ctx, w.tag); d != nil && !destination.IsDomain() {
		return d.ListenPacket(ctx, destination)
	}
	ep, err := w.ensureEndpoint(ctx)
	if err != nil {
		return nil, w.wrapDialError(ctx, w.activeOrAuto(), err)
	}
	epAddr := w.activeOrAuto()
	destination, resErr := w.resolveDestination(ctx, ep, destination)
	if resErr != nil {
		w.recordDialResult(ctx, ep, resErr)
		return nil, w.wrapDialError(ctx, epAddr, resErr)
	}
	pConn, err := ep.ListenPacket(ctx, destination)
	w.recordDialResult(ctx, ep, err)
	if err != nil {
		return nil, w.wrapDialError(ctx, epAddr, err)
	}
	return pConn, nil
}

func (w *warpAutoWireGuardOutbound) activeOrAuto() string {
	if ep := w.ActiveEndpoint(); ep != "" {
		return ep
	}
	return "auto"
}

func (w *warpAutoWireGuardOutbound) Close() error {
	if w.eng != nil {
		w.eng.resetWarpRemoteDoHTransport(w.tag)
	}
	return w.close(func() func() error {
		ep := w.ep
		w.ep = nil
		if ep == nil {
			return nil
		}
		return func() error {
			w.bindMu.Lock()
			defer w.bindMu.Unlock()
			return ep.Close()
		}
	})
}
