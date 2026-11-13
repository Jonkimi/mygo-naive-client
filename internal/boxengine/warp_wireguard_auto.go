package boxengine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
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
type warpAutoWireGuardOutbound struct {
	ctx         context.Context
	router      adapter.Router
	outboundMgr adapter.OutboundManager
	logger      log.ContextLogger
	tag         string
	opts        warpAutoWireGuardOptions
	eng         *Engine

	mu             sync.Mutex
	ep             *wireguard.Endpoint
	activeEndpoint string
	consecFails    int
	closed         bool
}

func newWarpAutoWireGuardOutbound(
	ctx context.Context,
	router adapter.Router,
	logger log.ContextLogger,
	tag string,
	opts warpAutoWireGuardOptions,
	eng *Engine,
) (adapter.Outbound, error) {
	return &warpAutoWireGuardOutbound{
		ctx:         ctx,
		router:      router,
		outboundMgr: service.FromContext[adapter.OutboundManager](ctx),
		logger:      logger,
		tag:         tag,
		opts:        opts,
		eng:         eng,
	}, nil
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
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil, errors.New("outbound closed")
	}
	if w.ep != nil {
		return w.ep, nil
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

	privKey := w.opts.PrivateKey
	peerPubKey := w.opts.PeerPubKey
	reserved := w.opts.Reserved
	ipv4 := w.opts.AddressIPv4
	ipv6 := w.opts.AddressIPv6

	var globalAcc warp.Account
	if w.eng != nil {
		w.eng.mu.RLock()
		if w.eng.cloudflareConfig != nil {
			globalAcc = w.eng.cloudflareConfig.Account
		}
		w.eng.mu.RUnlock()
	}

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
		var apiHTTPClient *http.Client
		if upstreamDialer != nil {
			tr := &http.Transport{
				DialContext: func(c context.Context, network, addr string) (net.Conn, error) {
					return upstreamDialer.DialContext(c, network, addr)
				},
				TLSClientConfig: &tls.Config{
					ServerName: "api.cloudflareclient.com",
				},
				ForceAttemptHTTP2:   true,
				TLSHandshakeTimeout: 5 * time.Second,
			}
			apiHTTPClient = &http.Client{
				Transport: tr,
				Timeout:   6 * time.Second,
			}
		}
		client := warp.NewClient(apiHTTPClient)
		provCtx, provCancel := context.WithTimeout(ctx, 6*time.Second)
		enrolled, err := client.ProvisionAll(provCtx, globalAcc, "")
		provCancel()
		if apiHTTPClient != nil {
			if tr, ok := apiHTTPClient.Transport.(*http.Transport); ok {
				tr.CloseIdleConnections()
			}
		}
		if err == nil {
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
			if w.eng != nil {
				w.eng.mu.Lock()
				if w.eng.cloudflareConfig != nil {
					w.eng.cloudflareConfig.Account = enrolled
				}
				w.eng.mu.Unlock()
			}
		}
	}

	if privKey == "" {
		if genPriv, _, err := warp.GenerateWireGuardKeypair(); err == nil {
			privKey = genPriv
		}
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

	selector := warp.DefaultEndpointSelector()
	if w.eng != nil && w.eng.endpointSelector != nil {
		selector = w.eng.endpointSelector
	}

	probeAcc := &warp.Account{
		WGPrivateKey:    privKey,
		WGPeerPublicKey: peerPubKey,
		Reserved:        reserved,
	}
	selCtx, selCancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	selected, err := selector.SelectWireGuardEndpoint(selCtx, w.scopeKey(), upstreamDialer, probeAcc)
	selCancel()

	targetEndpoint := warp.DefaultWireGuardEndpoint
	if err == nil && selected.Endpoint != "" {
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
	if p4, err := netip.ParsePrefix(ipv4PrefixStr); err == nil {
		addrs = append(addrs, p4)
	}
	if p6, err := netip.ParsePrefix(ipv6PrefixStr); err == nil {
		addrs = append(addrs, p6)
	}

	dialOpts := option.DialerOptions{}
	if w.opts.Detour != "" {
		dialOpts.Detour = w.opts.Detour
	}
	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:          w.ctx,
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

	networkManager := service.FromContext[adapter.NetworkManager](w.ctx)
	dnsRouter := service.FromContext[adapter.DNSRouter](w.ctx)
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
		Context:         w.ctx,
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
			return common.Must1(dialer.NewDefault(w.ctx, option.DialerOptions{
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
			return dnsRouter.Lookup(w.ctx, domain, outboundDialer.(dialer.ResolveDialer).QueryOptions())
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

	w.ep = wgEP
	w.activeEndpoint = targetEndpoint
	w.consecFails = 0
	return wgEP, nil
}

func (w *warpAutoWireGuardOutbound) recordDialResult(err error) {
	if err == nil {
		w.mu.Lock()
		w.consecFails = 0
		w.mu.Unlock()
		return
	}
	w.mu.Lock()
	w.consecFails++
	shouldRotate := w.consecFails >= 3 && w.ep != nil
	var oldEP *wireguard.Endpoint
	var failedAddr string
	if shouldRotate {
		oldEP = w.ep
		failedAddr = w.activeEndpoint
		w.ep = nil
		w.activeEndpoint = ""
		w.consecFails = 0
	}
	w.mu.Unlock()

	if shouldRotate {
		selector := warp.DefaultEndpointSelector()
		if w.eng != nil && w.eng.endpointSelector != nil {
			selector = w.eng.endpointSelector
		}
		if failedAddr != "" {
			selector.MarkFailed(warp.EndpointCacheKey{
				ScopeKey: w.scopeKey(),
				Mode:     warp.ModeWireGuard,
			}, failedAddr)
		}
		if oldEP != nil {
			_ = oldEP.Close()
		}
	}
}

func (w *warpAutoWireGuardOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ep, err := w.ensureEndpoint(ctx)
	if err != nil {
		return nil, fmt.Errorf("warp server (%s) connection failed: %w", w.activeOrAuto(), err)
	}
	if destination.IsDomain() {
		if w.opts.Detour == "" {
			if ip, rErr := resolveHostIP(ctx, destination.Fqdn); rErr == nil {
				destination = M.SocksaddrFrom(ip, destination.Port)
			}
		} else if dnsRouter := service.FromContext[adapter.DNSRouter](w.ctx); dnsRouter != nil {
			if addrs, lErr := dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{}); lErr == nil && len(addrs) > 0 {
				destination = M.SocksaddrFrom(addrs[0], destination.Port)
			}
		}
	}
	conn, err := ep.DialContext(ctx, network, destination)
	w.recordDialResult(err)
	if err != nil {
		return nil, fmt.Errorf("warp server (%s) connection failed: %w", w.activeOrAuto(), err)
	}
	return conn, nil
}

func (w *warpAutoWireGuardOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ep, err := w.ensureEndpoint(ctx)
	if err != nil {
		return nil, fmt.Errorf("warp server (%s) connection failed: %w", w.activeOrAuto(), err)
	}
	if destination.IsDomain() {
		if w.opts.Detour == "" {
			if ip, rErr := resolveHostIP(ctx, destination.Fqdn); rErr == nil {
				destination = M.SocksaddrFrom(ip, destination.Port)
			}
		} else if dnsRouter := service.FromContext[adapter.DNSRouter](w.ctx); dnsRouter != nil {
			if addrs, lErr := dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{}); lErr == nil && len(addrs) > 0 {
				destination = M.SocksaddrFrom(addrs[0], destination.Port)
			}
		}
	}
	pConn, err := ep.ListenPacket(ctx, destination)
	w.recordDialResult(err)
	if err != nil {
		return nil, fmt.Errorf("warp server (%s) connection failed: %w", w.activeOrAuto(), err)
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
	w.mu.Lock()
	w.closed = true
	ep := w.ep
	w.ep = nil
	w.mu.Unlock()
	if ep != nil {
		return ep.Close()
	}
	return nil
}
