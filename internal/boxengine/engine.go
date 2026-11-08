package boxengine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"naive-client/internal/blocker"
	"naive-client/internal/config"
	"naive-client/internal/geodata"
	"naive-client/internal/routing"
	"naive-client/internal/tailnet"
	"naive-client/internal/telemetry"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

// EngineOptions configures the embedded sing-box engine.
type EngineOptions struct {
	ListenAddr     string
	TrafficMode    string // "port", "sysproxy", "tun"
	TunFD          int    // file descriptor passed from tun-helper
	TunInterface   string // e.g. "utun8"
	TunAddresses   []string
	TunMTU         int
	TunCreator     func(options tun.Options) (tun.Tun, error)
	Services       []config.Service
	AllocatedPorts map[string]int
	Rules          []routing.Rule
	FinalAction    string
	FinalRoute     routing.RouteAction
	GeoSiteDB      *geodata.GeoSiteDB
	GeoIPDB        *geodata.GeoIPDB
	Tracker        *telemetry.Tracker
	FailureMonitor *telemetry.FailureMonitor
	Blocker               *blocker.Engine
	BootstrapDomains      []string
	BootstrapDNS          []string
	DomesticDoH    []string
	RemoteDoH      []string
	PreferIPv4        bool
	ActiveIDs         map[string]bool
	OnDemandStart     func(poolTag string)
	OnTelemetryUpdate func()

	// Tailnet integration (ADR-0007)
	TailnetConfig         *tailnet.Config
	TailnetMode           tailnet.Mode
	TailnetHostExcludes   []string
	TailnetMagicDNSSuffix string
	StateDir              string
}

// Engine manages the embedded sing-box instance (*box.Box) with dynamic node pools and telemetry.
type Engine struct {
	mu                sync.RWMutex
	box               *box.Box
	port              int
	addr              string
	services          []config.Service
	allocatedPorts    map[string]int
	activeIDs         map[string]bool
	tracker           *telemetry.Tracker
	failureMonitor    *telemetry.FailureMonitor
	blocker           *blocker.Engine
	connTracker       *BlockerConnectionTracker
	onDemandStart     func(poolTag string)
	onTelemetryUpdate func()
	boxCtx            context.Context
	cancel            context.CancelFunc
}

// New constructs a new Engine instance.
func New(opts EngineOptions) (*Engine, error) {
	listenHost := "127.0.0.1"
	listenPort := 10809

	if opts.ListenAddr != "" {
		h, pStr, err := net.SplitHostPort(opts.ListenAddr)
		if err == nil {
			listenHost = h
			if p, err := strconv.Atoi(pStr); err == nil {
				listenPort = p
			}
		}
	}

	if listenPort == 0 {
		ln, err := net.Listen("tcp", fmt.Sprintf("%s:0", listenHost))
		if err != nil {
			return nil, fmt.Errorf("failed to allocate ephemeral port: %w", err)
		}
		listenPort = ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()
	}

	allocated := opts.AllocatedPorts
	if allocated == nil {
		allocated = make(map[string]int)
	}

	eng := &Engine{
		port:           listenPort,
		addr:           fmt.Sprintf("%s:%d", listenHost, listenPort),
		services:       opts.Services,
		allocatedPorts: allocated,
		activeIDs:      opts.ActiveIDs,
		tracker:        opts.Tracker,
		failureMonitor: opts.FailureMonitor,
		blocker:           opts.Blocker,
		onDemandStart:     opts.OnDemandStart,
		onTelemetryUpdate: opts.OnTelemetryUpdate,
	}

	ctx, cancel := context.WithCancel(context.Background())
	eng.cancel = cancel

	boxCtx := createBoxContext(ctx, eng)
	if opts.TrafficMode == "tun" && opts.TunFD > 0 {
		tunPlatform := &TunPlatform{
			TunFD:      opts.TunFD,
			TunName:    opts.TunInterface,
			TunCreator: opts.TunCreator,
		}
		boxCtx = service.ContextWith[adapter.PlatformInterface](boxCtx, tunPlatform)
	}

	boxOpts, err := eng.buildConfig(boxCtx, opts, listenHost, listenPort)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("build sing-box options: %w", err)
	}

	b, err := box.New(box.Options{
		Context: boxCtx,
		Options: *boxOpts,
	})
	if err != nil {
		cancel()
		if strings.Contains(err.Error(), "with_tailscale") {
			return nil, fmt.Errorf("内嵌 Tailscale 节点需要添加编译标签 (-tags with_tailscale,with_gvisor): %w", err)
		}
		if strings.Contains(err.Error(), "with_utls") {
			return nil, fmt.Errorf("Reality / uTLS 节点需要添加编译标签 (-tags with_utls): %w", err)
		}
		if strings.Contains(err.Error(), "with_quic") {
			return nil, fmt.Errorf("Hysteria2 / TUIC 节点需要添加编译标签 (-tags with_quic): %w", err)
		}
		if strings.Contains(err.Error(), "with_naive_outbound") {
			return nil, fmt.Errorf("NaiveProxy 原生节点需要添加编译标签 (-tags with_naive_outbound): %w", err)
		}
		if strings.Contains(err.Error(), "with_wireguard") {
			return nil, fmt.Errorf("WireGuard 节点需要添加编译标签 (-tags with_wireguard): %w", err)
		}
		return nil, fmt.Errorf("create sing-box core: %w", err)
	}

	eng.boxCtx = boxCtx
	if eng.blocker != nil {
		eng.connTracker = &BlockerConnectionTracker{
			blocker:          eng.blocker,
			nodeNameResolver: eng.GetNodeName,
		}
		b.Router().AppendTracker(eng.connTracker)
		eng.blocker.SetOnUpdate(eng.ClearDNSCache)
	}

	eng.box = b
	return eng, nil
}

func createBoxContext(ctx context.Context, eng *Engine) context.Context {
	outboundReg := include.OutboundRegistry()
	type poolOption struct {
		PoolTag string `json:"pool_tag,omitempty"`
	}
	outbound.Register[poolOption](outboundReg, "pool", func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, pOpts poolOption) (adapter.Outbound, error) {
		var tracker *telemetry.Tracker
		var fm *telemetry.FailureMonitor
		var np NodeProvider
		var telemetryUpdate func()
		var bl *blocker.Engine
		if eng != nil {
			tracker = eng.tracker
			fm = eng.failureMonitor
			np = eng
			telemetryUpdate = eng.onTelemetryUpdate
			bl = eng.blocker
		}
		return NewPoolOutbound(PoolOutboundOptions{
			Tag:               tag,
			PoolTag:           pOpts.PoolTag,
			Tracker:           tracker,
			FailureMonitor:    fm,
			NodeProvider:      np,
			OnTelemetryUpdate: telemetryUpdate,
			Blocker:           bl,
		}), nil
	})

	var finalOutboundReg adapter.OutboundRegistry = outboundReg
	if eng != nil && (eng.blocker != nil || eng.failureMonitor != nil) {
		finalOutboundReg = &blockerOutboundRegistry{
			underlying: outboundReg,
			blocker:    eng.blocker,
			fm:         eng.failureMonitor,
		}
	}

	dnsReg := include.DNSTransportRegistry()
	var finalDNSReg adapter.DNSTransportRegistry = dnsReg
	if eng != nil && (eng.blocker != nil || eng.failureMonitor != nil) {
		finalDNSReg = &blockerTransportRegistry{
			underlying: dnsReg,
			blocker:    eng.blocker,
			fm:         eng.failureMonitor,
		}
	}

	return box.Context(
		ctx,
		include.InboundRegistry(),
		finalOutboundReg,
		include.EndpointRegistry(),
		finalDNSReg,
		include.ServiceRegistry(),
		include.CertificateProviderRegistry(),
	)
}

// Start launches the embedded sing-box engine.
func (e *Engine) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.box == nil {
		return errors.New("engine is closed")
	}
	return e.box.Start()
}

// Close gracefully closes the embedded engine.
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	var err error
	if e.box != nil {
		err = e.box.Close()
		e.box = nil
	}
	if e.cancel != nil {
		e.cancel()
		e.cancel = nil
	}
	return err
}

// Stop is an alias for Close to satisfy standard lifecycle interfaces.
func (e *Engine) Stop() error {
	return e.Close()
}

// Port returns the listening port of the mixed inbound gateway.
func (e *Engine) Port() int {
	return e.port
}

// Addr returns the listening host:port address.
func (e *Engine) Addr() string {
	return e.addr
}

func isSidecarService(svc config.Service) bool {
	if svc.EffectiveKind() == config.KindExternalProxy {
		return false
	}
	if svc.Engine == config.EngineSidecar {
		return true
	}
	if svc.Engine == "" && svc.EffectiveProtocol() == config.ProtoNaive {
		return true
	}
	return false
}

// UpdateNodes updates active services, allocated loopback ports, and active IDs without restarting the engine.
func (e *Engine) UpdateNodes(services []config.Service, allocatedPorts map[string]int, activeIDs map[string]bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.services = services
	if allocatedPorts != nil {
		e.allocatedPorts = allocatedPorts
	}
	if activeIDs != nil {
		e.activeIDs = activeIDs
	}
}

// GetCandidates implements NodeProvider.
func (e *Engine) GetCandidates(poolTag string) []string {
	cleanTag := strings.TrimSpace(poolTag)
	cleanTag = strings.TrimPrefix(cleanTag, "PROXY_TAG:")

	e.mu.RLock()
	candidates := e.findCandidates(cleanTag)
	e.mu.RUnlock()

	if len(candidates) == 0 && e.onDemandStart != nil {
		e.onDemandStart(cleanTag)
		e.mu.RLock()
		candidates = e.findCandidates(cleanTag)
		e.mu.RUnlock()
	}

	return candidates
}

func (e *Engine) findCandidates(cleanTag string) []string {
	var wantTags []string
	for _, part := range strings.Split(cleanTag, ",") {
		if p := strings.TrimSpace(part); p != "" {
			wantTags = append(wantTags, p)
		}
	}

	var candidates []string
	for _, svc := range e.services {
		if e.activeIDs != nil && !e.activeIDs[svc.ID] {
			continue
		}
		if isSidecarService(svc) {
			if e.allocatedPorts[svc.ID] <= 0 {
				continue
			}
		}

		if cleanTag == "" || cleanTag == "PROXY_POOL" || len(wantTags) == 0 {
			candidates = append(candidates, svc.ID)
			continue
		}

		// Check if service matches any requested tag
		matched := false
		for _, t := range svc.Tags {
			for _, wt := range wantTags {
				if strings.EqualFold(t, wt) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if matched {
			candidates = append(candidates, svc.ID)
		}
	}
	return candidates
}

func joinCleanTags(tags []string) string {
	var clean []string
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t != "" {
			clean = append(clean, t)
		}
	}
	return strings.Join(clean, ",")
}

func resolveRouteOutbound(act routing.RouteAction, tailnetMode tailnet.Mode) string {
	switch act.Type {
	case routing.ActionDirect:
		return "direct"
	case routing.ActionBlock:
		return "block"
	case routing.ActionProxyPool:
		return "PROXY_POOL"
	case routing.ActionProxyTag:
		if joined := joinCleanTags(act.GetTags()); joined != "" {
			return "PROXY_TAG:" + joined
		}
		return "PROXY_POOL"
	case routing.ActionProxyService:
		if svcID := strings.TrimSpace(act.ServiceID); svcID != "" {
			return "node-" + svcID
		}
		return "PROXY_POOL"
	case routing.ActionTailnet, routing.ActionTailnetExit:
		if tailnetMode == tailnet.ModeHost {
			return "direct"
		}
		return "tailscale-ep"
	default:
		return "direct"
	}
}

// GetOutbound implements NodeProvider.
func (e *Engine) GetOutbound(nodeID string) (adapter.Outbound, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.box == nil {
		return nil, false
	}
	if ob, ok := e.box.Outbound().Outbound("node-" + nodeID); ok {
		return ob, true
	}
	cleanID := strings.TrimPrefix(nodeID, "node-")
	if ob, ok := e.box.Outbound().Outbound("node-" + cleanID); ok {
		return ob, true
	}
	return e.box.Outbound().Outbound(nodeID)
}

// DialNode dials a destination address through the specified node outbound.
func (e *Engine) DialNode(ctx context.Context, nodeID string, network, addr string) (net.Conn, error) {
	cleanID := strings.TrimPrefix(nodeID, "node-")
	ob, ok := e.GetOutbound(cleanID)
	if !ok {
		return nil, fmt.Errorf("outbound not found for node %s", cleanID)
	}
	dest := M.ParseSocksaddr(addr)
	if !dest.IsValid() {
		return nil, fmt.Errorf("invalid destination addr %q", addr)
	}
	return ob.DialContext(ctx, network, dest)
}

// IsSidecar implements NodeProvider.
func (e *Engine) IsSidecar(nodeID string) bool {
	cleanID := strings.TrimPrefix(nodeID, "node-")
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, svc := range e.services {
		if svc.ID == cleanID {
			return isSidecarService(svc)
		}
	}
	return false
}

// GetNodeName returns the friendly name of a node by ID or tag, implementing NodeProvider.
func (e *Engine) GetNodeName(nodeID string) string {
	cleanID := strings.TrimPrefix(nodeID, "node-")
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, svc := range e.services {
		if svc.ID == cleanID {
			if svc.Name != "" {
				return svc.Name
			}
			return cleanID
		}
	}
	return cleanID
}

// extractSidecarExcludeAddresses extracts IP addresses from sidecar nodes as CIDR strings
// to populate route_exclude_address, preventing sidecar loops through sing-tun.
func extractSidecarExcludeAddresses(services []config.Service, resolver func(host string) []net.IP) []string {
	var results []string
	seen := make(map[string]bool)

	addIP := func(ip net.IP) {
		var cidr string
		if ip4 := ip.To4(); ip4 != nil {
			cidr = ip4.String() + "/32"
		} else if ip16 := ip.To16(); ip16 != nil {
			cidr = ip16.String() + "/128"
		}
		if cidr != "" && !seen[cidr] {
			seen[cidr] = true
			results = append(results, cidr)
		}
	}

	addHost := func(host string) {
		host = strings.TrimSpace(host)
		if host == "" {
			return
		}
		host = strings.TrimPrefix(host, "[")
		host = strings.TrimSuffix(host, "]")
		if ip := net.ParseIP(host); ip != nil {
			addIP(ip)
			return
		}
		if resolver != nil {
			for _, ip := range resolver(host) {
				addIP(ip)
			}
		}
	}

	for _, svc := range services {
		if !isSidecarService(svc) {
			continue
		}
		if svc.Server != "" {
			addHost(svc.Server)
		}
		for _, proxyURI := range svc.Proxies {
			if u, err := url.Parse(proxyURI); err == nil && u.Hostname() != "" {
				addHost(u.Hostname())
			}
		}
		if svc.ExternalURI != "" {
			if u, err := url.Parse(svc.ExternalURI); err == nil && u.Hostname() != "" {
				addHost(u.Hostname())
			}
		}
	}
	return results
}

func resolveFinalOutbound(opts EngineOptions) string {
	if opts.FinalRoute.Type != "" {
		return resolveRouteOutbound(opts.FinalRoute, opts.TailnetMode)
	}
	if opts.FinalAction != "" {
		fa := strings.TrimSpace(opts.FinalAction)
		if strings.HasPrefix(strings.ToUpper(fa), "PROXY_TAG:") {
			tag := strings.TrimSpace(fa[len("PROXY_TAG:"):])
			if tag != "" {
				return "PROXY_TAG:" + tag
			}
			return "PROXY_POOL"
		} else if strings.HasPrefix(fa, "node-") {
			return fa
		} else if strings.EqualFold(fa, "proxy") || strings.EqualFold(fa, "proxy_pool") || strings.EqualFold(fa, "proxy_tag") || strings.EqualFold(fa, "proxy_service") {
			return "PROXY_POOL"
		} else if strings.EqualFold(fa, "block") {
			return "block"
		}
	}
	return "direct"
}

func collectAllBootstrapDomains(opts EngineOptions) []string {
	bootstrapDomainSet := make(map[string]bool)
	for _, d := range opts.BootstrapDomains {
		d = strings.TrimSpace(d)
		if d != "" && net.ParseIP(d) == nil {
			bootstrapDomainSet[d] = true
		}
	}
	for _, svc := range opts.Services {
		if svc.Server != "" && net.ParseIP(svc.Server) == nil {
			bootstrapDomainSet[svc.Server] = true
		}
	}
	var allBootstrapDomains []string
	for d := range bootstrapDomainSet {
		allBootstrapDomains = append(allBootstrapDomains, d)
	}
	sort.Strings(allBootstrapDomains)
	return allBootstrapDomains
}

func collectRuleSetTags(opts EngineOptions) (siteTags, ipTags []string) {
	for _, r := range opts.Rules {
		if !r.Enabled {
			continue
		}
		for _, gs := range r.GeoSite {
			cleanGS := strings.ToLower(strings.TrimSpace(gs))
			if opts.Blocker != nil && cleanGS == "category-ads-all" {
				continue
			}
			siteTags = append(siteTags, gs)
		}
		ipTags = append(ipTags, r.GeoIP...)
	}
	return siteTags, ipTags
}

func buildInboundsConfig(opts EngineOptions, host string, port int) []map[string]any {
	inbounds := []map[string]any{
		{
			"type":        "mixed",
			"tag":         "mixed-in",
			"listen":      host,
			"listen_port": port,
		},
	}

	if opts.TailnetConfig != nil && opts.TailnetConfig.ExposeMixedPort {
		inbounds = append(inbounds, map[string]any{
			"type":        "mixed",
			"tag":         "tailnet-mixed-in",
			"listen":      "0.0.0.0",
			"listen_port": port,
		})
	}

	if opts.TrafficMode == "tun" {
		tunAddrs := opts.TunAddresses
		if len(tunAddrs) == 0 {
			tunAddrs = []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"}
		}
		mtu := opts.TunMTU
		if mtu <= 0 {
			mtu = 9000
		}
		tunIn := map[string]any{
			"type":         "tun",
			"tag":          "tun-in",
			"address":      tunAddrs,
			"mtu":          mtu,
			"auto_route":   true,
			"strict_route": true,
			"stack":        "system",
		}
		if opts.TunInterface != "" {
			tunIn["interface_name"] = opts.TunInterface
		}
		excludes := extractSidecarExcludeAddresses(opts.Services, nil)
		if opts.TailnetMode == tailnet.ModeHost {
			tailnetExcludes := append([]string{}, tailnet.DefaultTailnetSubnets...)
			tailnetExcludes = append(tailnetExcludes, opts.TailnetHostExcludes...)
			for _, te := range tailnetExcludes {
				te = strings.TrimSpace(te)
				if te != "" {
					excludes = append(excludes, te)
				}
			}
		}
		if len(excludes) > 0 {
			tunIn["route_exclude_address"] = excludes
		}
		inbounds = append(inbounds, tunIn)
	}
	return inbounds
}

func buildOutboundsConfig(opts EngineOptions, finalOutbound string, allocatedPorts map[string]int) ([]map[string]any, error) {
	outbounds := []map[string]any{
		{
			"type": "direct",
			"tag":  "direct",
		},
		{
			"type": "block",
			"tag":  "block",
		},
		{
			"type": "pool",
			"tag":  "PROXY_POOL",
		},
	}

	tagSet := make(map[string]bool)
	ensurePoolTag := func(t string) {
		t = strings.TrimSpace(t)
		if t != "" && !tagSet[t] {
			tagSet[t] = true
			outbounds = append(outbounds, map[string]any{
				"type":     "pool",
				"tag":      "PROXY_TAG:" + t,
				"pool_tag": t,
			})
		}
	}
	for _, svc := range opts.Services {
		for _, t := range svc.Tags {
			ensurePoolTag(t)
		}
	}
	for _, r := range opts.Rules {
		for _, t := range r.Action.GetTags() {
			ensurePoolTag(t)
		}
		if joined := joinCleanTags(r.Action.GetTags()); joined != "" {
			ensurePoolTag(joined)
		}
	}
	for _, t := range opts.FinalRoute.GetTags() {
		ensurePoolTag(t)
	}
	if joined := joinCleanTags(opts.FinalRoute.GetTags()); joined != "" {
		ensurePoolTag(joined)
	}
	if strings.HasPrefix(finalOutbound, "PROXY_TAG:") {
		ensurePoolTag(strings.TrimPrefix(finalOutbound, "PROXY_TAG:"))
	}

	// Node outbounds
	for _, svc := range opts.Services {
		nodeTag := "node-" + svc.ID
		if isSidecarService(svc) {
			allocPort := 0
			if allocatedPorts != nil && allocatedPorts[svc.ID] > 0 {
				allocPort = allocatedPorts[svc.ID]
			} else if listen := svc.PrimaryListen(); listen != "" {
				if ep, err := config.ParseListenURI(listen); err == nil && ep.Port > 0 {
					allocPort = ep.Port
				}
			}
			if allocPort <= 0 {
				return nil, fmt.Errorf("sidecar 节点 %q (%s) 缺少有效的本地监听端口，请检查配置或启动状态", svc.Name, svc.ID)
			}
			outbounds = append(outbounds, map[string]any{
				"type":        "socks",
				"tag":         nodeTag,
				"server":      "127.0.0.1",
				"server_port": allocPort,
			})
		} else {
			outbounds = append(outbounds, buildNativeOutbound(svc))
		}
	}
	return outbounds, nil
}

func buildEndpointsConfig(opts EngineOptions) []map[string]any {
	if opts.TailnetMode != tailnet.ModeEmbedded || opts.TailnetConfig == nil {
		return nil
	}
	stateDir := opts.StateDir
	if stateDir == "" {
		stateDir = "tsnet-state"
	} else {
		stateDir = filepath.Join(stateDir, "tsnet-state")
	}
	tsEp := map[string]any{
		"type":            "tailscale",
		"tag":             "tailscale-ep",
		"state_directory": stateDir,
		"domain_resolver": "bootstrap-dns",
	}
	if opts.TailnetConfig.AuthKey != "" {
		tsEp["auth_key"] = opts.TailnetConfig.AuthKey
	}
	if opts.TailnetConfig.ControlURL != "" {
		tsEp["control_url"] = opts.TailnetConfig.ControlURL
	}
	if opts.TailnetConfig.Hostname != "" {
		tsEp["hostname"] = opts.TailnetConfig.Hostname
	}
	if opts.TailnetConfig.AcceptRoutes {
		tsEp["accept_routes"] = true
	}
	if opts.TailnetConfig.ExitNode != "" {
		tsEp["exit_node"] = opts.TailnetConfig.ExitNode
	}
	if opts.TailnetConfig.AdvertiseExitNode {
		tsEp["advertise_exit_node"] = true
	}
	if len(opts.TailnetConfig.AdvertiseRoutes) > 0 {
		tsEp["advertise_routes"] = opts.TailnetConfig.AdvertiseRoutes
	}
	return []map[string]any{tsEp}
}

func buildDNSConfig(opts EngineOptions, finalOutbound string, allBootstrapDomains []string) map[string]any {
	bootstrapDNS := opts.BootstrapDNS
	if len(bootstrapDNS) == 0 {
		bootstrapDNS = DefaultBootstrapDNS
	}
	domesticDoH := opts.DomesticDoH
	if len(domesticDoH) == 0 {
		domesticDoH = DefaultDomesticDoH
	}
	remoteDoH := opts.RemoteDoH
	if len(remoteDoH) == 0 {
		remoteDoH = DefaultRemoteDoH
	}

	remoteDoHDetour := "PROXY_POOL"
	if strings.HasPrefix(finalOutbound, "PROXY_TAG:") || strings.HasPrefix(finalOutbound, "node-") {
		remoteDoHDetour = finalOutbound
	}

	dnsServers := []map[string]any{
		buildDNSServerMap("bootstrap-dns", bootstrapDNS[0], "", ""),
		buildDNSServerMap("domestic-doh", domesticDoH[0], "", "bootstrap-dns"),
		buildDNSServerMap("remote-doh", remoteDoH[0], remoteDoHDetour, "bootstrap-dns"),
	}

	var dnsRules []map[string]any
	if len(allBootstrapDomains) > 0 {
		dnsRules = append(dnsRules, map[string]any{
			"domain": allBootstrapDomains,
			"server": "bootstrap-dns",
		})
	}
	if opts.TailnetMode == tailnet.ModeHost {
		dnsServers = append(dnsServers, map[string]any{
			"type":        "udp",
			"tag":         "tailscale-host-dns",
			"server":      "100.100.100.100",
			"server_port": 53,
		})
		suffixes := []string{"ts.net"}
		if opts.TailnetMagicDNSSuffix != "" && opts.TailnetMagicDNSSuffix != "ts.net" {
			suffixes = append(suffixes, opts.TailnetMagicDNSSuffix)
		}
		dnsRules = append(dnsRules, map[string]any{
			"domain_suffix": suffixes,
			"server":        "tailscale-host-dns",
		})
	} else if opts.TailnetMode == tailnet.ModeEmbedded && opts.TailnetConfig != nil {
		dnsServers = append(dnsServers, map[string]any{
			"type":     "tailscale",
			"tag":      "tailscale-dns",
			"endpoint": "tailscale-ep",
		})
		suffixes := []string{"ts.net"}
		if opts.TailnetMagicDNSSuffix != "" && opts.TailnetMagicDNSSuffix != "ts.net" {
			suffixes = append(suffixes, opts.TailnetMagicDNSSuffix)
		}
		dnsRules = append(dnsRules, map[string]any{
			"domain_suffix": suffixes,
			"server":        "tailscale-dns",
		})
	}

	// Build DNS rules aligned with user routing rules (ADR-0003, ADR-0007).
	// Custom rules are prioritized before preset rules.
	prioritizedUserRules := routing.PrioritizedRules(opts.Rules)
	for _, r := range prioritizedUserRules {
		if !r.Enabled {
			continue
		}

		var targetDNSServer string
		switch r.Action.Type {
		case routing.ActionDirect:
			targetDNSServer = "domestic-doh"
		case routing.ActionProxyPool, routing.ActionProxyTag, routing.ActionProxyService:
			targetDNSServer = "remote-doh"
		case routing.ActionTailnet, routing.ActionTailnetExit:
			if opts.TailnetMode == tailnet.ModeHost {
				targetDNSServer = "tailscale-host-dns"
			} else {
				targetDNSServer = "tailscale-dns"
			}
		}

		if targetDNSServer == "" {
			continue
		}

		if len(r.DomainFull) > 0 || len(r.DomainSuffix) > 0 || len(r.DomainKeyword) > 0 {
			dr := map[string]any{"server": targetDNSServer}
			if len(r.DomainFull) > 0 {
				dr["domain"] = r.DomainFull
			}
			if len(r.DomainSuffix) > 0 {
				dr["domain_suffix"] = r.DomainSuffix
			}
			if len(r.DomainKeyword) > 0 {
				dr["domain_keyword"] = r.DomainKeyword
			}
			dnsRules = append(dnsRules, dr)
		}

		if len(r.GeoSite) > 0 {
			var rsets []string
			for _, gs := range r.GeoSite {
				cleanGS := strings.ToLower(strings.TrimSpace(gs))
				if opts.Blocker != nil && cleanGS == "category-ads-all" {
					continue
				}
				rsets = append(rsets, "geosite-"+cleanGS)
			}
			if len(rsets) > 0 {
				dnsRules = append(dnsRules, map[string]any{
					"rule_set": rsets,
					"server":   targetDNSServer,
				})
			}
		}
	}

	dnsFinal := "remote-doh"
	if finalOutbound == "direct" {
		dnsFinal = "domestic-doh"
	}

	dnsMap := map[string]any{
		"servers": dnsServers,
		"final":   dnsFinal,
	}
	if opts.PreferIPv4 {
		dnsMap["strategy"] = "prefer_ipv4"
	}
	if len(dnsRules) > 0 {
		dnsMap["rules"] = dnsRules
	}
	return dnsMap
}

func buildRouteConfig(opts EngineOptions, finalOutbound string, allBootstrapDomains []string) map[string]any {
	var singRules []map[string]any

	// 0. Packet sniffing (ADR-0003, Item 8)
	if opts.TrafficMode == "tun" {
		singRules = append(singRules, map[string]any{
			"inbound": []string{"tun-in"},
			"action":  "sniff",
		})
	}
	singRules = append(singRules, map[string]any{
		"ip_cidr": []string{"0.0.0.0/0", "::/0"},
		"action":  "sniff",
	})

	// 0.1 DNS hijacking (ADR-0003, ADR-0004)
	singRules = append(singRules, map[string]any{
		"protocol": "dns",
		"action":   "hijack-dns",
	})
	singRules = append(singRules, map[string]any{
		"port":   []int{53},
		"action": "hijack-dns",
	})

	// 0.2 Bootstrap domains routing directly to avoid TUN/proxy deadlocks (Item 6)
	if len(allBootstrapDomains) > 0 {
		singRules = append(singRules, map[string]any{
			"domain":   allBootstrapDomains,
			"outbound": "direct",
		})
	}

	// 4.1 Tailnet highest-priority routing & Pi-hole Blocker bypass
	if opts.TailnetMode == tailnet.ModeHost {
		tailnetCIDRs := append([]string{}, tailnet.DefaultTailnetSubnets...)
		tailnetCIDRs = append(tailnetCIDRs, opts.TailnetHostExcludes...)
		singRules = append(singRules, map[string]any{
			"ip_cidr":  tailnetCIDRs,
			"outbound": "direct",
		})
		suffixes := []string{"ts.net"}
		if opts.TailnetMagicDNSSuffix != "" && opts.TailnetMagicDNSSuffix != "ts.net" {
			suffixes = append(suffixes, opts.TailnetMagicDNSSuffix)
		}
		singRules = append(singRules, map[string]any{
			"domain_suffix": suffixes,
			"outbound":      "direct",
		})
	} else if opts.TailnetMode == tailnet.ModeEmbedded && opts.TailnetConfig != nil {
		suffixes := []string{"ts.net"}
		if opts.TailnetMagicDNSSuffix != "" && opts.TailnetMagicDNSSuffix != "ts.net" {
			suffixes = append(suffixes, opts.TailnetMagicDNSSuffix)
		}
		singRules = append(singRules, map[string]any{
			"domain_suffix": suffixes,
			"outbound":      "tailscale-ep",
		})
		singRules = append(singRules, map[string]any{
			"ip_cidr":  tailnet.DefaultTailnetSubnets,
			"outbound": "tailscale-ep",
		})
	}

	// 4.2 User rules (custom rules prioritized before preset rules)
	prioritizedUserRules := routing.PrioritizedRules(opts.Rules)
	for _, r := range prioritizedUserRules {
		if !r.Enabled {
			continue
		}

		outbound := resolveRouteOutbound(r.Action, opts.TailnetMode)

		// 1. Direct domain / CIDR matching rule
		if len(r.DomainFull) > 0 || len(r.DomainSuffix) > 0 || len(r.DomainKeyword) > 0 || len(r.IPCidr) > 0 {
			sr := map[string]any{"outbound": outbound}
			if len(r.DomainFull) > 0 {
				sr["domain"] = r.DomainFull
			}
			if len(r.DomainSuffix) > 0 {
				sr["domain_suffix"] = r.DomainSuffix
			}
			if len(r.DomainKeyword) > 0 {
				sr["domain_keyword"] = r.DomainKeyword
			}
			if len(r.IPCidr) > 0 {
				sr["ip_cidr"] = r.IPCidr
			}
			singRules = append(singRules, sr)
		}

		// 2. RuleSet matching rule (OR logic with domain criteria)
		if len(r.GeoSite) > 0 || len(r.GeoIP) > 0 {
			var rsets []string
			for _, gs := range r.GeoSite {
				cleanGS := strings.ToLower(strings.TrimSpace(gs))
				if opts.Blocker != nil && cleanGS == "category-ads-all" {
					continue
				}
				rsets = append(rsets, "geosite-"+cleanGS)
			}
			for _, gi := range r.GeoIP {
				rsets = append(rsets, "geoip-"+strings.ToLower(strings.TrimSpace(gi)))
			}
			if len(rsets) > 0 {
				singRules = append(singRules, map[string]any{
					"rule_set": rsets,
					"outbound": outbound,
				})
			}
		}
	}

	return map[string]any{
		"rules":                 singRules,
		"final":                 finalOutbound,
		"auto_detect_interface": true,
	}
}

func (e *Engine) buildConfig(ctx context.Context, opts EngineOptions, host string, port int) (*option.Options, error) {
	configMap := make(map[string]any)

	configMap["log"] = map[string]any{
		"level": "warn",
	}

	finalOutbound := resolveFinalOutbound(opts)
	allBootstrapDomains := collectAllBootstrapDomains(opts)

	configMap["inbounds"] = buildInboundsConfig(opts, host, port)
	outbounds, err := buildOutboundsConfig(opts, finalOutbound, e.allocatedPorts)
	if err != nil {
		return nil, fmt.Errorf("build outbounds: %w", err)
	}
	configMap["outbounds"] = outbounds
	if endpoints := buildEndpointsConfig(opts); len(endpoints) > 0 {
		configMap["endpoints"] = endpoints
	}
	configMap["dns"] = buildDNSConfig(opts, finalOutbound, allBootstrapDomains)
	configMap["route"] = buildRouteConfig(opts, finalOutbound, allBootstrapDomains)

	// Build RuleSets
	siteTags, ipTags := collectRuleSetTags(opts)
	ruleSets := geodata.BuildRuleSets(opts.GeoSiteDB, opts.GeoIPDB, siteTags, ipTags)

	rawJSON, err := json.Marshal(configMap)
	if err != nil {
		return nil, err
	}

	var boxOptions option.Options
	if err := boxOptions.UnmarshalJSONContext(ctx, rawJSON); err != nil {
		return nil, fmt.Errorf("unmarshal sing-box config: %w", err)
	}

	// Attach RuleSet directly
	if len(ruleSets) > 0 {
		if boxOptions.Route == nil {
			boxOptions.Route = &option.RouteOptions{}
		}
		boxOptions.Route.RuleSet = ruleSets
	}

	return &boxOptions, nil
}

// TailscaleEndpoint returns the adapter.TailscaleEndpoint if running in embedded mode.
func (e *Engine) TailscaleEndpoint() adapter.TailscaleEndpoint {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.box == nil {
		return nil
	}
	ep, ok := e.box.Endpoint().Get("tailscale-ep")
	if !ok {
		return nil
	}
	tsEp, _ := ep.(adapter.TailscaleEndpoint)
	return tsEp
}

// ClearDNSCache clears sing-box internal DNS cache (memory LRU and persistent store).
func (e *Engine) ClearDNSCache() {
	e.mu.RLock()
	boxCtx := e.boxCtx
	e.mu.RUnlock()
	if boxCtx == nil {
		return
	}
	dnsRouter := service.FromContext[adapter.DNSRouter](boxCtx)
	if dnsRouter != nil {
		dnsRouter.ClearCache()
	}
}

func buildDNSServerMap(tag string, rawAddr string, detour string, domainResolver string) map[string]any {
	rawAddr = strings.TrimSpace(rawAddr)
	if strings.HasPrefix(rawAddr, "https://") || strings.HasPrefix(rawAddr, "http://") {
		u, err := url.Parse(rawAddr)
		if err == nil {
			port := 443
			if u.Scheme == "http" {
				port = 80
			}
			if u.Port() != "" {
				if p, err := strconv.Atoi(u.Port()); err == nil && p > 0 {
					port = p
				}
			}
			path := u.Path
			if path == "" {
				path = "/dns-query"
			}
			m := map[string]any{
				"type":        "https",
				"tag":         tag,
				"server":      u.Hostname(),
				"server_port": port,
				"path":        path,
			}
			if detour != "" {
				m["detour"] = detour
			}
			if domainResolver != "" {
				m["domain_resolver"] = domainResolver
			}
			return m
		}
	}

	host, portStr, err := net.SplitHostPort(rawAddr)
	if err != nil {
		host = rawAddr
		portStr = "53"
	}
	port, _ := strconv.Atoi(portStr)
	if port <= 0 {
		port = 53
	}
	m := map[string]any{
		"type":        "udp",
		"tag":         tag,
		"server":      host,
		"server_port": port,
	}
	if detour != "" {
		m["detour"] = detour
	}
	if domainResolver != "" {
		m["domain_resolver"] = domainResolver
	}
	return m
}

func isCategoryAdsRule(r routing.Rule) bool {
	if r.ID == "preset-block-ads" {
		return true
	}
	if r.Action.Type == routing.ActionBlock {
		for _, gs := range r.GeoSite {
			if strings.EqualFold(strings.TrimSpace(gs), "category-ads-all") {
				return true
			}
		}
	}
	return false
}

