package boxengine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
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
	GeoSiteDB      *geodata.GeoSiteDB
	GeoIPDB        *geodata.GeoIPDB
	Tracker        *telemetry.Tracker
	FailureMonitor *telemetry.FailureMonitor
	Blocker        *blocker.Engine
	BootstrapDNS   []string
	DomesticDoH    []string
	RemoteDoH      []string
	PreferIPv4     bool
	ActiveIDs      map[string]bool
	OnDemandStart  func(poolTag string)

	// Tailnet integration (ADR-0007)
	TailnetConfig         *tailnet.Config
	TailnetMode           tailnet.Mode
	TailnetHostExcludes   []string
	TailnetMagicDNSSuffix string
	StateDir              string
}

// Engine manages the embedded sing-box instance (*box.Box) with dynamic node pools and telemetry.
type Engine struct {
	mu             sync.RWMutex
	box            *box.Box
	port           int
	addr           string
	services       []config.Service
	allocatedPorts map[string]int
	activeIDs      map[string]bool
	tracker        *telemetry.Tracker
	failureMonitor *telemetry.FailureMonitor
	blocker        *blocker.Engine
	onDemandStart  func(poolTag string)
	cancel         context.CancelFunc
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
		blocker:        opts.Blocker,
		onDemandStart:  opts.OnDemandStart,
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
		return nil, fmt.Errorf("create sing-box core: %w", err)
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
		if eng != nil {
			tracker = eng.tracker
			fm = eng.failureMonitor
			np = eng
		}
		return NewPoolOutbound(PoolOutboundOptions{
			Tag:            tag,
			PoolTag:        pOpts.PoolTag,
			Tracker:        tracker,
			FailureMonitor: fm,
			NodeProvider:   np,
		}), nil
	})

	return box.Context(
		ctx,
		include.InboundRegistry(),
		outboundReg,
		include.EndpointRegistry(),
		include.DNSTransportRegistry(),
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

		if cleanTag == "" || cleanTag == "PROXY_POOL" {
			candidates = append(candidates, svc.ID)
			continue
		}

		// Check if service matches tag
		for _, t := range svc.Tags {
			if strings.EqualFold(t, cleanTag) {
				candidates = append(candidates, svc.ID)
				break
			}
		}
	}
	return candidates
}

// GetOutbound implements NodeProvider.
func (e *Engine) GetOutbound(nodeID string) (adapter.Outbound, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.box == nil {
		return nil, false
	}
	return e.box.Outbound().Outbound("node-" + nodeID)
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

func (e *Engine) buildConfig(ctx context.Context, opts EngineOptions, host string, port int) (*option.Options, error) {
	configMap := make(map[string]any)

	configMap["log"] = map[string]any{
		"level": "warn",
	}

	// 1. Inbounds: mixed (HTTP + SOCKS5) and optional tun inbound
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
	configMap["inbounds"] = inbounds

	// 2. Outbounds: direct, block, node outbounds, and pool outbounds
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

	// Pool outbounds for tags
	tagSet := make(map[string]bool)
	for _, svc := range opts.Services {
		for _, t := range svc.Tags {
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
	}
	for _, r := range opts.Rules {
		for _, t := range r.Action.GetTags() {
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
	}

	// Node outbounds
	for _, svc := range opts.Services {
		nodeTag := "node-" + svc.ID
		if isSidecarService(svc) {
			allocPort := e.allocatedPorts[svc.ID]
			if allocPort <= 0 {
				allocPort = 1080 // fallback
			}
			outbounds = append(outbounds, map[string]any{
				"type":        "socks",
				"tag":         nodeTag,
				"server":      "127.0.0.1",
				"server_port": allocPort,
			})
		} else {
			// EngineSingBox native outbounds
			outbounds = append(outbounds, buildNativeOutbound(svc))
		}
	}
	configMap["outbounds"] = outbounds

	// 2.1 Endpoints: Tailscale embedded endpoint (ADR-0007)
	if opts.TailnetMode == tailnet.ModeEmbedded && opts.TailnetConfig != nil {
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
		configMap["endpoints"] = []map[string]any{tsEp}
	}

	// 3. DNS Configuration (ADR-0003, ADR-0007)
	dnsServers := []map[string]any{
		{
			"type":        "udp",
			"tag":         "bootstrap-dns",
			"server":      "223.5.5.5",
			"server_port": 53,
		},
		{
			"type":        "https",
			"tag":         "domestic-doh",
			"server":      "223.5.5.5",
			"server_port": 443,
			"path":        "/dns-query",
		},
		{
			"type":        "https",
			"tag":         "remote-doh",
			"server":      "1.1.1.1",
			"server_port": 443,
			"path":        "/dns-query",
			"detour":      "PROXY_POOL",
		},
	}

	var dnsRules []map[string]any
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

	dnsMap := map[string]any{
		"servers": dnsServers,
		"final":   "remote-doh",
	}
	if len(dnsRules) > 0 {
		dnsMap["rules"] = dnsRules
	}
	configMap["dns"] = dnsMap

	// 4. Routing configuration
	var siteTags, ipTags []string
	for _, r := range opts.Rules {
		siteTags = append(siteTags, r.GeoSite...)
		ipTags = append(ipTags, r.GeoIP...)
	}

	ruleSets := geodata.BuildRuleSets(opts.GeoSiteDB, opts.GeoIPDB, siteTags, ipTags)

	var singRules []map[string]any

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

	// 4.2 Blocker rules: denylist domains route to block (evaluated after Tailnet to allow bypass)
	if opts.Blocker != nil {
		deny := opts.Blocker.GetDenylist()
		if len(deny) > 0 {
			singRules = append(singRules, map[string]any{
				"domain_suffix": deny,
				"outbound":      "block",
			})
		}
	}

	// 4.3 User rules
	for _, r := range opts.Rules {
		if !r.Enabled {
			continue
		}

		outbound := "direct"
		switch r.Action.Type {
		case routing.ActionDirect:
			outbound = "direct"
		case routing.ActionBlock:
			outbound = "block"
		case routing.ActionProxyPool:
			outbound = "PROXY_POOL"
		case routing.ActionProxyTag:
			tag := r.Action.Tag
			if len(r.Action.Tags) > 0 {
				tag = r.Action.Tags[0]
			}
			outbound = "PROXY_TAG:" + tag
		case routing.ActionProxyService:
			outbound = "node-" + r.Action.ServiceID
		case routing.ActionTailnet, routing.ActionTailnetExit:
			if opts.TailnetMode == tailnet.ModeHost {
				outbound = "direct"
			} else {
				outbound = "tailscale-ep"
			}
		}

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
				rsets = append(rsets, "geosite-"+strings.ToLower(strings.TrimSpace(gs)))
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

	finalOutbound := "direct"
	if opts.FinalAction != "" {
		if strings.EqualFold(opts.FinalAction, "proxy") || strings.EqualFold(opts.FinalAction, "proxy_pool") {
			finalOutbound = "PROXY_POOL"
		} else if strings.EqualFold(opts.FinalAction, "block") {
			finalOutbound = "block"
		}
	}

	routeMap := map[string]any{
		"rules":                 singRules,
		"final":                 finalOutbound,
		"auto_detect_interface": true,
	}

	// Encode ruleSets into JSON for unmarshaling
	configMap["route"] = routeMap

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
