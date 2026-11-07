package boxengine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"naive-client/internal/blocker"
	"naive-client/internal/config"
	"naive-client/internal/geodata"
	"naive-client/internal/routing"
	"naive-client/internal/telemetry"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

// EngineOptions configures the embedded sing-box engine.
type EngineOptions struct {
	ListenAddr     string
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

	// Build custom outbound registry that includes PoolOutbound
	outboundReg := include.OutboundRegistry()
	type poolOption struct {
		PoolTag string `json:"pool_tag,omitempty"`
	}
	outbound.Register[poolOption](outboundReg, "pool", func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, pOpts poolOption) (adapter.Outbound, error) {
		return NewPoolOutbound(PoolOutboundOptions{
			Tag:            tag,
			PoolTag:        pOpts.PoolTag,
			Tracker:        eng.tracker,
			FailureMonitor: eng.failureMonitor,
			NodeProvider:   eng,
		}), nil
	})

	boxCtx := box.Context(
		ctx,
		include.InboundRegistry(),
		outboundReg,
		include.EndpointRegistry(),
		include.DNSTransportRegistry(),
		include.ServiceRegistry(),
		include.CertificateProviderRegistry(),
	)

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

func (e *Engine) buildConfig(ctx context.Context, opts EngineOptions, host string, port int) (*option.Options, error) {
	configMap := make(map[string]any)

	configMap["log"] = map[string]any{
		"level": "warn",
	}

	// 1. Inbound: mixed (HTTP + SOCKS5)
	configMap["inbounds"] = []map[string]any{
		{
			"type":        "mixed",
			"tag":         "mixed-in",
			"listen":      host,
			"listen_port": port,
		},
	}

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

	// 3. DNS Configuration (ADR-0003)
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
	configMap["dns"] = map[string]any{
		"servers": dnsServers,
		"final":   "remote-doh",
	}

	// 4. Routing configuration
	var siteTags, ipTags []string
	for _, r := range opts.Rules {
		siteTags = append(siteTags, r.GeoSite...)
		ipTags = append(ipTags, r.GeoIP...)
	}

	ruleSets := geodata.BuildRuleSets(opts.GeoSiteDB, opts.GeoIPDB, siteTags, ipTags)

	var singRules []map[string]any

	// Blocker rules: denylist domains route to block
	if opts.Blocker != nil {
		deny := opts.Blocker.GetDenylist()
		if len(deny) > 0 {
			singRules = append(singRules, map[string]any{
				"domain_suffix": deny,
				"outbound":      "block",
			})
		}
	}

	// User rules
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
		"rules": singRules,
		"final": finalOutbound,
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
