package boxengine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"naive-client/internal/blocker"
	"naive-client/internal/config"
	"naive-client/internal/geodata"
	"naive-client/internal/routing"
	"naive-client/internal/tailnet"
	"naive-client/internal/telemetry"
	"naive-client/internal/tunhelper"
	"naive-client/internal/warp"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
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
	NodeIPResolver     func(host string) []net.IP
	PreferIPv4         bool
	DNSStrategy        string
	DNSOptimisticCache bool
	ActiveIDs          map[string]bool
	OnDemandStart     func(poolTag string)
	OnTelemetryUpdate func()

	// Tailnet integration (ADR-0007)
	TailnetConfig         *tailnet.Config
	TailnetMode           tailnet.Mode
	TailnetHostExcludes   []string
	TailnetMagicDNSSuffix string
	TailnetHostRecords    map[string][]string
	TailnetHostInterface  string
	StateDir              string

	// Cloudflare integration (WARP egress & Tunnel ingress)
	CloudflareConfig          *warp.Config
	EndpointSelector          *warp.EndpointSelector
	OnCloudflareAccountUpdate func(warp.Account)

	// Logging configuration
	LogLevel string
	OnLog    func(level, message string)
}

var (
	ansiEscapeRegex   = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	singBoxPrefixExpr = regexp.MustCompile(`^(?:PANIC|FATAL|ERROR|WARN|INFO|DEBUG|TRACE)\[\d+\]\s*`)
)

func parseSingBoxLogLevel(level string) (string, log.Level) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug", "trace":
		return "debug", log.LevelDebug
	case "info":
		return "info", log.LevelInfo
	case "warn", "warning", "":
		return "warn", log.LevelWarn
	case "error", "fatal", "panic":
		return "error", log.LevelError
	default:
		return "warn", log.LevelWarn
	}
}

func cleanSingBoxLogMessage(msg string) string {
	clean := ansiEscapeRegex.ReplaceAllString(msg, "")
	clean = strings.TrimSpace(clean)
	clean = singBoxPrefixExpr.ReplaceAllString(clean, "")
	return strings.TrimSpace(clean)
}

type boxPlatformWriter struct {
	maxLevel atomic.Uint32
	onLog    func(level, message string)
}

func newBoxPlatformWriter(maxLevel log.Level, onLog func(level, message string)) *boxPlatformWriter {
	if onLog == nil {
		return nil
	}
	w := &boxPlatformWriter{onLog: onLog}
	w.maxLevel.Store(uint32(maxLevel))
	return w
}

func (w *boxPlatformWriter) DisableColors() bool {
	return true
}

func (w *boxPlatformWriter) WriteMessage(level log.Level, message string) {
	if w == nil || w.onLog == nil {
		return
	}
	if uint32(level) > w.maxLevel.Load() {
		return
	}
	clean := cleanSingBoxLogMessage(message)
	if clean == "" {
		return
	}
	lvlStr := strings.ToUpper(log.FormatLevel(level))
	w.onLog(lvlStr, clean)
}

// Engine manages the embedded sing-box instance (*box.Box) with dynamic node pools and telemetry.
type Engine struct {
	lifecycleMu       sync.Mutex
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
	staticInfraDomains map[string]bool
	nodeInfraDomains   map[string]bool
	onDemandStart      func(poolTag string)
	onTelemetryUpdate         func()
	onCloudflareAccountUpdate func(warp.Account)
	cloudflareConfig          *warp.Config
	endpointSelector      *warp.EndpointSelector
	tailnetMode           tailnet.Mode
	tailnetMagicDNSSuffix string
	tailnetHostRecords    map[string][]string
	logLevel              string
	logWriter             *boxPlatformWriter
	preferIPv4            bool
	dnsStrategy           string
	boxCtx                context.Context
	cancel            context.CancelFunc
	closersMu         sync.Mutex
	closers           []func() error
}

func (e *Engine) registerCloser(fn func() error) {
	if e == nil || fn == nil {
		return
	}
	e.closersMu.Lock()
	e.closers = append(e.closers, fn)
	e.closersMu.Unlock()
}

func (e *Engine) closeRegisteredClosers() {
	if e == nil {
		return
	}
	e.closersMu.Lock()
	closers := e.closers
	e.closers = nil
	e.closersMu.Unlock()
	for i := len(closers) - 1; i >= 0; i-- {
		_ = closers[i]()
	}
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

	cfCfg := &warp.Config{}
	if opts.CloudflareConfig != nil {
		*cfCfg = *opts.CloudflareConfig
		cfCfg.Account = cloneWarpAccount(cfCfg.Account)
	}

	normLvl, parsedLvl := parseSingBoxLogLevel(opts.LogLevel)
	eng := &Engine{
		port:                      listenPort,
		addr:                      fmt.Sprintf("%s:%d", listenHost, listenPort),
		services:                  opts.Services,
		allocatedPorts:            allocated,
		activeIDs:                 opts.ActiveIDs,
		tracker:                   opts.Tracker,
		failureMonitor:            opts.FailureMonitor,
		blocker:                   opts.Blocker,
		staticInfraDomains:        collectStaticInfraDomains(opts),
		nodeInfraDomains:          collectNodeInfraDomains(opts.Services),
		onDemandStart:             opts.OnDemandStart,
		onTelemetryUpdate:         opts.OnTelemetryUpdate,
		onCloudflareAccountUpdate: opts.OnCloudflareAccountUpdate,
		cloudflareConfig:          cfCfg,
		endpointSelector:          opts.EndpointSelector,
		tailnetMode:               opts.TailnetMode,
		tailnetMagicDNSSuffix:     opts.TailnetMagicDNSSuffix,
		tailnetHostRecords:        opts.TailnetHostRecords,
		logLevel:                  normLvl,
		logWriter:                 newBoxPlatformWriter(parsedLvl, opts.OnLog),
		preferIPv4:                opts.PreferIPv4,
		dnsStrategy:               effectiveDNSStrategy(opts),
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
		eng.closeRegisteredClosers()
		cancel()
		return nil, fmt.Errorf("build sing-box options: %w", err)
	}

	b, err := box.New(box.Options{
		Context: boxCtx,
		Options: *boxOpts,
	})
	if err != nil {
		eng.closeRegisteredClosers()
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
	if eng.logWriter != nil && b.LogFactory() != nil {
		b.LogFactory().AttachPlatformWriter(eng.logWriter)
		b.LogFactory().SetLevel(parsedLvl)
	}
	if eng.blocker != nil {
		eng.connTracker = &BlockerConnectionTracker{
			blocker:            eng.blocker,
			nodeNameResolver:   eng.GetNodeName,
			chainedWarpChecker: eng.IsChainedWarp,
		}
		b.Router().AppendTracker(eng.connTracker)
		eng.blocker.SetOnUpdate(eng.ClearDNSCache)
	}

	eng.box = b
	return eng, nil
}

func trackOutboundCloser(eng *Engine, ob adapter.Outbound, err error) (adapter.Outbound, error) {
	if err == nil && eng != nil {
		if c, ok := ob.(io.Closer); ok {
			eng.registerCloser(c.Close)
		}
	}
	return ob, err
}

func createBoxContext(ctx context.Context, eng *Engine) context.Context {
	outboundReg := include.OutboundRegistry()
	type poolOption struct {
		PoolTag        string              `json:"pool_tag,omitempty"`
		Targets        []routing.TargetRef `json:"targets,omitempty"`
		DispatchPolicy string              `json:"dispatch_policy,omitempty"`
		FallbackToPool bool                `json:"fallback_to_pool,omitempty"`
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
			Targets:           pOpts.Targets,
			DispatchPolicy:    pOpts.DispatchPolicy,
			FallbackToPool:    pOpts.FallbackToPool,
			Tracker:           tracker,
			FailureMonitor:    fm,
			NodeProvider:      np,
			OnTelemetryUpdate: telemetryUpdate,
			Blocker:           bl,
		}), nil
	})

	outbound.Register[warpMasqueOptions](outboundReg, "masque", func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, mOpts warpMasqueOptions) (adapter.Outbound, error) {
		ob, err := newWarpMasqueOutbound(ctx, router, logger, tag, mOpts, eng)
		return trackOutboundCloser(eng, ob, err)
	})
	outbound.Register[warpAutoWireGuardOptions](outboundReg, "warp-wg-auto", func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, wgOpts warpAutoWireGuardOptions) (adapter.Outbound, error) {
		ob, err := newWarpAutoWireGuardOutbound(ctx, router, logger, tag, wgOpts, eng)
		return trackOutboundCloser(eng, ob, err)
	})

	var finalOutboundReg adapter.OutboundRegistry = outboundReg
	if eng != nil && (eng.blocker != nil || eng.failureMonitor != nil) {
		finalOutboundReg = &blockerOutboundRegistry{
			underlying: outboundReg,
			blocker:    eng.blocker,
			fm:         eng.failureMonitor,
			provider:   eng,
		}
	}

	dnsReg := include.DNSTransportRegistry()
	var finalDNSReg adapter.DNSTransportRegistry = dnsReg
	if eng != nil && (eng.blocker != nil || eng.failureMonitor != nil || eng.tailnetMode == tailnet.ModeHost) {
		finalDNSReg = &blockerTransportRegistry{
			underlying:         dnsReg,
			blocker:            eng.blocker,
			fm:                 eng.failureMonitor,
			tailnetSuffix:      eng.tailnetMagicDNSSuffix,
			tailnetHostRecords: eng.tailnetHostRecords,
			skipDomain:         eng.IsInfrastructureDomain,
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
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()

	e.mu.RLock()
	b := e.box
	e.mu.RUnlock()
	if b == nil {
		return errors.New("engine is closed")
	}
	return b.Start()
}

// Close gracefully closes the embedded engine.
func (e *Engine) Close() error {
	e.mu.Lock()
	cancel := e.cancel
	e.cancel = nil
	e.mu.Unlock()
	if cancel != nil {
		cancel()
	}

	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()

	e.mu.Lock()
	b := e.box
	e.box = nil
	e.mu.Unlock()

	var err error
	if b != nil {
		err = b.Close()
	}
	e.closeRegisteredClosers()
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

// SetLogLevel dynamically updates the embedded sing-box log level without restarting the engine.
func (e *Engine) SetLogLevel(level string) {
	normLvl, parsedLvl := parseSingBoxLogLevel(level)
	e.mu.Lock()
	e.logLevel = normLvl
	if e.logWriter != nil {
		e.logWriter.maxLevel.Store(uint32(parsedLvl))
	}
	b := e.box
	e.mu.Unlock()
	if b != nil && b.LogFactory() != nil {
		b.LogFactory().SetLevel(parsedLvl)
	}
}

func isSidecarService(svc config.Service) bool {
	if svc.EffectiveKind() == config.KindExternalProxy {
		return false
	}
	if svc.Protocol == config.ProtoNaive {
		return true
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
	e.nodeInfraDomains = collectNodeInfraDomains(services)
	if allocatedPorts != nil {
		e.allocatedPorts = allocatedPorts
	}
	if activeIDs != nil {
		e.activeIDs = activeIDs
	}
}

// IsInfrastructureDomain reports whether domain is a configured proxy node server
// or DNS/bootstrap infrastructure host whose DNS queries should bypass blocker rules and Insights logs.
func (e *Engine) IsInfrastructureDomain(domain string) bool {
	if e == nil {
		return false
	}
	norm := tailnet.NormalizeHost(domain)
	if norm == "" {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.staticInfraDomains[norm] || e.nodeInfraDomains[norm]
}

func extractInfraHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
		raw = u.Hostname()
	} else if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = tailnet.NormalizeHost(raw)
	if raw == "" || net.ParseIP(raw) != nil {
		return ""
	}
	return raw
}

func collectStaticInfraDomains(opts EngineOptions) map[string]bool {
	set := make(map[string]bool)
	sources := [][]string{
		opts.BootstrapDomains,
		opts.DomesticDoH,
		opts.BootstrapDNS,
		opts.RemoteDoH,
		DefaultDomesticDoH,
		DefaultBootstrapDNS,
		DefaultRemoteDoH,
	}
	for _, list := range sources {
		for _, raw := range list {
			if host := extractInfraHost(raw); host != "" {
				set[host] = true
			}
		}
	}
	return set
}

func collectNodeInfraDomains(services []config.Service) map[string]bool {
	set := make(map[string]bool)
	add := func(raw string) {
		if host := extractInfraHost(raw); host != "" {
			set[host] = true
		}
	}
	for _, svc := range services {
		add(svc.Server)
		for _, proxyURI := range svc.Proxies {
			add(proxyURI)
		}
		add(svc.ExternalURI)
		if svc.WARPConfig != nil {
			add(svc.WARPConfig.Endpoint)
		}
	}
	return set
}

// GetCandidates implements NodeProvider.
func (e *Engine) GetCandidates(poolTag string) []string {
	cleanTag := strings.TrimSpace(poolTag)
	cleanTag = strings.TrimPrefix(cleanTag, "PROXY_TAG:")

	e.mu.RLock()
	candidates := e.findCandidates(cleanTag, true)
	e.mu.RUnlock()

	if len(candidates) == 0 && e.onDemandStart != nil {
		e.onDemandStart(cleanTag)
		e.mu.RLock()
		candidates = e.findCandidates(cleanTag, true)
		e.mu.RUnlock()
	}

	return candidates
}

// AllCandidates returns all configured candidate IDs matching poolTag regardless of active/sidecar state.
func (e *Engine) AllCandidates(poolTag string) []string {
	cleanTag := strings.TrimSpace(poolTag)
	cleanTag = strings.TrimPrefix(cleanTag, "PROXY_TAG:")

	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.findCandidates(cleanTag, false)
}

func (e *Engine) findCandidates(cleanTag string, activeOnly bool) []string {
	if strings.HasPrefix(cleanTag, "node:") {
		targetID := strings.TrimSpace(strings.TrimPrefix(cleanTag, "node:"))
		if targetID == "" {
			return nil
		}
		for _, svc := range e.services {
			if svc.ID != targetID {
				continue
			}
			if activeOnly {
				if e.activeIDs != nil && !e.activeIDs[svc.ID] {
					return nil
				}
				if isSidecarService(svc) && e.allocatedPorts[svc.ID] <= 0 {
					return nil
				}
			}
			return []string{svc.ID}
		}
		return nil
	}

	var wantTags []string
	for _, part := range strings.Split(cleanTag, ",") {
		if p := strings.TrimSpace(part); p != "" {
			wantTags = append(wantTags, p)
		}
	}

	var candidates []string
	for _, svc := range e.services {
		if activeOnly {
			if e.activeIDs != nil && !e.activeIDs[svc.ID] {
				continue
			}
			if isSidecarService(svc) && e.allocatedPorts[svc.ID] <= 0 {
				continue
			}
		}

		if cleanTag == "" || cleanTag == "PROXY_POOL" || len(wantTags) == 0 {
			if svc.IsBuiltinWarp() {
				continue
			}
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

type poolSpec struct {
	OutboundTag    string
	PoolTag        string
	Targets        []routing.TargetRef
	DispatchPolicy string
	FallbackToPool bool
	IsPool         bool
}

func shortSpecHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:10]
}

func buildCanonicalPoolTag(targets []routing.TargetRef, policy string, fallback bool) string {
	if len(targets) == 1 && targets[0].Kind == routing.TargetNode && policy == routing.DispatchSmart && !fallback {
		return "POOL:node:" + targets[0].Value
	}
	var b strings.Builder
	b.WriteString(policy)
	if fallback {
		b.WriteString("+pool")
	}
	for _, t := range targets {
		b.WriteByte('|')
		b.WriteString(string(t.Kind))
		b.WriteByte('=')
		b.WriteString(t.Value)
	}
	return "POOL:" + shortSpecHash(b.String())
}

func remoteDoHTagForOutbound(outboundTag string) string {
	return "remote-doh-" + shortSpecHash(outboundTag)
}

func resolvePoolSpec(act routing.RouteAction, tailnetMode tailnet.Mode) poolSpec {
	switch act.Type {
	case routing.ActionDirect:
		return poolSpec{OutboundTag: "direct"}
	case routing.ActionBlock:
		return poolSpec{OutboundTag: "block"}
	case routing.ActionTailnet, routing.ActionTailnetExit:
		if tailnetMode == tailnet.ModeHost {
			return poolSpec{OutboundTag: "direct"}
		}
		return poolSpec{OutboundTag: "tailscale-ep"}
	}

	if !act.IsProxyAction() {
		return poolSpec{OutboundTag: "direct"}
	}

	targets := act.NormalizedTargets()
	policy := act.EffectiveDispatchPolicy()
	fallback := act.FallbackToPool

	if len(targets) == 0 {
		return poolSpec{OutboundTag: "PROXY_POOL", IsPool: true}
	}

	allTags := true
	var tagVals []string
	for _, t := range targets {
		if t.Kind != routing.TargetTag {
			allTags = false
			break
		}
		tagVals = append(tagVals, t.Value)
	}
	if allTags && policy == routing.DispatchSmart && !fallback {
		if joined := joinCleanTags(tagVals); joined != "" {
			return poolSpec{
				OutboundTag:    "PROXY_TAG:" + joined,
				PoolTag:        joined,
				Targets:        targets,
				DispatchPolicy: policy,
				IsPool:         true,
			}
		}
		return poolSpec{OutboundTag: "PROXY_POOL", IsPool: true}
	}

	return poolSpec{
		OutboundTag:    buildCanonicalPoolTag(targets, policy, fallback),
		Targets:        targets,
		DispatchPolicy: policy,
		FallbackToPool: fallback,
		IsPool:         true,
	}
}

func resolveRouteOutbound(act routing.RouteAction, tailnetMode tailnet.Mode) string {
	return resolvePoolSpec(act, tailnetMode).OutboundTag
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
	if e.box.Endpoint() != nil {
		if ep, ok := e.box.Endpoint().Get("node-" + nodeID); ok {
			return ep, true
		}
	}
	cleanID := strings.TrimPrefix(nodeID, "node-")
	if ob, ok := e.box.Outbound().Outbound("node-" + cleanID); ok {
		return ob, true
	}
	if e.box.Endpoint() != nil {
		if ep, ok := e.box.Endpoint().Get("node-" + cleanID); ok {
			return ep, true
		}
	}
	if ob, ok := e.box.Outbound().Outbound(nodeID); ok {
		return ob, true
	}
	if e.box.Endpoint() != nil {
		if ep, ok := e.box.Endpoint().Get(nodeID); ok {
			return ep, true
		}
	}
	return nil, false
}

// ResolveWarpDomain resolves domain destinations inside the tunnel for static explicit-endpoint
// WireGuard WARP outbounds so domains do not fall back to dnsRouter/host resolvers.
func (e *Engine) ResolveWarpDomain(ctx context.Context, nodeID string, ob adapter.Outbound, dest M.Socksaddr) (M.Socksaddr, error) {
	if !dest.IsDomain() {
		return dest, nil
	}
	cleanID := strings.TrimPrefix(nodeID, "node-")
	if !e.isWarpNode(cleanID) {
		return dest, nil
	}
	_, isMasque := common.Cast[*warpMasqueOutbound](ob)
	_, isAutoWG := common.Cast[*warpAutoWireGuardOutbound](ob)
	if isMasque || isAutoWG {
		return dest, nil
	}
	e.mu.RLock()
	boxCtx := e.boxCtx
	e.mu.RUnlock()
	rCtx, rCancel := deriveLifecycleContext(ctx, boxCtx, 0)
	ip, rErr := resolveWarpDomainViaDoH(rCtx, e, boxCtx, "node-"+cleanID, e.IsChainedWarp(cleanID), ob, dest.Fqdn, true, true)
	rCancel()
	if rErr != nil {
		return dest, rErr
	}
	return M.SocksaddrFrom(ip, dest.Port), nil
}

func (e *Engine) resetWarpRemoteDoHTransport(warpOutboundTag string) {
	if e == nil {
		return
	}
	e.mu.RLock()
	boxCtx := e.boxCtx
	e.mu.RUnlock()
	if boxCtx == nil {
		return
	}
	transportMgr := service.FromContext[adapter.DNSTransportManager](boxCtx)
	if transportMgr == nil {
		return
	}
	baseTag := strings.TrimPrefix(warpOutboundTag, "wg-")
	for _, tag := range []string{
		remoteDoHTagForOutbound(baseTag),
		remoteDoHTagForOutbound(warpOutboundTag),
	} {
		if tr, ok := transportMgr.Transport(tag); ok && tr != nil {
			tr.Reset()
		}
		if baseTag == warpOutboundTag {
			break
		}
	}
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
	if e.blocker != nil && dest.IsDomain() && e.blocker.ShouldBlock(dest.Fqdn) {
		return nil, syscall.EPERM
	}
	isWarp := e.isWarpNode(cleanID)
	var err error
	if isWarp {
		dest, err = e.ResolveWarpDomain(ctx, cleanID, ob, dest)
	}
	var conn net.Conn
	if err == nil {
		conn, err = ob.DialContext(ctx, network, dest)
	}
	if err != nil && isWarp {
		if (ctx != nil && errors.Is(ctx.Err(), context.Canceled)) || errors.Is(err, context.Canceled) || errors.Is(err, warp.ErrNoDNSRecords) {
			return nil, err
		}
		errLower := strings.ToLower(err.Error())
		if !strings.Contains(errLower, "warp server") &&
			(strings.Contains(errLower, "not registered") ||
				strings.Contains(errLower, "凭证未注册") ||
				strings.Contains(errLower, "detour outbound") ||
				strings.Contains(errLower, "masque") ||
				strings.Contains(errLower, "wireguard")) {
			ep := e.getWarpEndpoint(cleanID)
			return nil, fmt.Errorf("warp server (%s) connection failed: %w", ep, err)
		}
	}
	return conn, err
}

// IsChainedWarp reports whether nodeID is a non-WARP proxy node with EnableWARP enabled.
func (e *Engine) IsChainedWarp(nodeID string) bool {
	return e.isChainedWarpNode(nodeID)
}

func (e *Engine) isWarpNode(nodeID string) bool {
	cleanID := strings.TrimPrefix(nodeID, "node-")
	if cleanID == config.BuiltinWarpServiceID {
		return true
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, svc := range e.services {
		if svc.ID == cleanID {
			return svc.EffectiveProtocol() == config.ProtoWARP || svc.EnableWARP
		}
	}
	return false
}

func (e *Engine) isChainedWarpNode(nodeID string) bool {
	cleanID := strings.TrimPrefix(nodeID, "node-")
	if cleanID == config.BuiltinWarpServiceID {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, svc := range e.services {
		if svc.ID == cleanID {
			return svc.EffectiveProtocol() != config.ProtoWARP && svc.EnableWARP
		}
	}
	return false
}

func (e *Engine) getWarpEndpoint(nodeID string) string {
	cleanID := strings.TrimPrefix(nodeID, "node-")
	if ob, ok := e.GetOutbound(cleanID); ok {
		type activeEndpointProvider interface {
			ActiveEndpoint() string
		}
		if p, ok := common.Cast[activeEndpointProvider](ob); ok {
			if ep := strings.TrimSpace(p.ActiveEndpoint()); ep != "" {
				return ep
			}
		}
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, svc := range e.services {
		if svc.ID == cleanID {
			mode := ResolveServiceWarpMode(svc, e.cloudflareConfig)
			if ep := resolveExplicitWarpEndpoint(svc, e.cloudflareConfig, mode); ep != "" {
				return ep
			}
			return "auto"
		}
	}
	if e.cloudflareConfig != nil && strings.TrimSpace(e.cloudflareConfig.CleanIP) != "" {
		host, port := e.cloudflareConfig.ResolveEndpoint(warp.ModeAuto)
		return net.JoinHostPort(host, strconv.Itoa(port))
	}
	return "auto"
}

// IsSidecar implements NodeProvider.
func (e *Engine) IsSidecar(nodeID string) bool {
	cleanID := strings.TrimPrefix(nodeID, "node-")
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, svc := range e.services {
		if svc.ID == cleanID {
			if isSidecarService(svc) {
				return true
			}
			if svc.EffectiveKind() == config.KindExternalProxy && svc.ExternalURI != "" {
				if u, err := url.Parse(svc.ExternalURI); err == nil {
					host := strings.ToLower(strings.TrimSpace(u.Hostname()))
					if host == "127.0.0.1" || host == "localhost" || host == "::1" {
						return true
					}
				}
			}
			return false
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

// extractNodeExcludeAddresses extracts IP addresses from ALL nodes (both native and sidecar) as CIDR strings
// to populate route_exclude_address, preventing node routing loops through sing-tun.
func extractNodeExcludeAddresses(services []config.Service, resolver func(host string) []net.IP) []string {
	var results []string
	seen := make(map[string]bool)
	var mu sync.Mutex

	addIP := func(ip net.IP) {
		var cidr string
		if ip4 := ip.To4(); ip4 != nil {
			cidr = ip4.String() + "/32"
		} else if ip16 := ip.To16(); ip16 != nil {
			cidr = ip16.String() + "/128"
		}
		if cidr != "" {
			mu.Lock()
			if !seen[cidr] {
				seen[cidr] = true
				results = append(results, cidr)
			}
			mu.Unlock()
		}
	}

	var pendingHosts []string
	seenHosts := make(map[string]bool)

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
		lower := strings.ToLower(host)
		if !seenHosts[lower] {
			seenHosts[lower] = true
			pendingHosts = append(pendingHosts, host)
		}
	}

	for _, svc := range services {
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
		if svc.WARPConfig != nil && svc.WARPConfig.Endpoint != "" {
			addHost(svc.WARPConfig.Endpoint)
		}
	}

	if resolver != nil && len(pendingHosts) > 0 {
		var wg sync.WaitGroup
		sem := make(chan struct{}, 8)
		for _, host := range pendingHosts {
			wg.Add(1)
			go func(h string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				for _, ip := range resolver(h) {
					addIP(ip)
				}
			}(host)
		}
		wg.Wait()
	}

	return results
}

func defaultNodeIPResolver() func(host string) []net.IP {
	var cacheMu sync.Mutex
	cache := make(map[string][]net.IP)
	return func(h string) []net.IP {
		key := strings.ToLower(strings.TrimSpace(h))
		cacheMu.Lock()
		if ips, ok := cache[key]; ok {
			cacheMu.Unlock()
			return ips
		}
		cacheMu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		defer cancel()
		ips, _ := net.DefaultResolver.LookupIP(ctx, "ip", h)
		if len(ips) == 0 {
			r := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{Timeout: 1000 * time.Millisecond}
					return d.DialContext(ctx, "udp", "223.5.5.5:53")
				},
			}
			ips, _ = r.LookupIP(ctx, "ip", h)
		}

		cacheMu.Lock()
		cache[key] = ips
		cacheMu.Unlock()
		return ips
	}
}

func resolveNodeExcludes(opts EngineOptions) []string {
	resolver := opts.NodeIPResolver
	if resolver == nil {
		base := defaultNodeIPResolver()
		resolver = func(h string) []net.IP {
			if tailnet.IsTailnetHostname(opts.TailnetMode, h, opts.TailnetMagicDNSSuffix) {
				if len(opts.TailnetHostRecords) > 0 {
					norm := tailnet.NormalizeHost(h)
					rawIPs := opts.TailnetHostRecords[norm]
					if len(rawIPs) == 0 && !strings.Contains(norm, ".") {
						if sfx := tailnet.NormalizeHost(opts.TailnetMagicDNSSuffix); sfx != "" {
							rawIPs = opts.TailnetHostRecords[norm+"."+sfx]
						}
					}
					var parsed []net.IP
					for _, rawIP := range rawIPs {
						if ip := net.ParseIP(strings.TrimSpace(rawIP)); ip != nil {
							parsed = append(parsed, ip)
						}
					}
					if len(parsed) > 0 {
						return parsed
					}
				}
				return nil
			}
			return base(h)
		}
	}
	raw := extractNodeExcludeAddresses(opts.Services, resolver)
	if opts.TailnetMode != tailnet.ModeHost && opts.TailnetMode != tailnet.ModeEmbedded {
		return raw
	}
	filtered := make([]string, 0, len(raw))
	for _, exc := range raw {
		if tailnet.IsTailnetIPString(exc) {
			continue
		}
		filtered = append(filtered, exc)
	}
	return filtered
}

func tailnetDomainSuffixes(opts EngineOptions) []string {
	suffixes := []string{"ts.net"}
	if sfx := tailnet.NormalizeHost(opts.TailnetMagicDNSSuffix); sfx != "" && sfx != "ts.net" {
		suffixes = append(suffixes, sfx)
	}
	return suffixes
}

func buildTailnetRouteRules(opts EngineOptions) []map[string]any {
	var rules []map[string]any
	if opts.TailnetMode == tailnet.ModeHost {
		var tailnetCIDRs []string
		seen := make(map[string]bool)
		addCIDR := func(c string) {
			c = strings.TrimSpace(c)
			if c == "" || c == "0.0.0.0/0" || c == "::/0" || seen[c] {
				return
			}
			seen[c] = true
			tailnetCIDRs = append(tailnetCIDRs, c)
		}
		for _, c := range tailnet.DefaultTailnetSubnets {
			addCIDR(c)
		}
		for _, c := range opts.TailnetHostExcludes {
			addCIDR(c)
		}
		addCIDR("100.100.100.100/32")
		if len(tailnetCIDRs) > 0 {
			rules = append(rules, map[string]any{
				"ip_cidr":  tailnetCIDRs,
				"outbound": "tailnet-direct",
			})
		}
		rules = append(rules, map[string]any{
			"domain_suffix": tailnetDomainSuffixes(opts),
			"outbound":      "tailnet-direct",
		})
		rules = append(rules, map[string]any{
			"domain_regex": []string{`^[^.]+$`},
			"outbound":     "tailnet-direct",
		})
	} else if opts.TailnetMode == tailnet.ModeEmbedded && opts.TailnetConfig != nil {
		rules = append(rules, map[string]any{
			"domain_suffix": tailnetDomainSuffixes(opts),
			"outbound":      "tailscale-ep",
		})
		rules = append(rules, map[string]any{
			"domain_regex": []string{`^[^.]+$`},
			"outbound":     "tailscale-ep",
		})
		rules = append(rules, map[string]any{
			"ip_cidr":  append([]string{}, tailnet.DefaultTailnetSubnets...),
			"outbound": "tailscale-ep",
		})
	}
	return rules
}


func resolveFinalPoolSpec(opts EngineOptions) poolSpec {
	if opts.FinalRoute.Type != "" || len(opts.FinalRoute.Targets) > 0 {
		return resolvePoolSpec(opts.FinalRoute, opts.TailnetMode)
	}
	if opts.FinalAction != "" {
		fa := strings.TrimSpace(opts.FinalAction)
		if strings.EqualFold(fa, string(routing.ActionWarp)) {
			return resolvePoolSpec(routing.NewWarpTargetAction(), opts.TailnetMode)
		} else if strings.HasPrefix(strings.ToUpper(fa), "PROXY_TAG:") {
			tag := strings.TrimSpace(fa[len("PROXY_TAG:"):])
			if tag != "" {
				var tags []string
				for _, part := range strings.Split(tag, ",") {
					if p := strings.TrimSpace(part); p != "" {
						tags = append(tags, p)
					}
				}
				return resolvePoolSpec(routing.RouteAction{Type: routing.ActionProxyTag, Tags: tags}, opts.TailnetMode)
			}
			return poolSpec{OutboundTag: "PROXY_POOL", IsPool: true}
		} else if strings.HasPrefix(fa, "node-") {
			return resolvePoolSpec(routing.RouteAction{
				Type:      routing.ActionProxyService,
				ServiceID: strings.TrimPrefix(fa, "node-"),
			}, opts.TailnetMode)
		} else if strings.EqualFold(fa, "proxy") || strings.EqualFold(fa, "proxy_pool") || strings.EqualFold(fa, "proxy_tag") || strings.EqualFold(fa, "proxy_service") {
			return poolSpec{OutboundTag: "PROXY_POOL", IsPool: true}
		} else if strings.EqualFold(fa, "block") {
			return poolSpec{OutboundTag: "block"}
		}
	}
	return poolSpec{OutboundTag: "direct"}
}

func resolveFinalOutbound(opts EngineOptions) string {
	return resolveFinalPoolSpec(opts).OutboundTag
}

// collectDoHBootstrapDomains returns the hostnames of the DNS servers themselves
// (domestic DoH and bootstrap DNS). These must stay on bootstrap-dns: a server
// cannot resolve its own address through itself.
func collectDoHBootstrapDomains(opts EngineOptions) map[string]bool {
	set := make(map[string]bool)
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			raw = u.Hostname()
		} else if host, _, err := net.SplitHostPort(raw); err == nil {
			raw = host
		}
		raw = tailnet.NormalizeHost(raw)
		if raw != "" && net.ParseIP(raw) == nil {
			set[raw] = true
		}
	}
	for _, ep := range opts.DomesticDoH {
		add(ep)
	}
	for _, ep := range opts.BootstrapDNS {
		add(ep)
	}
	return set
}

func collectAllBootstrapDomains(opts EngineOptions) []string {
	bootstrapDomainSet := make(map[string]bool)
	addDomain := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			raw = u.Hostname()
		} else if host, _, err := net.SplitHostPort(raw); err == nil {
			raw = host
		}
		raw = tailnet.NormalizeHost(raw)
		if raw != "" && net.ParseIP(raw) == nil && !tailnet.IsTailnetHostname(opts.TailnetMode, raw, opts.TailnetMagicDNSSuffix) {
			bootstrapDomainSet[raw] = true
		}
	}

	for _, d := range opts.BootstrapDomains {
		addDomain(d)
	}
	for _, svc := range opts.Services {
		if svc.Server != "" {
			addDomain(svc.Server)
		}
		for _, proxyURI := range svc.Proxies {
			addDomain(proxyURI)
		}
		if svc.ExternalURI != "" {
			addDomain(svc.ExternalURI)
		}
	}
	for _, ep := range opts.DomesticDoH {
		addDomain(ep)
	}
	for _, ep := range opts.BootstrapDNS {
		addDomain(ep)
	}
	var allBootstrapDomains []string
	for d := range bootstrapDomainSet {
		allBootstrapDomains = append(allBootstrapDomains, d)
	}
	sort.Strings(allBootstrapDomains)
	return allBootstrapDomains
}

func loopbackInterfaceName() string {
	switch runtime.GOOS {
	case "darwin":
		return "lo0"
	case "linux":
		return "lo"
	default:
		return ""
	}
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

	if opts.CloudflareConfig != nil && opts.CloudflareConfig.Tunnel.Enabled && strings.TrimSpace(opts.CloudflareConfig.Tunnel.Token) != "" {
		tunnelIn := map[string]any{
			"type":  "cloudflared",
			"tag":   "cloudflare-tunnel-in",
			"token": strings.TrimSpace(opts.CloudflareConfig.Tunnel.Token),
		}
		if proto := strings.ToLower(strings.TrimSpace(opts.CloudflareConfig.Tunnel.Protocol)); proto != "" && proto != "auto" {
			tunnelIn["protocol"] = proto
		}
		if opts.CloudflareConfig.Tunnel.HAConnections > 0 {
			tunnelIn["ha_connections"] = opts.CloudflareConfig.Tunnel.HAConnections
		}
		if opts.CloudflareConfig.Tunnel.PostQuantum {
			tunnelIn["post_quantum"] = true
		}
		inbounds = append(inbounds, tunnelIn)
	}

	if opts.TrafficMode == "tun" {
		tunAddrs := opts.TunAddresses
		if len(tunAddrs) == 0 {
			tunAddrs = []string{tunhelper.TunIPv4Prefix, tunhelper.TunIPv6Prefix}
		}
		mtu := opts.TunMTU
		if mtu <= 0 {
			mtu = 9000
		}
		isWindows := runtime.GOOS == "windows"
		tunIn := map[string]any{
			"type":         "tun",
			"tag":          "tun-in",
			"address":      tunAddrs,
			"mtu":          mtu,
			"auto_route":   isWindows,
			"strict_route": isWindows,
			"stack":        "system",
			"dns_address":  []string{tunhelper.DNSAddress},
		}
		if isWindows {
			// On Windows, setting dns_mode to "hijack" combined with strict_route installs
			// WFP (Windows Filtering Platform) filters to block non-TUN port 53 outbound queries,
			// preventing SMHNR (Smart Multi-Homed Name Resolution) from leaking DNS queries to
			// other physical or virtual network adapters.
			tunIn["dns_mode"] = "hijack"
		}
		if opts.TunInterface != "" {
			tunIn["interface_name"] = opts.TunInterface
		}
		excludes := resolveNodeExcludes(opts)
		// Exclude loopback addresses from TUN capture so 127.0.0.1 is never trapped in TUN
		excludes = append(excludes, "127.0.0.0/8", "::1/128")
		// Exclude Cloudflare WARP Anycast endpoints so local WARP clients do not loop into TUN
		excludes = append(excludes,
			"162.159.192.0/24",
			"162.159.193.0/24",
			"162.159.195.0/24",
			"162.159.198.0/24",
			"162.159.200.0/24",
			"162.159.204.0/24",
			"188.114.96.0/22",
		)
		if opts.TailnetMode == tailnet.ModeHost {
			tailnetExcludes := append([]string{}, tailnet.DefaultTailnetSubnets...)
			tailnetExcludes = append(tailnetExcludes, opts.TailnetHostExcludes...)
			tailnetExcludes = append(tailnetExcludes, "100.100.100.100/32")
			for _, te := range tailnetExcludes {
				te = strings.TrimSpace(te)
				if te != "" && te != "0.0.0.0/0" && te != "::/0" {
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
	// Outbound interface selection is left to route.auto_detect_interface, which
	// follows network changes (Wi-Fi/Ethernet switch, wake) instead of a stale bind.
	directOut := map[string]any{
		"type": "direct",
		"tag":  "direct",
	}

	loopbackOut := map[string]any{
		"type": "direct",
		"tag":  "loopback-direct",
	}
	if ifName := loopbackInterfaceName(); ifName != "" {
		loopbackOut["bind_interface"] = ifName
	}

	tailnetHostIf := strings.TrimSpace(opts.TailnetHostInterface)
	if tailnetHostIf == "" {
		tailnetHostIf = tailnet.DetectHostInterface()
	}

	tailnetDirectOut := map[string]any{
		"type": "direct",
		"tag":  "tailnet-direct",
		// A non-zero dial option keeps this outbound from being "empty", otherwise it
		// cannot be used as a DNS server detour (tailscale-host-dns).
		"connect_timeout": "10s",
	}
	if tailnetHostIf != "" {
		tailnetDirectOut["bind_interface"] = tailnetHostIf
	}

	outbounds := []map[string]any{
		directOut,
		loopbackOut,
		tailnetDirectOut,
		{
			"type": "block",
			"tag":  "block",
		},
		{
			"type": "pool",
			"tag":  "PROXY_POOL",
		},
	}

	poolOutboundSet := map[string]bool{"PROXY_POOL": true}
	ensurePoolSpec := func(spec poolSpec) {
		if !spec.IsPool || spec.OutboundTag == "" || poolOutboundSet[spec.OutboundTag] {
			return
		}
		poolOutboundSet[spec.OutboundTag] = true
		ob := map[string]any{
			"type": "pool",
			"tag":  spec.OutboundTag,
		}
		if spec.PoolTag != "" {
			ob["pool_tag"] = spec.PoolTag
		}
		if len(spec.Targets) > 0 {
			ob["targets"] = spec.Targets
		}
		if spec.DispatchPolicy != "" && spec.DispatchPolicy != routing.DispatchSmart {
			ob["dispatch_policy"] = spec.DispatchPolicy
		}
		if spec.FallbackToPool {
			ob["fallback_to_pool"] = true
		}
		outbounds = append(outbounds, ob)
	}
	ensurePoolTag := func(t string) {
		t = strings.TrimSpace(t)
		if t == "" {
			return
		}
		ensurePoolSpec(poolSpec{
			OutboundTag: "PROXY_TAG:" + t,
			PoolTag:     t,
			IsPool:      true,
		})
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
		ensurePoolSpec(resolvePoolSpec(r.Action, opts.TailnetMode))
	}
	for _, t := range opts.FinalRoute.GetTags() {
		ensurePoolTag(t)
	}
	ensurePoolSpec(resolveFinalPoolSpec(opts))
	if strings.HasPrefix(finalOutbound, "PROXY_TAG:") {
		ensurePoolTag(strings.TrimPrefix(finalOutbound, "PROXY_TAG:"))
	}

	// Node outbounds
	for _, svc := range opts.Services {
		if svc.EffectiveProtocol() == config.ProtoWARP {
			if isWarpWireGuard(svc, opts.CloudflareConfig) {
				if resolveExplicitWarpEndpoint(svc, opts.CloudflareConfig, warp.ModeWireGuard) == "" {
					outbounds = append(outbounds, buildAutoWireGuardOutboundConfig(svc, opts.CloudflareConfig, "node-"+svc.ID, ""))
				}
				// Explicit endpoints are handled in buildEndpointsConfig as WireGuard endpoint.
				continue
			}
			masqueOb := buildMasqueOutboundConfig(svc, opts.CloudflareConfig, "node-"+svc.ID, "", false)
			outbounds = append(outbounds, masqueOb)
			continue
		}

		baseTag := "node-" + svc.ID
		if svc.EnableWARP {
			baseTag = "raw-node-" + svc.ID
		}

		if isSidecarService(svc) {
			allocPort, hasAutoZero := resolveSidecarPort(svc, allocatedPorts)
			if allocPort <= 0 {
				if hasAutoZero {
					// Sidecar uses auto-allocated loopback port (:0) and is not currently running;
					// skip creating its outbound until it starts and allocates a concrete port.
					continue
				}
				return nil, fmt.Errorf("sidecar 节点 %q (%s) 缺少有效的本地监听端口，请检查配置或启动状态", svc.Name, svc.ID)
			}
			sidecarOb := map[string]any{
				"type":        "socks",
				"tag":         baseTag,
				"server":      "127.0.0.1",
				"server_port": allocPort,
			}
			if ifName := loopbackInterfaceName(); ifName != "" {
				sidecarOb["bind_interface"] = ifName
			}
			outbounds = append(outbounds, sidecarOb)
		} else {
			nativeOb := buildNativeOutbound(svc)
			nativeOb["tag"] = baseTag
			ConfigureNativeOutboundTailnet(nativeOb, opts, tailnetHostIf)
			outbounds = append(outbounds, nativeOb)
		}

		if svc.EnableWARP {
			isTCPOnly := svc.IsTCPOnlyProxy()
			if isWarpWireGuard(svc, opts.CloudflareConfig) {
				if resolveExplicitWarpEndpoint(svc, opts.CloudflareConfig, warp.ModeWireGuard) == "" {
					outbounds = append(outbounds, buildAutoWireGuardOutboundConfig(svc, opts.CloudflareConfig, "node-"+svc.ID, baseTag))
				}
				// Explicit endpoints are handled in buildEndpointsConfig as WireGuard endpoint.
				continue
			}
			masqueOb := buildMasqueOutboundConfig(svc, opts.CloudflareConfig, "node-"+svc.ID, baseTag, isTCPOnly)
			outbounds = append(outbounds, masqueOb)
		}
	}
	return outbounds, nil
}

func resolveSidecarPort(svc config.Service, allocatedPorts map[string]int) (port int, hasAutoZero bool) {
	if allocatedPorts != nil && allocatedPorts[svc.ID] > 0 {
		return allocatedPorts[svc.ID], false
	}
	if listen := svc.PrimaryListen(); listen != "" {
		if ep, err := config.ParseListenURI(listen); err == nil {
			if ep.Port > 0 {
				return ep.Port, false
			}
			return 0, true
		}
	}
	return 0, false
}

// ResolveServiceWarpMode returns the effective WARP transport mode for svc given globalCfg.
func ResolveServiceWarpMode(svc config.Service, globalCfg *warp.Config) warp.Mode {
	if svc.IsTCPOnlyProxy() {
		return warp.ModeMASQUE
	}
	if svc.WARPConfig != nil && svc.WARPConfig.Transport != "" {
		switch svc.WARPConfig.Transport {
		case config.WarpTransportWireGuard:
			return warp.ModeWireGuard
		case config.WarpTransportMasque:
			return warp.ModeMASQUE
		case config.WarpTransportAuto:
			// Legacy persisted "auto": preserve smart default per node role
			if svc.EffectiveProtocol() == config.ProtoWARP {
				if globalCfg != nil {
					return globalCfg.EffectiveDirectMode()
				}
				return warp.ModeMASQUE
			}
			if globalCfg != nil {
				return globalCfg.EffectiveChainedMode()
			}
			return warp.ModeWireGuard
		}
	}
	if svc.EffectiveProtocol() == config.ProtoWARP {
		if globalCfg != nil {
			return globalCfg.EffectiveDirectMode()
		}
		return warp.ModeMASQUE
	}
	if globalCfg != nil {
		return globalCfg.EffectiveChainedMode()
	}
	return warp.ModeWireGuard
}

func resolveServiceMasquePreferH2(svc config.Service, globalCfg *warp.Config) bool {
	if svc.WARPConfig != nil && svc.WARPConfig.MasquePreferH2 != nil {
		return *svc.WARPConfig.MasquePreferH2
	}
	if globalCfg != nil {
		return globalCfg.MasquePreferH2
	}
	return false
}

func isWarpActive(svc config.Service) bool {
	return svc.EffectiveProtocol() == config.ProtoWARP || svc.EnableWARP
}

func isWarpWireGuard(svc config.Service, globalCfg *warp.Config) bool {
	if svc.IsTCPOnlyProxy() {
		return false
	}
	return ResolveServiceWarpMode(svc, globalCfg) == warp.ModeWireGuard
}

// resolveExplicitWarpEndpoint returns the explicitly configured WARP endpoint for svc.
// Global CleanIP/CleanPort applies ONLY to direct WARP nodes (ProtoWARP, including builtin-warp).
// Chained proxy+WARP nodes (svc.EnableWARP) default to "" (runtime per-egress auto-selection)
// unless the node itself has an explicit WARPConfig.Endpoint configured.
func resolveExplicitWarpEndpoint(svc config.Service, globalCfg *warp.Config, mode warp.Mode) string {
	if svc.WARPConfig != nil && strings.TrimSpace(svc.WARPConfig.Endpoint) != "" {
		return strings.TrimSpace(svc.WARPConfig.Endpoint)
	}
	if svc.EffectiveProtocol() == config.ProtoWARP && globalCfg != nil && strings.TrimSpace(globalCfg.CleanIP) != "" {
		host, port := globalCfg.ResolveEndpoint(mode)
		return net.JoinHostPort(host, strconv.Itoa(port))
	}
	return ""
}

func buildMasqueOutboundConfig(svc config.Service, globalCfg *warp.Config, tag, detour string, tcpOnlyDetour bool) map[string]any {
	endpoint := resolveExplicitWarpEndpoint(svc, globalCfg, warp.ModeMASQUE)

	privKey := ""
	certPEM := ""
	ipv4 := warp.DefaultIPv4
	ipv6 := warp.DefaultIPv6

	if svc.WARPConfig != nil {
		if svc.WARPConfig.PrivateKey != "" {
			privKey = svc.WARPConfig.PrivateKey
		}
		if svc.WARPConfig.AddressIPv4 != "" {
			ipv4 = svc.WARPConfig.AddressIPv4
		}
		if svc.WARPConfig.AddressIPv6 != "" {
			ipv6 = svc.WARPConfig.AddressIPv6
		}
	}

	if privKey == "" && globalCfg != nil {
		privKey = globalCfg.Account.MASQUEPrivateKey
		certPEM = globalCfg.Account.MASQUECertPEM
		if globalCfg.Account.MASQUEIPv4 != "" {
			ipv4 = globalCfg.Account.MASQUEIPv4
		} else if globalCfg.Account.IPv4 != "" {
			ipv4 = globalCfg.Account.IPv4
		}
		if globalCfg.Account.MASQUEIPv6 != "" {
			ipv6 = globalCfg.Account.MASQUEIPv6
		} else if globalCfg.Account.IPv6 != "" {
			ipv6 = globalCfg.Account.IPv6
		}
	}

	ob := map[string]any{
		"type":        "masque",
		"tag":         tag,
		"endpoint":    endpoint,
		"private_key": privKey,
		"cert_pem":    certPEM,
		"ipv4":        ipv4,
		"ipv6":        ipv6,
	}
	if detour != "" {
		ob["detour"] = detour
	}
	if tcpOnlyDetour {
		ob["tcp_only_detour"] = true
	}
	if !tcpOnlyDetour && resolveServiceMasquePreferH2(svc, globalCfg) {
		ob["prefer_h2"] = true
	}
	return ob
}

func buildWireGuardEndpointConfig(svc config.Service, globalCfg *warp.Config, tag, detour string) map[string]any {
	peerHost := "162.159.192.1"
	peerPort := 2408
	if explicitEP := resolveExplicitWarpEndpoint(svc, globalCfg, warp.ModeWireGuard); explicitEP != "" {
		if h, pStr, err := net.SplitHostPort(explicitEP); err == nil {
			peerHost = h
			if p, err := strconv.Atoi(pStr); err == nil && p > 0 {
				peerPort = p
			}
		} else {
			peerHost = explicitEP
		}
	}

	privKey := ""
	peerPubKey := warp.DefaultWireGuardPubKey
	reserved := []uint8{0, 0, 0}
	ipv4 := warp.DefaultIPv4
	ipv6 := warp.DefaultIPv6

	if svc.WARPConfig != nil {
		if svc.WARPConfig.PrivateKey != "" {
			privKey = svc.WARPConfig.PrivateKey
		}
		if svc.WARPConfig.PeerPubKey != "" {
			peerPubKey = svc.WARPConfig.PeerPubKey
		}
		if len(svc.WARPConfig.Reserved) == 3 {
			reserved = svc.WARPConfig.Reserved
		}
		if svc.WARPConfig.AddressIPv4 != "" {
			ipv4 = svc.WARPConfig.AddressIPv4
		}
		if svc.WARPConfig.AddressIPv6 != "" {
			ipv6 = svc.WARPConfig.AddressIPv6
		}
	}

	if privKey == "" && globalCfg != nil {
		privKey = globalCfg.Account.WGPrivateKey
		if globalCfg.Account.WGPeerPublicKey != "" {
			peerPubKey = globalCfg.Account.WGPeerPublicKey
		}
		if len(globalCfg.Account.Reserved) == 3 {
			reserved = globalCfg.Account.Reserved
		}
		if globalCfg.Account.IPv4 != "" {
			ipv4 = globalCfg.Account.IPv4
		}
		if globalCfg.Account.IPv6 != "" {
			ipv6 = globalCfg.Account.IPv6
		}
	}

	if privKey == "" {
		if priv, _, err := warp.GenerateWireGuardKeypair(); err == nil {
			privKey = priv
		}
	}

	ipv4Prefix := ipv4
	if !strings.Contains(ipv4Prefix, "/") {
		ipv4Prefix += "/32"
	}
	ipv6Prefix := ipv6
	if !strings.Contains(ipv6Prefix, "/") {
		ipv6Prefix += "/128"
	}

	ep := map[string]any{
		"type":        "wireguard",
		"tag":         tag,
		"address":     []string{ipv4Prefix, ipv6Prefix},
		"private_key": privKey,
		"mtu":         1280,
		"peers": []map[string]any{
			{
				"address":     peerHost,
				"port":        peerPort,
				"public_key":  peerPubKey,
				"allowed_ips": []string{"0.0.0.0/0", "::/0"},
				"reserved":    reserved,
			},
		},
	}
	if detour != "" {
		ep["detour"] = detour
	}
	if net.ParseIP(peerHost) == nil {
		ep["domain_resolver"] = "domestic-doh"
	}
	return ep
}

func buildAutoWireGuardOutboundConfig(svc config.Service, globalCfg *warp.Config, tag, detour string) map[string]any {
	privKey := ""
	peerPubKey := ""
	var reserved []uint8
	ipv4 := ""
	ipv6 := ""

	if svc.WARPConfig != nil {
		if svc.WARPConfig.PrivateKey != "" {
			privKey = svc.WARPConfig.PrivateKey
		}
		if svc.WARPConfig.PeerPubKey != "" {
			peerPubKey = svc.WARPConfig.PeerPubKey
		}
		if len(svc.WARPConfig.Reserved) == 3 {
			reserved = svc.WARPConfig.Reserved
		}
		if svc.WARPConfig.AddressIPv4 != "" {
			ipv4 = svc.WARPConfig.AddressIPv4
		}
		if svc.WARPConfig.AddressIPv6 != "" {
			ipv6 = svc.WARPConfig.AddressIPv6
		}
	}
	if privKey == "" && globalCfg != nil {
		privKey = globalCfg.Account.WGPrivateKey
		if peerPubKey == "" {
			peerPubKey = globalCfg.Account.WGPeerPublicKey
		}
		if len(reserved) != 3 && len(globalCfg.Account.Reserved) == 3 {
			reserved = globalCfg.Account.Reserved
		}
		if ipv4 == "" {
			ipv4 = globalCfg.Account.IPv4
		}
		if ipv6 == "" {
			ipv6 = globalCfg.Account.IPv6
		}
	}

	ob := map[string]any{
		"type":         "warp-wg-auto",
		"tag":          tag,
		"private_key":  privKey,
		"peer_pub_key": peerPubKey,
		"reserved":     reserved,
		"address_ipv4": ipv4,
		"address_ipv6": ipv6,
		"mtu":          uint32(warp.DefaultMTU),
	}
	if detour != "" {
		ob["detour"] = detour
	}
	return ob
}

func buildEndpointsConfig(opts EngineOptions) []map[string]any {
	var endpoints []map[string]any
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
		endpoints = append(endpoints, tsEp)
	}

	for _, svc := range opts.Services {
		if isWarpActive(svc) {
			if svc.IsTCPOnlyProxy() {
				continue
			}
			detour := ""
			if svc.EffectiveProtocol() != config.ProtoWARP && svc.EnableWARP {
				if isSidecarService(svc) {
					allocPort, _ := resolveSidecarPort(svc, opts.AllocatedPorts)
					if allocPort <= 0 {
						continue
					}
				}
				detour = "raw-node-" + svc.ID
			}
			mode := ResolveServiceWarpMode(svc, opts.CloudflareConfig)
			if resolveExplicitWarpEndpoint(svc, opts.CloudflareConfig, warp.ModeWireGuard) != "" {
				if mode == warp.ModeWireGuard {
					wgEp := buildWireGuardEndpointConfig(svc, opts.CloudflareConfig, "node-"+svc.ID, detour)
					endpoints = append(endpoints, wgEp)
				}
			}
		}
	}

	return endpoints
}

func isDomesticRule(r routing.Rule) bool {
	if r.ID == "preset-lan-direct" || r.ID == "preset-cn-direct" {
		return true
	}
	if r.Action.Type == routing.ActionDirect {
		return true
	}
	if r.Action.TargetsNode(config.BuiltinWarpServiceID) {
		for _, gs := range r.GeoSite {
			clean := strings.ToLower(strings.TrimSpace(gs))
			if clean == "cn" || clean == "geolocation-cn" || clean == "tld-cn" {
				return true
			}
		}
		for _, gi := range r.GeoIP {
			if strings.EqualFold(strings.TrimSpace(gi), "cn") {
				return true
			}
		}
	}
	return false
}

func isProxyOutboundTag(outboundTag string) bool {
	return outboundTag == "PROXY_POOL" ||
		strings.HasPrefix(outboundTag, "PROXY_TAG:") ||
		strings.HasPrefix(outboundTag, "POOL:") ||
		strings.HasPrefix(outboundTag, "node-")
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
	if isProxyOutboundTag(finalOutbound) {
		remoteDoHDetour = finalOutbound
	}
	hasPoolProxy := false
	for _, s := range opts.Services {
		if !s.IsBuiltinWarp() {
			hasPoolProxy = true
			break
		}
	}
	if !hasPoolProxy && remoteDoHDetour == "PROXY_POOL" {
		remoteDoHDetour = ""
	}

	// bootstrap-dns and domestic-doh intentionally have no detour: they use the default
	// dialer, which route.auto_detect_interface binds to the physical NIC. A detour to a
	// bare "direct" outbound is rejected by sing-box ("detour to an empty direct outbound
	// makes no sense"), which silently breaks every DNS lookup.
	dnsServers := []map[string]any{
		buildDNSServerMap("bootstrap-dns", bootstrapDNS[0], "", ""),
		buildDNSServerMap("domestic-doh", domesticDoH[0], "", "bootstrap-dns"),
		buildDNSServerMap("remote-doh", remoteDoH[0], remoteDoHDetour, "bootstrap-dns"),
		{
			"type": "hosts",
			"tag":  "local-dns",
		},
	}

	remoteDoHByOutbound := make(map[string]string)
	if remoteDoHDetour != "" {
		remoteDoHByOutbound[remoteDoHDetour] = "remote-doh"
	}
	ensureRemoteDoHForOutbound := func(outboundTag string) string {
		if outboundTag == "" || outboundTag == remoteDoHDetour || (remoteDoHDetour == "" && outboundTag == "PROXY_POOL") {
			return "remote-doh"
		}
		if existing, ok := remoteDoHByOutbound[outboundTag]; ok {
			return existing
		}
		tag := remoteDoHTagForOutbound(outboundTag)
		remoteDoHByOutbound[outboundTag] = tag
		dnsServers = append(dnsServers, buildDNSServerMap(tag, remoteDoH[0], outboundTag, "bootstrap-dns"))
		return tag
	}
	for _, svc := range opts.Services {
		if svc.EffectiveProtocol() == config.ProtoWARP || !svc.EnableWARP {
			continue
		}
		if isSidecarService(svc) {
			allocPort, hasAutoZero := resolveSidecarPort(svc, opts.AllocatedPorts)
			if allocPort <= 0 && hasAutoZero {
				continue
			}
		}
		ensureRemoteDoHForOutbound("node-" + svc.ID)
	}

	var dnsRules []map[string]any
	dnsRules = append(dnsRules, map[string]any{
		"domain":        []string{"localhost"},
		"domain_suffix": []string{".local", ".localhost"},
		"server":        "local-dns",
	})
	dnsRules = append(dnsRules, map[string]any{
		"domain":        []string{"connect.rom.miui.com", "cp.cloudflare.com"},
		"domain_suffix": []string{".miui.com", ".xiaomi.com", ".qualcomm.cn"},
		"server":        "domestic-doh",
	})
	// DNS server hostnames (domestic DoH / bootstrap) stay on bootstrap-dns since a server
	// cannot resolve itself. Proxy node domains go through domestic-doh, which is direct
	// (no detour), so resolving them never depends on the proxy.
	dohDomains := collectDoHBootstrapDomains(opts)
	var dohRuleDomains, nodeRuleDomains []string
	for _, d := range allBootstrapDomains {
		if dohDomains[d] {
			dohRuleDomains = append(dohRuleDomains, d)
		} else {
			nodeRuleDomains = append(nodeRuleDomains, d)
		}
	}
	if len(dohRuleDomains) > 0 {
		dnsRules = append(dnsRules, map[string]any{
			"domain": dohRuleDomains,
			"server": "bootstrap-dns",
		})
	}
	if len(nodeRuleDomains) > 0 {
		dnsRules = append(dnsRules, map[string]any{
			"domain": nodeRuleDomains,
			"server": "domestic-doh",
		})
	}
	if opts.TailnetMode == tailnet.ModeHost {
		dnsServers = append(dnsServers, map[string]any{
			"type":        "udp",
			"tag":         "tailscale-host-dns",
			"server":      "100.100.100.100",
			"server_port": 53,
			"detour":      "tailnet-direct",
		})
		dnsRules = append(dnsRules, map[string]any{
			"domain_suffix": tailnetDomainSuffixes(opts),
			"server":        "tailscale-host-dns",
		})
		// Match short names (single-label domain without dots, e.g. "nas", "debian") to MagicDNS
		dnsRules = append(dnsRules, map[string]any{
			"domain_regex":  []string{`^[^.]+$`},
			"server":        "tailscale-host-dns",
		})
		// Reverse DNS for Tailscale CGNAT addresses
		dnsRules = append(dnsRules, map[string]any{
			"domain_suffix": []string{".100.in-addr.arpa"},
			"server":        "tailscale-host-dns",
		})
	} else if opts.TailnetMode == tailnet.ModeEmbedded && opts.TailnetConfig != nil {
		dnsServers = append(dnsServers, map[string]any{
			"type":     "tailscale",
			"tag":      "tailscale-dns",
			"endpoint": "tailscale-ep",
		})
		dnsRules = append(dnsRules, map[string]any{
			"domain_suffix": tailnetDomainSuffixes(opts),
			"server":        "tailscale-dns",
		})
		dnsRules = append(dnsRules, map[string]any{
			"domain_regex":  []string{`^[^.]+$`},
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
		switch {
		case r.Action.Type == routing.ActionTailnet || r.Action.Type == routing.ActionTailnetExit:
			if opts.TailnetMode == tailnet.ModeHost {
				targetDNSServer = "tailscale-host-dns"
			} else {
				targetDNSServer = "tailscale-dns"
			}
		case r.Action.Type == routing.ActionBlock:
			targetDNSServer = ""
		case isDomesticRule(r):
			targetDNSServer = "domestic-doh"
		case r.Action.IsProxyAction():
			outTag := resolveRouteOutbound(r.Action, opts.TailnetMode)
			targetDNSServer = ensureRemoteDoHForOutbound(outTag)
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
		"servers":         dnsServers,
		"final":           dnsFinal,
		"reverse_mapping": true,
	}
	if strategy := effectiveDNSStrategy(opts); strategy != "" {
		dnsMap["strategy"] = strategy
	}
	if opts.DNSOptimisticCache {
		dnsMap["optimistic"] = true
	}
	if len(dnsRules) > 0 {
		dnsMap["rules"] = dnsRules
	}
	return dnsMap
}

func effectiveDNSStrategy(opts EngineOptions) string {
	switch strings.ToLower(strings.TrimSpace(opts.DNSStrategy)) {
	case "ipv4_only", "prefer_ipv4", "prefer_ipv6", "ipv6_only":
		return strings.ToLower(strings.TrimSpace(opts.DNSStrategy))
	case "as_is", "default":
		return ""
	}
	if opts.PreferIPv4 {
		return "prefer_ipv4"
	}
	return ""
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

	// 0.2 Ensure loopback traffic is routed to loopback-direct (bound to lo0) to avoid en0 binding (Errno 49)
	singRules = append(singRules, map[string]any{
		"ip_cidr":  []string{"127.0.0.0/8", "::1/128"},
		"outbound": "loopback-direct",
	})
	singRules = append(singRules, map[string]any{
		"domain":        []string{"localhost"},
		"domain_suffix": []string{".local", ".localhost"},
		"outbound":      "loopback-direct",
	})

	// 0.22 Tailnet traffic (CGNAT, MagicDNS domains/short names, advertised subnet routes) must match
	// before RFC1918/CGNAT direct rules (0.25) and node CIDR direct rules (0.3).
	singRules = append(singRules, buildTailnetRouteRules(opts)...)

	// 0.25 Ensure RFC1918 private / LAN traffic is always routed direct to protect local network services
	singRules = append(singRules, map[string]any{
		"ip_cidr": []string{
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"169.254.0.0/16",
			"100.64.0.0/10",
			"fc00::/7",
			"fe80::/10",
		},
		"outbound": "direct",
	})
	singRules = append(singRules, map[string]any{
		"domain_suffix": []string{".lan", ".internal", ".home.arpa"},
		"outbound":      "direct",
	})

	// 0.3 Node Server IPs routed directly to guarantee sidecars (naive, xray) never loop into proxy pool
	var nodeCIDRs []string
	for _, exc := range resolveNodeExcludes(opts) {
		if !strings.HasPrefix(exc, "127.") && exc != "::1/128" {
			nodeCIDRs = append(nodeCIDRs, exc)
		}
	}
	if len(nodeCIDRs) > 0 {
		singRules = append(singRules, map[string]any{
			"ip_cidr":  nodeCIDRs,
			"outbound": "direct",
		})
	}

	// 0.4 Cloudflare WARP Anycast endpoints routed directly to prevent local WARP routing loops
	singRules = append(singRules, map[string]any{
		"ip_cidr": []string{
			"162.159.192.0/24",
			"162.159.193.0/24",
			"162.159.195.0/24",
			"162.159.198.0/24",
			"162.159.200.0/24",
			"162.159.204.0/24",
			"188.114.96.0/24",
			"188.114.97.0/24",
			"188.114.98.0/24",
			"188.114.99.0/24",
			"2606:4700:d0::/48",
			"2606:4700:d1::/48",
		},
		"outbound": "direct",
	})

	// 0.4 Bootstrap domains & IPs routing directly to avoid TUN/proxy deadlocks (Item 6)
	if len(allBootstrapDomains) > 0 {
		singRules = append(singRules, map[string]any{
			"domain":   allBootstrapDomains,
			"outbound": "direct",
		})
	}
	var bootstrapIPs []string
	bootstrapList := opts.BootstrapDNS
	if len(bootstrapList) == 0 {
		bootstrapList = DefaultBootstrapDNS
	}
	for _, raw := range bootstrapList {
		raw = strings.TrimSpace(raw)
		if host, _, err := net.SplitHostPort(raw); err == nil {
			raw = host
		}
		if ip := net.ParseIP(raw); ip != nil {
			bootstrapIPs = append(bootstrapIPs, ip.String())
		}
	}
	for _, doh := range opts.DomesticDoH {
		if u, err := url.Parse(doh); err == nil && u.Hostname() != "" {
			if ip := net.ParseIP(u.Hostname()); ip != nil {
				bootstrapIPs = append(bootstrapIPs, ip.String())
			}
		}
	}
	if len(bootstrapIPs) > 0 {
		singRules = append(singRules, map[string]any{
			"ip_cidr":  bootstrapIPs,
			"outbound": "direct",
		})
	}

	// 4.2 User rules (custom rules prioritized before preset rules)
	prioritizedUserRules := routing.PrioritizedRules(opts.Rules)
	for _, r := range prioritizedUserRules {
		if !r.Enabled {
			continue
		}

		outbound := resolveRouteOutbound(r.Action, opts.TailnetMode)

		// 1. Direct domain matching rule
		if len(r.DomainFull) > 0 || len(r.DomainSuffix) > 0 || len(r.DomainKeyword) > 0 {
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
			singRules = append(singRules, sr)
		}

		// 2. IP CIDR matching rule (separate rule; sing-box evaluates fields within a single rule with logical AND)
		if len(r.IPCidr) > 0 {
			singRules = append(singRules, map[string]any{
				"ip_cidr":  r.IPCidr,
				"outbound": outbound,
			})
		}

		// 3. RuleSet matching rule (OR logic with domain criteria)
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
				cleanGI := strings.ToLower(strings.TrimSpace(gi))
				rsets = append(rsets, "geoip-"+cleanGI)
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

	normLvl, _ := parseSingBoxLogLevel(opts.LogLevel)
	configMap["log"] = map[string]any{
		"level": normLvl,
	}

	finalOutbound := resolveFinalOutbound(opts)
	allBootstrapDomains := collectAllBootstrapDomains(opts)
	if opts.AllocatedPorts == nil && len(e.allocatedPorts) > 0 {
		opts.AllocatedPorts = e.allocatedPorts
	}

	if opts.NodeIPResolver == nil {
		opts.NodeIPResolver = defaultNodeIPResolver()
	}

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
			} else if ip := net.ParseIP(u.Hostname()); ip != nil && ip.IsLoopback() {
				if ifName := loopbackInterfaceName(); ifName != "" {
					m["bind_interface"] = ifName
				}
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
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			if ifName := loopbackInterfaceName(); ifName != "" {
				m["bind_interface"] = ifName
			}
		} else {
			m["detour"] = detour
		}
	} else if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if ifName := loopbackInterfaceName(); ifName != "" {
			m["bind_interface"] = ifName
		}
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

