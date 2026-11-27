package boxengine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"naive-client/internal/blocker"
	"naive-client/internal/config"
	"naive-client/internal/routing"
	"naive-client/internal/telemetry"
	"naive-client/internal/warp"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

type poolDialContextKey struct{}

func withPoolDial(ctx context.Context) context.Context {
	return context.WithValue(ctx, poolDialContextKey{}, true)
}

func isPoolDialContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(poolDialContextKey{}).(bool)
	return v
}

// NodeProvider abstracts the dynamic discovery of active nodes and their Outbounds.
type NodeProvider interface {
	GetCandidates(poolTag string) []string
	GetOutbound(nodeID string) (adapter.Outbound, bool)
	IsSidecar(nodeID string) bool
}

type warpDomainResolverProvider interface {
	ResolveWarpDomain(ctx context.Context, nodeID string, ob adapter.Outbound, dest M.Socksaddr) (M.Socksaddr, error)
}

type nodeIPv6Provider interface {
	GetNodeIPv6Mode(nodeID string) string
	IsWarpNode(nodeID string) bool
}

type poolDialAttempt struct {
	candID            string
	useDomainFallback bool
	forcedCap         bool
}

// PoolOutboundOptions defines configuration for a PoolOutbound instance.
type PoolOutboundOptions struct {
	Tag               string
	PoolTag           string
	Targets           []routing.TargetRef
	DispatchPolicy    string
	FallbackToPool    bool
	Tracker           *telemetry.Tracker
	FailureMonitor    *telemetry.FailureMonitor
	NodeProvider      NodeProvider
	OnTelemetryUpdate func()
	Blocker           *blocker.Engine
}

// PoolOutbound implements sing-box adapter.Outbound to dynamically route traffic across node pools.
type PoolOutbound struct {
	tag               string
	poolTag           string
	targets           []routing.TargetRef
	dispatchPolicy    string
	fallbackToPool    bool
	tracker           *telemetry.Tracker
	failureMonitor    *telemetry.FailureMonitor
	provider          NodeProvider
	onTelemetryUpdate func()
	blocker           *blocker.Engine
	mu                sync.RWMutex
}

// NewPoolOutbound creates a new adaptive proxy pool outbound.
func NewPoolOutbound(opts PoolOutboundOptions) *PoolOutbound {
	policy := routing.DispatchSmart
	if strings.EqualFold(strings.TrimSpace(opts.DispatchPolicy), routing.DispatchOrder) {
		policy = routing.DispatchOrder
	}
	return &PoolOutbound{
		tag:               opts.Tag,
		poolTag:           opts.PoolTag,
		targets:           routing.NormalizeTargets(opts.Targets),
		dispatchPolicy:    policy,
		fallbackToPool:    opts.FallbackToPool,
		tracker:           opts.Tracker,
		failureMonitor:    opts.FailureMonitor,
		provider:          opts.NodeProvider,
		onTelemetryUpdate: opts.OnTelemetryUpdate,
		blocker:           opts.Blocker,
	}
}

func (p *PoolOutbound) Targets() []routing.TargetRef {
	return append([]routing.TargetRef(nil), p.targets...)
}

func (p *PoolOutbound) DispatchPolicy() string {
	return p.dispatchPolicy
}

func (p *PoolOutbound) FallbackToPool() bool {
	return p.fallbackToPool
}

func (p *PoolOutbound) Type() string {
	return "pool"
}

func (p *PoolOutbound) Tag() string {
	return p.tag
}

func (p *PoolOutbound) Network() []string {
	return []string{"tcp", "udp"}
}

func (p *PoolOutbound) Dependencies() []string {
	return nil
}

var _ adapter.Referrer = (*PoolOutbound)(nil)

// References reports all candidate node outbound tags this pool can dispatch to
// so sing-box's ReferenceManager preserves idle connection pooling on them.
func (p *PoolOutbound) References() []string {
	if p.provider == nil {
		return nil
	}
	lookup := p.provider.GetCandidates
	if ap, ok := p.provider.(interface{ AllCandidates(string) []string }); ok {
		lookup = ap.AllCandidates
	}
	seen := make(map[string]bool)
	var refs []string
	addIDs := func(ids []string) {
		for _, id := range ids {
			if id == "" {
				continue
			}
			tag := id
			if !strings.HasPrefix(tag, "node-") {
				tag = "node-" + tag
			}
			if !seen[tag] {
				seen[tag] = true
				refs = append(refs, tag)
			}
		}
	}
	if len(p.targets) == 0 {
		tagKey := p.poolTag
		if tagKey == "" {
			tagKey = p.tag
		}
		addIDs(lookup(tagKey))
		return refs
	}
	for _, t := range p.targets {
		switch t.Kind {
		case routing.TargetNode:
			addIDs([]string{t.Value})
		case routing.TargetTag:
			addIDs(lookup(t.Value))
		}
	}
	if p.fallbackToPool {
		addIDs(lookup("PROXY_POOL"))
	}
	return refs
}

func extractTargetHost(ctx context.Context, destination M.Socksaddr) string {
	if destination.IsFqdn() || destination.Fqdn != "" {
		return destination.Fqdn
	}
	if ctx != nil {
		if inboundCtx := adapter.ContextFrom(ctx); inboundCtx != nil && inboundCtx.Domain != "" {
			return inboundCtx.Domain
		}
	}
	if destination.IsIP() {
		return destination.Addr.String()
	}
	return destination.AddrString()
}

// orderCandidates sorts candidate node IDs according to tracker affinity and quality score.
func (p *PoolOutbound) orderCandidates(candidates []string, targetHost string) []string {
	if len(candidates) <= 1 || p.tracker == nil {
		return candidates
	}

	bestID, _, hasBest := p.tracker.PeekBest(candidates, targetHost)

	// Sort remaining by score
	type candidateScore struct {
		id    string
		score float64
	}
	scores := make([]candidateScore, 0, len(candidates))
	for _, c := range candidates {
		sc := p.tracker.GetScore(c)
		scores = append(scores, candidateScore{id: c, score: sc.Score})
	}
	sort.SliceStable(scores, func(i, j int) bool {
		return scores[i].score < scores[j].score
	})

	ordered := make([]string, 0, len(candidates))
	if hasBest {
		ordered = append(ordered, bestID)
	}
	for _, s := range scores {
		if hasBest && s.id == bestID {
			continue
		}
		ordered = append(ordered, s.id)
	}
	return ordered
}

func (p *PoolOutbound) candidatesForTarget(t routing.TargetRef) []string {
	if p.provider == nil {
		return nil
	}
	switch t.Kind {
	case routing.TargetNode:
		return p.provider.GetCandidates("node:" + t.Value)
	case routing.TargetTag:
		return p.provider.GetCandidates(t.Value)
	default:
		return nil
	}
}

func (p *PoolOutbound) isCandidateBroken(candID string) bool {
	if p.tracker == nil {
		return false
	}
	return p.tracker.GetScore(candID).IsBroken
}

func (p *PoolOutbound) resolveOrderedCandidates(targetHost string) []string {
	if p.provider == nil {
		return nil
	}
	if len(p.targets) == 0 {
		tagKey := p.poolTag
		if tagKey == "" {
			tagKey = p.tag
		}
		candidates := p.provider.GetCandidates(tagKey)
		if len(candidates) == 0 {
			return nil
		}
		return p.orderCandidates(candidates, targetHost)
	}

	seen := make(map[string]bool)
	dedup := func(list []string) []string {
		var out []string
		for _, id := range list {
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
		return out
	}

	if p.dispatchPolicy == routing.DispatchOrder {
		var healthyOrdered []string
		var brokenOrdered []string
		appendTier := func(cands []string) {
			if len(cands) == 0 {
				return
			}
			var healthy, broken []string
			for _, id := range cands {
				if p.isCandidateBroken(id) {
					broken = append(broken, id)
				} else {
					healthy = append(healthy, id)
				}
			}
			if len(healthy) > 0 {
				healthyOrdered = append(healthyOrdered, p.orderCandidates(healthy, targetHost)...)
			}
			if len(broken) > 0 {
				brokenOrdered = append(brokenOrdered, p.orderCandidates(broken, targetHost)...)
			}
		}

		for _, t := range p.targets {
			appendTier(dedup(p.candidatesForTarget(t)))
		}
		if p.fallbackToPool {
			appendTier(dedup(p.provider.GetCandidates("PROXY_POOL")))
		}
		return append(healthyOrdered, brokenOrdered...)
	}

	var primary []string
	for _, t := range p.targets {
		primary = append(primary, dedup(p.candidatesForTarget(t))...)
	}
	ordered := p.orderCandidates(primary, targetHost)
	if p.fallbackToPool {
		fb := dedup(p.provider.GetCandidates("PROXY_POOL"))
		if len(fb) > 0 {
			ordered = append(ordered, p.orderCandidates(fb, targetHost)...)
		}
	}
	return ordered
}

// SelectCandidate returns the top-ranked candidate node ID for targetHost in this pool.
func (p *PoolOutbound) SelectCandidate(targetHost string) string {
	ordered := p.resolveOrderedCandidates(targetHost)
	if len(ordered) == 0 {
		return ""
	}
	return ordered[0]
}

func (p *PoolOutbound) resolveNodeName(candID string) string {
	if np, ok := p.provider.(interface{ GetNodeName(string) string }); ok {
		if name := np.GetNodeName(candID); name != "" {
			return name
		}
	}
	return candID
}

func formatConnectionError(err error) string {
	if err == nil {
		return ""
	}
	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "no active proxy") || strings.Contains(errStr, "no candidates") {
		return "节点未启动"
	}
	if errors.Is(err, errFirstPacketAborted) {
		return "首包未响应中断"
	}
	if errors.Is(err, io.EOF) || strings.Contains(errStr, "unexpected eof") || strings.Contains(errStr, "eof") {
		return "远端断开: EOF"
	}
	if strings.Contains(errStr, "connection reset") || strings.Contains(errStr, "reset by peer") {
		return "连接重置: RST"
	}
	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline exceeded") {
		return "连接超时"
	}
	if strings.Contains(errStr, "connection refused") {
		return "拒绝连接"
	}
	if strings.Contains(errStr, "handshake") || strings.Contains(errStr, "tls") {
		return "TLS握手失败"
	}
	if strings.Contains(errStr, "no route to host") {
		return "无可用路由"
	}
	if strings.Contains(errStr, "network is unreachable") {
		return "网络不可达"
	}
	if strings.Contains(errStr, "permission denied") || strings.Contains(errStr, "operation not permitted") {
		return "权限拒绝"
	}
	return "连接失败"
}

func (p *PoolOutbound) resolveCandidateDestination(ctx context.Context, candID string, ob adapter.Outbound, destination M.Socksaddr) (M.Socksaddr, error) {
	if !destination.IsDomain() {
		return destination, nil
	}
	if wp, ok := p.provider.(warpDomainResolverProvider); ok {
		return wp.ResolveWarpDomain(ctx, candID, ob, destination)
	}
	return destination, nil
}

func extractSniffedDomain(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	inboundCtx := adapter.ContextFrom(ctx)
	if inboundCtx == nil {
		return ""
	}
	dom := strings.Trim(strings.ToLower(strings.TrimSpace(inboundCtx.Domain)), ".")
	if dom == "" || net.ParseIP(dom) != nil {
		return ""
	}
	return dom
}

func (p *PoolOutbound) effectiveIPv6Capability(candID string) (telemetry.IPv6Capability, bool) {
	if np, ok := p.provider.(nodeIPv6Provider); ok {
		switch config.NormalizeIPv6Mode(np.GetNodeIPv6Mode(candID)) {
		case config.IPv6ModeSupported:
			return telemetry.IPv6Supported, true
		case config.IPv6ModeUnsupported:
			return telemetry.IPv6Unsupported, true
		}
		if np.IsWarpNode(candID) {
			return telemetry.IPv6Supported, true
		}
	}
	if p.tracker != nil {
		cap, _ := p.tracker.GetIPv6Capability(candID)
		return cap, false
	}
	return telemetry.IPv6Unknown, false
}

func (p *PoolOutbound) buildDialAttempts(ordered []string, dest M.Socksaddr, sniffedDomain string) []poolDialAttempt {
	if !dest.IsIPv6() {
		attempts := make([]poolDialAttempt, 0, len(ordered))
		for _, id := range ordered {
			attempts = append(attempts, poolDialAttempt{candID: id})
		}
		return attempts
	}
	var supported, unknown, unsupported []poolDialAttempt
	for _, id := range ordered {
		cap, forced := p.effectiveIPv6Capability(id)
		switch cap {
		case telemetry.IPv6Supported:
			supported = append(supported, poolDialAttempt{candID: id, forcedCap: forced})
		case telemetry.IPv6Unsupported:
			if sniffedDomain != "" {
				unsupported = append(unsupported, poolDialAttempt{
					candID:            id,
					useDomainFallback: true,
					forcedCap:         forced,
				})
			}
		default:
			unknown = append(unknown, poolDialAttempt{candID: id, forcedCap: forced})
		}
	}
	attempts := make([]poolDialAttempt, 0, len(supported)+len(unknown)+len(unsupported))
	attempts = append(attempts, supported...)
	attempts = append(attempts, unknown...)
	attempts = append(attempts, unsupported...)
	return attempts
}

func (p *PoolOutbound) markPassiveIPv6Supported(candID string, forced bool) {
	if forced || p.tracker == nil {
		return
	}
	if cap, _ := p.tracker.GetIPv6Capability(candID); cap == telemetry.IPv6Unknown {
		p.tracker.SetIPv6Capability(candID, telemetry.IPv6Supported)
	}
}

func (p *PoolOutbound) dialAttempt(
	ctx, dialCtx context.Context,
	network string,
	destination M.Socksaddr,
	sniffedDomain, targetHost, sourceKey string,
	attempt poolDialAttempt,
	singleCandidate bool,
) (conn net.Conn, err error, abort bool, ipv6Unsupported bool) {
	ob, ok := p.provider.GetOutbound(attempt.candID)
	if !ok || ob == nil {
		return nil, nil, false, false
	}

	isSidecar := false
	if p.provider != nil {
		isSidecar = p.provider.IsSidecar(attempt.candID)
	}

	attemptDest := destination
	if attempt.useDomainFallback && sniffedDomain != "" {
		attemptDest = M.Socksaddr{Fqdn: sniffedDomain, Port: destination.Port}
	}

	start := time.Now()
	candDest, err := p.resolveCandidateDestination(dialCtx, attempt.candID, ob, attemptDest)
	if err != nil && (errors.Is(err, warp.ErrNoDNSRecords) || (ctx != nil && errors.Is(ctx.Err(), context.Canceled)) || errors.Is(err, context.Canceled)) {
		if sourceKey != "" && p.blocker != nil && p.blocker.Logger() != nil {
			p.blocker.Logger().AnnotateBySource(sourceKey, formatConnectionError(err))
		}
		return nil, err, true, false
	}
	if err == nil {
		conn, err = ob.DialContext(dialCtx, network, candDest)
	}
	rtt := time.Since(start)

	if err != nil {
		if errors.Is(err, warp.ErrNoDNSRecords) || (ctx != nil && errors.Is(ctx.Err(), context.Canceled)) || errors.Is(err, context.Canceled) {
			if sourceKey != "" && p.blocker != nil && p.blocker.Logger() != nil {
				p.blocker.Logger().AnnotateBySource(sourceKey, formatConnectionError(err))
			}
			return nil, err, true, false
		}
		if attemptDest.IsIPv6() && telemetry.IsIPv6UnsupportedError(err) {
			if !attempt.forcedCap && p.tracker != nil {
				p.tracker.SetIPv6Capability(attempt.candID, telemetry.IPv6Unsupported)
			}
			return nil, err, false, true
		}
		if p.tracker != nil {
			if isSidecar {
				p.tracker.RecordDial(attempt.candID, targetHost, 0, err)
			} else {
				p.tracker.RecordDial(attempt.candID, targetHost, rtt, err)
			}
		}
		return nil, err, false, false
	}

	if isSidecar && network == "tcp" {
		// Sidecar outbounds connect to localhost (127.0.0.1:allocPort).
		// Local loopback TCP acceptance does not mean the remote proxy tunnel succeeded.
		// Defer both dial success/failure and real internet TTFB RTT recording to wrapFirstRTTConn
		// so remote timeouts, resets, and blackholes accurately update SuccessRate and CircuitBreaker.
		destPort := destination.Port
		poolTag := p.tag
		candID := attempt.candID
		forcedCap := attempt.forcedCap
		attemptIsV6 := attemptDest.IsIPv6()
		var stalledPenalized atomic.Bool
		wrapped := wrapFirstRTTConn(conn, func(realRTT time.Duration, isTLS bool, firstErr error) {
			skipPenalty := firstErr != nil && attemptIsV6 && telemetry.IsIPv6UnsupportedError(firstErr)
			if skipPenalty {
				if !forcedCap && p.tracker != nil {
					p.tracker.SetIPv6Capability(candID, telemetry.IPv6Unsupported)
				}
			} else if firstErr == nil && attemptIsV6 {
				p.markPassiveIPv6Supported(candID, forcedCap)
			}
			if !skipPenalty && p.tracker != nil && !errors.Is(firstErr, errPreWriteAborted) {
				trackerRTT := realRTT
				if firstErr == nil {
					// Only plausible first-response RTTs feed the tracker; the log keeps the real value.
					if trackerRTT < minValidFirstRTT {
						trackerRTT = 0
					} else if trackerRTT > maxValidFirstRTT {
						trackerRTT = maxValidFirstRTT
					}
				}
				if !isTLS && firstErr == nil && realRTT >= telemetry.SeverePacketLossRTT {
					// For non-TLS traffic, latencies >= SeverePacketLossRTT (3000ms) typically reflect
					// backend application computation (e.g. AI inference, slow search, report export)
					// rather than network RTO packet loss.
					// Pass trackerRTT = 0 to record a successful dial and maintain domain affinity
					// without contaminating network EWMA or triggering false packet-loss stalls.
					trackerRTT = 0
				}
				if stalledPenalized.Load() {
					if firstErr == nil && trackerRTT > 0 {
						p.tracker.RecordRecoveredStalledDial(candID, trackerRTT)
					}
				} else {
					p.tracker.RecordDial(candID, targetHost, trackerRTT, firstErr)
				}
			}
			if firstErr != nil && sourceKey != "" && p.blocker != nil && p.blocker.Logger() != nil {
				p.blocker.Logger().AnnotateFailureBySource(sourceKey, formatConnectionError(firstErr), realRTT)
			} else if firstErr == nil && sourceKey != "" && p.blocker != nil && p.blocker.Logger() != nil {
				p.blocker.Logger().AnnotateDurationBySource(sourceKey, realRTT)
			}
			if !skipPenalty && firstErr != nil && !errors.Is(firstErr, errPreWriteAborted) && p.failureMonitor != nil && singleCandidate {
				p.failureMonitor.Record(telemetry.FailureEvent{
					Category:       telemetry.FailureProxy,
					Target:         targetHost,
					Port:           destPort,
					OriginalAction: poolTag,
					Error:          firstErr,
				})
			}
			if p.onTelemetryUpdate != nil {
				p.onTelemetryUpdate()
			}
		}, func() {
			if p.tracker != nil && p.tracker.RecordStall(candID, targetHost) {
				stalledPenalized.Store(true)
			}
			if p.onTelemetryUpdate != nil {
				p.onTelemetryUpdate()
			}
		})
		if fc, ok := wrapped.(*firstRTTConn); ok {
			fc.dialCtx = ctx
		}
		return wrapped, nil, false, false
	}

	if attemptDest.IsIPv6() {
		p.markPassiveIPv6Supported(attempt.candID, attempt.forcedCap)
	}
	if sourceKey != "" && p.blocker != nil && p.blocker.Logger() != nil {
		p.blocker.Logger().AnnotateDurationBySource(sourceKey, rtt)
	}
	if p.tracker != nil {
		if isSidecar {
			p.tracker.RecordDial(attempt.candID, targetHost, 0, nil)
		} else {
			p.tracker.RecordDial(attempt.candID, targetHost, rtt, nil)
		}
	}
	if p.onTelemetryUpdate != nil {
		p.onTelemetryUpdate()
	}
	return conn, nil, false, false
}

func (p *PoolOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if p.provider == nil {
		return nil, errors.New("node provider is nil")
	}

	sourceKey := ""
	if inboundCtx := adapter.ContextFrom(ctx); inboundCtx != nil && inboundCtx.Source.Port != 0 {
		sourceKey = inboundCtx.Source.String()
	}

	targetHost := extractTargetHost(ctx, destination)
	if p.blocker != nil && targetHost != "" && p.blocker.ShouldBlock(targetHost) {
		return nil, syscall.EPERM
	}

	tagKey := p.poolTag
	if tagKey == "" {
		tagKey = p.tag
	}

	ordered := p.resolveOrderedCandidates(targetHost)
	if len(ordered) == 0 {
		err := fmt.Errorf("no active proxy candidates available for pool %s", tagKey)
		if sourceKey != "" && p.blocker != nil && p.blocker.Logger() != nil {
			p.blocker.Logger().AnnotateBySource(sourceKey, "节点未启动")
		}
		if p.onTelemetryUpdate != nil {
			p.onTelemetryUpdate()
		}
		if p.failureMonitor != nil {
			p.failureMonitor.Record(telemetry.FailureEvent{
				Category:       telemetry.FailureProxy,
				Target:         targetHost,
				Port:           destination.Port,
				OriginalAction: p.tag,
				Error:          err,
			})
		}
		return nil, err
	}

	sniffedDomain := extractSniffedDomain(ctx)
	attempts := p.buildDialAttempts(ordered, destination, sniffedDomain)
	if destination.IsIPv6() && len(attempts) == 0 {
		err := fmt.Errorf("no IPv6-capable candidates available in %s", p.tag)
		if sourceKey != "" && p.blocker != nil && p.blocker.Logger() != nil {
			p.blocker.Logger().AnnotateBySource(sourceKey, "无支持 IPv6 的节点")
		}
		if p.onTelemetryUpdate != nil {
			p.onTelemetryUpdate()
		}
		return nil, err
	}

	dialCtx := withPoolDial(ctx)
	var lastErr error
	var domainRetry []poolDialAttempt
	singleCandidate := len(ordered) == 1

	for _, attempt := range attempts {
		conn, err, abort, v6Unsupported := p.dialAttempt(ctx, dialCtx, network, destination, sniffedDomain, targetHost, sourceKey, attempt, singleCandidate)
		if abort {
			return nil, err
		}
		if err == nil && conn != nil {
			return conn, nil
		}
		if v6Unsupported && sniffedDomain != "" && !attempt.useDomainFallback {
			domainRetry = append(domainRetry, poolDialAttempt{
				candID:            attempt.candID,
				useDomainFallback: true,
				forcedCap:         attempt.forcedCap,
			})
		}
		if err != nil {
			lastErr = err
		}
	}

	for _, retry := range domainRetry {
		conn, err, abort, _ := p.dialAttempt(ctx, dialCtx, network, destination, sniffedDomain, targetHost, sourceKey, retry, singleCandidate)
		if abort {
			return nil, err
		}
		if err == nil && conn != nil {
			return conn, nil
		}
		if err != nil {
			lastErr = err
		}
	}

	if lastErr == nil {
		lastErr = errors.New("all candidates skipped")
	}

	if sourceKey != "" && p.blocker != nil && p.blocker.Logger() != nil {
		p.blocker.Logger().AnnotateBySource(sourceKey, formatConnectionError(lastErr))
	}
	if p.onTelemetryUpdate != nil {
		p.onTelemetryUpdate()
	}

	if p.failureMonitor != nil {
		p.failureMonitor.Record(telemetry.FailureEvent{
			Category:       telemetry.FailureProxy,
			Target:         targetHost,
			Port:           destination.Port,
			OriginalAction: p.tag,
			Error:          lastErr,
		})
	}

	return nil, fmt.Errorf("all candidates failed in %s: %w", p.tag, lastErr)
}

func (p *PoolOutbound) listenPacketAttempt(
	ctx, packetCtx context.Context,
	destination M.Socksaddr,
	sniffedDomain, targetHost, udpSourceKey string,
	attempt poolDialAttempt,
) (conn net.PacketConn, err error, abort bool, ipv6Unsupported bool) {
	ob, ok := p.provider.GetOutbound(attempt.candID)
	if !ok || ob == nil {
		return nil, nil, false, false
	}

	attemptDest := destination
	if attempt.useDomainFallback && sniffedDomain != "" {
		attemptDest = M.Socksaddr{Fqdn: sniffedDomain, Port: destination.Port}
	}

	candDest, err := p.resolveCandidateDestination(packetCtx, attempt.candID, ob, attemptDest)
	if err != nil && (errors.Is(err, warp.ErrNoDNSRecords) || (ctx != nil && errors.Is(ctx.Err(), context.Canceled)) || errors.Is(err, context.Canceled)) {
		if udpSourceKey != "" && p.blocker != nil && p.blocker.Logger() != nil {
			p.blocker.Logger().AnnotateBySource(udpSourceKey, formatConnectionError(err))
		}
		return nil, err, true, false
	}
	if err == nil {
		conn, err = ob.ListenPacket(packetCtx, candDest)
	}
	if err == nil {
		if attemptDest.IsIPv6() {
			p.markPassiveIPv6Supported(attempt.candID, attempt.forcedCap)
		}
		if udpSourceKey != "" && p.blocker != nil && p.blocker.Logger() != nil {
			p.blocker.Logger().UnbindSourceConn(udpSourceKey)
		}
		return conn, nil, false, false
	}
	if errors.Is(err, warp.ErrNoDNSRecords) || (ctx != nil && errors.Is(ctx.Err(), context.Canceled)) || errors.Is(err, context.Canceled) {
		if udpSourceKey != "" && p.blocker != nil && p.blocker.Logger() != nil {
			p.blocker.Logger().AnnotateBySource(udpSourceKey, formatConnectionError(err))
		}
		return nil, err, true, false
	}
	if attemptDest.IsIPv6() && telemetry.IsIPv6UnsupportedError(err) {
		if !attempt.forcedCap && p.tracker != nil {
			p.tracker.SetIPv6Capability(attempt.candID, telemetry.IPv6Unsupported)
		}
		return nil, err, false, true
	}
	if p.tracker != nil {
		p.tracker.RecordDial(attempt.candID, targetHost, 0, err)
	}
	return nil, err, false, false
}

func (p *PoolOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if p.provider == nil {
		return nil, errors.New("node provider is nil")
	}

	udpSourceKey := ""
	if inboundCtx := adapter.ContextFrom(ctx); inboundCtx != nil && inboundCtx.Source.Port != 0 {
		udpSourceKey = inboundCtx.Source.String()
	}

	targetHost := extractTargetHost(ctx, destination)
	if p.blocker != nil && targetHost != "" && p.blocker.ShouldBlock(targetHost) {
		return nil, syscall.EPERM
	}

	tagKey := p.poolTag
	if tagKey == "" {
		tagKey = p.tag
	}

	ordered := p.resolveOrderedCandidates(targetHost)
	if len(ordered) == 0 {
		if udpSourceKey != "" && p.blocker != nil && p.blocker.Logger() != nil {
			p.blocker.Logger().AnnotateBySource(udpSourceKey, "节点未启动")
		}
		return nil, fmt.Errorf("no active proxy candidates for UDP packet in pool %s", tagKey)
	}

	sniffedDomain := extractSniffedDomain(ctx)
	attempts := p.buildDialAttempts(ordered, destination, sniffedDomain)
	if destination.IsIPv6() && len(attempts) == 0 {
		if udpSourceKey != "" && p.blocker != nil && p.blocker.Logger() != nil {
			p.blocker.Logger().AnnotateBySource(udpSourceKey, "无支持 IPv6 的节点")
		}
		return nil, fmt.Errorf("no IPv6-capable candidates available for UDP packet in %s", p.tag)
	}

	packetCtx := withPoolDial(ctx)
	var lastErr error
	var domainRetry []poolDialAttempt

	for _, attempt := range attempts {
		conn, err, abort, v6Unsupported := p.listenPacketAttempt(ctx, packetCtx, destination, sniffedDomain, targetHost, udpSourceKey, attempt)
		if abort {
			return nil, err
		}
		if err == nil && conn != nil {
			return conn, nil
		}
		if v6Unsupported && sniffedDomain != "" && !attempt.useDomainFallback {
			domainRetry = append(domainRetry, poolDialAttempt{
				candID:            attempt.candID,
				useDomainFallback: true,
				forcedCap:         attempt.forcedCap,
			})
		}
		if err != nil {
			lastErr = err
		}
	}

	for _, retry := range domainRetry {
		conn, err, abort, _ := p.listenPacketAttempt(ctx, packetCtx, destination, sniffedDomain, targetHost, udpSourceKey, retry)
		if abort {
			return nil, err
		}
		if err == nil && conn != nil {
			return conn, nil
		}
		if err != nil {
			lastErr = err
		}
	}

	if lastErr == nil {
		lastErr = errors.New("all candidates skipped for UDP")
	}
	if udpSourceKey != "" && p.blocker != nil && p.blocker.Logger() != nil {
		p.blocker.Logger().AnnotateBySource(udpSourceKey, formatConnectionError(lastErr))
	}
	return nil, fmt.Errorf("all candidates failed UDP in %s: %w", p.tag, lastErr)
}

const (
	minValidFirstRTT = 2 * time.Millisecond
	maxValidFirstRTT = 10 * time.Second
)

var (
	firstPacketTimeout       = 8 * time.Second
	firstPacketStall         = 3500 * time.Millisecond
	nonTLSFirstPacketTimeout = 60 * time.Second
)

var errFirstPacketAborted = errors.New("connection closed before receiving first response byte")
var errPreWriteAborted = errors.New("connection closed before sending request data")

type firstRTTConn struct {
	net.Conn
	dialCtx    context.Context
	onResult   func(rtt time.Duration, isTLS bool, err error)
	onStall    func()
	writeTime  time.Time
	hasWritten bool
	isTLS      bool
	done       bool
	stalled    bool
	stallTimer *time.Timer
	mu         sync.Mutex
}

// isTLSClientHello checks if the payload starts with a TLS ClientHello record.
func isTLSClientHello(b []byte) bool {
	// TLS Record Layer:
	// b[0] == 0x16 (ContentType: Handshake)
	// b[1] == 0x03 (TLS protocol major version 3: SSLv3, TLS 1.0, 1.1, 1.2, 1.3)
	// b[5] == 0x01 (HandshakeType: ClientHello)
	return len(b) >= 6 && b[0] == 0x16 && b[1] == 0x03 && b[5] == 0x01
}

func wrapFirstRTTConn(conn net.Conn, onResult func(rtt time.Duration, isTLS bool, err error), onStall ...func()) net.Conn {
	if conn == nil {
		return nil
	}
	var stallFn func()
	if len(onStall) > 0 {
		stallFn = onStall[0]
	}
	return &firstRTTConn{
		Conn:     conn,
		onResult: onResult,
		onStall:  stallFn,
	}
}

func (c *firstRTTConn) Write(b []byte) (int, error) {
	if len(b) > 0 {
		c.mu.Lock()
		if !c.hasWritten {
			c.hasWritten = true
			c.isTLS = isTLSClientHello(b)
			c.writeTime = time.Now()
			if c.isTLS {
				if firstPacketTimeout > 0 {
					_ = c.Conn.SetReadDeadline(time.Now().Add(firstPacketTimeout))
				}
				if c.onStall != nil && firstPacketStall > 0 {
					c.stallTimer = time.AfterFunc(firstPacketStall, func() {
						c.mu.Lock()
						if !c.done && c.hasWritten && !c.stalled {
							c.stalled = true
							c.mu.Unlock()
							if c.onStall != nil {
								c.onStall()
							}
							return
						}
						c.mu.Unlock()
					})
				}
			} else {
				// Non-TLS traffic (plaintext HTTP, arbitrary TCP):
				// Response latency includes server application computation time (e.g. AI inference, slow search).
				// 1. Do not arm aggressive 3.5s in-flight stall timer to avoid false degradation / affinity eviction.
				// 2. Apply relaxed deadline (default 60s) instead of 8s to prevent aborting slow endpoints.
				if nonTLSFirstPacketTimeout > 0 {
					_ = c.Conn.SetReadDeadline(time.Now().Add(nonTLSFirstPacketTimeout))
				}
			}
		}
		c.mu.Unlock()
	}
	n, err := c.Conn.Write(b)
	if err != nil {
		c.mu.Lock()
		if !c.done && c.hasWritten {
			c.done = true
			if c.stallTimer != nil {
				c.stallTimer.Stop()
			}
			_ = c.Conn.SetReadDeadline(time.Time{})
			var elapsed time.Duration
			if !c.writeTime.IsZero() {
				elapsed = time.Since(c.writeTime)
			}
			isTLS := c.isTLS
			c.mu.Unlock()
			if c.onResult != nil {
				c.onResult(elapsed, isTLS, err)
			}
			return n, err
		}
		c.mu.Unlock()
	}
	return n, err
}

func (c *firstRTTConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.mu.Lock()
		if !c.done && c.hasWritten && !c.writeTime.IsZero() {
			c.done = true
			if c.stallTimer != nil {
				c.stallTimer.Stop()
			}
			_ = c.Conn.SetReadDeadline(time.Time{})
			rtt := time.Since(c.writeTime)
			isTLS := c.isTLS
			c.mu.Unlock()
			if c.onResult != nil {
				// Report the real measured RTT; consumers decide whether it is a valid tracker sample.
				c.onResult(rtt, isTLS, nil)
			}
		} else {
			c.mu.Unlock()
		}
		return n, err
	}
	if err != nil {
		c.mu.Lock()
		if !c.done && c.hasWritten {
			c.done = true
			if c.stallTimer != nil {
				c.stallTimer.Stop()
			}
			_ = c.Conn.SetReadDeadline(time.Time{})
			var elapsed time.Duration
			if !c.writeTime.IsZero() {
				elapsed = time.Since(c.writeTime)
			}
			isTLS := c.isTLS
			c.mu.Unlock()
			if c.onResult != nil {
				c.onResult(elapsed, isTLS, err)
			}
			return n, err
		}
		c.mu.Unlock()
	}
	return n, err
}

func (c *firstRTTConn) Close() error {
	c.mu.Lock()
	if c.stallTimer != nil {
		c.stallTimer.Stop()
	}
	_ = c.Conn.SetReadDeadline(time.Time{})
	if !c.done {
		c.done = true
		hasWritten := c.hasWritten
		var elapsed time.Duration
		if !c.writeTime.IsZero() {
			elapsed = time.Since(c.writeTime)
		}
		isTLS := c.isTLS
		dialCtx := c.dialCtx
		c.mu.Unlock()
		if c.onResult != nil {
			closeErr := errFirstPacketAborted
			if !hasWritten {
				closeErr = errPreWriteAborted
			} else if dialCtx != nil && errors.Is(dialCtx.Err(), context.Canceled) {
				closeErr = context.Canceled
			}
			c.onResult(elapsed, isTLS, closeErr)
		}
	} else {
		c.mu.Unlock()
	}
	return c.Conn.Close()
}

func (c *firstRTTConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
