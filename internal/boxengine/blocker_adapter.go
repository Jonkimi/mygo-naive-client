package boxengine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"naive-client/internal/blocker"
	"naive-client/internal/routing"
	"naive-client/internal/tailnet"
	"naive-client/internal/telemetry"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	boxDNS "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type blockerTransportRegistry struct {
	underlying         adapter.DNSTransportRegistry
	blocker            *blocker.Engine
	fm                 *telemetry.FailureMonitor
	tailnetSuffix      string
	tailnetHostRecords map[string][]string
}

func (r *blockerTransportRegistry) OptionTypes() []string {
	return r.underlying.OptionTypes()
}

func (r *blockerTransportRegistry) CreateOptions(transportType string) (any, bool) {
	return r.underlying.CreateOptions(transportType)
}

func (r *blockerTransportRegistry) CreateDNSTransport(ctx context.Context, logger log.ContextLogger, tag string, transportType string, options any) (adapter.DNSTransport, error) {
	tr, err := r.underlying.CreateDNSTransport(ctx, logger, tag, transportType, options)
	if err != nil {
		return nil, err
	}
	if tag == "tailscale-host-dns" {
		tr = newTailscaleHostDNSTransport(tr, r.tailnetSuffix, r.tailnetHostRecords)
	}
	if r.blocker == nil && r.fm == nil {
		return tr, nil
	}
	return &blockerDNSTransport{
		underlying: tr,
		blocker:    r.blocker,
		fm:         r.fm,
	}, nil
}

const tailscaleHostDNSRecordFallbackTimeout = 1500 * time.Millisecond

// tailscaleHostDNSTransport wraps tailscale-host-dns to support single-label MagicDNS
// search-domain expansion and fallback resolution from cached LocalAPI host records.
type tailscaleHostDNSTransport struct {
	underlying     adapter.DNSTransport
	magicDNSSuffix string
	hostRecords    map[string][]netip.Addr
}

func newTailscaleHostDNSTransport(underlying adapter.DNSTransport, magicDNSSuffix string, rawRecords map[string][]string) *tailscaleHostDNSTransport {
	parsed := make(map[string][]netip.Addr, len(rawRecords))
	for k, vals := range rawRecords {
		normKey := tailnet.NormalizeHost(k)
		if normKey == "" {
			continue
		}
		var addrs []netip.Addr
		for _, rawIP := range vals {
			if addr, err := netip.ParseAddr(strings.TrimSpace(rawIP)); err == nil {
				addrs = append(addrs, addr)
			}
		}
		if len(addrs) > 0 {
			parsed[normKey] = addrs
		}
	}
	return &tailscaleHostDNSTransport{
		underlying:     underlying,
		magicDNSSuffix: tailnet.NormalizeHost(magicDNSSuffix),
		hostRecords:    parsed,
	}
}

func (t *tailscaleHostDNSTransport) Type() string {
	return t.underlying.Type()
}

func (t *tailscaleHostDNSTransport) Tag() string {
	return t.underlying.Tag()
}

func (t *tailscaleHostDNSTransport) Dependencies() []string {
	return t.underlying.Dependencies()
}

func (t *tailscaleHostDNSTransport) Upstream() any {
	return t.underlying
}

func (t *tailscaleHostDNSTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return t.underlying.Start(stage, scope)
}

func (t *tailscaleHostDNSTransport) Reset() {
	t.underlying.Reset()
}

func (t *tailscaleHostDNSTransport) lookupHostRecord(q mDNS.Question, messageID uint16) (*mDNS.Msg, bool) {
	if len(t.hostRecords) == 0 {
		return nil, false
	}
	norm := tailnet.NormalizeHost(q.Name)
	addrs, ok := t.hostRecords[norm]
	if !ok && norm != "" && !strings.Contains(norm, ".") && t.magicDNSSuffix != "" {
		addrs, ok = t.hostRecords[norm+"."+t.magicDNSSuffix]
	}
	if !ok {
		return nil, false
	}
	return boxDNS.FixedResponse(messageID, q, addrs, 30), true
}

func restoreDNSResponseName(resp *mDNS.Msg, fromName, toName string) {
	if resp == nil {
		return
	}
	for i := range resp.Question {
		if strings.EqualFold(resp.Question[i].Name, fromName) {
			resp.Question[i].Name = toName
		}
	}
	rewriteRRs := func(rrs []mDNS.RR) {
		for _, rr := range rrs {
			if rr == nil {
				continue
			}
			hdr := rr.Header()
			if strings.EqualFold(hdr.Name, fromName) {
				hdr.Name = toName
			}
		}
	}
	rewriteRRs(resp.Answer)
	rewriteRRs(resp.Ns)
	rewriteRRs(resp.Extra)
}

func (t *tailscaleHostDNSTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	if message == nil || len(message.Question) == 0 {
		return t.underlying.Exchange(ctx, message)
	}
	origQ := message.Question[0]
	fallbackResp, hasHostRecord := t.lookupHostRecord(origQ, message.Id)

	queryCtx := ctx
	var cancel context.CancelFunc
	if hasHostRecord {
		queryCtx, cancel = context.WithTimeout(ctx, tailscaleHostDNSRecordFallbackTimeout)
		defer cancel()
	}

	norm := tailnet.NormalizeHost(origQ.Name)
	isSingleLabel := norm != "" && !strings.Contains(norm, ".") && norm != "localhost" && net.ParseIP(norm) == nil

	var resp *mDNS.Msg
	var err error

	if isSingleLabel && t.magicDNSSuffix != "" {
		expandedName := mDNS.Fqdn(norm + "." + t.magicDNSSuffix)
		expandedMsg := message.Copy()
		expandedMsg.Question[0].Name = expandedName
		resp, err = t.underlying.Exchange(queryCtx, expandedMsg)
		if err == nil && resp != nil && resp.Rcode == mDNS.RcodeSuccess {
			restoreDNSResponseName(resp, expandedName, origQ.Name)
			return resp, nil
		}
		// Only retry the unexpanded single-label name upstream if 100.100.100.100 actually
		// responded cleanly with a negative code (e.g., LAN search-domain host forwarded by Tailscale).
		if err == nil && queryCtx.Err() == nil {
			rawResp, rawErr := t.underlying.Exchange(queryCtx, message)
			if rawErr == nil && rawResp != nil && rawResp.Rcode == mDNS.RcodeSuccess {
				return rawResp, nil
			}
			if rawErr != nil || rawResp != nil {
				resp, err = rawResp, rawErr
			}
		}
	} else {
		resp, err = t.underlying.Exchange(queryCtx, message)
		if err == nil && resp != nil && resp.Rcode == mDNS.RcodeSuccess {
			return resp, nil
		}
	}

	if hasHostRecord && ctx.Err() == nil {
		return fallbackResp, nil
	}
	return resp, err
}

func (t *tailscaleHostDNSTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	go func() {
		resp, err := t.Exchange(ctx, message)
		callback(resp, err)
	}()
}

type blockerDNSTransport struct {
	underlying adapter.DNSTransport
	blocker    *blocker.Engine
	fm         *telemetry.FailureMonitor
}

func (t *blockerDNSTransport) Type() string {
	return t.underlying.Type()
}

func (t *blockerDNSTransport) Tag() string {
	return t.underlying.Tag()
}

func (t *blockerDNSTransport) Dependencies() []string {
	return t.underlying.Dependencies()
}

func (t *blockerDNSTransport) Upstream() any {
	return t.underlying
}

func (t *blockerDNSTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return t.underlying.Start(stage, scope)
}

func (t *blockerDNSTransport) Reset() {
	t.underlying.Reset()
}

func (t *blockerDNSTransport) handleQuery(q mDNS.Question) (*mDNS.Msg, bool, int64) {
	if t.blocker == nil {
		return nil, false, 0
	}
	domain := strings.Trim(q.Name, ".")
	blocked, rule, verdict := t.blocker.Evaluate(domain)
	chain := formatDNSChain(t.underlying.Tag(), blocked, rule)
	var logID int64
	if t.blocker.Logger() != nil {
		logID = t.blocker.Logger().RecordWithChain(domain, blocker.SourceDNS, verdict, rule, chain)
	}
	if blocked {
		var addrs []netip.Addr
		if q.Qtype == mDNS.TypeAAAA {
			addrs = []netip.Addr{netip.IPv6Unspecified()}
		} else {
			addrs = []netip.Addr{netip.IPv4Unspecified()}
		}
		return boxDNS.FixedResponse(0, q, addrs, 60), true, logID
	}
	return nil, false, logID
}

func (t *blockerDNSTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	var logID int64
	if len(message.Question) > 0 {
		var resp *mDNS.Msg
		var blocked bool
		resp, blocked, logID = t.handleQuery(message.Question[0])
		if blocked {
			resp.Id = message.Id
			return resp, nil
		}
	}
	start := time.Now()
	resp, err := t.underlying.Exchange(ctx, message)
	duration := time.Since(start)
	if t.blocker != nil && t.blocker.Logger() != nil && logID > 0 {
		t.blocker.Logger().SetDurationByLogID(logID, duration)
		if err != nil {
			t.blocker.Logger().AnnotateByLogID(logID, "DNS查询失败")
		}
	}
	if err != nil && t.fm != nil && len(message.Question) > 0 {
		domain := strings.Trim(message.Question[0].Name, ".")
		t.fm.Record(telemetry.FailureEvent{
			Category:       telemetry.FailureDNS,
			Target:         domain,
			OriginalAction: "dns",
			Error:          err,
		})
	}
	return resp, err
}

func (t *blockerDNSTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	var logID int64
	if len(message.Question) > 0 {
		var resp *mDNS.Msg
		var blocked bool
		resp, blocked, logID = t.handleQuery(message.Question[0])
		if blocked {
			resp.Id = message.Id
			callback(resp, nil)
			return
		}
	}
	start := time.Now()
	t.underlying.ExchangeAsync(ctx, message, func(resp *mDNS.Msg, err error) {
		duration := time.Since(start)
		if t.blocker != nil && t.blocker.Logger() != nil && logID > 0 {
			t.blocker.Logger().SetDurationByLogID(logID, duration)
			if err != nil {
				t.blocker.Logger().AnnotateByLogID(logID, "DNS查询失败")
			}
		}
		if err != nil && t.fm != nil && len(message.Question) > 0 {
			domain := strings.Trim(message.Question[0].Name, ".")
			t.fm.Record(telemetry.FailureEvent{
				Category:       telemetry.FailureDNS,
				Target:         domain,
				OriginalAction: "dns",
				Error:          err,
			})
		}
		callback(resp, err)
	})
}

// blockerOutbound wraps an outbound to intercept blocked connections before dialing remote.
type blockerOutbound struct {
	adapter.Outbound
	blocker  *blocker.Engine
	fm       *telemetry.FailureMonitor
	provider NodeProvider
}

func startWrappedOutbound(ob adapter.Outbound, stage adapter.StartStage, scope *adapter.Scope) error {
	if lifecycle, ok := ob.(adapter.Lifecycle); ok {
		return lifecycle.Start(stage, scope)
	}
	return nil
}

func (o *blockerOutbound) Upstream() any {
	return o.Outbound
}

// Start forwards sing-box lifecycle hooks so wrapped outbounds register close cleanups and start cleanly.
func (o *blockerOutbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return startWrappedOutbound(o.Outbound, stage, scope)
}

func (o *blockerOutbound) InterfaceUpdated(ctx context.Context) {
	if listener, ok := o.Outbound.(adapter.InterfaceUpdateListener); ok {
		listener.InterfaceUpdated(ctx)
	}
}

func shouldAnnotateDirectOutbound(ob adapter.Outbound) bool {
	if ob == nil {
		return false
	}
	if _, isPool := ob.(*PoolOutbound); isPool {
		return false
	}
	tag := ob.Tag()
	return tag != "" && tag != "block" && !strings.HasPrefix(tag, "PROXY_")
}

func (o *blockerOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	host := extractTargetHost(ctx, destination)
	if o.blocker != nil && host != "" && o.blocker.ShouldBlock(host) {
		return nil, syscall.EPERM
	}
	start := time.Now()
	conn, err := o.Outbound.DialContext(ctx, network, destination)
	rtt := time.Since(start)
	annotate := !isPoolDialContext(ctx) && shouldAnnotateDirectOutbound(o.Outbound)
	if err != nil && !errors.Is(err, syscall.EPERM) {
		if o.blocker != nil && o.blocker.Logger() != nil && annotate {
			if inboundCtx := adapter.ContextFrom(ctx); inboundCtx != nil && inboundCtx.Source.Port != 0 {
				if rtt <= 0 {
					rtt = time.Microsecond
				}
				o.blocker.Logger().AnnotateFailureBySource(inboundCtx.Source.String(), formatConnectionError(err), rtt)
			}
		}
		if o.fm != nil && o.Outbound.Tag() == "direct" {
			o.fm.Record(telemetry.FailureEvent{
				Category:       telemetry.FailureDirect,
				Target:         host,
				Port:           destination.Port,
				OriginalAction: "direct",
				Error:          err,
			})
		}
	} else if err == nil && annotate {
		isSidecar := network == "tcp" && o.provider != nil && strings.HasPrefix(o.Outbound.Tag(), "node-") && o.provider.IsSidecar(o.Outbound.Tag())
		if isSidecar {
			sourceKey := ""
			if inboundCtx := adapter.ContextFrom(ctx); inboundCtx != nil && inboundCtx.Source.Port != 0 {
				sourceKey = inboundCtx.Source.String()
			}
			if sourceKey != "" && o.blocker != nil && o.blocker.Logger() != nil {
				conn = wrapFirstRTTConn(conn, func(realRTT time.Duration, isTLS bool, firstErr error) {
					if o.blocker == nil || o.blocker.Logger() == nil || sourceKey == "" {
						return
					}
					if firstErr != nil {
						o.blocker.Logger().AnnotateFailureBySource(sourceKey, formatConnectionError(firstErr), realRTT)
					} else {
						o.blocker.Logger().AnnotateDurationBySource(sourceKey, realRTT)
					}
				})
			}
		} else if o.blocker != nil && o.blocker.Logger() != nil {
			if inboundCtx := adapter.ContextFrom(ctx); inboundCtx != nil && inboundCtx.Source.Port != 0 {
				if rtt <= 0 {
					rtt = time.Microsecond
				}
				o.blocker.Logger().AnnotateDurationBySource(inboundCtx.Source.String(), rtt)
			}
		}
	}
	return conn, err
}

func (o *blockerOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	host := extractTargetHost(ctx, destination)
	if o.blocker != nil && host != "" && o.blocker.ShouldBlock(host) {
		return nil, syscall.EPERM
	}
	conn, err := o.Outbound.ListenPacket(ctx, destination)
	if o.blocker != nil && o.blocker.Logger() != nil && !isPoolDialContext(ctx) && shouldAnnotateDirectOutbound(o.Outbound) {
		if inboundCtx := adapter.ContextFrom(ctx); inboundCtx != nil && inboundCtx.Source.Port != 0 {
			if err != nil {
				o.blocker.Logger().AnnotateBySource(inboundCtx.Source.String(), formatConnectionError(err))
			} else {
				o.blocker.Logger().UnbindSourceConn(inboundCtx.Source.String())
			}
		}
	}
	return conn, err
}

type rejectOutbound struct {
	adapter.Outbound
}

func (o *rejectOutbound) Upstream() any {
	return o.Outbound
}

func (o *rejectOutbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return startWrappedOutbound(o.Outbound, stage, scope)
}

func (o *rejectOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, syscall.ECONNREFUSED
}

func (o *rejectOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, syscall.ECONNREFUSED
}

type blockerOutboundRegistry struct {
	underlying adapter.OutboundRegistry
	blocker    *blocker.Engine
	fm         *telemetry.FailureMonitor
	provider   NodeProvider
}

func (r *blockerOutboundRegistry) OptionTypes() []string {
	return r.underlying.OptionTypes()
}

func (r *blockerOutboundRegistry) CreateOptions(outboundType string) (any, bool) {
	return r.underlying.CreateOptions(outboundType)
}

func (r *blockerOutboundRegistry) CreateOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) (adapter.Outbound, error) {
	ob, err := r.underlying.CreateOutbound(ctx, router, logger, tag, outboundType, options)
	if err != nil {
		return nil, err
	}
	if tag == "block" || outboundType == "block" {
		return &rejectOutbound{Outbound: ob}, nil
	}
	// Only wrap direct outbounds; pooled/proxy/WARP traffic is already checked and
	// annotated in BlockerConnectionTracker and PoolOutbound, so leaving those
	// outbounds unwrapped preserves native sing-box Lifecycle and connection pooling.
	if outboundType != "direct" {
		return ob, nil
	}
	if r.blocker == nil && r.fm == nil {
		return ob, nil
	}
	return &blockerOutbound{
		Outbound: ob,
		blocker:  r.blocker,
		fm:       r.fm,
		provider: r.provider,
	}, nil
}

// BlockerConnectionTracker intercepts routed connections and logs/blocks based on blocker rules.
type BlockerConnectionTracker struct {
	blocker            *blocker.Engine
	nodeNameResolver   func(nodeID string) string
	chainedWarpChecker func(nodeID string) bool
}

func (t *BlockerConnectionTracker) recordConnection(target string, matchedRule adapter.Rule, matchOutbound adapter.Outbound) bool {
	blocked, _ := t.recordConnectionWithID(target, matchedRule, matchOutbound, "tcp")
	return blocked
}

func (t *BlockerConnectionTracker) recordConnectionWithID(target string, matchedRule adapter.Rule, matchOutbound adapter.Outbound, network string) (bool, int64) {
	isBlockOutbound := matchOutbound != nil && matchOutbound.Tag() == "block"
	blocked, rule, verdict := t.blocker.Evaluate(target)
	if isBlockOutbound {
		blocked = true
		verdict = blocker.VerdictBlocked
		if rule == "" {
			if matchedRule != nil {
				rule = formatRouteRule(matchedRule)
			} else {
				rule = "routing:block"
			}
		}
	}
	chain := formatGatewayChain(target, matchedRule, matchOutbound, blocked, rule, t.nodeNameResolver, t.chainedWarpChecker)
	var logID int64
	if t.blocker.Logger() != nil {
		logID = t.blocker.Logger().RecordWithChain(target, blocker.SourceGateway, verdict, rule, chain)
		t.blocker.Logger().SetNetworkByLogID(logID, network)
	}
	return blocked, logID
}

func (t *BlockerConnectionTracker) RoutedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	if t.blocker == nil {
		return conn
	}
	target := extractDomainFromMetadata(metadata)
	if target == "" && metadata.Destination.Addr.IsValid() {
		if dnsRouter := service.FromContext[adapter.DNSRouter](ctx); dnsRouter != nil {
			if rev, ok := dnsRouter.LookupReverseMapping(metadata.Destination.Addr); ok && rev != "" {
				target = strings.Trim(strings.ToLower(strings.TrimSpace(rev)), ".")
			}
		}
	}
	if target == "" {
		if metadata.Destination.Addr.IsValid() {
			target = metadata.Destination.Addr.String()
		} else if metadata.Destination.Fqdn != "" {
			target = metadata.Destination.Fqdn
		}
	}

	if target != "" {
		blocked, logID := t.recordConnectionWithID(target, matchedRule, matchOutbound, "tcp")
		if blocked {
			_ = conn.Close()
			return conn
		}
		if logID > 0 && metadata.Source.Port != 0 && t.blocker != nil && t.blocker.Logger() != nil {
			t.blocker.Logger().BindSourceConn(metadata.Source.String(), logID)
		}
	}
	return conn
}

func (t *BlockerConnectionTracker) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) N.PacketConn {
	if t.blocker == nil {
		return conn
	}
	target := extractDomainFromMetadata(metadata)
	if target == "" && metadata.Destination.Addr.IsValid() {
		if dnsRouter := service.FromContext[adapter.DNSRouter](ctx); dnsRouter != nil {
			if rev, ok := dnsRouter.LookupReverseMapping(metadata.Destination.Addr); ok && rev != "" {
				target = strings.Trim(strings.ToLower(strings.TrimSpace(rev)), ".")
			}
		}
	}
	if target == "" {
		if metadata.Destination.Addr.IsValid() {
			target = metadata.Destination.Addr.String()
		} else if metadata.Destination.Fqdn != "" {
			target = metadata.Destination.Fqdn
		}
	}
	if target != "" {
		blocked, logID := t.recordConnectionWithID(target, matchedRule, matchOutbound, "udp")
		if blocked {
			_ = conn.Close()
			return conn
		}
		if logID > 0 && metadata.Source.Port != 0 && t.blocker != nil && t.blocker.Logger() != nil {
			t.blocker.Logger().BindSourceConn(metadata.Source.String(), logID)
		}
	}
	return conn
}

func (t *BlockerConnectionTracker) RoutedFlow(ctx context.Context, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) tun.FlowTracker {
	return nil
}

func formatRouteRule(r adapter.Rule) string {
	if r == nil {
		return "final"
	}
	s := strings.TrimSpace(r.String())
	if s == "" {
		return "final"
	}
	if strings.HasPrefix(s, "rule_set=") {
		tag := strings.TrimPrefix(s, "rule_set=")
		tag = strings.Trim(tag, "[]")
		return "rule_set(" + tag + ")"
	}
	if strings.HasPrefix(s, "domain_suffix=") {
		tag := strings.TrimPrefix(s, "domain_suffix=")
		tag = strings.Trim(tag, "[]")
		return "domain_suffix(" + tag + ")"
	}
	if strings.HasPrefix(s, "domain=") {
		tag := strings.TrimPrefix(s, "domain=")
		tag = strings.Trim(tag, "[]")
		return "domain(" + tag + ")"
	}
	if strings.HasPrefix(s, "ip_cidr=") {
		tag := strings.TrimPrefix(s, "ip_cidr=")
		tag = strings.Trim(tag, "[]")
		return "ip_cidr(" + tag + ")"
	}
	return s
}

func formatGatewayChain(target string, matchedRule adapter.Rule, matchOutbound adapter.Outbound, blocked bool, blockerRule string, nodeNameResolver func(nodeID string) string, chainedWarpChecker ...func(nodeID string) bool) string {
	if blocked {
		if blockerRule != "" {
			return blockerRule + " -> block"
		}
		return "block"
	}
	var isChainedWarp func(string) bool
	if len(chainedWarpChecker) > 0 {
		isChainedWarp = chainedWarpChecker[0]
	}
	rulePart := formatRouteRule(matchedRule)
	outboundPart := "direct"
	if matchOutbound != nil && matchOutbound.Tag() != "" {
		tag := matchOutbound.Tag()
		if strings.HasPrefix(tag, "node-") && nodeNameResolver != nil {
			if nodeName := nodeNameResolver(tag); nodeName != "" {
				outboundPart = nodeName
			} else {
				outboundPart = tag
			}
		} else {
			outboundPart = tag
		}
		if strings.HasPrefix(tag, "node-") && isChainedWarp != nil && isChainedWarp(tag) {
			outboundPart += " -> WARP"
		}
	}
	chain := rulePart + " -> " + outboundPart
	current := matchOutbound
	for {
		if bo, ok := current.(*blockerOutbound); ok {
			current = bo.Outbound
			continue
		}
		break
	}
	if pool, ok := current.(*PoolOutbound); ok {
		targets := pool.Targets()
		if len(targets) == 1 && targets[0].Kind == routing.TargetNode && !pool.FallbackToPool() {
			candID := pool.SelectCandidate(target)
			if candID == "" {
				candID = targets[0].Value
			}
			nodeName := candID
			if nodeNameResolver != nil {
				if resolved := nodeNameResolver(candID); resolved != "" {
					nodeName = resolved
				}
			}
			if nodeName != "" {
				out := rulePart + " -> " + nodeName
				if isChainedWarp != nil && isChainedWarp(candID) {
					out += " -> WARP"
				}
				return out
			}
		}
		if strings.HasPrefix(outboundPart, "POOL:") {
			if pool.DispatchPolicy() == routing.DispatchOrder {
				chain = rulePart + " -> POOL(order)"
			} else {
				chain = rulePart + " -> POOL"
			}
		}
		if candID := pool.SelectCandidate(target); candID != "" {
			nodeName := candID
			if nodeNameResolver != nil {
				if resolved := nodeNameResolver(candID); resolved != "" {
					nodeName = resolved
				}
			}
			if nodeName != "" {
				chain = chain + " -> " + nodeName
				if isChainedWarp != nil && isChainedWarp(candID) {
					chain += " -> WARP"
				}
			}
		}
	}
	return chain
}

func formatDNSChain(serverTag string, blocked bool, blockerRule string) string {
	if blocked {
		if blockerRule != "" {
			return blockerRule + " -> 0.0.0.0"
		}
		return "block -> 0.0.0.0"
	}
	switch {
	case serverTag == "domestic-doh":
		return "direct -> domestic-doh"
	case serverTag == "remote-doh" || strings.HasPrefix(serverTag, "remote-doh-"):
		return "proxy -> " + serverTag
	case serverTag == "tailscale-dns" || serverTag == "tailscale-host-dns":
		return "tailnet -> " + serverTag
	case serverTag == "bootstrap-dns":
		return "bootstrap -> direct"
	default:
		if serverTag != "" {
			return "server(" + serverTag + ")"
		}
		return "server"
	}
}

func extractDomainFromMetadata(metadata adapter.InboundContext) string {
	d := metadata.Domain
	if d == "" && metadata.Destination.Fqdn != "" {
		d = metadata.Destination.Fqdn
	}
	if d == "" {
		return ""
	}
	d = strings.Trim(strings.ToLower(strings.TrimSpace(d)), ".")
	if net.ParseIP(d) != nil {
		return ""
	}
	return d
}
