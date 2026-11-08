package boxengine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"

	"naive-client/internal/blocker"
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
	underlying adapter.DNSTransportRegistry
	blocker    *blocker.Engine
	fm         *telemetry.FailureMonitor
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
	if r.blocker == nil && r.fm == nil {
		return tr, nil
	}
	return &blockerDNSTransport{
		underlying: tr,
		blocker:    r.blocker,
		fm:         r.fm,
	}, nil
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

func (t *blockerDNSTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return t.underlying.Start(stage, scope)
}

func (t *blockerDNSTransport) Reset() {
	t.underlying.Reset()
}

func (t *blockerDNSTransport) handleQuery(q mDNS.Question) (*mDNS.Msg, bool) {
	if t.blocker == nil {
		return nil, false
	}
	domain := strings.Trim(q.Name, ".")
	blocked, rule, verdict := t.blocker.Evaluate(domain)
	chain := formatDNSChain(t.underlying.Tag(), blocked, rule)
	if t.blocker.Logger() != nil {
		t.blocker.Logger().RecordWithChain(domain, blocker.SourceDNS, verdict, rule, chain)
	}
	if blocked {
		var addrs []netip.Addr
		if q.Qtype == mDNS.TypeAAAA {
			addrs = []netip.Addr{netip.IPv6Unspecified()}
		} else {
			addrs = []netip.Addr{netip.IPv4Unspecified()}
		}
		return boxDNS.FixedResponse(0, q, addrs, 60), true
	}
	return nil, false
}

func (t *blockerDNSTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	if len(message.Question) > 0 {
		if resp, blocked := t.handleQuery(message.Question[0]); blocked {
			resp.Id = message.Id
			return resp, nil
		}
	}
	resp, err := t.underlying.Exchange(ctx, message)
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
	if len(message.Question) > 0 {
		if resp, blocked := t.handleQuery(message.Question[0]); blocked {
			resp.Id = message.Id
			callback(resp, nil)
			return
		}
	}
	t.underlying.ExchangeAsync(ctx, message, func(resp *mDNS.Msg, err error) {
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
	blocker *blocker.Engine
	fm      *telemetry.FailureMonitor
}

func (o *blockerOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if o.blocker != nil {
		host := destination.Fqdn
		if host == "" && destination.Addr.IsValid() {
			host = destination.Addr.String()
		}
		if host != "" && o.blocker.ShouldBlock(host) {
			return nil, syscall.EPERM
		}
	}
	conn, err := o.Outbound.DialContext(ctx, network, destination)
	if err != nil && !errors.Is(err, syscall.EPERM) {
		host := destination.Fqdn
		if host == "" && destination.Addr.IsValid() {
			host = destination.Addr.String()
		}
		if o.blocker != nil && o.blocker.Logger() != nil {
			if inboundCtx := adapter.ContextFrom(ctx); inboundCtx != nil && inboundCtx.Source.Port != 0 {
				o.blocker.Logger().AnnotateBySource(inboundCtx.Source.String(), formatConnectionError(err))
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
	}
	return conn, err
}

func (o *blockerOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if o.blocker != nil {
		host := destination.Fqdn
		if host == "" && destination.Addr.IsValid() {
			host = destination.Addr.String()
		}
		if host != "" && o.blocker.ShouldBlock(host) {
			return nil, syscall.EPERM
		}
	}
	return o.Outbound.ListenPacket(ctx, destination)
}

type rejectOutbound struct {
	adapter.Outbound
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
	if r.blocker == nil && r.fm == nil {
		return ob, nil
	}
	return &blockerOutbound{
		Outbound: ob,
		blocker:  r.blocker,
		fm:       r.fm,
	}, nil
}

type sourceUnbindConn struct {
	net.Conn
	onClose func()
	once    sync.Once
}

func (c *sourceUnbindConn) Close() error {
	c.once.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
	})
	return c.Conn.Close()
}

func (c *sourceUnbindConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *sourceUnbindConn) Upstream() any {
	return c.Conn
}

func (c *sourceUnbindConn) ReaderReplaceable() bool {
	return true
}

func (c *sourceUnbindConn) WriterReplaceable() bool {
	return true
}

// BlockerConnectionTracker intercepts routed connections and logs/blocks based on blocker rules.
type BlockerConnectionTracker struct {
	blocker          *blocker.Engine
	nodeNameResolver func(nodeID string) string
}

func (t *BlockerConnectionTracker) recordConnection(target string, matchedRule adapter.Rule, matchOutbound adapter.Outbound) bool {
	blocked, _ := t.recordConnectionWithID(target, matchedRule, matchOutbound)
	return blocked
}

func (t *BlockerConnectionTracker) recordConnectionWithID(target string, matchedRule adapter.Rule, matchOutbound adapter.Outbound) (bool, int64) {
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
	chain := formatGatewayChain(target, matchedRule, matchOutbound, blocked, rule, t.nodeNameResolver)
	var logID int64
	if t.blocker.Logger() != nil {
		logID = t.blocker.Logger().RecordWithChain(target, blocker.SourceGateway, verdict, rule, chain)
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
		blocked, logID := t.recordConnectionWithID(target, matchedRule, matchOutbound)
		if blocked {
			_ = conn.Close()
			return conn
		}
		if logID > 0 && metadata.Source.Port != 0 && t.blocker != nil && t.blocker.Logger() != nil {
			sourceKey := metadata.Source.String()
			t.blocker.Logger().BindSourceConn(sourceKey, logID)
			conn = &sourceUnbindConn{
				Conn: conn,
				onClose: func() {
					t.blocker.Logger().UnbindSourceConn(sourceKey)
				},
			}
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
		if t.recordConnection(target, matchedRule, matchOutbound) {
			_ = conn.Close()
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

func formatGatewayChain(target string, matchedRule adapter.Rule, matchOutbound adapter.Outbound, blocked bool, blockerRule string, nodeNameResolver func(nodeID string) string) string {
	if blocked {
		if blockerRule != "" {
			return blockerRule + " -> block"
		}
		return "block"
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
		if candID := pool.SelectCandidate(target); candID != "" {
			nodeName := candID
			if nodeNameResolver != nil {
				if resolved := nodeNameResolver(candID); resolved != "" {
					nodeName = resolved
				}
			}
			if nodeName != "" {
				chain = chain + " -> " + nodeName
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
	switch serverTag {
	case "domestic-doh":
		return "direct -> domestic-doh"
	case "remote-doh":
		return "proxy -> remote-doh"
	case "tailscale-dns", "tailscale-host-dns":
		return "tailnet -> " + serverTag
	case "bootstrap-dns":
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
