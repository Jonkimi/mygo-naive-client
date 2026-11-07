package boxengine

import (
	"context"
	"net"
	"net/netip"
	"strings"

	"naive-client/internal/blocker"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	boxDNS "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	N "github.com/sagernet/sing/common/network"
)

type blockerTransportRegistry struct {
	underlying adapter.DNSTransportRegistry
	blocker    *blocker.Engine
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
	if r.blocker == nil {
		return tr, nil
	}
	return &blockerDNSTransport{
		underlying: tr,
		blocker:    r.blocker,
	}, nil
}

type blockerDNSTransport struct {
	underlying adapter.DNSTransport
	blocker    *blocker.Engine
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
	return t.underlying.Exchange(ctx, message)
}

func (t *blockerDNSTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	if len(message.Question) > 0 {
		if resp, blocked := t.handleQuery(message.Question[0]); blocked {
			resp.Id = message.Id
			callback(resp, nil)
			return
		}
	}
	t.underlying.ExchangeAsync(ctx, message, callback)
}

// BlockerConnectionTracker intercepts routed connections and logs/blocks based on blocker rules.
type BlockerConnectionTracker struct {
	blocker *blocker.Engine
}

func (t *BlockerConnectionTracker) recordConnection(target string, matchedRule adapter.Rule, matchOutbound adapter.Outbound) bool {
	blocked, rule, verdict := t.blocker.Evaluate(target)
	chain := formatGatewayChain(matchedRule, matchOutbound, blocked, rule)
	if t.blocker.Logger() != nil {
		t.blocker.Logger().RecordWithChain(target, blocker.SourceGateway, verdict, rule, chain)
	}
	return blocked
}

func (t *BlockerConnectionTracker) RoutedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	if t.blocker == nil {
		return conn
	}
	target := extractDomainFromMetadata(metadata)
	if target == "" {
		return conn
	}
	if t.recordConnection(target, matchedRule, matchOutbound) {
		_ = conn.Close()
	}
	return conn
}

func (t *BlockerConnectionTracker) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) N.PacketConn {
	if t.blocker == nil {
		return conn
	}
	target := extractDomainFromMetadata(metadata)
	if target == "" {
		return conn
	}
	if t.recordConnection(target, matchedRule, matchOutbound) {
		_ = conn.Close()
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

func formatGatewayChain(matchedRule adapter.Rule, matchOutbound adapter.Outbound, blocked bool, blockerRule string) string {
	if blocked {
		if blockerRule != "" {
			return blockerRule + " -> block"
		}
		return "block"
	}
	rulePart := formatRouteRule(matchedRule)
	outboundPart := "direct"
	if matchOutbound != nil && matchOutbound.Tag() != "" {
		outboundPart = matchOutbound.Tag()
	}
	return rulePart + " -> " + outboundPart
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
		return "rule_set(geosite-cn) -> domestic-doh"
	case "remote-doh":
		return "final -> remote-doh"
	case "tailscale-dns", "tailscale-host-dns":
		return "domain_suffix(ts.net) -> " + serverTag
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
