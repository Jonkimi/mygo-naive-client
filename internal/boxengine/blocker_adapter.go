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

func (t *blockerDNSTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	if len(message.Question) > 0 && t.blocker != nil {
		q := message.Question[0]
		domain := strings.Trim(q.Name, ".")
		blocked, _ := t.blocker.AsDNS().Match(domain)
		if blocked {
			var addrs []netip.Addr
			if q.Qtype == mDNS.TypeAAAA {
				addrs = []netip.Addr{netip.IPv6Unspecified()}
			} else {
				addrs = []netip.Addr{netip.IPv4Unspecified()}
			}
			return boxDNS.FixedResponse(message.Id, q, addrs, 60), nil
		}
	}
	return t.underlying.Exchange(ctx, message)
}

func (t *blockerDNSTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	if len(message.Question) > 0 && t.blocker != nil {
		q := message.Question[0]
		domain := strings.Trim(q.Name, ".")
		blocked, _ := t.blocker.AsDNS().Match(domain)
		if blocked {
			var addrs []netip.Addr
			if q.Qtype == mDNS.TypeAAAA {
				addrs = []netip.Addr{netip.IPv6Unspecified()}
			} else {
				addrs = []netip.Addr{netip.IPv4Unspecified()}
			}
			callback(boxDNS.FixedResponse(message.Id, q, addrs, 60), nil)
			return
		}
	}
	t.underlying.ExchangeAsync(ctx, message, callback)
}

// BlockerConnectionTracker intercepts routed connections and logs/blocks based on blocker rules.
type BlockerConnectionTracker struct {
	blocker *blocker.Engine
}

func (t *BlockerConnectionTracker) RoutedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	if t.blocker == nil {
		return conn
	}
	target := extractDomainFromMetadata(metadata)
	if target == "" {
		return conn
	}
	blocked, _ := t.blocker.AsGateway().Match(target)
	if blocked {
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
	blocked, _ := t.blocker.AsGateway().Match(target)
	if blocked {
		_ = conn.Close()
	}
	return conn
}

func (t *BlockerConnectionTracker) RoutedFlow(ctx context.Context, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) tun.FlowTracker {
	return nil
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
