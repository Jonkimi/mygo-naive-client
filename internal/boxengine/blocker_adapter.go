package boxengine

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"naive-client/internal/blocker"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	boxDNS "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
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
	blocker          *blocker.Engine
	nodeNameResolver func(nodeID string) string
	recentDialsMu    sync.RWMutex
	recentDials      map[string]recentDialInfo
	ipDomains        map[string]recentIPDomainInfo
}

type recentDialInfo struct {
	nodeName  string
	timestamp time.Time
}

type recentIPDomainInfo struct {
	domain    string
	timestamp time.Time
}

// RecordIPDomain records a recent IP -> domain mapping from DNS reverse lookup so subsequent
// IP-based outbound dials can update the corresponding domain's gateway log entry.
func (t *BlockerConnectionTracker) RecordIPDomain(ipStr string, domain string) {
	if ipStr == "" || domain == "" {
		return
	}
	cleanIP := strings.TrimSpace(ipStr)
	cleanDomain := strings.Trim(strings.ToLower(strings.TrimSpace(domain)), ".")
	t.recentDialsMu.Lock()
	if t.ipDomains == nil {
		t.ipDomains = make(map[string]recentIPDomainInfo)
	}
	t.ipDomains[cleanIP] = recentIPDomainInfo{
		domain:    cleanDomain,
		timestamp: time.Now(),
	}
	if len(t.ipDomains) > 256 {
		cutoff := time.Now().Add(-10 * time.Second)
		for k, v := range t.ipDomains {
			if v.timestamp.Before(cutoff) {
				delete(t.ipDomains, k)
			}
		}
	}
	t.recentDialsMu.Unlock()
}

// ResolveIPDomain returns the domain recently associated with ipStr if within TTL.
func (t *BlockerConnectionTracker) ResolveIPDomain(ipStr string) string {
	if ipStr == "" {
		return ""
	}
	cleanIP := strings.TrimSpace(ipStr)
	t.recentDialsMu.RLock()
	defer t.recentDialsMu.RUnlock()
	if t.ipDomains == nil {
		return ""
	}
	info, ok := t.ipDomains[cleanIP]
	if !ok || time.Since(info.timestamp) > 5*time.Second {
		return ""
	}
	return info.domain
}

// RecordDialSuccess records that targetHost was successfully dialed via nodeName.
func (t *BlockerConnectionTracker) RecordDialSuccess(targetHost string, nodeName string) {
	if targetHost == "" || nodeName == "" {
		return
	}
	cleanHost := strings.Trim(strings.ToLower(strings.TrimSpace(targetHost)), ".")
	t.recentDialsMu.Lock()
	if t.recentDials == nil {
		t.recentDials = make(map[string]recentDialInfo)
	}
	t.recentDials[cleanHost] = recentDialInfo{
		nodeName:  nodeName,
		timestamp: time.Now(),
	}
	if len(t.recentDials) > 256 {
		cutoff := time.Now().Add(-10 * time.Second)
		for k, v := range t.recentDials {
			if v.timestamp.Before(cutoff) {
				delete(t.recentDials, k)
			}
		}
	}
	t.recentDialsMu.Unlock()
}

func (t *BlockerConnectionTracker) getRecentNode(targetHost string) string {
	if targetHost == "" {
		return ""
	}
	cleanHost := strings.Trim(strings.ToLower(strings.TrimSpace(targetHost)), ".")
	t.recentDialsMu.RLock()
	defer t.recentDialsMu.RUnlock()
	if t.recentDials == nil {
		return ""
	}
	info, ok := t.recentDials[cleanHost]
	if !ok || time.Since(info.timestamp) > 5*time.Second {
		return ""
	}
	return info.nodeName
}

func (t *BlockerConnectionTracker) recordConnection(target string, matchedRule adapter.Rule, matchOutbound adapter.Outbound) bool {
	blocked, rule, verdict := t.blocker.Evaluate(target)
	chain := formatGatewayChain(matchedRule, matchOutbound, blocked, rule, t.nodeNameResolver)
	if t.blocker.Logger() != nil {
		t.blocker.Logger().RecordWithChain(target, blocker.SourceGateway, verdict, rule, chain)
	}
	return blocked
}

func (t *BlockerConnectionTracker) recordConnectionWithFallback(target string, fallbackAddr string, matchedRule adapter.Rule, matchOutbound adapter.Outbound) bool {
	blocked, rule, verdict := t.blocker.Evaluate(target)
	chain := formatGatewayChain(matchedRule, matchOutbound, blocked, rule, t.nodeNameResolver)
	if !blocked {
		nodeName := ""
		if fallbackAddr != "" {
			nodeName = t.getRecentNode(fallbackAddr)
		}
		if nodeName == "" {
			nodeName = t.getRecentNode(target)
		}
		if nodeName != "" && !strings.HasSuffix(chain, " -> "+nodeName) {
			chain = chain + " -> " + nodeName
		}
	}
	if t.blocker.Logger() != nil {
		t.blocker.Logger().RecordWithChain(target, blocker.SourceGateway, verdict, rule, chain)
	}
	return blocked
}

type sniffingConn struct {
	net.Conn
	tracker       *BlockerConnectionTracker
	matchedRule   adapter.Rule
	matchOutbound adapter.Outbound
	fallbackAddr  string
	once          sync.Once
}

func (c *sniffingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.once.Do(func() {
			var meta adapter.InboundContext
			// 1. Try sniffing TLS ClientHello for SNI domain
			if sErr := sniff.TLSClientHello(context.Background(), &meta, bytes.NewReader(p[:n])); sErr == nil && meta.Domain != "" {
				target := strings.Trim(strings.ToLower(meta.Domain), ".")
				if c.tracker.recordConnectionWithFallback(target, c.fallbackAddr, c.matchedRule, c.matchOutbound) {
					_ = c.Conn.Close()
				}
				return
			}
			// 2. Try sniffing HTTP Host
			if sErr := sniff.HTTPHost(context.Background(), &meta, bytes.NewReader(p[:n])); sErr == nil && meta.Domain != "" {
				target := strings.Trim(strings.ToLower(meta.Domain), ".")
				if c.tracker.recordConnectionWithFallback(target, c.fallbackAddr, c.matchedRule, c.matchOutbound) {
					_ = c.Conn.Close()
				}
				return
			}
			// 3. Fallback to destination IP address
			if c.fallbackAddr != "" {
				if c.tracker.recordConnectionWithFallback(c.fallbackAddr, "", c.matchedRule, c.matchOutbound) {
					_ = c.Conn.Close()
				}
			}
		})
	}
	return n, err
}

func (c *sniffingConn) Close() error {
	c.once.Do(func() {
		if c.fallbackAddr != "" {
			c.tracker.recordConnection(c.fallbackAddr, c.matchedRule, c.matchOutbound)
		}
	})
	return c.Conn.Close()
}

func (t *BlockerConnectionTracker) RoutedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	if t.blocker == nil {
		return conn
	}
	// 1. If domain is already present in metadata (e.g. SOCKS5 domain, HTTP CONNECT domain)
	target := extractDomainFromMetadata(metadata)
	if target != "" {
		if t.recordConnection(target, matchedRule, matchOutbound) {
			_ = conn.Close()
		}
		return conn
	}

	// 2. Check if DNS reverse mapping has the domain for this destination IP
	if metadata.Destination.Addr.IsValid() {
		if dnsRouter := service.FromContext[adapter.DNSRouter](ctx); dnsRouter != nil {
			if rev, ok := dnsRouter.LookupReverseMapping(metadata.Destination.Addr); ok && rev != "" {
				target = strings.Trim(strings.ToLower(strings.TrimSpace(rev)), ".")
				t.RecordIPDomain(metadata.Destination.Addr.String(), target)
				if t.recordConnection(target, matchedRule, matchOutbound) {
					_ = conn.Close()
				}
				return conn
			}
		}
	}

	// 3. Neither metadata nor reverse mapping has the domain (e.g. curl -x socks5:// IP):
	// Wrap conn to sniff TLS SNI / HTTP Host upon the first read, falling back to destination IP
	var fallback string
	if metadata.Destination.Addr.IsValid() {
		fallback = metadata.Destination.Addr.String()
	} else if metadata.Destination.Fqdn != "" {
		fallback = metadata.Destination.Fqdn
	}
	return &sniffingConn{
		Conn:          conn,
		tracker:       t,
		matchedRule:   matchedRule,
		matchOutbound: matchOutbound,
		fallbackAddr:  fallback,
	}
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
				t.RecordIPDomain(metadata.Destination.Addr.String(), target)
			}
		}
		if target == "" {
			target = metadata.Destination.Addr.String()
		}
	}
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

func formatGatewayChain(matchedRule adapter.Rule, matchOutbound adapter.Outbound, blocked bool, blockerRule string, nodeNameResolver func(nodeID string) string) string {
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
