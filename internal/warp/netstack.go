package warp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
)

const nicID = 1

// ErrNoDNSRecords indicates the in-tunnel DNS server answered cleanly without any A/AAAA records.
var ErrNoDNSRecords = errors.New("no DNS records")

// Netstack provides an isolated user-space TCP/IP stack over a channel link endpoint.
type Netstack struct {
	Stack  *stack.Stack
	LinkEP *channel.Endpoint
	IPv4   netip.Addr
	IPv6   netip.Addr

	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
}

// NewNetstack creates and initializes a user-space gVisor network stack.
func NewNetstack(ipv4Str, ipv6Str string) (*Netstack, error) {
	ctx, cancel := context.WithCancel(context.Background())

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})

	// Channel buffer of 1024 packets with MTU 1280 (Cloudflare standard)
	linkEP := channel.New(1024, DefaultMTU, "")

	if err := s.CreateNIC(nicID, linkEP); err != nil {
		cancel()
		return nil, fmt.Errorf("create NIC failed: %s", err)
	}

	ns := &Netstack{
		Stack:  s,
		LinkEP: linkEP,
		ctx:    ctx,
		cancel: cancel,
	}

	cleanV4 := strings.Split(strings.TrimSpace(ipv4Str), "/")[0]
	if cleanV4 == "" {
		cleanV4 = DefaultIPv4
	}
	if parsed4, err := netip.ParseAddr(cleanV4); err == nil && parsed4.Is4() {
		ns.IPv4 = parsed4
		v4Addr := tcpip.AddrFromSlice(parsed4.AsSlice())
		_ = s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
			Protocol:          ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{Address: v4Addr, PrefixLen: 32},
		}, stack.AddressProperties{})
	}

	cleanV6 := strings.Split(strings.TrimSpace(ipv6Str), "/")[0]
	if cleanV6 == "" {
		cleanV6 = DefaultIPv6
	}
	if parsed6, err := netip.ParseAddr(cleanV6); err == nil && parsed6.Is6() {
		ns.IPv6 = parsed6
		v6Addr := tcpip.AddrFromSlice(parsed6.AsSlice())
		_ = s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
			Protocol:          ipv6.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{Address: v6Addr, PrefixLen: 128},
		}, stack.AddressProperties{})
	}

	_ = s.SetPromiscuousMode(nicID, true)
	_ = s.SetSpoofing(nicID, true)

	// Route all IPv4 and IPv6 traffic to NIC 1
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         nicID,
		},
	})

	return ns, nil
}

// InjectPacket injects an inbound raw IP packet received from the tunnel into the stack.
func (ns *Netstack) InjectPacket(raw []byte) error {
	if len(raw) == 0 {
		return nil
	}

	var proto tcpip.NetworkProtocolNumber
	version := raw[0] >> 4
	if version == 4 {
		proto = ipv4.ProtocolNumber
	} else if version == 6 {
		proto = ipv6.ProtocolNumber
	} else {
		return fmt.Errorf("unsupported IP version %d", version)
	}

	buf := buffer.MakeWithData(raw)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buf,
	})
	ns.LinkEP.InjectInbound(proto, pkt)
	pkt.DecRef()
	return nil
}

// ReadPacket reads an outbound raw IP packet from the stack destined for the tunnel.
func (ns *Netstack) ReadPacket(ctx context.Context) ([]byte, error) {
	pkt := ns.LinkEP.ReadContext(ctx)
	if pkt == nil {
		return nil, context.Canceled
	}
	defer pkt.DecRef()

	view := pkt.ToView()
	data := make([]byte, view.Size())
	copy(data, view.AsSlice())
	return data, nil
}

// DialContextTCP dials a TCP connection through the virtual user-space stack.
func (ns *Netstack) DialContextTCP(ctx context.Context, dest string) (net.Conn, error) {
	if ns.ctx.Err() != nil {
		return nil, errors.New("tunnel closed")
	}
	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port %q", portStr)
	}

	addr, err := ns.resolveHostIP(ctx, host)
	if err != nil {
		return nil, err
	}

	return ns.dialIPTCP(ctx, addr, uint16(port))
}

func (ns *Netstack) dialIPTCP(ctx context.Context, addr netip.Addr, port uint16) (net.Conn, error) {
	if ns.ctx.Err() != nil {
		return nil, errors.New("tunnel closed")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	var netProto tcpip.NetworkProtocolNumber
	var laddr tcpip.FullAddress
	if addr.Is4() {
		netProto = ipv4.ProtocolNumber
		if ns.IPv4.IsValid() {
			laddr = tcpip.FullAddress{
				NIC:  nicID,
				Addr: tcpip.AddrFromSlice(ns.IPv4.AsSlice()),
			}
		}
	} else {
		netProto = ipv6.ProtocolNumber
		if ns.IPv6.IsValid() {
			laddr = tcpip.FullAddress{
				NIC:  nicID,
				Addr: tcpip.AddrFromSlice(ns.IPv6.AsSlice()),
			}
		}
	}

	fullAddr := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(addr.AsSlice()),
		Port: port,
	}

	// Tie dial lifetime to ns.ctx so a closed tunnel fails dialing immediately instead of waiting for ctx timeout.
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopWatch := context.AfterFunc(ns.ctx, cancel)
	defer stopWatch()

	return gonet.DialTCPWithBind(dialCtx, ns.Stack, laddr, fullAddr, netProto)
}

// DialUDP dials a UDP pseudo-connection through the virtual user-space stack.
func (ns *Netstack) DialUDP(ctx context.Context, dest string) (net.Conn, error) {
	if ns.ctx.Err() != nil {
		return nil, errors.New("tunnel closed")
	}
	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port %q", portStr)
	}

	addr, err := ns.resolveHostIP(ctx, host)
	if err != nil {
		return nil, err
	}

	return ns.dialIPUDP(addr, uint16(port))
}

func (ns *Netstack) dialIPUDP(addr netip.Addr, port uint16) (net.Conn, error) {
	if ns.ctx.Err() != nil {
		return nil, errors.New("tunnel closed")
	}

	var netProto tcpip.NetworkProtocolNumber
	var laddr *tcpip.FullAddress
	if addr.Is4() {
		netProto = ipv4.ProtocolNumber
		if ns.IPv4.IsValid() {
			laddr = &tcpip.FullAddress{
				NIC:  nicID,
				Addr: tcpip.AddrFromSlice(ns.IPv4.AsSlice()),
			}
		}
	} else {
		netProto = ipv6.ProtocolNumber
		if ns.IPv6.IsValid() {
			laddr = &tcpip.FullAddress{
				NIC:  nicID,
				Addr: tcpip.AddrFromSlice(ns.IPv6.AsSlice()),
			}
		}
	}

	raddr := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(addr.AsSlice()),
		Port: port,
	}

	return gonet.DialUDP(ns.Stack, laddr, &raddr, netProto)
}

// Close closes the netstack and cancels internal routines.
func (ns *Netstack) Close() error {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	if ns.closed {
		return nil
	}
	ns.closed = true
	ns.cancel()
	ns.LinkEP.Close()
	ns.Stack.Close()
	return nil
}

func (ns *Netstack) resolveHostIP(ctx context.Context, host string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr, nil
	}
	if strings.EqualFold(host, "localhost") {
		return netip.MustParseAddr("127.0.0.1"), nil
	}
	if ns.ctx.Err() != nil {
		return netip.Addr{}, errors.New("tunnel closed")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return netip.Addr{}, err
	}

	// Resolve strictly inside the WARP tunnel via Cloudflare DNS so domains never
	// leak to the host system resolver or local ISP.
	return ns.resolveInTunnelDNS(ctx, host)
}

func (ns *Netstack) resolveInTunnelDNS(ctx context.Context, host string) (netip.Addr, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	dnsCtx, dnsCancel := context.WithCancel(ctx)
	if ns.ctx.Err() != nil {
		dnsCancel()
	}
	stopWatch := context.AfterFunc(ns.ctx, dnsCancel)
	defer func() {
		stopWatch()
		dnsCancel()
	}()
	return ResolveDNSOverTunnel(dnsCtx, func(dCtx context.Context, network string, server netip.Addr, port uint16) (net.Conn, error) {
		if network == "tcp" {
			return ns.dialIPTCP(dCtx, server, port)
		}
		return ns.dialIPUDP(server, port)
	}, host, ns.IPv4.IsValid() || !ns.IPv6.IsValid(), ns.IPv6.IsValid())
}

// ResolveDNSOverTunnel resolves host via Cloudflare's in-tunnel DNS (1.1.1.1:53 UDP, then 1.0.0.1:53 TCP)
// using the supplied tunnel dial function.
func ResolveDNSOverTunnel(
	ctx context.Context,
	dial func(ctx context.Context, network string, server netip.Addr, port uint16) (net.Conn, error),
	host string,
	allowV4 bool,
	allowV6 bool,
) (netip.Addr, error) {
	if dial == nil {
		return netip.Addr{}, errors.New("nil dialer")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return netip.Addr{}, err
	}
	qtype := dns.TypeA
	if !allowV4 && allowV6 {
		qtype = dns.TypeAAAA
	}

	query := func(qt uint16, server netip.Addr, useTCP bool) (netip.Addr, error) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(host), qt)
		m.RecursionDesired = true
		qCtx, qCancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		defer qCancel()
		return exchangeTunnelDNS(qCtx, dial, m, server, useTCP)
	}

	udpServer := netip.MustParseAddr("1.1.1.1")
	addr, err := query(qtype, udpServer, false)
	if err == nil {
		return addr, nil
	}
	if ctx.Err() != nil {
		return netip.Addr{}, err
	}
	if errors.Is(err, ErrNoDNSRecords) {
		if qtype == dns.TypeA && allowV6 {
			addr, v6Err := query(dns.TypeAAAA, udpServer, false)
			if v6Err == nil || errors.Is(v6Err, ErrNoDNSRecords) || ctx.Err() != nil {
				return addr, v6Err
			}
			// UDP AAAA timed out or hit a transport error; fall through to TCP.
			err = v6Err
		} else {
			return netip.Addr{}, err
		}
	}

	// Fallback to TCP 1.0.0.1:53 inside the tunnel when UDP fails at transport level.
	tcpServer := netip.MustParseAddr("1.0.0.1")
	addr, tcpErr := query(qtype, tcpServer, true)
	if tcpErr == nil || ctx.Err() != nil {
		return addr, tcpErr
	}
	if qtype == dns.TypeA && allowV6 && errors.Is(tcpErr, ErrNoDNSRecords) {
		return query(dns.TypeAAAA, tcpServer, true)
	}
	return netip.Addr{}, tcpErr
}

func exchangeTunnelDNS(
	ctx context.Context,
	dial func(ctx context.Context, network string, server netip.Addr, port uint16) (net.Conn, error),
	msg *dns.Msg,
	server netip.Addr,
	useTCP bool,
) (netip.Addr, error) {
	network := "udp"
	if useTCP {
		network = "tcp"
	}
	rawConn, err := dial(ctx, network, server, 53)
	if err != nil {
		return netip.Addr{}, err
	}
	defer rawConn.Close()

	stopWatch := context.AfterFunc(ctx, func() {
		_ = rawConn.Close()
	})
	defer stopWatch()

	co := &dns.Conn{Conn: rawConn}
	cli := &dns.Client{
		Timeout: 1500 * time.Millisecond,
	}
	resp, _, err := cli.ExchangeWithConnContext(ctx, msg, co)
	if err != nil {
		return netip.Addr{}, err
	}
	if resp.Truncated {
		return netip.Addr{}, fmt.Errorf("DNS response truncated for %s", msg.Question[0].Name)
	}
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		return netip.Addr{}, fmt.Errorf("DNS query failed with rcode %s for %s", dns.RcodeToString[resp.Rcode], msg.Question[0].Name)
	}
	for _, ans := range resp.Answer {
		switch rr := ans.(type) {
		case *dns.A:
			if parsed, ok := netip.AddrFromSlice(rr.A.To4()); ok {
				return parsed, nil
			}
		case *dns.AAAA:
			if parsed, ok := netip.AddrFromSlice(rr.AAAA.To16()); ok {
				return parsed, nil
			}
		}
	}
	return netip.Addr{}, fmt.Errorf("%w for %s", ErrNoDNSRecords, msg.Question[0].Name)
}
