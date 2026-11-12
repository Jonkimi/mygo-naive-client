package warp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"sync"

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

	var netProto tcpip.NetworkProtocolNumber
	if addr.Is4() {
		netProto = ipv4.ProtocolNumber
	} else {
		netProto = ipv6.ProtocolNumber
	}

	fullAddr := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(addr.AsSlice()),
		Port: uint16(port),
	}

	return gonet.DialContextTCP(ctx, ns.Stack, fullAddr, netProto)
}

// DialUDP dials a UDP pseudo-connection through the virtual user-space stack.
func (ns *Netstack) DialUDP(ctx context.Context, dest string) (net.Conn, error) {
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

	var netProto tcpip.NetworkProtocolNumber
	if addr.Is4() {
		netProto = ipv4.ProtocolNumber
	} else {
		netProto = ipv6.ProtocolNumber
	}

	raddr := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(addr.AsSlice()),
		Port: uint16(port),
	}

	return gonet.DialUDP(ns.Stack, nil, &raddr, netProto)
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
	netProto := "ip"
	if ns.IPv4.IsValid() && (!ns.IPv6.IsValid() || ns.IPv6.IsUnspecified()) {
		netProto = "ip4"
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, netProto, host)
	if err != nil || len(ips) == 0 {
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 1000 * time.Millisecond}
				return d.DialContext(ctx, "udp", "223.5.5.5:53")
			},
		}
		ips, _ = r.LookupIP(ctx, netProto, host)
	}
	if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("failed to resolve host %q: %w", host, err)
	}
	selected := ips[0]
	if ns.IPv4.IsValid() {
		for _, ip := range ips {
			if ip.To4() != nil {
				selected = ip
				break
			}
		}
	}
	parsed, err := netip.ParseAddr(selected.String())
	if err != nil {
		return netip.Addr{}, fmt.Errorf("failed to parse resolved IP %q: %w", selected.String(), err)
	}
	return parsed, nil
}
