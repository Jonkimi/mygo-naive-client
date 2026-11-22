package warp

import (
	"context"
	"net"
	"strings"
	"syscall"
)

// NewBypassTUNDialer returns a Dialer that binds outbound sockets directly to the
// active physical default interface (when not in a TUN/loopback interface), so
// WARP Anycast endpoint scans bypass system TUN capture routes (0.0.0.0/1, 128.0.0.0/1).
func NewBypassTUNDialer() Dialer {
	ifIdx, localIP := detectPhysicalInterface()
	if ifIdx <= 0 && localIP == nil {
		return &defaultDialer{}
	}
	return &bypassTUNDialer{
		ifIndex: ifIdx,
		localIP: localIP,
	}
}

type bypassTUNDialer struct {
	ifIndex int
	localIP net.IP
}

func (d *bypassTUNDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	nd := net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			return bindSocketToInterface(network, d.ifIndex, c)
		},
	}
	if d.localIP != nil && isIPv4NetworkOrAddr(network, addr) {
		nd.LocalAddr = &net.TCPAddr{IP: d.localIP}
	}
	return nd.DialContext(ctx, network, addr)
}

func (d *bypassTUNDialer) ListenPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return bindSocketToInterface(network, d.ifIndex, c)
		},
	}
	listenNet, listenAddr := packetListenTarget(network, addr, d.localIP)
	return lc.ListenPacket(ctx, listenNet, listenAddr)
}

func packetListenTarget(network, addr string, localIPv4 net.IP) (string, string) {
	if !isIPv4NetworkOrAddr(network, addr) {
		listenNet := network
		if network == "udp" {
			listenNet = "udp6"
		}
		return listenNet, "[::]:0"
	}
	listenAddr := "0.0.0.0:0"
	if localIPv4 != nil && (strings.HasPrefix(network, "udp") || network == "ip") {
		if ip4 := localIPv4.To4(); ip4 != nil {
			listenAddr = net.JoinHostPort(ip4.String(), "0")
		}
	}
	return network, listenAddr
}

func hasGlobalIPv6() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if isVirtualTunInterface(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.To4() == nil && ip.IsGlobalUnicast() && !ip.IsPrivate() {
				return true
			}
		}
	}
	return false
}

func isIPv4NetworkOrAddr(network, addr string) bool {
	if strings.HasSuffix(network, "6") {
		return false
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip.To4() != nil
		}
	}
	return true
}

func detectPhysicalInterface() (int, net.IP) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0, nil
	}
	// First determine which interface owns the default physical route by checking
	// non-virtual interfaces that have a non-loopback IPv4 address.
	preferredName := defaultPhysicalRouteInterface()
	if preferredName != "" {
		if iface, err := net.InterfaceByName(preferredName); err == nil && iface.Flags&net.FlagUp != 0 {
			if ip := firstInterfaceIPv4(iface); ip != nil {
				return iface.Index, ip
			}
		}
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if isVirtualTunInterface(iface.Name) {
			continue
		}
		if ip := firstInterfaceIPv4(&iface); ip != nil {
			return iface.Index, ip
		}
	}
	return 0, nil
}

func firstInterfaceIPv4(iface *net.Interface) net.IP {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip4 := ip.To4(); ip4 != nil && !ip4.IsLoopback() && !ip4.IsLinkLocalUnicast() {
			return ip4
		}
	}
	return nil
}

func isVirtualTunInterface(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	return strings.HasPrefix(lower, "utun") ||
		strings.HasPrefix(lower, "tun") ||
		strings.HasPrefix(lower, "tap") ||
		strings.HasPrefix(lower, "wg") ||
		strings.HasPrefix(lower, "tailscale") ||
		strings.HasPrefix(lower, "lo")
}
