package warp

import (
	"context"
	"net"
	"strings"
	"syscall"
)

// NewBypassTUNDialer returns a Dialer that binds outbound sockets directly to the
// active physical default interface (when not in a TUN/loopback interface), so
// WARP Anycast endpoint scans bypass system TUN capture routes (0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1).
func NewBypassTUNDialer() Dialer {
	ifIdxV4, ipV4, ifIdxV6, ipV6 := detectPhysicalInterfaces()
	if ifIdxV4 <= 0 && ipV4 == nil && ifIdxV6 <= 0 && ipV6 == nil {
		return &defaultDialer{}
	}
	return &bypassTUNDialer{
		ifIndexV4: ifIdxV4,
		localIPv4: ipV4,
		ifIndexV6: ifIdxV6,
		localIPv6: ipV6,
	}
}

type bypassTUNDialer struct {
	ifIndexV4 int
	localIPv4 net.IP
	ifIndexV6 int
	localIPv6 net.IP
}

func (d *bypassTUNDialer) targetInterfaceAndIP(network, addr string) (int, net.IP, bool) {
	isV4 := isIPv4NetworkOrAddr(network, addr)
	if isV4 {
		idx := d.ifIndexV4
		if idx <= 0 {
			idx = d.ifIndexV6
		}
		return idx, d.localIPv4, true
	}
	idx := d.ifIndexV6
	if idx <= 0 {
		idx = d.ifIndexV4
	}
	return idx, d.localIPv6, false
}

func (d *bypassTUNDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	ifIdx, localIP, isV4 := d.targetInterfaceAndIP(network, addr)
	bindNet := network
	if !isV4 && !strings.HasSuffix(bindNet, "6") {
		bindNet = network + "6"
	}
	nd := net.Dialer{
		Control: func(ctrlNet, address string, c syscall.RawConn) error {
			if !isV4 && !strings.HasSuffix(ctrlNet, "6") {
				ctrlNet = bindNet
			}
			return bindSocketToInterface(ctrlNet, ifIdx, c)
		},
	}
	if localIP != nil {
		nd.LocalAddr = &net.TCPAddr{IP: localIP}
	}
	return nd.DialContext(ctx, network, addr)
}

func (d *bypassTUNDialer) ListenPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	ifIdx, _, isV4 := d.targetInterfaceAndIP(network, addr)
	listenNet, listenAddr := packetListenTarget(network, addr, d.localIPv4, d.localIPv6)
	lc := net.ListenConfig{
		Control: func(ctrlNet, address string, c syscall.RawConn) error {
			if !isV4 && !strings.HasSuffix(ctrlNet, "6") {
				ctrlNet = listenNet
			}
			return bindSocketToInterface(ctrlNet, ifIdx, c)
		},
	}
	return lc.ListenPacket(ctx, listenNet, listenAddr)
}

func packetListenTarget(network, addr string, localIPv4, localIPv6 net.IP) (string, string) {
	if !isIPv4NetworkOrAddr(network, addr) {
		listenNet := network
		if network == "udp" {
			listenNet = "udp6"
		}
		listenAddr := "[::]:0"
		if localIPv6 != nil && localIPv6.To4() == nil && (strings.HasPrefix(network, "udp") || network == "ip") {
			listenAddr = net.JoinHostPort(localIPv6.String(), "0")
		}
		return listenNet, listenAddr
	}
	listenAddr := "0.0.0.0:0"
	if localIPv4 != nil && (strings.HasPrefix(network, "udp") || network == "ip") {
		if ip4 := localIPv4.To4(); ip4 != nil {
			listenAddr = net.JoinHostPort(ip4.String(), "0")
		}
	}
	return network, listenAddr
}

// HasIPv4Connectivity reports whether any active physical interface has a non-loopback, non-link-local IPv4 address.
func HasIPv4Connectivity() bool {
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
		if firstInterfaceIPv4(&iface) != nil {
			return true
		}
	}
	return false
}

// HasGlobalIPv6 reports whether any active physical interface has a global unicast IPv6 address.
func HasGlobalIPv6() bool {
	return hasGlobalIPv6()
}

// IsIPv6OnlyHost reports whether the host has global IPv6 connectivity and no physical IPv4 address.
func IsIPv6OnlyHost() bool {
	return !HasIPv4Connectivity() && HasGlobalIPv6()
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
		if firstInterfaceGlobalIPv6(&iface) != nil {
			return true
		}
	}
	return false
}

func isIPv4NetworkOrAddr(network, addr string) bool {
	if strings.HasSuffix(network, "6") {
		return false
	}
	if strings.HasSuffix(network, "4") {
		return true
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
			return ip.To4() != nil
		}
	} else if ip := net.ParseIP(strings.Trim(addr, "[]")); ip != nil {
		return ip.To4() != nil
	}
	return !IsIPv6OnlyHost()
}

func detectPhysicalInterfaces() (int, net.IP, int, net.IP) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0, nil, 0, nil
	}

	var ifIdxV4 int
	var ipV4 net.IP
	if preferredV4 := defaultPhysicalRouteInterfaceV4(); preferredV4 != "" {
		if iface, err := net.InterfaceByName(preferredV4); err == nil && iface.Flags&net.FlagUp != 0 {
			if ip := firstInterfaceIPv4(iface); ip != nil {
				ifIdxV4, ipV4 = iface.Index, ip
			}
		}
	}
	if ifIdxV4 == 0 {
		for i := range ifaces {
			iface := &ifaces[i]
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || isVirtualTunInterface(iface.Name) {
				continue
			}
			if ip := firstInterfaceIPv4(iface); ip != nil {
				ifIdxV4, ipV4 = iface.Index, ip
				break
			}
		}
	}

	var ifIdxV6 int
	var ipV6 net.IP
	if preferredV6 := defaultPhysicalRouteInterfaceV6(); preferredV6 != "" {
		if iface, err := net.InterfaceByName(preferredV6); err == nil && iface.Flags&net.FlagUp != 0 {
			if ip := firstInterfaceGlobalIPv6(iface); ip != nil {
				ifIdxV6, ipV6 = iface.Index, ip
			}
		}
	}
	if ifIdxV6 == 0 {
		for i := range ifaces {
			iface := &ifaces[i]
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || isVirtualTunInterface(iface.Name) {
				continue
			}
			if ip := firstInterfaceGlobalIPv6(iface); ip != nil {
				ifIdxV6, ipV6 = iface.Index, ip
				break
			}
		}
	}

	return ifIdxV4, ipV4, ifIdxV6, ipV6
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

func firstInterfaceGlobalIPv6(iface *net.Interface) net.IP {
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
		if ip != nil && ip.To4() == nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() {
			return ip
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
