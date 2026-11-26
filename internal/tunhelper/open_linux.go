//go:build linux

package tunhelper

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// OpenPlatformTUN opens /dev/net/tun with IFF_TUN and retrieves its interface name.
func OpenPlatformTUN() (int, string, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return 0, "", fmt.Errorf("open /dev/net/tun: %w", err)
	}

	var ifr [40]byte
	// IFF_TUN = 0x0001, IFF_NO_PI = 0x1000
	flags := uint16(0x0001 | 0x1000)
	*(*uint16)(unsafe.Pointer(&ifr[16])) = flags

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		_ = unix.Close(fd)
		return 0, "", fmt.Errorf("ioctl TUNSETIFF: %w", errno)
	}

	name := unix.ByteSliceToString(ifr[:16])

	// Configure IP addresses
	_ = exec.Command("ip", "addr", "add", TunIPv4Prefix, "dev", name).Run()
	_ = exec.Command("ip", "link", "set", "dev", name, "up").Run()
	_ = exec.Command("ip", "-6", "addr", "add", TunIPv6Prefix, "dev", name).Run()

	return fd, name, nil
}

func isBypassSafe(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return false
		}
	}
	if len(ip) == 16 && ip[0] == 0xfd && ip[1] == 0x7a && ip[2] == 0x11 && ip[3] == 0x5c && ip[4] == 0xa1 && ip[5] == 0xe0 {
		return false
	}
	return true
}

func isBypassSafeCIDR(ipNet *net.IPNet) bool {
	if ipNet == nil {
		return false
	}
	ones, bits := ipNet.Mask.Size()
	if ones == 0 || bits == 0 {
		return false
	}
	return isBypassSafe(ipNet.IP)
}

// SetupRoutes installs default 0/1 and 128/1 routes on Linux pointing to the TUN interface,
// and installs specific direct routes for excludeIPs (hosts and CIDRs).
func SetupRoutes(name string, excludeIPs []string) error {
	return SetupRoutesWithOptions(name, excludeIPs, false)
}

// SetupRoutesWithOptions installs default routes on Linux with optional forced IPv6 TUN capture routes.
func SetupRoutesWithOptions(name string, excludeIPs []string, forceIPv6Route bool) error {
	_ = TeardownRoutes(name, excludeIPs)

	gw4, dev4 := getDefaultGatewayV4()
	gw6, dev6 := getDefaultGatewayV6()

	for _, r := range buildLinuxExcludeRouteCommands(excludeIPs, gw4, dev4, gw6, dev6) {
		_ = exec.Command(r[0], r[1:]...).Run()
	}

	installIPv6 := forceIPv6Route || gw6 != "" || dev6 != ""
	for _, r := range buildLinuxDefaultRouteCommands(name, installIPv6) {
		_ = exec.Command(r[0], r[1:]...).Run()
	}
	return nil
}

func isLinuxVirtualInterface(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	return strings.HasPrefix(lower, "tun") ||
		strings.HasPrefix(lower, "utun") ||
		strings.HasPrefix(lower, "tap") ||
		strings.HasPrefix(lower, "wg") ||
		strings.HasPrefix(lower, "tailscale") ||
		strings.HasPrefix(lower, "lo")
}

func parseLinuxDefaultRoute(out string) (gw, dev string) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		var lineGW, lineDev string
		for i := 0; i+1 < len(fields); i++ {
			switch fields[i] {
			case "via":
				lineGW = fields[i+1]
			case "dev":
				lineDev = fields[i+1]
			}
		}
		if lineDev != "" && !isLinuxVirtualInterface(lineDev) {
			return lineGW, lineDev
		}
	}
	return "", ""
}

func getDefaultGatewayV4() (string, string) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "", ""
	}
	return parseLinuxDefaultRoute(string(out))
}

func getDefaultGatewayV6() (string, string) {
	out, err := exec.Command("ip", "-6", "route", "show", "default").Output()
	if err != nil {
		return "", ""
	}
	return parseLinuxDefaultRoute(string(out))
}

func buildLinuxExcludeRouteCommands(excludeIPs []string, gw4, dev4, gw6, dev6 string) [][]string {
	var cmds [][]string
	addRoute := func(isV6 bool, target string) {
		if !isV6 {
			switch {
			case gw4 != "" && dev4 != "":
				cmds = append(cmds, []string{"ip", "route", "replace", target, "via", gw4, "dev", dev4})
			case gw4 != "":
				cmds = append(cmds, []string{"ip", "route", "replace", target, "via", gw4})
			case dev4 != "":
				cmds = append(cmds, []string{"ip", "route", "replace", target, "dev", dev4})
			default:
				cmds = append(cmds, []string{"ip", "route", "add", target, "scope", "link"})
			}
			return
		}
		switch {
		case gw6 != "" && dev6 != "":
			cmds = append(cmds, []string{"ip", "-6", "route", "replace", target, "via", gw6, "dev", dev6})
		case gw6 != "":
			cmds = append(cmds, []string{"ip", "-6", "route", "replace", target, "via", gw6})
		case dev6 != "":
			cmds = append(cmds, []string{"ip", "-6", "route", "replace", target, "dev", dev6})
		case dev4 != "":
			cmds = append(cmds, []string{"ip", "-6", "route", "replace", target, "dev", dev4})
		default:
			cmds = append(cmds, []string{"ip", "-6", "route", "add", target, "scope", "link"})
		}
	}

	for _, entry := range excludeIPs {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}
		if strings.Contains(trimmed, "/") {
			_, ipNet, err := net.ParseCIDR(trimmed)
			if err != nil || !isBypassSafeCIDR(ipNet) {
				continue
			}
			addRoute(ipNet.IP.To4() == nil, ipNet.String())
			continue
		}
		ip := net.ParseIP(strings.Trim(trimmed, "[]"))
		if !isBypassSafe(ip) {
			continue
		}
		if ip.To4() != nil {
			addRoute(false, ip.String()+"/32")
		} else {
			addRoute(true, ip.String()+"/128")
		}
	}
	return cmds
}

func buildLinuxDefaultRouteCommands(name string, installIPv6 bool) [][]string {
	routes := [][]string{
		{"ip", "route", "add", "0.0.0.0/1", "dev", name},
		{"ip", "route", "add", "128.0.0.0/1", "dev", name},
	}
	if installIPv6 {
		routes = append(routes,
			[]string{"ip", "-6", "route", "add", "::/1", "dev", name},
			[]string{"ip", "-6", "route", "add", "8000::/1", "dev", name},
		)
	}
	return routes
}

// TeardownRoutes removes default 0/1 and 128/1 routes and host/subnet routes on Linux.
func TeardownRoutes(name string, excludeIPs []string) error {
	for _, entry := range excludeIPs {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}
		if strings.Contains(trimmed, "/") {
			_, ipNet, err := net.ParseCIDR(trimmed)
			if err != nil || !isBypassSafeCIDR(ipNet) {
				continue
			}
			if ipNet.IP.To4() != nil {
				_ = exec.Command("ip", "route", "del", ipNet.String()).Run()
			} else {
				_ = exec.Command("ip", "-6", "route", "del", ipNet.String()).Run()
			}
			continue
		}
		ip := net.ParseIP(trimmed)
		if !isBypassSafe(ip) {
			continue
		}
		if ip.To4() != nil {
			_ = exec.Command("ip", "route", "del", ip.String()+"/32").Run()
		} else {
			_ = exec.Command("ip", "-6", "route", "del", ip.String()+"/128").Run()
		}
	}

	var routes [][]string
	if name != "" {
		routes = append(routes,
			[]string{"ip", "route", "del", "0.0.0.0/1", "dev", name},
			[]string{"ip", "route", "del", "128.0.0.0/1", "dev", name},
			[]string{"ip", "-6", "route", "del", "::/1", "dev", name},
			[]string{"ip", "-6", "route", "del", "8000::/1", "dev", name},
		)
	}
	routes = append(routes,
		[]string{"ip", "route", "del", "0.0.0.0/1"},
		[]string{"ip", "route", "del", "128.0.0.0/1"},
		[]string{"ip", "-6", "route", "del", "::/1"},
		[]string{"ip", "-6", "route", "del", "8000::/1"},
	)
	for _, r := range routes {
		_ = exec.Command(r[0], r[1:]...).Run()
	}
	return nil
}
