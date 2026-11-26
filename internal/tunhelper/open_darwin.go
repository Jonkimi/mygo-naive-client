//go:build darwin

package tunhelper

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const utunControlName = "com.apple.net.utun_control"

// OpenPlatformTUN creates and opens a macOS utun interface socket and retrieves its assigned name.
func OpenPlatformTUN() (int, string, error) {
	tunFd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2 /* SYSPROTO_CONTROL */)
	if err != nil {
		return 0, "", fmt.Errorf("open af_system socket: %w", err)
	}

	ctlInfo := &unix.CtlInfo{}
	copy(ctlInfo.Name[:], utunControlName)
	if err := unix.IoctlCtlInfo(tunFd, ctlInfo); err != nil {
		_ = unix.Close(tunFd)
		return 0, "", fmt.Errorf("ioctl ctl_info: %w", err)
	}

	// Connect to utun unit 0 (auto-assign next available utunX)
	if err := unix.Connect(tunFd, &unix.SockaddrCtl{
		ID:   ctlInfo.Id,
		Unit: 0,
	}); err != nil {
		_ = unix.Close(tunFd)
		return 0, "", fmt.Errorf("connect sockaddr_ctl: %w", err)
	}

	// Retrieve allocated interface name (e.g. utun3)
	name, err := unix.GetsockoptString(tunFd, 2 /* SYSPROTO_CONTROL */, 2 /* UTUN_OPT_IFNAME */)
	if err != nil {
		_ = unix.Close(tunFd)
		return 0, "", fmt.Errorf("getsockopt utun_opt_ifname: %w", err)
	}

	// Configure utun interface with IP addresses while running with root privileges
	cmd := exec.Command("ifconfig", name, TunIPv4, TunIPv4Peer, "netmask", TunIPv4Netmask, "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		_ = unix.Close(tunFd)
		return 0, "", fmt.Errorf("configure utun ipv4 (%s): %w: %s", name, err, string(out))
	}
	cmd6 := exec.Command("ifconfig", name, "inet6", TunIPv6, "prefixlen", "126", "up")
	_ = cmd6.Run()

	return tunFd, name, nil
}

func isBypassSafe(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		// Skip Tailscale CGNAT range (100.64.0.0/10) including MagicDNS 100.100.100.100
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return false
		}
	}
	// Skip Tailscale ULA range (fd7a:115c:a1e0::/48)
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

// SetupRoutes configures system routes (0/1 and 128/1) pointing to the utun interface on macOS,
// installs direct host/subnet routes for excludeIPs to bypass the TUN interface,
// and installs a high-priority DynamicStore DNS entry for Split DNS hijacking.
func SetupRoutes(name string, excludeIPs []string) error {
	return SetupRoutesWithOptions(name, excludeIPs, false)
}

// SetupRoutesWithOptions configures system routes on macOS with optional forced IPv6 capture routes
// (for IPv6-over-IPv4 tunneling when the host lacks a native IPv6 default route).
func SetupRoutesWithOptions(name string, excludeIPs []string, forceIPv6Route bool) error {
	_ = teardownRoutesInternal(name, excludeIPs, false)

	gw4, iface4 := getDefaultGateway()
	gw6, iface6 := getDefaultGatewayV6()

	// 1. Install specific host/subnet routes for node and Anycast IPs to bypass TUN directly via physical gateway
	for _, r := range buildDarwinExcludeRouteCommands(excludeIPs, gw4, iface4, gw6, iface6) {
		_ = exec.Command(r[0], r[1:]...).Run()
	}

	// 2. Install default 0/1 and 128/1 routes pointing to utun
	installIPv6 := forceIPv6Route || checkDarwinIPv6()
	for _, r := range buildDarwinDefaultRouteCommands(name, installIPv6) {
		_ = exec.Command(r[0], r[1:]...).Run()
	}

	// 3. Configure macOS DynamicStore DNS so utun intercepts all DNS requests with highest priority
	setupDarwinDNS(name)

	_ = exec.Command("dscacheutil", "-flushcache").Run()
	_ = exec.Command("killall", "-HUP", "mDNSResponder").Run()
	return nil
}

func buildDarwinExcludeRouteCommands(excludeIPs []string, gw4, iface4, gw6, iface6 string) [][]string {
	var cmds [][]string
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
				if gw4 != "" {
					cmds = append(cmds, []string{"route", "-q", "-n", "add", "-net", ipNet.String(), gw4})
				} else if iface4 != "" {
					cmds = append(cmds, []string{"route", "-q", "-n", "add", "-net", ipNet.String(), "-interface", iface4})
				}
			} else {
				if gw6 != "" {
					cmds = append(cmds, []string{"route", "-q", "-n", "add", "-inet6", ipNet.String(), gw6})
				} else if iface6 != "" {
					cmds = append(cmds, []string{"route", "-q", "-n", "add", "-inet6", ipNet.String(), "-interface", iface6})
				} else if iface4 != "" {
					cmds = append(cmds, []string{"route", "-q", "-n", "add", "-inet6", ipNet.String(), "-interface", iface4})
				}
			}
			continue
		}
		ip := net.ParseIP(strings.Trim(trimmed, "[]"))
		if !isBypassSafe(ip) {
			continue
		}
		if ip.To4() != nil {
			if gw4 != "" {
				cmds = append(cmds, []string{"route", "-q", "-n", "add", "-host", ip.String(), gw4})
			} else if iface4 != "" {
				cmds = append(cmds, []string{"route", "-q", "-n", "add", "-host", ip.String(), "-interface", iface4})
			}
		} else {
			target := ip.String() + "/128"
			if gw6 != "" {
				cmds = append(cmds, []string{"route", "-q", "-n", "add", "-inet6", target, gw6})
			} else if iface6 != "" {
				cmds = append(cmds, []string{"route", "-q", "-n", "add", "-inet6", target, "-interface", iface6})
			} else if iface4 != "" {
				cmds = append(cmds, []string{"route", "-q", "-n", "add", "-inet6", target, "-interface", iface4})
			}
		}
	}
	return cmds
}

func buildDarwinDefaultRouteCommands(name string, installIPv6 bool) [][]string {
	routes := [][]string{
		{"route", "-q", "-n", "add", "-net", "0.0.0.0/1", "-interface", name},
		{"route", "-q", "-n", "add", "-net", "128.0.0.0/1", "-interface", name},
	}
	if installIPv6 {
		routes = append(routes,
			[]string{"route", "-q", "-n", "add", "-inet6", "::/1", "-interface", name},
			[]string{"route", "-q", "-n", "add", "-inet6", "8000::/1", "-interface", name},
		)
	}
	return routes
}

// TeardownRoutes removes the 0/1 and 128/1 routes, node host routes, and DynamicStore DNS on macOS.
func TeardownRoutes(name string, excludeIPs []string) error {
	return teardownRoutesInternal(name, excludeIPs, true)
}

func teardownRoutesInternal(name string, excludeIPs []string, flushDNS bool) error {
	if name != "" && flushDNS {
		teardownDarwinDNS(name)
	}
	if flushDNS {
		cleanupStaleDarwinDNS()
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
			if ipNet.IP.To4() != nil {
				_ = exec.Command("route", "-q", "-n", "delete", "-net", ipNet.String()).Run()
			} else {
				_ = exec.Command("route", "-q", "-n", "delete", "-inet6", ipNet.String()).Run()
			}
			continue
		}
		ip := net.ParseIP(trimmed)
		if !isBypassSafe(ip) {
			continue
		}
		if ip.To4() != nil {
			_ = exec.Command("route", "-q", "-n", "delete", "-host", ip.String()).Run()
		} else {
			_ = exec.Command("route", "-q", "-n", "delete", "-inet6", ip.String()+"/128").Run()
		}
	}

	var routes [][]string
	if name != "" {
		routes = append(routes,
			[]string{"route", "-q", "-n", "delete", "-net", "0.0.0.0/1", "-interface", name},
			[]string{"route", "-q", "-n", "delete", "-net", "128.0.0.0/1", "-interface", name},
			[]string{"route", "-q", "-n", "delete", "-inet6", "::/1", "-interface", name},
			[]string{"route", "-q", "-n", "delete", "-inet6", "8000::/1", "-interface", name},
		)
	}
	// Also clean without interface constraint in case interface was deleted or changed across restarts
	routes = append(routes,
		[]string{"route", "-q", "-n", "delete", "-net", "0.0.0.0/1"},
		[]string{"route", "-q", "-n", "delete", "-net", "128.0.0.0/1"},
		[]string{"route", "-q", "-n", "delete", "-inet6", "::/1"},
		[]string{"route", "-q", "-n", "delete", "-inet6", "8000::/1"},
	)
	for _, r := range routes {
		_ = exec.Command(r[0], r[1:]...).Run()
	}
	if flushDNS {
		_ = exec.Command("dscacheutil", "-flushcache").Run()
		_ = exec.Command("killall", "-HUP", "mDNSResponder").Run()
	}
	return nil
}

func setupDarwinDNS(ifName string) {
	cleanupStaleDarwinDNS()
	searchDomains := collectDarwinSearchDomains("/etc/resolv.conf", "/etc/resolver")
	cmd := exec.Command("scutil")
	cmd.Stdin = strings.NewReader(buildDarwinDNSCommands(ifName, searchDomains))
	_ = cmd.Run()
}

func buildDarwinDNSCommands(ifName string, searchDomains []string) string {
	var sb strings.Builder
	sb.WriteString("d.init\n")
	sb.WriteString("d.add ServerAddresses * " + DNSAddress + " " + DNSAddressV6 + "\n")
	sb.WriteString(fmt.Sprintf("d.add InterfaceName %s\n", ifName))
	if len(searchDomains) > 0 {
		sb.WriteString("d.add SearchDomains * " + strings.Join(searchDomains, " ") + "\n")
		sb.WriteString("d.add SupplementalMatchDomains * \"\"")
		for _, d := range searchDomains {
			sb.WriteString(" " + d + ".")
		}
		sb.WriteString("\n")
		// Explicitly assign the lowest SupplementalMatchOrders (highest priority) as CFNumber (* # ...)
		// within Apple's standard VPN supplemental resolver range (100000..150000).
		// 100000 is the theoretical minimum base order for VPNs, ensuring it precedes
		// Tailscale (101800) and other registered VPN services without breaking convention.
		sb.WriteString("d.add SupplementalMatchOrders * #")
		for i := 0; i <= len(searchDomains); i++ {
			sb.WriteString(" 100000")
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("d.add SupplementalMatchDomains * \"\"\n")
		sb.WriteString("d.add SupplementalMatchOrders * # 100000\n")
	}
	sb.WriteString(fmt.Sprintf("set State:/Network/Service/%s/DNS\n", ifName))
	sb.WriteString("quit\n")
	return sb.String()
}

// cleanupStaleDarwinDNS removes DynamicStore DNS entries left behind by a previous helper that
// was killed before it could tear down (SIGKILL, crash). Such an entry points at the TUN DNS
// address of a dead interface and breaks system-wide DNS. Only entries whose ServerAddresses
// contain DNSAddress are touched, so DNS entries owned by other VPNs are left alone.
func cleanupStaleDarwinDNS() {
	list := exec.Command("scutil")
	list.Stdin = strings.NewReader("list State:/Network/Service/.*DNS\nquit\n")
	out, err := list.Output()
	if err != nil {
		return
	}
	keys := parseScutilKeys(string(out))
	if len(keys) == 0 {
		return
	}

	var sb strings.Builder
	for _, key := range keys {
		sb.WriteString("show " + key + "\n")
	}
	sb.WriteString("quit\n")

	show := exec.Command("scutil")
	show.Stdin = strings.NewReader(sb.String())
	showOut, err := show.Output()
	if err != nil {
		return
	}

	var rmSb strings.Builder
	hasRemovals := false
	sections := strings.Split(string(showOut), "subKey [")
	for idx, key := range keys {
		match := false
		if idx+1 < len(sections) {
			if strings.Contains(sections[idx+1], DNSAddress) || strings.Contains(sections[idx+1], DNSAddressV6) {
				match = true
			}
		} else if strings.Contains(string(showOut), DNSAddress) || strings.Contains(string(showOut), DNSAddressV6) {
			match = true
		}
		if match {
			rmSb.WriteString("remove " + key + "\n")
			hasRemovals = true
		}
	}

	if hasRemovals {
		rmSb.WriteString("quit\n")
		rm := exec.Command("scutil")
		rm.Stdin = strings.NewReader(rmSb.String())
		_ = rm.Run()
	}
}

// parseScutilKeys extracts keys from `scutil` "list" output lines like
// "  subKey [0] = State:/Network/Service/utun5/DNS".
func parseScutilKeys(out string) []string {
	var keys []string
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, " = State:/"); i >= 0 {
			keys = append(keys, strings.TrimSpace(line[i+3:]))
		}
	}
	return keys
}

func teardownDarwinDNS(ifName string) {
	cmd := exec.Command("scutil")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("remove State:/Network/Service/%s/DNS\nquit\n", ifName))
	_ = cmd.Run()
}

func collectDarwinSearchDomains(resolvConfPath, resolverDir string) []string {
	var domains []string
	seen := make(map[string]bool)
	addDomain := func(raw string) {
		clean := strings.ToLower(strings.Trim(strings.TrimSpace(raw), "."))
		if clean == "" || seen[clean] {
			return
		}
		seen[clean] = true
		domains = append(domains, clean)
	}

	if resolvConfPath != "" {
		if data, err := os.ReadFile(resolvConfPath); err == nil {
			for _, l := range strings.Split(string(data), "\n") {
				fields := strings.Fields(l)
				if len(fields) >= 2 && (fields[0] == "search" || fields[0] == "domain") {
					for _, tok := range fields[1:] {
						addDomain(tok)
					}
				}
			}
		}
	}

	if resolverDir != "" {
		if entries, err := os.ReadDir(resolverDir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				name := strings.TrimSpace(entry.Name())
				if name == "" || strings.HasPrefix(name, ".") {
					continue
				}
				data, err := os.ReadFile(filepath.Join(resolverDir, name))
				if err != nil {
					continue
				}
				content := string(data)
				isTailscaleResolver := strings.Contains(content, "100.100.100.100") ||
					strings.Contains(content, "tailscaled") ||
					strings.HasSuffix(strings.ToLower(strings.Trim(name, ".")), ".ts.net")
				if !isTailscaleResolver {
					continue
				}
				if strings.Contains(name, ".") {
					addDomain(name)
				}
				for _, l := range strings.Split(content, "\n") {
					fields := strings.Fields(l)
					if len(fields) >= 2 && (fields[0] == "search" || fields[0] == "domain") {
						for _, tok := range fields[1:] {
							addDomain(tok)
						}
					}
				}
			}
		}
	}

	return domains
}

func checkDarwinIPv6() bool {
	out, err := exec.Command("route", "-n", "get", "-inet6", "default").Output()
	if err != nil {
		return false
	}
	s := string(out)
	return strings.Contains(s, "interface:") && !strings.Contains(s, "not in table")
}

func getDefaultGateway() (string, string) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return "", ""
	}
	return parseDarwinRouteOutput(string(out))
}

func getDefaultGatewayV6() (string, string) {
	out, err := exec.Command("route", "-n", "get", "-inet6", "default").Output()
	if err != nil {
		return "", ""
	}
	return parseDarwinRouteOutput(string(out))
}

func parseDarwinRouteOutput(out string) (string, string) {
	var gw, iface string
	lines := strings.Split(out, "\n")
	for _, l := range lines {
		fields := strings.Fields(l)
		if len(fields) >= 2 {
			if fields[0] == "gateway:" {
				gw = fields[1]
			} else if fields[0] == "interface:" {
				cand := fields[1]
				if !strings.HasPrefix(cand, "utun") && !strings.HasPrefix(cand, "tun") && !strings.HasPrefix(cand, "lo") {
					iface = cand
				}
			}
		}
	}
	return gw, iface
}
