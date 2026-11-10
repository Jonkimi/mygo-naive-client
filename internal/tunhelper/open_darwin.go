//go:build darwin

package tunhelper

import (
	"fmt"
	"net"
	"os/exec"
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
	cmd := exec.Command("ifconfig", name, "172.19.0.1", "172.19.0.2", "netmask", "255.255.255.252", "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		_ = unix.Close(tunFd)
		return 0, "", fmt.Errorf("configure utun ipv4 (%s): %w: %s", name, err, string(out))
	}
	cmd6 := exec.Command("ifconfig", name, "inet6", "fdfe:dcba:9876::1", "prefixlen", "126", "up")
	_ = cmd6.Run()

	return tunFd, name, nil
}

// SetupRoutes configures system routes (0/1 and 128/1) pointing to the utun interface on macOS,
// and installs direct host routes for excludeIPs to bypass the TUN interface.
func SetupRoutes(name string, excludeIPs []string) error {
	_ = TeardownRoutes(name, excludeIPs)

	gw, iface := getDefaultGateway()

	// 1. Install specific host routes for node IPs to bypass TUN directly via physical gateway
	for _, ipStr := range excludeIPs {
		ip := net.ParseIP(strings.TrimSpace(ipStr))
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			if gw != "" {
				_ = exec.Command("route", "-q", "-n", "add", "-host", ip.String(), gw).Run()
			} else if iface != "" {
				_ = exec.Command("route", "-q", "-n", "add", "-host", ip.String(), "-interface", iface).Run()
			}
		} else {
			if iface != "" {
				_ = exec.Command("route", "-q", "-n", "add", "-inet6", ip.String()+"/128", "-interface", iface).Run()
			}
		}
	}

	// 2. Install default 0/1 and 128/1 routes pointing to utun
	routes := [][]string{
		{"route", "-q", "-n", "add", "-net", "0.0.0.0/1", "-interface", name},
		{"route", "-q", "-n", "add", "-net", "128.0.0.0/1", "-interface", name},
		{"route", "-q", "-n", "add", "-inet6", "::/1", "-interface", name},
		{"route", "-q", "-n", "add", "-inet6", "8000::/1", "-interface", name},
	}
	for _, r := range routes {
		_ = exec.Command(r[0], r[1:]...).Run()
	}
	_ = exec.Command("dscacheutil", "-flushcache").Run()
	return nil
}

// TeardownRoutes removes the 0/1 and 128/1 routes and node host routes on macOS.
func TeardownRoutes(name string, excludeIPs []string) error {
	for _, ipStr := range excludeIPs {
		ip := net.ParseIP(strings.TrimSpace(ipStr))
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			_ = exec.Command("route", "-q", "-n", "delete", "-host", ip.String()).Run()
		} else {
			_ = exec.Command("route", "-q", "-n", "delete", "-inet6", ip.String()+"/128").Run()
		}
	}

	routes := [][]string{
		{"route", "-q", "-n", "delete", "-net", "0.0.0.0/1", "-interface", name},
		{"route", "-q", "-n", "delete", "-net", "128.0.0.0/1", "-interface", name},
		{"route", "-q", "-n", "delete", "-inet6", "::/1", "-interface", name},
		{"route", "-q", "-n", "delete", "-inet6", "8000::/1", "-interface", name},
	}
	for _, r := range routes {
		_ = exec.Command(r[0], r[1:]...).Run()
	}
	_ = exec.Command("dscacheutil", "-flushcache").Run()
	return nil
}

func getDefaultGateway() (string, string) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return "", ""
	}
	var gw, iface string
	lines := strings.Split(string(out), "\n")
	for _, l := range lines {
		fields := strings.Fields(l)
		if len(fields) >= 2 {
			if fields[0] == "gateway:" {
				gw = fields[1]
			} else if fields[0] == "interface:" {
				iface = fields[1]
			}
		}
	}
	return gw, iface
}
