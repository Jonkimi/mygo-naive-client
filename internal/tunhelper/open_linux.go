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
	_ = exec.Command("ip", "addr", "add", "172.19.0.1/30", "dev", name).Run()
	_ = exec.Command("ip", "link", "set", "dev", name, "up").Run()
	_ = exec.Command("ip", "-6", "addr", "add", "fdfe:dcba:9876::1/126", "dev", name).Run()

	return fd, name, nil
}

// SetupRoutes installs default 0/1 and 128/1 routes on Linux pointing to the TUN interface,
// and installs specific direct routes for excludeIPs.
func SetupRoutes(name string, excludeIPs []string) error {
	_ = TeardownRoutes(name, excludeIPs)

	for _, ipStr := range excludeIPs {
		ip := net.ParseIP(strings.TrimSpace(ipStr))
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			_ = exec.Command("ip", "route", "add", ip.String()+"/32", "scope", "link").Run()
		} else {
			_ = exec.Command("ip", "-6", "route", "add", ip.String()+"/128", "scope", "link").Run()
		}
	}

	routes := [][]string{
		{"ip", "route", "add", "0.0.0.0/1", "dev", name},
		{"ip", "route", "add", "128.0.0.0/1", "dev", name},
		{"ip", "-6", "route", "add", "::/1", "dev", name},
		{"ip", "-6", "route", "add", "8000::/1", "dev", name},
	}
	for _, r := range routes {
		_ = exec.Command(r[0], r[1:]...).Run()
	}
	return nil
}

// TeardownRoutes removes default 0/1 and 128/1 routes and host routes on Linux.
func TeardownRoutes(name string, excludeIPs []string) error {
	for _, ipStr := range excludeIPs {
		ip := net.ParseIP(strings.TrimSpace(ipStr))
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			_ = exec.Command("ip", "route", "del", ip.String()+"/32").Run()
		} else {
			_ = exec.Command("ip", "-6", "route", "del", ip.String()+"/128").Run()
		}
	}

	routes := [][]string{
		{"ip", "route", "del", "0.0.0.0/1", "dev", name},
		{"ip", "route", "del", "128.0.0.0/1", "dev", name},
		{"ip", "-6", "route", "del", "::/1", "dev", name},
		{"ip", "-6", "route", "del", "8000::/1", "dev", name},
	}
	for _, r := range routes {
		_ = exec.Command(r[0], r[1:]...).Run()
	}
	return nil
}
