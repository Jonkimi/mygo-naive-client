//go:build darwin

package tunhelper

import (
	"fmt"
	"os/exec"

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
