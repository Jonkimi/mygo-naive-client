//go:build linux

package warp

import (
	"net"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func bindSocketToInterface(network string, ifIndex int, c syscall.RawConn) error {
	if ifIndex <= 0 {
		return nil
	}
	iface, err := net.InterfaceByIndex(ifIndex)
	if err != nil || iface.Name == "" {
		return nil
	}
	var opErr error
	if err := c.Control(func(fd uintptr) {
		opErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface.Name)
	}); err != nil {
		return err
	}
	// SO_BINDTODEVICE requires CAP_NET_RAW on older kernels; fall back to source IP bind if EPERM.
	if opErr == unix.EPERM || opErr == unix.EACCES {
		return nil
	}
	return opErr
}

func defaultPhysicalRouteInterface() string {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "dev" && !isVirtualTunInterface(fields[i+1]) {
				return fields[i+1]
			}
		}
	}
	return ""
}
