//go:build darwin

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
	var opErr error
	if err := c.Control(func(fd uintptr) {
		if strings.HasSuffix(network, "6") {
			opErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, ifIndex)
			return
		}
		opErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, ifIndex)
	}); err != nil {
		return err
	}
	return opErr
}

func defaultPhysicalRouteInterface() string {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "interface:" {
			cand := strings.TrimSpace(fields[1])
			if !isVirtualTunInterface(cand) {
				return cand
			}
		}
	}
	// If default route is currently utun, inspect routing table for default gateway on physical interface.
	out2, err := exec.Command("netstat", "-rn", "-f", "inet").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out2), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == "default" {
			cand := fields[3]
			if !isVirtualTunInterface(cand) {
				if _, err := net.InterfaceByName(cand); err == nil {
					return cand
				}
			}
		}
	}
	return ""
}
