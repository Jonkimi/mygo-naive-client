//go:build linux

package tunhelper

import (
	"fmt"
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
	return fd, name, nil
}
