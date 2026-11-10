//go:build !windows

package tunhelper

import "os"

// IsElevated reports whether the current process is running with root/elevated privileges.
func IsElevated() bool {
	return os.Geteuid() == 0
}
