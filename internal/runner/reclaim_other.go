//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd

package runner

func reclaimSidecarOnPort(port int) bool {
	return false
}
