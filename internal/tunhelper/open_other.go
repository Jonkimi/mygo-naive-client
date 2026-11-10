//go:build !darwin && !linux

package tunhelper

import "errors"

func OpenPlatformTUN() (int, string, error) {
	return 0, "", errors.New("TUN helper not supported on this platform")
}

func SetupRoutes(name string, excludeIPs []string) error {
	return nil
}

func TeardownRoutes(name string, excludeIPs []string) error {
	return nil
}
