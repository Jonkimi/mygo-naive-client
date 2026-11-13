//go:build !darwin && !linux

package warp

import "syscall"

func bindSocketToInterface(network string, ifIndex int, c syscall.RawConn) error {
	return nil
}

func defaultPhysicalRouteInterface() string {
	return ""
}
