//go:build !linux

package netx

import "syscall"

// bindControl is a no-op where SO_BINDTODEVICE and SO_MARK do not exist, so
// the package builds and its tests run on a development machine.
func bindControl(string, uint32) func(network, address string, c syscall.RawConn) error {
	return nil
}
