//go:build linux

package netx

import (
	"syscall"
)

// bindControl returns the dialer hook that binds a connection to an interface
// (SO_BINDTODEVICE) and marks it (SO_MARK), or nil when the request asks for
// neither.
func bindControl(iface string, mark uint32) func(network, address string, c syscall.RawConn) error {
	if iface == "" && mark == 0 {
		return nil
	}
	return func(_, _ string, c syscall.RawConn) error {
		var failure error
		err := c.Control(func(fd uintptr) {
			if iface != "" {
				if e := syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface); e != nil {
					failure = e
					return
				}
			}
			if mark != 0 {
				if e := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark)); e != nil {
					failure = e
				}
			}
		})
		if err != nil {
			return err
		}
		return failure
	}
}
