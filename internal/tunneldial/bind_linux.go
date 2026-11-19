//go:build linux

package tunneldial

import "syscall"

// bindToDevice sets SO_BINDTODEVICE on the socket.
func bindToDevice(fd uintptr, iface string) error {
	return syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
}
