//go:build !linux

package tunneldial

import "errors"

// bindToDevice fails: binding a socket to a device is Linux only, and there
// is no unbound fallback.
func bindToDevice(uintptr, string) error {
	return errors.New("binding a socket to a device is supported on Linux only")
}
