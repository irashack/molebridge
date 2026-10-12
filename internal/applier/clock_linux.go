//go:build linux

package applier

import (
	"syscall"
	"unsafe"
)

const clockMonotonic = 1

// BootClock is CLOCK_MONOTONIC in seconds, the clock the attempt record keeps
// its deadlines on (together with the boot id, so a value from another boot is
// recognised).
func BootClock() float64 {
	var ts syscall.Timespec
	if _, _, errno := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, clockMonotonic, uintptr(unsafe.Pointer(&ts)), 0); errno != 0 {
		return 0
	}
	return float64(ts.Sec) + float64(ts.Nsec)/1e9
}
