//go:build linux

package bootclock

import (
	"time"

	"golang.org/x/sys/unix"
)

func now() time.Duration {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		// CLOCK_BOOTTIME exists since Linux 2.6.39; fall back to the
		// monotonic clock rather than report zero.
		_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	}
	return time.Duration(ts.Sec)*time.Second + time.Duration(ts.Nsec)
}
