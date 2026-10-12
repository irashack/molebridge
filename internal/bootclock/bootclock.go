// Package bootclock is the kernel's boot clock: CLOCK_BOOTTIME on Linux, a
// clock that keeps counting while the host is suspended and that wall-clock
// changes do not move. The supervisor's lease and the worker's progress
// reports are stated on it, so a changed system date can neither extend nor
// shorten them.
//
// Elsewhere (development machines) it falls back to the monotonic time since
// the process started, which is all the tests need.
package bootclock

import "time"

// Clock reads the boot clock as a duration since boot.
type Clock func() time.Duration

// System returns the real boot clock.
func System() Clock { return now }

// Seconds is a Clock's reading in whole seconds, the unit of the legacy owner
// record.
func (c Clock) Seconds() uint64 { return uint64(c() / time.Second) }
