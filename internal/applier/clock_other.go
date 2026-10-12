//go:build !linux

package applier

import "time"

var processStart = time.Now()

// BootClock stands in for CLOCK_MONOTONIC where it is not available: seconds
// since the process started. Only the development machine uses it.
func BootClock() float64 { return time.Since(processStart).Seconds() }
