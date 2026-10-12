//go:build !linux

package bootclock

import "time"

var start = time.Now()

func now() time.Duration { return time.Since(start) }
