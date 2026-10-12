package tunnel

import "time"

// Retry curve of the bring-up: 2 seconds, doubling, capped at 60.
const (
	FirstDelay = 2 * time.Second
	MaxDelay   = 60 * time.Second
)

// Delay returns the wait after a failed attempt given the previous wait; zero
// starts the curve. It is the curve routing/molebridge-exit used.
func Delay(previous time.Duration) time.Duration {
	if previous <= 0 {
		return FirstDelay
	}
	next := previous * 2
	if next > MaxDelay {
		return MaxDelay
	}
	return next
}
