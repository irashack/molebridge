package rtnl

import (
	"errors"
	"syscall"
)

// ErrOverrun is returned by the event subscription when the kernel dropped
// multicast messages because the socket's receive buffer filled (ENOBUFS).
// Events were lost; the caller must run a full pass.
var ErrOverrun = errors.New("rtnl: netlink events were lost (receive buffer overrun)")

// ErrInconsistent is returned by a dump the kernel flagged as interrupted by
// concurrent changes (NLM_F_DUMP_INTR) on every attempt.
var ErrInconsistent = errors.New("rtnl: dump kept being interrupted by concurrent changes")

// IsExist reports EEXIST.
func IsExist(err error) bool { return errors.Is(err, syscall.EEXIST) }

// IsNotExist reports ENOENT, ESRCH (what a route delete returns when nothing
// matches) or ENODEV.
func IsNotExist(err error) bool {
	return errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ESRCH) || errors.Is(err, syscall.ENODEV)
}
