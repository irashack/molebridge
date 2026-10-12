package rtnl

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrStuck is returned when a call did not return even after its connection
// was closed.
var ErrStuck = errors.New("rtnl: a netlink call did not return after its connection was closed")

// DefaultAbortGrace is how long RunBounded waits for a call to return after
// the connection under it was closed.
const DefaultAbortGrace = time.Second

// RunBounded runs fn, which makes calls on a connection that has no deadline
// of its own (a WireGuard or nftables netlink connection), so that it cannot
// outlast ctx.
//
// If fn returns first, its result is returned. If ctx ends first, abort is
// called, which must close the connection fn is blocked on: closing a netlink
// socket unblocks its pending read. RunBounded then waits up to grace for fn
// to return, because a mutation whose reply was cut off may still have been
// applied and nothing else may start until this one is finished; it returns
// fn's result if there is one, and otherwise ctx's error wrapped as a deadline
// error. The caller must discard the connection abort closed and open a fresh
// one for its next call. If fn is still running after grace, ErrStuck says so.
func RunBounded(ctx context.Context, grace time.Duration, abort func(), fn func() error) error {
	if err := ctx.Err(); err != nil {
		return boundedErr(err)
	}
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
	}
	abort()
	if grace <= 0 {
		grace = DefaultAbortGrace
	}
	t := time.NewTimer(grace)
	defer t.Stop()
	select {
	case err := <-done:
		if err == nil {
			return nil
		}
		return fmt.Errorf("%w (%v)", boundedErr(ctx.Err()), err)
	case <-t.C:
		return fmt.Errorf("%w: %w", ErrStuck, boundedErr(ctx.Err()))
	}
}

func boundedErr(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrDeadline
	}
	return err
}
