//go:build linux

package rtnl

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// maxSnapshotAttempts bounds how many times a whole snapshot is taken again
// because a dump was interrupted by a concurrent change or the request stream
// had to be replaced.
const maxSnapshotAttempts = 8

// Take dumps the rules, the routes of the wanted tables, the links and the
// addresses. Callers that watch for changes must have joined the multicast
// groups (Subscribe) before calling it. See TakeContext.
func (c *Conn) Take(in Interest) (*Snapshot, error) { return c.TakeContext(context.Background(), in) }

// TakeContext is Take bounded by ctx and by the Conn's deadline: one absolute
// deadline covers every dump and every retry, and cancellation is checked
// between dumps.
//
// A snapshot is only as good as its weakest dump. If any dump is marked
// NLM_F_DUMP_INTR (on an entry or on NLMSG_DONE), or the request stream has to
// be replaced because a reply was lost, late or out of sequence, everything
// read so far is discarded and the whole snapshot is taken again on the
// (possibly fresh) socket. A timeout is not retried; the operation is out of
// time.
func (c *Conn) TakeContext(ctx context.Context, in Interest) (*Snapshot, error) {
	var last error
	for attempt := 0; attempt < maxSnapshotAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s, err := c.takeOnce(ctx, in)
		switch {
		case err == nil:
			return s, nil
		case errors.Is(err, errInterrupted):
			last = ErrInconsistent
		case IsStreamError(err) && !errors.Is(err, os.ErrDeadlineExceeded):
			last = err
		default:
			return nil, err
		}
	}
	return nil, fmt.Errorf("rtnl: no consistent snapshot after %d attempts: %w", maxSnapshotAttempts, last)
}

func (c *Conn) takeOnce(ctx context.Context, in Interest) (*Snapshot, error) {
	s := NewSnapshot()
	want := func(t uint32) bool {
		for _, w := range in.Tables {
			if w == t {
				return true
			}
		}
		return false
	}
	for _, f := range []Family{V4, V6} {
		rules, err := c.rulesOnce(ctx, f)
		if err != nil {
			return nil, err
		}
		s.Rules[f] = rules
		routes, err := c.routesOnce(ctx, f, want)
		if err != nil {
			return nil, err
		}
		s.Routes[f] = routes
		addrs, err := c.addrsOnce(ctx, f)
		if err != nil {
			return nil, err
		}
		s.Addrs[f] = addrs
	}
	links, err := c.linksOnce(ctx)
	if err != nil {
		return nil, err
	}
	s.Links = links
	return s, nil
}
