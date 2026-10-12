package mutator

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/rtnl"
)

// A kernel that takes one absolute deadline for the whole operation and a
// context for its snapshots, as rtnl.Conn does.
type deadlineKernel struct {
	*fakeKernel
	mu        sync.Mutex
	deadlines []time.Time
	ctxs      []context.Context
}

func (d *deadlineKernel) SetDeadline(t time.Time) {
	d.mu.Lock()
	d.deadlines = append(d.deadlines, t)
	d.mu.Unlock()
}
func (d *deadlineKernel) TakeContext(ctx context.Context, in rtnl.Interest) (*rtnl.Snapshot, error) {
	d.mu.Lock()
	d.ctxs = append(d.ctxs, ctx)
	d.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return d.fakeKernel.Take(in)
}

func TestTheOperationsOneDeadlineGoesToTheKernel(t *testing.T) {
	d := &deadlineKernel{fakeKernel: newFakeKernel()}
	m := startWith(t, d, nativeSpec(), func(o *Options) { o.OpTimeout = 3 * time.Second })
	var opDeadline time.Time
	err := m.Do(context.Background(), "x", func(tx *Tx) error {
		opDeadline, _ = tx.Context().Deadline()
		if _, err := tx.Snapshot(); err != nil {
			return err
		}
		return tx.AddRule(rtnl.Rule{Family: 4, Priority: 5000, Action: rtnl.FRActUnreachable})
	})
	if err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.deadlines) < 3 {
		t.Fatalf("%v", d.deadlines)
	}
	for _, dl := range d.deadlines[:len(d.deadlines)-1] {
		if !dl.Equal(opDeadline) {
			t.Errorf("a request was given %v, the operation's deadline is %v", dl, opDeadline)
		}
	}
	if last := d.deadlines[len(d.deadlines)-1]; !last.IsZero() {
		t.Errorf("the deadline outlived the operation: %v", last)
	}
	if len(d.ctxs) != 1 {
		t.Errorf("snapshot did not go through TakeContext")
	}
}

func TestCancellationReachesTheKernelsSnapshot(t *testing.T) {
	d := &deadlineKernel{fakeKernel: newFakeKernel()}
	m := startWith(t, d, nativeSpec())
	ctx, cancel := context.WithCancel(context.Background())
	err := m.Do(ctx, "x", func(tx *Tx) error {
		cancel()
		_, err := tx.Snapshot()
		return err
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
}
