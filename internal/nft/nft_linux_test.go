//go:build linux

package nft

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/nftables"
)

type fakeConn struct {
	stall  bool
	once   sync.Once
	closed chan struct{}
	chains []*nftables.Chain
}

func (f *fakeConn) ListChains() ([]*nftables.Chain, error) {
	if f.stall {
		<-f.closed
		return nil, errors.New("closed")
	}
	return f.chains, nil
}
func (f *fakeConn) CloseLasting() error { f.once.Do(func() { close(f.closed) }); return nil }

func TestAStalledChainDumpEndsAtTheDeadline(t *testing.T) { // finding: a stalled dump waited forever
	f := &fakeConn{stall: true, closed: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := listChains(ctx, func() (lister, error) { return f, nil })
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("%v", err)
	}
	if time.Since(start) > 250*time.Millisecond {
		t.Errorf("took %v", time.Since(start))
	}
	select {
	case <-f.closed:
	default:
		t.Error("the connection was not closed")
	}
}

func TestChainsAreMapped(t *testing.T) {
	f := &fakeConn{closed: make(chan struct{}), chains: []*nftables.Chain{
		{Name: "netbird-acl", Table: &nftables.Table{Name: "netbird", Family: nftables.TableFamilyIPv4}},
		{Name: "orphan"},
	}}
	got, err := listChains(context.Background(), func() (lister, error) { return f, nil })
	if err != nil || len(got) != 1 || got[0].Family != "ip" || got[0].Table != "netbird" {
		t.Fatalf("%+v %v", got, err)
	}
	select {
	case <-f.closed:
	default:
		t.Error("the lasting connection was left open")
	}
}

func TestAnOpenFailureIsReported(t *testing.T) {
	_, err := listChains(context.Background(), func() (lister, error) { return nil, errors.New("no netlink") })
	if err == nil {
		t.Fatal("no error")
	}
}

// A connection that is still being opened when the deadline passes is closed
// when it arrives, not left open.
func TestAConnectionDeliveredAfterCancellationIsClosed(t *testing.T) {
	late := &fakeConn{closed: make(chan struct{})}
	release := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := listChains(ctx, func() (lister, error) { <-release; return late, nil })
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("%v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the stalled open outlived its deadline")
	}
	close(release) // the dial finishes now, too late
	select {
	case <-late.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("the connection delivered after cancellation was left open")
	}
}

// If cancellation closes the lasting connection before the dump starts, the
// connection redials a transient socket of its own. Every socket carries the
// absolute deadline (nftables.WithSockOptions), so that dump ends at the
// deadline, not whenever the kernel answers. The fake models exactly that.
type redialingConn struct {
	deadline time.Time
	once     sync.Once
	closed   chan struct{}
	started  chan struct{}
}

func (r *redialingConn) ListChains() ([]*nftables.Chain, error) {
	<-r.started
	select {
	case <-r.closed: // already closed: the transient redial, bounded by the socket's own deadline
		time.Sleep(time.Until(r.deadline))
		return nil, os.ErrDeadlineExceeded
	default:
	}
	<-r.closed
	return nil, errors.New("closed")
}
func (r *redialingConn) CloseLasting() error { r.once.Do(func() { close(r.closed) }); return nil }

func TestARedialAfterCancellationStillEndsAtTheDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	dl, _ := ctx.Deadline()
	r := &redialingConn{deadline: dl, closed: make(chan struct{}), started: make(chan struct{})}
	go func() { time.Sleep(60 * time.Millisecond); close(r.started) }() // the worker acquires its connection late
	start := time.Now()
	_, err := listChains(ctx, func() (lister, error) { return r, nil })
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("%v", err)
	}
	if time.Since(start) > 400*time.Millisecond {
		t.Errorf("took %v", time.Since(start))
	}
}

func TestAnExpiredContextOpensNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	opened := false
	if _, err := listChains(ctx, func() (lister, error) { opened = true; return nil, nil }); err == nil || opened {
		t.Fatalf("%v %v", err, opened)
	}
}
