//go:build linux

package nft

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"

	"github.com/irashack/molebridge/internal/rtnl"
)

// A change whose context is already over never opens a socket or touches the
// kernel, and says so with the deadline error the owner reports.
func TestForwardChangesHonorTheDeadline(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	target := netip.MustParseAddr("100.64.0.9")
	for name, err := range map[string]error{
		"guard":  InstallIngressGuard(ctx, 0, "mullvad", "wt0"),
		"apply":  ApplyForwardRules(ctx, 0, "mullvad", "wt0", 41234, target),
		"remove": RemoveForwardRules(ctx, 0),
	} {
		if !errors.Is(err, rtnl.ErrDeadline) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := ApplyForwardRules(context.Background(), 0, "mullvad", "wt0", 0, target); err == nil {
		t.Error("port 0 must be refused before any socket opens")
	}
}

// A mutation whose acknowledgement never comes: Flush holds the library's
// mutex while it reads, so cancelling through CloseLasting would wait behind
// it and the deadline would never fire. The socket is closed directly and the
// call reports the deadline (or, when the fake socket ignores the close, that
// it is stuck) within the grace, not when the kernel finally answers.
func TestAStalledMutationEndsAtTheDeadlineAndTheSocketIsClosedDirectly(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var requests, sockets atomic.Int32
	extraConnOptions = func() []nftables.ConnOption {
		return []nftables.ConnOption{
			nftables.WithTestDial(func([]netlink.Message) ([]netlink.Message, error) {
				requests.Add(1)
				<-release // no acknowledgement
				return nil, errors.New("released")
			}),
			nftables.WithSockOptions(func(*netlink.Conn) error { sockets.Add(1); return nil }),
		}
	}
	var deadlines atomic.Int32
	setSocketDeadline = func(c *netlink.Conn, t time.Time) error { deadlines.Add(1); return nil }
	t.Cleanup(func() {
		extraConnOptions = nil
		setSocketDeadline = func(c *netlink.Conn, t time.Time) error { return c.SetDeadline(t) }
	})
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	start := time.Now()
	done := make(chan error, 1)
	go func() {
		done <- InstallIngressGuard(ctx, 0, "mullvad", "wt0")
	}()
	select {
	case err := <-done:
		if err == nil || !errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, rtnl.ErrStuck) {
			t.Fatalf("%v", err)
		}
		if took := time.Since(start); took > 3*time.Second {
			t.Errorf("took %v for an 80 ms deadline", took)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the mutation did not end at its deadline")
	}
	if requests.Load() == 0 {
		t.Error("the fake never saw the request")
	}
	if deadlines.Load() != 1 {
		t.Errorf("the deadline was put on %d sockets", deadlines.Load())
	}
	if sockets.Load() != 1 {
		t.Errorf("%d sockets were opened for one mutation", sockets.Load())
	}
}

// One socket per mutation: a second one the library dials is refused, and a
// socket that cannot take its deadline is not used.
func TestOnlyTheFirstSocketIsKeptAndItMustTakeItsDeadline(t *testing.T) {
	o := &owned{dl: time.Now().Add(time.Second)}
	first := newStallSocket()
	if err := o.option(netlink.NewConn(first, 1)); err != nil {
		t.Fatal(err)
	}
	if first.deadlineSet().IsZero() {
		t.Error("the socket was not given the deadline")
	}
	second := newStallSocket()
	if err := o.option(netlink.NewConn(second, 1)); !errors.Is(err, errSecondSocket) {
		t.Errorf("a second socket was not refused: %v", err)
	}
	select {
	case <-second.closed:
	default:
		t.Error("the refused socket was left open")
	}
	o.close()
	select {
	case <-first.closed:
	default:
		t.Error("close did not close the kept socket")
	}
	// A socket without deadline support is closed, not used.
	bare := nltest.Dial(func([]netlink.Message) ([]netlink.Message, error) { return nil, nil })
	if err := (&owned{dl: time.Now().Add(time.Second)}).option(bare); err == nil {
		t.Error("a socket that cannot take a deadline was kept")
	}
}
