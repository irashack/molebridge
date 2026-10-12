//go:build drill && linux

package drill

// Partial failure of PIA's address change against a real kernel: whatever step
// of the change fails, every address that is live on the tunnel interface
// keeps its return-path pair, observed continuously from an independent socket
// from before the change until after it.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/mutator"
	"github.com/irashack/molebridge/internal/rtnl"
)

// pairWatch polls the kernel and records the first moment a live global
// IPv4 address on the tunnel interface lacked rule 94 or rule 98.
type pairWatch struct {
	r      *rig
	stop   chan struct{}
	wg     sync.WaitGroup
	mu     sync.Mutex
	broken string
	polls  atomic.Int64
}

func watchPairs(r *rig) *pairWatch {
	w := &pairWatch{r: r, stop: make(chan struct{})}
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		for {
			select {
			case <-w.stop:
				return
			default:
			}
			snap, err := r.obs.Take(r.spec.Interest())
			if err != nil {
				continue
			}
			w.polls.Add(1)
			link, ok := snap.Link(exitIf)
			if !ok {
				continue
			}
			for _, a := range snap.Addrs[rtnl.V4] {
				if a.Index != link.Index || !a.Global() {
					continue
				}
				has := map[uint32]bool{}
				for _, rule := range snap.Rules[rtnl.V4] {
					if rule.Src.IsValid() && rule.Src.Addr() == a.Local.Addr() {
						has[rule.Priority] = true
					}
				}
				if !has[94] || !has[98] {
					w.mu.Lock()
					if w.broken == "" {
						w.broken = fmt.Sprintf("live address %s lacked its pair (94 %v, 98 %v)", a.Local.Addr(), has[94], has[98])
					}
					w.mu.Unlock()
				}
			}
		}
	}()
	return w
}

func (w *pairWatch) finish(t *testing.T, what string) {
	t.Helper()
	close(w.stop)
	w.wg.Wait()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.broken != "" {
		t.Errorf("%s: %s", what, w.broken)
	}
	if w.polls.Load() < 5 {
		t.Errorf("%s: only %d observations", what, w.polls.Load())
	}
}

func ipNS(ns string, args ...string) error {
	out, err := exec.Command("ip", append([]string{"-n", ns}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %v: %v\n%s", args, err, out)
	}
	return nil
}

func ruleSources(r *rig) map[string][]string {
	snap, _ := r.obs.Take(r.spec.Interest())
	out := map[string][]string{}
	for _, rule := range snap.Rules[rtnl.V4] {
		if rule.Priority == 94 || rule.Priority == 98 {
			out[rule.Src.Addr().String()] = append(out[rule.Src.Addr().String()], fmt.Sprint(rule.Priority))
		}
	}
	return out
}

func registered(t *testing.T) *rig {
	r := piaRig(t)
	// The address the interface already has is registered: its pair goes in.
	if err := r.mut.ChangeReturnPath(context.Background(), rtnl.V4, netip.Addr{}, tunnel4, func(*mutator.Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	r.waitHealthy(2 * time.Second)
	return r
}

func TestAddressThatArrivedBeforeALaterStepFailedKeepsItsPair(t *testing.T) {
	r := registered(t)
	next := netip.MustParseAddr("203.0.113.12")
	w := watchPairs(r)
	err := r.mut.ChangeReturnPath(context.Background(), rtnl.V4, tunnel4, next, func(tx *mutator.Tx) error {
		if err := ipNS(r.exit.Name, "-4", "addr", "add", next.String()+"/32", "dev", exitIf); err != nil {
			return err
		}
		return errors.New("setting the peer failed")
	})
	if err == nil {
		t.Fatal("the failure was not reported")
	}
	time.Sleep(30 * time.Millisecond)
	w.finish(t, "a failure after the address arrived")
	got := ruleSources(r)
	for _, a := range []string{tunnel4.String(), next.String()} {
		if len(got[a]) != 2 {
			t.Errorf("%s: rules %v after the failure (both addresses are live)", a, got)
		}
	}
	if !r.healthy() {
		t.Error("the contract does not hold afterwards")
	}
}

func TestAChangeThatFailsBeforeTheAddressArrivesTakesTheNewPairBackOut(t *testing.T) {
	r := registered(t)
	next := netip.MustParseAddr("203.0.113.13")
	w := watchPairs(r)
	err := r.mut.ChangeReturnPath(context.Background(), rtnl.V4, tunnel4, next, func(tx *mutator.Tx) error {
		return errors.New("registration refused")
	})
	if err == nil {
		t.Fatal("no error")
	}
	w.finish(t, "a failure before the address arrived")
	got := ruleSources(r)
	if len(got[next.String()]) != 0 || len(got[tunnel4.String()]) != 2 {
		t.Errorf("rules %v: the address that never arrived must lose its pair and the live one keep it", got)
	}
}

func TestTheSameAddressIsNeverLeftWithoutItsPair(t *testing.T) {
	r := registered(t)
	w := watchPairs(r)
	for _, failure := range []error{nil, errors.New("registration failed"), nil, errors.New("again")} {
		failure := failure
		err := r.mut.ChangeReturnPath(context.Background(), rtnl.V4, tunnel4, tunnel4, func(tx *mutator.Tx) error { return failure })
		if (err == nil) != (failure == nil) {
			t.Fatalf("%v for %v", err, failure)
		}
	}
	w.finish(t, "old == new")
	if got := ruleSources(r); len(got[tunnel4.String()]) != 2 {
		t.Errorf("%v", got)
	}
}

func TestAnAddressThatLeftLosesItsPairOnlyAfterItIsGone(t *testing.T) {
	r := registered(t)
	next := netip.MustParseAddr("203.0.113.14")
	w := watchPairs(r)
	err := r.mut.ChangeReturnPath(context.Background(), rtnl.V4, tunnel4, next, func(tx *mutator.Tx) error {
		// The new address arrives; the old one is not removed (a half change).
		return ipNS(r.exit.Name, "-4", "addr", "add", next.String()+"/32", "dev", exitIf)
	})
	if err != nil {
		t.Fatal(err)
	}
	// Success, but the old address is still on the interface: it keeps its pair.
	w.finish(t, "a change that left the old address in place")
	got := ruleSources(r)
	if len(got[tunnel4.String()]) != 2 || len(got[next.String()]) != 2 {
		t.Errorf("%v", got)
	}
	// A later change that does remove it takes the pair out.
	err = r.mut.ChangeReturnPath(context.Background(), rtnl.V4, tunnel4, next, func(tx *mutator.Tx) error {
		return ipNS(r.exit.Name, "-4", "addr", "del", tunnel4.String()+"/24", "dev", exitIf)
	})
	if err != nil {
		t.Fatal(err)
	}
	got = ruleSources(r)
	if len(got[tunnel4.String()]) != 0 || len(got[next.String()]) != 2 {
		t.Errorf("%v", got)
	}
}
