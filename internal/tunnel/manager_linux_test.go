//go:build linux

package tunnel

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
	"github.com/irashack/molebridge/internal/tunnelconf"
)

// ---- the WireGuard socket ----

// A WireGuard connection that answers when told to and otherwise blocks until
// it is closed, as a read on a netlink socket does.
type fakeWG struct {
	id      int
	stall   bool
	ignores bool // does not return when closed
	mark    int
	closed  chan struct{}
	once    sync.Once
	broken  atomic.Bool
	ctxs    []context.Context
	mu      sync.Mutex
}

func (c *fakeWG) block(ctx context.Context) error {
	if c.ignores {
		select {} // never returns
	}
	select {
	case <-c.closed:
		return errors.New("use of a closed connection")
	case <-ctx.Done():
		c.broken.Store(true) // as wgnl does at a deadline
		return os.ErrDeadlineExceeded
	}
}

func (c *fakeWG) note(ctx context.Context) { c.mu.Lock(); c.ctxs = append(c.ctxs, ctx); c.mu.Unlock() }

func (c *fakeWG) Configure(ctx context.Context, _ string, _ wgtypes.Config) error {
	c.note(ctx)
	if c.stall {
		return c.block(ctx)
	}
	return nil
}

func (c *fakeWG) Device(ctx context.Context, name string) (*wgtypes.Device, error) {
	c.note(ctx)
	if name == "gone" {
		return nil, os.ErrNotExist
	}
	if c.stall {
		return nil, c.block(ctx)
	}
	return &wgtypes.Device{FirewallMark: c.mark}, nil
}

func (c *fakeWG) Broken() bool { return c.broken.Load() }
func (c *fakeWG) Close() error {
	c.broken.Store(true)
	c.once.Do(func() { close(c.closed) })
	return nil
}

type wgFactory struct {
	mu      sync.Mutex
	opened  []*fakeWG
	stalled func(n int) (stall, ignores bool)
}

func (f *wgFactory) dial(context.Context) (wgAPI, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := len(f.opened)
	c := &fakeWG{id: n, mark: 0x1bd00, closed: make(chan struct{})}
	if f.stalled != nil {
		c.stall, c.ignores = f.stalled(n)
	}
	f.opened = append(f.opened, c)
	return c, nil
}

func (f *wgFactory) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.opened) }

func newWGManager(f *wgFactory) *Manager { return &Manager{dialWG: f.dial} }

func TestAStalledFwmarkReadEndsAtTheDeadlineAndTheConnectionIsReplaced(t *testing.T) { // finding: the fwmark monitor's next sample
	f := &wgFactory{stalled: func(n int) (bool, bool) { return n == 0, false }}
	m := newWGManager(f)
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := m.FwmarkContext(ctx, "wt0")
	if err == nil || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("%v", err)
	}
	if took := time.Since(start); took > 250*time.Millisecond {
		t.Errorf("took %v for an 80 ms deadline", took)
	}
	select {
	case <-f.opened[0].closed:
	default:
		t.Error("the stalled connection was not closed")
	}
	// The next sample opens a fresh connection and succeeds.
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	mark, err := m.FwmarkContext(ctx2, "wt0")
	if err != nil || mark != 0x1bd00 || f.count() != 2 {
		t.Fatalf("%x %v (%d connections)", mark, err, f.count())
	}
	if SampleBudget != 2*time.Second {
		t.Errorf("the sample budget is %v", SampleBudget)
	}
}

func TestAReadWithoutADeadlineIsGivenTheSampleBudget(t *testing.T) {
	f := &wgFactory{}
	m := newWGManager(f)
	if _, err := m.FwmarkContext(context.Background(), "wt0"); err != nil {
		t.Fatal(err)
	}
	dl, ok := f.opened[0].ctxs[0].Deadline()
	if !ok || time.Until(dl) > SampleBudget {
		t.Errorf("deadline %v ok=%v", dl, ok)
	}
}

func TestAStalledMutationIsCutOffAndReported(t *testing.T) {
	f := &wgFactory{stalled: func(n int) (bool, bool) { return n == 0, false }}
	m := newWGManager(f)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	err := m.configure(ctx, Params{ExitIf: "x", Conf: testConf(t)})
	if err == nil || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("%v", err)
	}
	// No second operation is admitted before the first is finished: the call
	// returned only after its connection was closed.
	select {
	case <-f.opened[0].closed:
	default:
		t.Fatal("the connection was not closed before the call returned")
	}
}

func TestAConnectionThatIgnoresTheCloseIsReportedStuck(t *testing.T) {
	f := &wgFactory{stalled: func(n int) (bool, bool) { return n == 0, true }}
	m := newWGManager(f)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := m.FwmarkContext(ctx, "wt0")
	if !errors.Is(err, rtnl.ErrStuck) {
		t.Fatalf("%v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("took %v", time.Since(start))
	}
	// And the next call does not queue behind the stuck one: it has a new connection.
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if _, err := m.FwmarkContext(ctx2, "wt0"); err != nil {
		t.Fatal(err)
	}
}

func TestAMissingDeviceIsAnswerNotAFailure(t *testing.T) {
	m := newWGManager(&wgFactory{})
	if _, err := m.FwmarkContext(context.Background(), "gone"); !errors.Is(err, ErrNoDevice) {
		t.Fatalf("%v", err)
	}
}

func TestWireGuardCallsAreOneAtATime(t *testing.T) {
	f := &wgFactory{}
	m := newWGManager(f)
	var running, maxRunning atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = m.wgCall(context.Background(), func(wgAPI) error {
				n := running.Add(1)
				for {
					m := maxRunning.Load()
					if n <= m || maxRunning.CompareAndSwap(m, n) {
						break
					}
				}
				time.Sleep(5 * time.Millisecond)
				running.Add(-1)
				return nil
			})
		}()
	}
	wg.Wait()
	if maxRunning.Load() != 1 || f.count() != 1 {
		t.Fatalf("%d at once, %d connections", maxRunning.Load(), f.count())
	}
}

func TestCloseUnblocksAStalledCall(t *testing.T) {
	f := &wgFactory{stalled: func(int) (bool, bool) { return true, false }}
	m := newWGManager(f)
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	go func() { _, err := m.FwmarkContext(ctx, "wt0"); done <- err }()
	time.Sleep(30 * time.Millisecond)
	_ = m.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("no error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock the call")
	}
}

func TestTheWireGuardDialIsGivenTheContextsDeadline(t *testing.T) {
	var got time.Time
	m := &Manager{dialWG: func(ctx context.Context) (wgAPI, error) {
		got, _ = ctx.Deadline()
		return &fakeWG{closed: make(chan struct{})}, nil
	}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	want, _ := ctx.Deadline()
	if _, err := m.FwmarkContext(ctx, "wt0"); err != nil || !got.Equal(want) {
		t.Fatalf("%v: the dial was given %v, want %v", err, got, want)
	}
}

func TestAConnectionBrokenByItsDeadlineIsNotReused(t *testing.T) {
	f := &wgFactory{}
	m := newWGManager(f)
	if _, err := m.Device(context.Background(), "wt0"); err != nil {
		t.Fatal(err)
	}
	f.opened[0].broken.Store(true) // closed at some earlier deadline
	if _, err := m.Device(context.Background(), "wt0"); err != nil || f.count() != 2 {
		t.Fatalf("%v (%d connections)", err, f.count())
	}
}

func TestADeviceReadThatNeverStartsIsNotSent(t *testing.T) {
	f := &wgFactory{}
	m := newWGManager(f)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.Device(ctx, "wt0"); err == nil || f.count() != 0 {
		t.Fatalf("%v, %d connections", err, f.count())
	}
}

func testConf(t *testing.T) *tunnelconf.Conf {
	t.Helper()
	key := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	text := "[Interface]\nPrivateKey = " + key + "\nMTU = 1420\nTable = off\nPostUp = ip route replace default dev %i table 51821\nPreDown = ip route del default dev %i table 51821\n"
	c, err := tunnelconf.Parse(text, tunnelconf.PIA, 51821)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// ---- the route socket ----

// A route socket whose calls each take a while, and which blocks a chosen
// call until it is interrupted, as a read on a netlink socket does.
type fakeRT struct {
	mu        sync.Mutex
	per       time.Duration
	stallOn   string // a method name, "*" for every call, "" for none
	ignores   bool   // a stalled call does not return when interrupted
	missing   bool
	calls     []string
	deadlines []time.Time
	intr      chan struct{}
	closed    atomic.Bool
}

func newFakeRT() *fakeRT { return &fakeRT{intr: make(chan struct{})} }

func (f *fakeRT) call(name string) error {
	f.mu.Lock()
	f.calls = append(f.calls, name)
	stall := f.stallOn == name || f.stallOn == "*"
	ch := f.intr
	f.mu.Unlock()
	if stall {
		if f.ignores {
			select {} // never returns
		}
		<-ch
		return errors.New("use of a closed socket")
	}
	select {
	case <-time.After(f.per):
		return nil
	case <-ch:
		return errors.New("use of a closed socket")
	}
}

func (f *fakeRT) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeRT) LinkByName(name string) (rtnl.Link, error) {
	if err := f.call("LinkByName"); err != nil {
		return rtnl.Link{}, err
	}
	if f.missing {
		return rtnl.Link{}, syscall.ENODEV
	}
	return rtnl.Link{Index: 7, Name: name, Kind: "wireguard"}, nil
}
func (f *fakeRT) AddLink(string, string) error  { return f.call("AddLink") }
func (f *fakeRT) DelLink(uint32) error          { return f.call("DelLink") }
func (f *fakeRT) SetLinkMTU(_, _ uint32) error  { return f.call("SetLinkMTU") }
func (f *fakeRT) SetLinkUp(uint32) error        { return f.call("SetLinkUp") }
func (f *fakeRT) AddAddr(rtnl.Addr) error       { return f.call("AddAddr") }
func (f *fakeRT) ReplaceRoute(rtnl.Route) error { return f.call("ReplaceRoute") }
func (f *fakeRT) DelRoute(rtnl.Route) error     { return f.call("DelRoute") }
func (f *fakeRT) SetDeadline(t time.Time) {
	f.mu.Lock()
	f.deadlines = append(f.deadlines, t)
	f.mu.Unlock()
}
func (f *fakeRT) Interrupt() {
	f.mu.Lock()
	close(f.intr)
	f.intr = make(chan struct{})
	f.stallOn = "" // the kernel is reachable again on the next socket
	f.mu.Unlock()
}
func (f *fakeRT) Close() error { f.closed.Store(true); return nil }

type rtFactory struct {
	mu     sync.Mutex
	opened []*fakeRT
	make   func(n int) *fakeRT
}

func (r *rtFactory) dial() (routeAPI, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f := newFakeRT()
	if r.make != nil {
		f = r.make(len(r.opened))
	}
	r.opened = append(r.opened, f)
	return f, nil
}

func (r *rtFactory) count() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.opened) }

func newRTManager(r *rtFactory) *Manager { return &Manager{dialRT: r.dial} }

func TestAGroupOfRouteCallsSharesOneAbsoluteDeadline(t *testing.T) { // finding: each receive restarted a relative timeout
	r := &rtFactory{make: func(int) *fakeRT { f := newFakeRT(); f.per = 40 * time.Millisecond; return f }}
	m := newRTManager(r)
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Millisecond)
	defer cancel()
	want, _ := ctx.Deadline()
	start := time.Now()
	err := m.rtDo(ctx, func(rt routeAPI) error {
		// Three calls of 40 ms each: 120 ms against a 70 ms deadline.
		for i := 0; i < 3; i++ {
			if _, err := rt.LinkByName("x"); err != nil {
				return err
			}
		}
		return nil
	})
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("%v", err)
	}
	if took := time.Since(start); took > 140*time.Millisecond {
		t.Errorf("took %v for a 70 ms deadline", took)
	}
	f := r.opened[0]
	f.mu.Lock()
	if len(f.deadlines) == 0 || !f.deadlines[0].Equal(want) {
		t.Errorf("the socket was given %v, want %v", f.deadlines, want)
	}
	f.mu.Unlock()
	// The same socket serves the next group (the real one reopens itself).
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if err := m.rtDo(ctx2, func(rt routeAPI) error { _, err := rt.LinkByName("x"); return err }); err != nil || r.count() != 1 {
		t.Fatalf("%v (%d sockets)", err, r.count())
	}
}

func TestACancelledContextInterruptsTheCallBeforeItsDeadline(t *testing.T) {
	r := &rtFactory{make: func(int) *fakeRT { f := newFakeRT(); f.stallOn = "*"; return f }}
	m := newRTManager(r)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	go func() { time.Sleep(30 * time.Millisecond); cancel() }()
	start := time.Now()
	err := m.rtDo(ctx, func(rt routeAPI) error { _, err := rt.LinkByName("x"); return err })
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("%v after %v", err, time.Since(start))
	}
}

func TestACallThatIgnoresTheInterruptIsReportedStuckAndItsSocketReplaced(t *testing.T) {
	r := &rtFactory{make: func(n int) *fakeRT {
		f := newFakeRT()
		if n == 0 {
			f.stallOn, f.ignores = "*", true
		}
		return f
	}}
	m := newRTManager(r)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	err := m.rtDo(ctx, func(rt routeAPI) error { _, err := rt.LinkByName("x"); return err })
	if !errors.Is(err, rtnl.ErrStuck) {
		t.Fatalf("%v", err)
	}
	if !r.opened[0].closed.Load() {
		t.Error("the abandoned socket was left open")
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if err := m.rtDo(ctx2, func(rt routeAPI) error { _, err := rt.LinkByName("x"); return err }); err != nil || r.count() != 2 {
		t.Fatalf("%v (%d sockets)", err, r.count())
	}
}

func TestEveryStalledStepOfUpEndsAtTheDeadline(t *testing.T) {
	for _, step := range []string{"LinkByName", "AddLink", "SetLinkMTU", "SetLinkUp", "ReplaceRoute"} {
		t.Run(step, func(t *testing.T) {
			r := &rtFactory{make: func(int) *fakeRT { f := newFakeRT(); f.stallOn = step; return f }}
			w := &wgFactory{}
			m := &Manager{dialRT: r.dial, dialWG: w.dial}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
			defer cancel()
			start := time.Now()
			err := m.UpContext(ctx, Params{ExitIf: "wg0", Conf: testConf(t)})
			if err == nil || !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("%v", err)
			}
			if took := time.Since(start); took > 700*time.Millisecond {
				t.Errorf("took %v for a 60 ms deadline", took)
			}
			// Whatever the deadline said, the half-built link was taken out
			// under the cleanup budget, on a socket that works again.
			calls := r.opened[0].called()
			if calls[len(calls)-1] != "DelLink" {
				t.Errorf("the half-built link was not removed: %v", calls)
			}
		})
	}
}

func TestUpSendsTheRequestsInTheOrderWgQuickDid(t *testing.T) {
	r := &rtFactory{}
	w := &wgFactory{}
	m := &Manager{dialRT: r.dial, dialWG: w.dial}
	r.make = func(int) *fakeRT { f := newFakeRT(); f.missing = true; return f }
	// The link is not there before; after AddLink the fake still reports it
	// missing, so the lookup that follows fails: only the order matters here.
	_ = m.UpContext(context.Background(), Params{ExitIf: "wg0", Conf: testConf(t)})
	got := r.opened[0].called()
	if len(got) < 3 || got[0] != "LinkByName" || got[1] != "AddLink" || got[2] != "LinkByName" {
		t.Fatalf("%v", got)
	}
}

func TestDownBoundsItsLookupAndItsDelete(t *testing.T) {
	r := &rtFactory{make: func(int) *fakeRT { f := newFakeRT(); f.per = 35 * time.Millisecond; return f }}
	m := newRTManager(r)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := m.DownContext(ctx, Params{ExitIf: "wg0"})
	if err == nil || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("%v", err)
	}
	if time.Since(start) > 150*time.Millisecond {
		t.Errorf("took %v", time.Since(start))
	}
}

func TestDownOfAMissingLinkIsNothing(t *testing.T) {
	r := &rtFactory{make: func(int) *fakeRT { f := newFakeRT(); f.missing = true; return f }}
	m := newRTManager(r)
	if err := m.DownContext(context.Background(), Params{ExitIf: "wg0", Conf: testConf(t)}); err != nil {
		t.Fatal(err)
	}
	if got := r.opened[0].called(); len(got) != 1 {
		t.Errorf("%v", got)
	}
}

func TestAStalledCleanupEndsAtTheDeadlineAndNamesWhatRemains(t *testing.T) {
	r := &rtFactory{make: func(int) *fakeRT { f := newFakeRT(); f.stallOn = "*"; return f }}
	m := newRTManager(r)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := m.CleanupContext(ctx, contract.Native, "wg0", "wt0")
	if err == nil {
		t.Fatal("no error")
	}
	// Both links are tried, each under the same absolute deadline: the second
	// is cut off at once.
	if took := time.Since(start); took > 400*time.Millisecond {
		t.Errorf("took %v", took)
	}
}

func TestRouteOperationsAreOneAtATime(t *testing.T) {
	r := &rtFactory{}
	m := newRTManager(r)
	var running, maxRunning atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = m.DownContext(context.Background(), Params{ExitIf: "wg0"})
			m.opMu.Lock()
			n := running.Add(1)
			if n > maxRunning.Load() {
				maxRunning.Store(n)
			}
			running.Add(-1)
			m.opMu.Unlock()
		}()
	}
	wg.Wait()
	if maxRunning.Load() != 1 {
		t.Fatalf("%d at once", maxRunning.Load())
	}
}

func TestACancelledOperationSendsNothing(t *testing.T) {
	r := &rtFactory{}
	m := newRTManager(r)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.DownContext(ctx, Params{ExitIf: "wg0"}); err == nil || r.count() != 0 {
		t.Fatalf("%v, %d sockets", err, r.count())
	}
}
