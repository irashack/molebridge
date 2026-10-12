//go:build linux

package tunnel

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	vnetlink "github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
	"github.com/irashack/molebridge/internal/tunnelconf"
)

// A WireGuard connection that answers when told to and otherwise blocks until
// it is closed, as a read on a netlink socket does.
type stallClient struct {
	id      int
	stall   bool
	ignores bool // does not return when closed
	mark    int
	closed  chan struct{}
	once    sync.Once
}

func (c *stallClient) block() error {
	if !c.ignores {
		<-c.closed
		return errors.New("use of a closed connection")
	}
	select {} // never returns
}

func (c *stallClient) ConfigureDevice(string, wgtypes.Config) error {
	if c.stall {
		return c.block()
	}
	return nil
}

func (c *stallClient) Device(name string) (*wgtypes.Device, error) {
	if name == "gone" {
		return nil, os.ErrNotExist
	}
	if c.stall {
		return nil, c.block()
	}
	return &wgtypes.Device{FirewallMark: c.mark}, nil
}

func (c *stallClient) Close() error { c.once.Do(func() { close(c.closed) }); return nil }

type factory struct {
	mu      sync.Mutex
	opened  []*stallClient
	stalled func(n int) (stall, ignores bool)
}

func (f *factory) open() (wgClient, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := len(f.opened)
	c := &stallClient{id: n, mark: 0x1bd00, closed: make(chan struct{})}
	if f.stalled != nil {
		c.stall, c.ignores = f.stalled(n)
	}
	f.opened = append(f.opened, c)
	return c, nil
}

func newStalled(f *factory) *Manager {
	return &Manager{openWG: func(context.Context) (wgClient, error) { return f.open() }}
}

func TestAStalledFwmarkReadEndsAtTheDeadlineAndTheConnectionIsReplaced(t *testing.T) { // finding: the fwmark monitor's next sample
	f := &factory{stalled: func(n int) (bool, bool) { return n == 0, false }}
	m := newStalled(f)
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := m.FwmarkContext(ctx, "wt0")
	took := time.Since(start)
	if err == nil || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("%v", err)
	}
	if took > 250*time.Millisecond {
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
	if err != nil || mark != 0x1bd00 || len(f.opened) != 2 {
		t.Fatalf("%x %v (%d connections)", mark, err, len(f.opened))
	}
	if SampleBudget != 2*time.Second {
		t.Errorf("the sample budget is %v", SampleBudget)
	}
}

func TestAStalledMutationIsCutOffAndReported(t *testing.T) {
	f := &factory{stalled: func(n int) (bool, bool) { return n == 0, false }}
	m := newStalled(f)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	err := m.configure(ctx, Params{ExitIf: "x", Conf: testConf(t)})
	if err == nil || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("%v", err)
	}
	// No second operation is admitted before the first is finished: the call
	// returned only after its connection was closed and the call came back.
	select {
	case <-f.opened[0].closed:
	default:
		t.Fatal("the connection was not closed before the call returned")
	}
}

func TestAConnectionThatIgnoresTheCloseIsReportedStuck(t *testing.T) {
	f := &factory{stalled: func(n int) (bool, bool) { return n == 0, true }}
	m := newStalled(f)
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
	m := newStalled(&factory{})
	if _, err := m.FwmarkContext(context.Background(), "gone"); !errors.Is(err, ErrNoDevice) {
		t.Fatalf("%v", err)
	}
}

func TestWireGuardCallsAreOneAtATime(t *testing.T) {
	f := &factory{}
	m := newStalled(f)
	var running, maxRunning atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = m.wgDo(context.Background(), func(wgClient) error {
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
	if maxRunning.Load() != 1 || len(f.opened) != 1 {
		t.Fatalf("%d at once, %d connections", maxRunning.Load(), len(f.opened))
	}
}

func TestCloseUnblocksAStalledCall(t *testing.T) {
	f := &factory{stalled: func(int) (bool, bool) { return true, false }}
	m := newStalled(f)
	done := make(chan error, 1)
	go func() { _, err := m.FwmarkContext(context.Background(), "wt0"); done <- err }()
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

// ---- the link handle ----

// A link handle whose calls each take a while and whose receives block until
// the handle is closed once stalled.
type fakeLinks struct {
	per     time.Duration
	stall   bool
	calls   atomic.Int32
	closed  chan struct{}
	once    sync.Once
	missing bool
}

func (f *fakeLinks) wait() error {
	f.calls.Add(1)
	if f.stall {
		<-f.closed
		return errors.New("use of a closed handle")
	}
	select {
	case <-time.After(f.per):
		return nil
	case <-f.closed:
		return errors.New("use of a closed handle")
	}
}
func (f *fakeLinks) LinkByName(name string) (vnetlink.Link, error) {
	if err := f.wait(); err != nil {
		return nil, err
	}
	if f.missing {
		return nil, vnetlink.LinkNotFoundError{}
	}
	return &vnetlink.Wireguard{LinkAttrs: vnetlink.LinkAttrs{Name: name, Index: 7}}, nil
}
func (f *fakeLinks) LinkAdd(vnetlink.Link) error                 { return f.wait() }
func (f *fakeLinks) LinkDel(vnetlink.Link) error                 { return f.wait() }
func (f *fakeLinks) LinkSetMTU(vnetlink.Link, int) error         { return f.wait() }
func (f *fakeLinks) LinkSetUp(vnetlink.Link) error               { return f.wait() }
func (f *fakeLinks) AddrAdd(vnetlink.Link, *vnetlink.Addr) error { return f.wait() }
func (f *fakeLinks) Close()                                      { f.once.Do(func() { close(f.closed) }) }

func newLinkManager(open func() (linkAPI, error)) *Manager { return &Manager{openLK: open} }

func TestAGroupOfLinkCallsSharesOneAbsoluteDeadline(t *testing.T) { // finding: each receive restarted a relative timeout
	var all []*fakeLinks
	var mu sync.Mutex
	m := newLinkManager(func() (linkAPI, error) {
		f := &fakeLinks{per: 40 * time.Millisecond, closed: make(chan struct{})}
		mu.Lock()
		all = append(all, f)
		mu.Unlock()
		return f, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := m.linkDo(ctx, func(h linkAPI) error {
		// Three calls of 40 ms each: 120 ms against a 70 ms deadline.
		for i := 0; i < 3; i++ {
			if _, err := h.LinkByName("x"); err != nil {
				return err
			}
		}
		return nil
	})
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("%v", err)
	}
	if took := time.Since(start); took > 110*time.Millisecond {
		t.Errorf("took %v for a 70 ms deadline", took)
	}
	select {
	case <-all[0].closed:
	default:
		t.Error("the handle was not closed at the deadline")
	}
	// The next group opens a new handle.
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if err := m.linkDo(ctx2, func(h linkAPI) error { _, err := h.LinkByName("x"); return err }); err != nil || len(all) != 2 {
		t.Fatalf("%v (%d handles)", err, len(all))
	}
}

func TestAStalledReceiveIsInterruptedByClosingTheHandle(t *testing.T) {
	m := newLinkManager(func() (linkAPI, error) { return &fakeLinks{stall: true, closed: make(chan struct{})}, nil })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := m.CleanupContext(ctx, contract.Native, "wg0", "wt0")
	if err == nil {
		t.Fatal("no error")
	}
	// Both links are tried, each under the same absolute deadline: the second
	// gets a handle that is cut off at once.
	if took := time.Since(start); took > 400*time.Millisecond {
		t.Errorf("took %v", took)
	}
}

func TestDownBoundsItsLookupAndItsDelete(t *testing.T) {
	m := newLinkManager(func() (linkAPI, error) {
		return &fakeLinks{per: 35 * time.Millisecond, closed: make(chan struct{})}, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := m.DownContext(ctx, Params{ExitIf: "wg0"})
	if err == nil || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("%v", err)
	}
	if time.Since(start) > 120*time.Millisecond {
		t.Errorf("took %v", time.Since(start))
	}
}

func TestALinkHandleDeliveredAfterTheDeadlineIsClosed(t *testing.T) {
	late := &fakeLinks{closed: make(chan struct{})}
	release := make(chan struct{})
	m := newLinkManager(func() (linkAPI, error) { <-release; return late, nil })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := m.linkDo(ctx, func(linkAPI) error { return nil }); err == nil {
		t.Fatal("no error")
	}
	close(release)
	select {
	case <-late.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("the handle delivered after cancellation was left open")
	}
	m.cmu.Lock()
	kept := m.lk
	m.cmu.Unlock()
	if kept != nil {
		t.Error("the late handle was kept")
	}
}

func TestAWireGuardClientDeliveredAfterTheDeadlineIsClosed(t *testing.T) { // finding: a late client leaked
	late := &stallClient{closed: make(chan struct{})}
	release := make(chan struct{})
	m := &Manager{openWG: func(context.Context) (wgClient, error) { <-release; return late, nil }}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := m.FwmarkContext(ctx, "wt0")
	if !errors.Is(err, os.ErrDeadlineExceeded) || time.Since(start) > 400*time.Millisecond {
		t.Fatalf("%v after %v", err, time.Since(start))
	}
	close(release)
	select {
	case <-late.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("the client delivered after cancellation was left open")
	}
}

func TestTheWireGuardOpenIsGivenTheDeadline(t *testing.T) {
	var got time.Time
	m := &Manager{openWG: func(ctx context.Context) (wgClient, error) {
		got, _ = ctx.Deadline()
		return &stallClient{closed: make(chan struct{})}, nil
	}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	want, _ := ctx.Deadline()
	if _, err := m.FwmarkContext(ctx, "wt0"); err != nil || !got.Equal(want) {
		t.Fatalf("%v: the open was given %v, want %v", err, got, want)
	}
}
