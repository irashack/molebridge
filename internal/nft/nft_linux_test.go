//go:build linux

package nft

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

// A netlink socket that, like the real one, ends a blocked read when it is
// closed or when its deadline passes, and otherwise never answers.
type stallSocket struct {
	mu       sync.Mutex
	deadline time.Time
	closed   chan struct{}
	once     sync.Once
	ignores  bool // does not return when closed
	noDL     bool // ignores its deadline too
}

func newStallSocket() *stallSocket { return &stallSocket{closed: make(chan struct{})} }

func (s *stallSocket) Close() error                         { s.once.Do(func() { close(s.closed) }); return nil }
func (s *stallSocket) Send(netlink.Message) error           { return nil }
func (s *stallSocket) SendMessages([]netlink.Message) error { return nil }
func (s *stallSocket) SetDeadline(t time.Time) error {
	s.mu.Lock()
	s.deadline = t
	s.mu.Unlock()
	return nil
}
func (s *stallSocket) SetReadDeadline(t time.Time) error { return s.SetDeadline(t) }
func (s *stallSocket) SetWriteDeadline(time.Time) error  { return nil }
func (s *stallSocket) deadlineSet() time.Time            { s.mu.Lock(); defer s.mu.Unlock(); return s.deadline }
func (s *stallSocket) Receive() ([]netlink.Message, error) {
	if s.ignores {
		select {}
	}
	s.mu.Lock()
	dl := s.deadline
	s.mu.Unlock()
	var timeout <-chan time.Time
	if !dl.IsZero() && !s.noDL {
		timeout = time.After(time.Until(dl))
	}
	select {
	case <-s.closed:
		return nil, errors.New("use of closed connection")
	case <-timeout:
		return nil, os.ErrDeadlineExceeded
	}
}

// socketLister is a lister that sends its dump on a real netlink.Conn over
// the fake socket, after the connector has run the library's socket option on
// it, as nftables.New does for a lasting connection.
type socketLister struct{ c *netlink.Conn }

func (l socketLister) ListChains() ([]*nftables.Chain, error) {
	_, err := l.c.Execute(netlink.Message{Header: netlink.Header{Flags: netlink.Request | netlink.Dump}})
	return nil, err
}

// via returns a connector that dials the given fake sockets in order.
func via(socks ...*stallSocket) (connector, *atomic.Int32) {
	var n atomic.Int32
	return func(opt nftables.SockOption, _ int) (lister, error) {
		i := int(n.Add(1)) - 1
		c := netlink.NewConn(socks[i], 1)
		if err := opt(c); err != nil {
			return nil, err
		}
		return socketLister{c}, nil
	}, &n
}

func TestAStalledChainDumpEndsAtTheDeadline(t *testing.T) { // finding: a stalled dump waited forever
	s := newStallSocket()
	s.noDL = true // even a socket that ignores its deadline is closed at it
	open, _ := via(s)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := listChains(ctx, 0, open)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("%v", err)
	}
	if time.Since(start) > 250*time.Millisecond {
		t.Errorf("took %v", time.Since(start))
	}
	select {
	case <-s.closed:
	default:
		t.Error("the socket was not closed")
	}
}

func TestTheSocketCarriesTheAbsoluteDeadlineFromTheStart(t *testing.T) {
	s := newStallSocket()
	open, _ := via(s)
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Millisecond)
	defer cancel()
	want, _ := ctx.Deadline()
	start := time.Now()
	_, err := listChains(ctx, 0, open)
	if !errors.Is(err, os.ErrDeadlineExceeded) || !s.deadlineSet().Equal(want) {
		t.Fatalf("%v: deadline %v, want %v", err, s.deadlineSet(), want)
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Errorf("took %v", time.Since(start))
	}
}

func TestACallWithoutADeadlineIsGivenOne(t *testing.T) {
	s := newStallSocket()
	open, _ := via(s)
	start := time.Now()
	_, err := listChains(context.Background(), 0, open)
	if err == nil || time.Since(start) > ContextBudget+time.Second {
		t.Fatalf("%v after %v", err, time.Since(start))
	}
	dl := s.deadlineSet()
	if dl.IsZero() || dl.Sub(start) > ContextBudget+100*time.Millisecond {
		t.Errorf("deadline %v", dl)
	}
}

func TestACancelledContextEndsTheDumpBeforeItsDeadline(t *testing.T) {
	s := newStallSocket()
	s.noDL = true
	open, _ := via(s)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	go func() { time.Sleep(30 * time.Millisecond); cancel() }()
	start := time.Now()
	if _, err := listChains(ctx, 0, open); err == nil || time.Since(start) > time.Second {
		t.Fatalf("%v after %v", err, time.Since(start))
	}
}

func TestADumpThatIgnoresTheCloseIsReportedStuck(t *testing.T) {
	s := newStallSocket()
	s.ignores = true
	open, _ := via(s)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := listChains(ctx, 0, open)
	if err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("%v after %v", err, time.Since(start))
	}
}

func TestEveryCallOpensItsOwnSocketAndClosesIt(t *testing.T) {
	a, b := newStallSocket(), newStallSocket()
	open, n := via(a, b)
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, _ = listChains(ctx, 0, open)
		cancel()
	}
	if n.Load() != 2 {
		t.Fatalf("%d sockets", n.Load())
	}
	for i, s := range []*stallSocket{a, b} {
		select {
		case <-s.closed:
		default:
			t.Errorf("socket %d was left open", i)
		}
	}
}

func TestAnOpenFailureIsReported(t *testing.T) {
	_, err := listChains(context.Background(), 0, func(nftables.SockOption, int) (lister, error) { return nil, errors.New("no netlink") })
	if err == nil {
		t.Fatal("no error")
	}
}

func TestAnExpiredContextOpensNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	opened := false
	if _, err := listChains(ctx, 0, func(nftables.SockOption, int) (lister, error) { opened = true; return nil, nil }); err == nil || opened {
		t.Fatalf("%v %v", err, opened)
	}
}

type fixedLister []*nftables.Chain

func (f fixedLister) ListChains() ([]*nftables.Chain, error) { return f, nil }

func TestChainsAreMapped(t *testing.T) {
	got, err := listChains(context.Background(), 0, func(nftables.SockOption, int) (lister, error) {
		return fixedLister{
			{Name: "netbird-acl", Table: &nftables.Table{Name: "netbird", Family: nftables.TableFamilyIPv4}},
			{Name: "orphan"},
		}, nil
	})
	if err != nil || len(got) != 1 || got[0].Family != "ip" || got[0].Table != "netbird" {
		t.Fatalf("%+v %v", got, err)
	}
}

// ---- the library itself ----

// If the socket is closed directly, the library keeps its lasting connection
// and does not open a transient one of its own; if its lasting connection is
// cleared (CloseLasting) it would, and the socket option is what refuses the
// second socket.
func TestClosingTheSocketDirectlyDoesNotMakeTheLibraryRedial(t *testing.T) {
	var dials atomic.Int32
	var first *netlink.Conn
	var refused atomic.Int32
	dial := nltest.Func(func([]netlink.Message) ([]netlink.Message, error) {
		return nil, errors.New("stalled")
	})
	var mu sync.Mutex
	opt := func(c *netlink.Conn) error {
		mu.Lock()
		defer mu.Unlock()
		if dials.Add(1) > 1 {
			refused.Add(1)
			_ = c.Close()
			return errSecondSocket
		}
		first = c
		return nil
	}
	cc, err := nftables.New(nftables.AsLasting(), nftables.WithSockOptions(opt), nftables.WithTestDial(dial))
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Close()
	_, _ = cc.ListChains()
	if dials.Load() != 1 {
		t.Fatalf("the library opened %d sockets after the first was closed", dials.Load())
	}
	// Whereas CloseLasting makes it redial, and the option refuses.
	_ = cc.CloseLasting()
	if _, err := cc.ListChains(); !errors.Is(err, errSecondSocket) || refused.Load() != 1 {
		t.Fatalf("%v (refused %d)", err, refused.Load())
	}
}

func TestTheRealSocketAcceptsItsDeadlineAndSeesTheKernel(t *testing.T) {
	// A real nftables socket is created, given its deadline by the socket
	// option, and used; in an environment without nftables the dump may be
	// refused, which is still an answer, not a hang.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	_, err := ListChainsContext(ctx, 0)
	if time.Since(start) > 3*time.Second {
		t.Fatalf("took %v", time.Since(start))
	}
	if err != nil && !errors.Is(err, unix.EPERM) && !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EPROTONOSUPPORT) && !errors.Is(err, unix.ENOENT) {
		t.Logf("a refusal: %v", err)
	}
}
