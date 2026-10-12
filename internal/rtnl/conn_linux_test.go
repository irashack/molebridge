//go:build linux

package rtnl

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// The request socket's stream layer, tested through its real receive path: a
// Conn whose transport is one end of a datagram socketpair (message
// boundaries as netlink has them), and a goroutine playing the kernel on the
// other end, free to answer late, out of sequence, with DONE|DUMP_INTR, with
// garbage, or not at all.

type fileTransport struct{ f *os.File }

func (t *fileTransport) send(b []byte) error { _, err := t.f.Write(b); return err }
func (t *fileTransport) recv(buf []byte) (int, error) {
	return t.f.Read(buf)
}
func (t *fileTransport) setDeadline(d time.Time) error { return t.f.SetDeadline(d) }
func (t *fileTransport) close() error                  { return t.f.Close() }

type request struct {
	typ, flags uint16
	seq        uint32
	data       []byte
}

// kernelFn answers one request with datagrams (each possibly several framed
// messages), written in order; it may also sleep.
type kernelFn func(n int, r request) [][]byte

type fakeKernelEnd struct {
	t        *testing.T
	mu       sync.Mutex
	requests []request
	pairs    int
	handler  kernelFn
	wg       sync.WaitGroup
	kernEnds []*os.File
}

func (k *fakeKernelEnd) shutdown() {
	k.mu.Lock()
	for _, f := range k.kernEnds {
		_ = f.Close()
	}
	k.mu.Unlock()
	k.wg.Wait()
}

func frame(typ, flags uint16, seq uint32, data []byte) []byte {
	b := make([]byte, nlmsgHdrLen, nlmsgHdrLen+len(data)+3)
	native.PutUint32(b[0:4], uint32(nlmsgHdrLen+len(data)))
	native.PutUint16(b[4:6], typ)
	native.PutUint16(b[6:8], flags)
	native.PutUint32(b[8:12], seq)
	b = append(b, data...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func errnoBody(e syscall.Errno) []byte {
	b := make([]byte, 4)
	native.PutUint32(b, uint32(-int32(e)))
	return b
}

func ruleEntry(seq uint32, priority uint32, flags uint16) []byte {
	r := Rule{Family: V4, Priority: priority, Action: FRActUnreachable, IifName: "wt0"}
	return frame(rtmNewRule, nlmMulti|flags, seq, r.Marshal())
}

func doneMsg(seq uint32, flags uint16) []byte {
	return frame(nlmsgDone, nlmMulti|flags, seq, errnoBody(0))
}
func ackMsg(seq uint32) []byte { return frame(nlmsgError, 0, seq, errnoBody(0)) }

func (k *fakeKernelEnd) open() (transport, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	conn := os.NewFile(uintptr(fds[0]), "conn")
	kern := os.NewFile(uintptr(fds[1]), "kernel")
	k.mu.Lock()
	k.pairs++
	k.kernEnds = append(k.kernEnds, kern)
	k.mu.Unlock()
	k.wg.Add(1)
	go func() {
		defer k.wg.Done()
		buf := make([]byte, 1<<16)
		for {
			n, err := kern.Read(buf)
			if err != nil {
				return
			}
			if n < nlmsgHdrLen {
				continue
			}
			r := request{typ: native.Uint16(buf[4:6]), flags: native.Uint16(buf[6:8]), seq: native.Uint32(buf[8:12]), data: cloneBytes(buf[nlmsgHdrLen:n])}
			k.mu.Lock()
			k.requests = append(k.requests, r)
			idx := len(k.requests) - 1
			h := k.handler
			k.mu.Unlock()
			for _, d := range h(idx, r) {
				if _, err := kern.Write(d); err != nil {
					return
				}
			}
		}
	}()
	return &fileTransport{f: conn}, nil
}

func (k *fakeKernelEnd) count() int { k.mu.Lock(); defer k.mu.Unlock(); return len(k.requests) }

func newFake(t *testing.T, h kernelFn) (*Conn, *fakeKernelEnd) {
	t.Helper()
	k := &fakeKernelEnd{t: t, handler: h}
	c := &Conn{timeout: 2 * time.Second, dial: k.open}
	tr, err := c.dial()
	if err != nil {
		t.Fatal(err)
	}
	c.t = tr
	t.Cleanup(func() { _ = c.Close(); k.shutdown() })
	return c, k
}

// ordinary answers every dump with two rules and every other request with an
// acknowledgement.
func ordinary(n int, r request) [][]byte {
	if r.flags&nlmDump == nlmDump {
		return [][]byte{append(ruleEntry(r.seq, 95, 0), ruleEntry(r.seq, 97, 0)...), doneMsg(r.seq, 0)}
	}
	return [][]byte{ackMsg(r.seq)}
}

func TestADumpInterruptedOnDoneAloneIsDiscardedAndTakenAgain(t *testing.T) { // finding: the vendored Conn trims DONE
	var attempts atomic.Int32
	c, k := newFake(t, func(n int, r request) [][]byte {
		if r.flags&nlmDump == nlmDump && attempts.Add(1) == 1 {
			// Entries clean; only the closing message carries the mark.
			return [][]byte{ruleEntry(r.seq, 95, 0), ruleEntry(r.seq, 96, 0), doneMsg(r.seq, nlmDumpIntr)}
		}
		return ordinary(n, r)
	})
	rules, err := c.Rules(V4)
	if err != nil {
		t.Fatal(err)
	}
	if k.count() != 2 || len(rules) != 2 || rules[0].Priority != 95 || rules[1].Priority != 97 {
		t.Fatalf("requests %d, rules %v: the interrupted dump's entries must not be used", k.count(), rules)
	}
	if c.Resets() != 0 {
		t.Error("an interrupted dump is fully read; the stream is fine")
	}
}

func TestASnapshotWithAnInterruptedDumpIsTakenAgainWhole(t *testing.T) {
	var dumps atomic.Int32
	c, k := newFake(t, func(n int, r request) [][]byte {
		if r.flags&nlmDump == nlmDump && dumps.Add(1) == 3 { // the third dump of the first attempt
			return [][]byte{doneMsg(r.seq, nlmDumpIntr)}
		}
		return ordinary(n, r)
	})
	s, err := c.Take(Interest{Tables: []uint32{254}})
	if err != nil {
		t.Fatal(err)
	}
	// Seven dumps make a look and a snapshot is two looks that agree: the
	// first attempt stopped at its third dump, so all of the second followed.
	if got := k.count(); got != 3+2*7 { // each look is taken twice and the two compared
		t.Fatalf("%d dumps", got)
	}
	if len(s.Rules[V4]) != 2 || len(s.Rules[V6]) != 2 {
		t.Fatalf("%+v", s.Rules)
	}
}

func TestADumpThatKeepsBeingInterruptedIsAnError(t *testing.T) {
	c, k := newFake(t, func(n int, r request) [][]byte { return [][]byte{ruleEntry(r.seq, 95, nlmDumpIntr), doneMsg(r.seq, 0)} })
	if _, err := c.Rules(V4); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("%v", err)
	}
	if k.count() != maxDumpAttempts {
		t.Errorf("%d attempts", k.count())
	}
	if _, err := c.Take(Interest{}); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("%v", err)
	}
}

func TestALostReplyDoesNotAnswerTheNextRequest(t *testing.T) { // finding: one lost reply kept every later pass one behind
	var late atomic.Pointer[fakeKernelEnd]
	var stale [][]byte
	c, k := newFake(t, func(n int, r request) [][]byte {
		if n == 0 {
			// Answer the first request only after the caller gave up on it.
			time.Sleep(150 * time.Millisecond)
			stale = ordinary(n, r)
			return stale
		}
		return ordinary(n, r)
	})
	late.Store(k)
	c.SetTimeout(40 * time.Millisecond)
	if _, err := c.Rules(V4); !IsStreamError(err) || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a request that got no answer in time: %v", err)
	}
	c.SetTimeout(2 * time.Second)
	time.Sleep(200 * time.Millisecond) // the late reply is on the old socket now
	for i := 0; i < 3; i++ {
		rules, err := c.Rules(V4)
		if err != nil || len(rules) != 2 {
			t.Fatalf("request %d after the loss: %v %v", i, rules, err)
		}
	}
	if c.Resets() != 1 || k.pairs != 2 {
		t.Errorf("resets %d, sockets %d: the socket should be replaced once", c.Resets(), k.pairs)
	}
}

func TestSequenceMismatchAndGarbageReplaceTheSocket(t *testing.T) {
	cases := map[string]func(request) [][]byte{
		"a reply for another request": func(r request) [][]byte { return [][]byte{doneMsg(r.seq+1, 0)} },
		"a short header":              func(r request) [][]byte { return [][]byte{{1, 2, 3}} },
		"a length beyond the datagram": func(r request) [][]byte {
			b := frame(nlmsgDone, 0, r.seq, nil)
			native.PutUint32(b[0:4], 500)
			return [][]byte{b}
		},
		"the kernel's overrun": func(r request) [][]byte { return [][]byte{frame(nlmsgOverrun, 0, r.seq, nil)} },
		"an entry that does not decode": func(r request) [][]byte {
			return [][]byte{frame(rtmNewRule, nlmMulti, r.seq, []byte{1, 2, 3}), doneMsg(r.seq, 0)}
		},
	}
	for name, bad := range cases {
		var first atomic.Bool
		c, k := newFake(t, func(n int, r request) [][]byte {
			if first.CompareAndSwap(false, true) {
				return bad(r)
			}
			return ordinary(n, r)
		})
		// Either the retry already succeeded on a fresh socket, or the error
		// said so; in both cases the next request works.
		_, _ = c.Rules(V4)
		rules, err := c.Rules(V4)
		if err != nil || len(rules) != 2 || c.Resets() == 0 || k.pairs < 2 {
			t.Errorf("%s: after the bad reply: %v %v (resets %d, sockets %d)", name, rules, err, c.Resets(), k.pairs)
		}
	}
}

func TestENOBUFSOnTheRequestSocketReplacesIt(t *testing.T) {
	var failing atomic.Bool
	failing.Store(true)
	k := &fakeKernelEnd{t: t, handler: ordinary}
	c := &Conn{timeout: time.Second, dial: func() (transport, error) {
		tr, err := k.open()
		if err != nil {
			return nil, err
		}
		return &flaky{transport: tr, fail: &failing}, nil
	}}
	tr, _ := c.dial()
	c.t = tr
	t.Cleanup(func() { _ = c.Close(); k.shutdown() })
	_, err := c.Links()
	if !IsStreamError(err) && err == nil {
		t.Fatal("expected the lost reply to be reported")
	}
	failing.Store(false)
	// The replacement socket answers; the unread reply of the lost one is gone with the old socket.
	for i := 0; i < 4; i++ {
		if _, err := c.Links(); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
}

type flaky struct {
	transport
	fail *atomic.Bool
}

func (f *flaky) recv(buf []byte) (int, error) {
	if f.fail.Load() {
		_, _ = f.transport.recv(buf) // the reply is consumed and lost with the error
		return 0, syscall.ENOBUFS
	}
	return f.transport.recv(buf)
}

func TestKernelRefusalsAreClassifiedAndLeaveTheStreamAlone(t *testing.T) {
	c, k := newFake(t, func(n int, r request) [][]byte {
		switch n {
		case 0:
			return [][]byte{frame(nlmsgError, 0, r.seq, errnoBody(syscall.EEXIST))}
		case 1:
			return [][]byte{frame(nlmsgError, 0, r.seq, errnoBody(syscall.ENOENT))}
		case 2:
			return [][]byte{frame(nlmsgError, 0, r.seq, errnoBody(syscall.ESRCH))}
		}
		return ordinary(n, r)
	})
	if err := c.AddRule(Rule{Family: V4, Priority: 1}); !IsExist(err) || IsNotExist(err) {
		t.Errorf("%v", err)
	}
	if err := c.DelRulePriority(V4, 1); !IsNotExist(err) {
		t.Errorf("%v", err)
	}
	if err := c.DelRoute(Route{Family: V4}); !IsNotExist(err) {
		t.Errorf("%v", err)
	}
	if err := c.AddRule(Rule{Family: V4, Priority: 2}); err != nil {
		t.Errorf("%v", err)
	}
	if c.Resets() != 0 || k.pairs != 1 {
		t.Errorf("a refusal replaced the socket (%d resets)", c.Resets())
	}
}

func TestAnExtendedAcknowledgementMessageIsKept(t *testing.T) {
	c, _ := newFake(t, func(n int, r request) [][]byte {
		// errno, the echoed header (capped), then NLMSGERR_ATTR_MSG.
		body := append(errnoBody(syscall.EINVAL), make([]byte, nlmsgHdrLen)...)
		body = appendAttrStr(body, nlmsgerrAMsg, "Nexthop has invalid gateway")
		return [][]byte{frame(nlmsgError, nlmCapped|nlmAckTLVs, r.seq, body)}
	})
	err := c.ReplaceRoute(Route{Family: V4, Dst: netip.PrefixFrom(netip.IPv4Unspecified(), 0)})
	if !errors.Is(err, syscall.EINVAL) || err == nil || !strings.Contains(err.Error(), "Nexthop has invalid gateway") {
		t.Fatalf("%v", err)
	}
}

func TestOneAbsoluteDeadlineCoversASnapshot(t *testing.T) { // finding: each dump restarted the clock
	c, k := newFake(t, func(n int, r request) [][]byte {
		time.Sleep(30 * time.Millisecond)
		return ordinary(n, r)
	})
	c.SetDeadline(time.Now().Add(80 * time.Millisecond))
	start := time.Now()
	_, err := c.Take(Interest{})
	took := time.Since(start)
	if err == nil || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a seven-dump snapshot at 30 ms a dump finished inside 80 ms: %v", err)
	}
	if took > 130*time.Millisecond {
		t.Errorf("took %v against an 80 ms deadline", took)
	}
	if n := k.count(); n > 4 {
		t.Errorf("%d requests were made after the deadline should have stopped them", n)
	}
	// A deadline already passed makes no request at all.
	before := k.count()
	if _, err := c.Take(Interest{}); !errors.Is(err, os.ErrDeadlineExceeded) || k.count() != before {
		t.Errorf("%v, %d new requests", err, k.count()-before)
	}
	// Clearing it restores per-request timeouts.
	c.SetDeadline(time.Time{})
	if _, err := c.Take(Interest{}); err != nil {
		t.Fatalf("after clearing the deadline: %v", err)
	}
}

func TestDeadlineAlsoBoundsRetriesOfAnInterruptedDump(t *testing.T) {
	c, _ := newFake(t, func(n int, r request) [][]byte {
		time.Sleep(20 * time.Millisecond)
		return [][]byte{doneMsg(r.seq, nlmDumpIntr)}
	})
	c.SetDeadline(time.Now().Add(70 * time.Millisecond))
	start := time.Now()
	_, err := c.Rules(V4)
	if time.Since(start) > 120*time.Millisecond || err == nil {
		t.Fatalf("%v after %v: eight 20 ms retries must not outlast a 70 ms deadline", err, time.Since(start))
	}
}

func TestCancellationIsCheckedBetweenDumps(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c, k := newFake(t, func(n int, r request) [][]byte {
		if n == 1 {
			cancel()
		}
		return ordinary(n, r)
	})
	_, err := c.TakeContext(ctx, Interest{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
	if k.count() > 3 {
		t.Errorf("%d requests after cancellation", k.count())
	}
}

func TestCloseUnblocksARequestInFlight(t *testing.T) {
	release := make(chan struct{})
	c, _ := newFake(t, func(n int, r request) [][]byte { <-release; return nil })
	t.Cleanup(func() { close(release) })
	done := make(chan error, 1)
	go func() { _, err := c.Rules(V4); done <- err }()
	time.Sleep(50 * time.Millisecond)
	_ = c.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("no error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock the request")
	}
}

func TestRequestsCarryTheRightMessageTypesAndFlags(t *testing.T) {
	c, k := newFake(t, ordinary)
	_ = c.AddRule(Rule{Family: V4, Priority: 5, Action: FRActUnreachable})
	_ = c.DelRule(Rule{Family: V4, Priority: 5, Action: FRActUnreachable})
	_ = c.DelRulePriority(V6, 7)
	_ = c.ReplaceRoute(Route{Family: V4})
	_ = c.DelRoute(Route{Family: V4})
	want := []struct{ typ, flags uint16 }{
		{rtmNewRule, nlmRequest | nlmAck | nlmCreate | nlmExcl},
		{rtmDelRule, nlmRequest | nlmAck},
		{rtmDelRule, nlmRequest | nlmAck},
		{rtmNewRoute, nlmRequest | nlmAck | nlmCreate | nlmReplace},
		{rtmDelRoute, nlmRequest | nlmAck},
	}
	for i, w := range want {
		r := k.requests[i]
		if r.typ != w.typ || r.flags != w.flags {
			t.Errorf("request %d: type %d flags %#x, want %d %#x", i, r.typ, r.flags, w.typ, w.flags)
		}
	}
	// And the sequence numbers are distinct and increasing.
	for i := 1; i < len(k.requests); i++ {
		if k.requests[i].seq != k.requests[i-1].seq+1 {
			t.Errorf("sequence %d then %d", k.requests[i-1].seq, k.requests[i].seq)
		}
	}
}

var _ = netlink.Request

type scriptedReceiver struct {
	msgs [][]netlink.Message
	errs []error
	n    int
}

func (s *scriptedReceiver) Receive() ([]netlink.Message, error) {
	i := s.n
	s.n++
	if i < len(s.errs) && s.errs[i] != nil {
		return nil, s.errs[i]
	}
	return s.msgs[i], nil
}
func (s *scriptedReceiver) SetReadDeadline(time.Time) error { return nil }
func (s *scriptedReceiver) Close() error                    { return nil }

func TestTheSubscriberSaysSoWhenEventsWereLost(t *testing.T) {
	enobufs := &netlink.OpError{Op: "receive", Err: os.NewSyscallError("recvmsg", syscall.ENOBUFS)}
	timeout := &netlink.OpError{Op: "receive", Err: os.ErrDeadlineExceeded}
	r := &scriptedReceiver{
		msgs: [][]netlink.Message{
			{{Header: netlink.Header{Type: rtmNewRule}, Data: Rule{Family: V6, Priority: 5, Action: FRActUnreachable}.Marshal()},
				{Header: netlink.Header{Type: rtmDelRoute}, Data: Route{Family: V4, Table: 51821, Dst: netip.PrefixFrom(netip.IPv4Unspecified(), 0)}.Marshal()},
				{Header: netlink.Header{Type: 999}, Data: nil}},
			nil, nil, nil,
		},
		errs: []error{nil, enobufs, timeout, errors.New("socket failed")},
	}
	s := &Subscriber{c: r}
	ev, err := s.Next(time.Time{})
	if err != nil || len(ev) != 2 {
		t.Fatalf("%+v %v", ev, err)
	}
	if ev[0].Kind != EventRule || ev[0].Family != V6 || ev[0].Deleted || ev[1].Kind != EventRoute || !ev[1].Deleted || ev[1].Table != 51821 {
		t.Errorf("%+v", ev)
	}
	if _, err := s.Next(time.Time{}); !errors.Is(err, ErrOverrun) {
		t.Errorf("ENOBUFS: %v", err)
	}
	if _, err := s.Next(time.Time{}); !Timeout(err) || errors.Is(err, ErrOverrun) {
		t.Errorf("timeout: %v", err)
	}
	if _, err := s.Next(time.Time{}); err == nil || errors.Is(err, ErrOverrun) || Timeout(err) {
		t.Errorf("other: %v", err)
	}
}

func TestAnEventThatDoesNotDecodeStillCounts(t *testing.T) {
	r := &scriptedReceiver{msgs: [][]netlink.Message{{{Header: netlink.Header{Type: rtmNewRule}, Data: []byte{1, 2, 3}}}}, errs: []error{nil}}
	ev, err := (&Subscriber{c: r}).Next(time.Time{})
	if err != nil || len(ev) != 1 || ev[0].Kind != EventRule || ev[0].Err == nil {
		t.Fatalf("%+v %v", ev, err)
	}
}

func TestTwoLooksThatNeverAgreeGiveAnUnstableSnapshot(t *testing.T) {
	var n atomic.Int32
	c, _ := newFake(t, func(i int, r request) [][]byte {
		if r.flags&nlmDump == nlmDump {
			// A different rule every time: the kernel never holds still.
			return [][]byte{ruleEntry(r.seq, uint32(100+n.Add(1)), 0), doneMsg(r.seq, 0)}
		}
		return [][]byte{ackMsg(r.seq)}
	})
	s, err := c.Take(Interest{})
	if err != nil || !s.Unstable {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestTwoLooksThatAgreeGiveAStableSnapshot(t *testing.T) {
	c, _ := newFake(t, ordinary)
	s, err := c.Take(Interest{})
	if err != nil || s.Unstable {
		t.Fatalf("%+v %v", s, err)
	}
}

// ---- the change detector ----

type fakeChurn struct {
	mu      sync.Mutex
	pending []Event
	err     error
}

func (f *fakeChurn) push(e ...Event) { f.mu.Lock(); f.pending = append(f.pending, e...); f.mu.Unlock() }
func (f *fakeChurn) Next(time.Time) ([]Event, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		err := f.err
		f.err = nil
		return nil, err
	}
	if len(f.pending) == 0 {
		return nil, os.ErrDeadlineExceeded
	}
	out := f.pending
	f.pending = nil
	return out, nil
}
func (f *fakeChurn) Close() error { return nil }

func TestASnapshotDuringWhichTheKernelChangedIsTakenAgain(t *testing.T) {
	churn := &fakeChurn{}
	var dumps atomic.Int32
	c, k := newFake(t, func(n int, r request) [][]byte {
		if r.flags&nlmDump == nlmDump && dumps.Add(1) == 4 {
			churn.push(Event{Kind: EventRule, Family: V4}) // a rule changed in the middle of the first snapshot
		}
		return ordinary(n, r)
	})
	c.churn = churn
	s, err := c.Take(Interest{Tables: []uint32{51821}})
	if err != nil || s.Unstable {
		t.Fatalf("%+v %v", s, err)
	}
	if got := k.count(); got != 7+7 {
		t.Fatalf("%d dumps: one snapshot discarded, one kept", got)
	}
}

func TestChangesElsewhereDoNotSpoilASnapshot(t *testing.T) {
	churn := &fakeChurn{}
	c, k := newFake(t, func(n int, r request) [][]byte {
		if n == 2 {
			churn.push(Event{Kind: EventRoute, Table: 254, Family: V4}, Event{Kind: EventRoute, Table: 7120, Family: V6})
		}
		return ordinary(n, r)
	})
	c.churn = churn
	s, err := c.Take(Interest{Tables: []uint32{51821}})
	if err != nil || s.Unstable || k.count() != 7 {
		t.Fatalf("%+v %v (%d dumps)", s, err, k.count())
	}
	// A route in a table the snapshot reads, or a link or address change, does.
	for _, e := range []Event{{Kind: EventRoute, Table: 51821}, {Kind: EventLink, Name: "wg0"}, {Kind: EventAddr}, {Kind: EventRoute, Table: 254, Err: errors.New("undecodable")}} {
		if !relevantToSnapshot(e, Interest{Tables: []uint32{51821}}) {
			t.Errorf("%+v should spoil it", e)
		}
	}
}

func TestAKernelThatNeverHoldsStillGivesAnUnstableSnapshotNotAnError(t *testing.T) {
	churn := &fakeChurn{}
	c, _ := newFake(t, func(n int, r request) [][]byte {
		if r.flags&nlmDump == nlmDump {
			churn.push(Event{Kind: EventRule, Family: V4})
		}
		return ordinary(n, r)
	})
	c.churn = churn
	s, err := c.Take(Interest{})
	if err != nil || !s.Unstable {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestLostChangeNotificationsSpoilTheSnapshotToo(t *testing.T) {
	churn := &fakeChurn{}
	var first atomic.Bool
	c, k := newFake(t, func(n int, r request) [][]byte {
		if r.flags&nlmDump == nlmDump && first.CompareAndSwap(false, true) {
			churn.mu.Lock()
			churn.err = ErrOverrun
			churn.mu.Unlock()
		}
		return ordinary(n, r)
	})
	c.churn = churn
	s, err := c.Take(Interest{})
	if err != nil || s.Unstable || k.count() != 14 {
		t.Fatalf("%+v %v (%d dumps)", s, err, k.count())
	}
}
