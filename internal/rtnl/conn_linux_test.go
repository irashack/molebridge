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

// dumps counts the dump requests only (a snapshot also sends one barrier).
func (k *fakeKernelEnd) dumps() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	n := 0
	for _, r := range k.requests {
		if r.flags&nlmDump == nlmDump {
			n++
		}
	}
	return n
}

func (k *fakeKernelEnd) barriers() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	n := 0
	for _, r := range k.requests {
		if r.typ == rtmNewLink {
			n++
		}
	}
	return n
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
	if got := k.dumps(); got != 9+9 { // a full look and a look at the rules, twice
		t.Fatalf("%d dumps: one pair of looks discarded, one kept", got)
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
	if err != nil || s.Unstable || k.dumps() != 9 {
		t.Fatalf("%+v %v (%d dumps)", s, err, k.dumps())
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
	if err != nil || s.Unstable || k.dumps() != 18 {
		t.Fatalf("%+v %v (%d dumps)", s, err, k.dumps())
	}
}

// ---- finding: observation failure is not silence; draining is bounded ----

// endlessChurn always has an irrelevant notification waiting, and a read takes
// as long as its deadline allows, up to a millisecond.
type endlessChurn struct{ reads atomic.Int32 }

func (e *endlessChurn) Next(deadline time.Time) ([]Event, error) {
	e.reads.Add(1)
	d := time.Until(deadline)
	if d > time.Millisecond {
		d = time.Millisecond
	}
	if d > 0 {
		time.Sleep(d)
	}
	return []Event{{Kind: EventRoute, Table: 7120, Family: V4}}, nil
}
func (e *endlessChurn) Close() error { return nil }

func TestNotificationDrainingIsBoundedByTheOperationDeadline(t *testing.T) {
	c, k := newFake(t, ordinary)
	c.churn = &endlessChurn{}
	c.SetDeadline(time.Now().Add(15 * time.Millisecond))
	start := time.Now()
	s, err := c.Take(Interest{Tables: []uint32{51821}})
	if err == nil || !errors.Is(err, os.ErrDeadlineExceeded) || s != nil {
		t.Fatalf("%+v %v", s, err)
	}
	if took := time.Since(start); took > 60*time.Millisecond {
		t.Errorf("took %v for a 15 ms deadline (256 one-millisecond reads would be 256 ms)", took)
	}
	if k.count() != 0 {
		t.Errorf("a dump was made after the deadline passed in the pre-dump drain: %d", k.count())
	}
}

// After the dumps the same bound applies, and a snapshot is not handed over
// after the deadline.
type lateChurn struct {
	dumps *atomic.Int32
	after int32
}

func (l *lateChurn) Next(deadline time.Time) ([]Event, error) {
	if l.dumps.Load() < l.after {
		return nil, os.ErrDeadlineExceeded
	}
	d := time.Until(deadline)
	if d > time.Millisecond {
		d = time.Millisecond
	}
	if d > 0 {
		time.Sleep(d)
	}
	return []Event{{Kind: EventRoute, Table: 7120}}, nil
}
func (l *lateChurn) Close() error { return nil }

func TestPostDumpDrainingIsBoundedToo(t *testing.T) {
	var dumps atomic.Int32
	c, _ := newFake(t, func(n int, r request) [][]byte {
		if r.flags&nlmDump == nlmDump {
			dumps.Add(1)
		}
		return ordinary(n, r)
	})
	c.churn = &lateChurn{dumps: &dumps, after: 7}
	c.SetDeadline(time.Now().Add(40 * time.Millisecond))
	start := time.Now()
	s, err := c.Take(Interest{Tables: []uint32{51821}})
	if err == nil || s != nil || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("%+v %v", s, err)
	}
	if time.Since(start) > 120*time.Millisecond {
		t.Errorf("took %v", time.Since(start))
	}
}

type brokenChurn struct {
	dumps  *atomic.Int32
	after  int32
	closed atomic.Bool
}

func (b *brokenChurn) Next(d time.Time) ([]Event, error) {
	if b.dumps.Load() >= b.after {
		return nil, errors.New("receive failed: bad message")
	}
	return nil, os.ErrDeadlineExceeded
}
func (b *brokenChurn) Close() error { b.closed.Store(true); return nil }

func TestAFailedNotificationReadIsNotSilence(t *testing.T) { // finding: it returned a stable snapshot
	var dumps atomic.Int32
	c, _ := newFake(t, func(n int, r request) [][]byte {
		if r.flags&nlmDump == nlmDump {
			dumps.Add(1)
		}
		return ordinary(n, r)
	})
	bad := &brokenChurn{dumps: &dumps, after: 7}
	c.churn = bad
	reopened := 0
	good := &fakeChurn{}
	c.reopen = func() (churnSource, error) { reopened++; return good, nil }
	s, err := c.Take(Interest{Tables: []uint32{51821}})
	if err != nil || s.Unstable {
		t.Fatalf("%+v %v", s, err)
	}
	if reopened != 1 || !bad.closed.Load() {
		t.Errorf("the failed subscription was not replaced (reopened %d, closed %v)", reopened, bad.closed.Load())
	}
	if dumps.Load() < 14 {
		t.Errorf("%d dumps: the snapshot the failed read could not vouch for must be taken again", dumps.Load())
	}
}

func TestIfNotificationsCanNeverBeReadTheSnapshotIsUnstable(t *testing.T) {
	var dumps atomic.Int32
	c, _ := newFake(t, func(n int, r request) [][]byte {
		if r.flags&nlmDump == nlmDump {
			dumps.Add(1)
		}
		return ordinary(n, r)
	})
	c.churn = &brokenChurn{dumps: &dumps, after: 0}
	c.reopen = func() (churnSource, error) { return &brokenChurn{dumps: &dumps, after: 0}, nil }
	s, err := c.Take(Interest{})
	if err != nil || !s.Unstable {
		t.Fatalf("%+v %v", s, err)
	}
	// With no way to reopen at all, the same.
	c.churn = &brokenChurn{dumps: &dumps, after: 0}
	c.reopen = func() (churnSource, error) { return nil, errors.New("cannot subscribe") }
	s, err = c.Take(Interest{})
	if err != nil || !s.Unstable {
		t.Fatalf("%+v %v", s, err)
	}
}

// A notification read that ends at the operation's deadline is not evidence
// of an empty queue; no snapshot, stable or not, is handed over after the
// deadline.
type atDeadlineChurn struct {
	dumps *atomic.Int32
	after int32
	until time.Time
}

func (a *atDeadlineChurn) Next(deadline time.Time) ([]Event, error) {
	if a.dumps.Load() >= a.after {
		time.Sleep(time.Until(a.until)) // the read lasts until the operation's deadline
	}
	return nil, os.ErrDeadlineExceeded
}
func (a *atDeadlineChurn) Close() error { return nil }

func TestAReadThatEndsAtTheOperationDeadlineIsNotSilence(t *testing.T) {
	var dumps atomic.Int32
	c, _ := newFake(t, func(n int, r request) [][]byte {
		if r.flags&nlmDump == nlmDump {
			dumps.Add(1)
		}
		return ordinary(n, r)
	})
	dl := time.Now().Add(60 * time.Millisecond)
	c.churn = &atDeadlineChurn{dumps: &dumps, after: 7, until: dl}
	c.SetDeadline(dl)
	s, err := c.Take(Interest{})
	if err == nil || s != nil || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("%+v %v: a snapshot was certified by the expiry of its own deadline", s, err)
	}
}

func TestNoSnapshotIsReturnedAfterTheDeadlineEvenWithoutASubscription(t *testing.T) {
	c, _ := newFake(t, func(n int, r request) [][]byte {
		time.Sleep(4 * time.Millisecond)
		return ordinary(n, r)
	})
	c.SetDeadline(time.Now().Add(40 * time.Millisecond))
	// Two looks of seven dumps at 4 ms each cannot both fit.
	s, err := c.Take(Interest{})
	if err == nil || s != nil {
		t.Fatalf("%+v %v", s, err)
	}
}

func linkReply(seq uint32, index uint32, name string) []byte {
	return frame(rtmNewLink, 0, seq, appendAttrStr(ifinfo(index, 0, 0), iflaIfname, name))
}

func TestLinkOperationsSendTheKernelsRequests(t *testing.T) {
	c, k := newFake(t, func(n int, r request) [][]byte {
		if r.typ == rtmGetLink {
			return [][]byte{linkReply(r.seq, 7, "wt0")}
		}
		return [][]byte{ackMsg(r.seq)}
	})
	l, err := c.LinkByName("wt0")
	if err != nil || l.Index != 7 || l.Name != "wt0" {
		t.Fatalf("%+v %v", l, err)
	}
	for name, f := range map[string]func() error{
		"add":     func() error { return c.AddLink("wt0", "wireguard") },
		"del":     func() error { return c.DelLink(7) },
		"mtu":     func() error { return c.SetLinkMTU(7, 1380) },
		"up":      func() error { return c.SetLinkUp(7) },
		"addr":    func() error { return c.AddAddr(HostAddr(7, netip.MustParseAddr("198.51.100.2"))) },
		"deladdr": func() error { return c.DelAddr(HostAddr(7, netip.MustParseAddr("198.51.100.2"))) },
	} {
		if err := f(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	type want struct {
		typ   uint16
		flags uint16
	}
	wants := []want{
		{rtmGetLink, nlmRequest},
		{rtmNewLink, nlmRequest | nlmAck | nlmCreate | nlmExcl},
		{rtmDelLink, nlmRequest | nlmAck},
		{rtmNewLink, nlmRequest | nlmAck},
		{rtmNewLink, nlmRequest | nlmAck},
		{rtmNewAddr, nlmRequest | nlmAck | nlmCreate | nlmExcl},
		{rtmDelAddr, nlmRequest | nlmAck},
	}
	// The map iterates in any order: compare as a multiset of (type, flags).
	got := map[want]int{}
	k.mu.Lock()
	for _, r := range k.requests {
		got[want{r.typ, r.flags}]++
	}
	k.mu.Unlock()
	exp := map[want]int{}
	for _, w := range wants {
		exp[w]++
	}
	for w, n := range exp {
		if got[w] != n {
			t.Errorf("%+v sent %d times, want %d", w, got[w], n)
		}
	}
}

func TestAMissingLinkIsNotExist(t *testing.T) {
	c, _ := newFake(t, func(n int, r request) [][]byte {
		return [][]byte{frame(nlmsgError, 0, r.seq, errnoBody(syscall.ENODEV))}
	})
	if _, err := c.LinkByName("nope"); !IsNotExist(err) {
		t.Fatalf("%v", err)
	}
	if c.Resets() != 0 {
		t.Errorf("a refusal replaced the socket (%d dials)", c.Resets())
	}
}

// Every link and address call ends at the one absolute deadline when the
// kernel never answers, and the next call finds a fresh socket.
func TestAStalledLinkOperationEndsAtTheDeadline(t *testing.T) {
	calls := map[string]func(c *Conn) error{
		"lookup":  func(c *Conn) error { _, err := c.LinkByName("wt0"); return err },
		"add":     func(c *Conn) error { return c.AddLink("wt0", "wireguard") },
		"del":     func(c *Conn) error { return c.DelLink(7) },
		"mtu":     func(c *Conn) error { return c.SetLinkMTU(7, 1380) },
		"up":      func(c *Conn) error { return c.SetLinkUp(7) },
		"addr":    func(c *Conn) error { return c.AddAddr(HostAddr(7, netip.MustParseAddr("198.51.100.2"))) },
		"deladdr": func(c *Conn) error { return c.DelAddr(HostAddr(7, netip.MustParseAddr("198.51.100.2"))) },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			var stalled atomic.Bool
			stalled.Store(true)
			c, k := newFake(t, func(n int, r request) [][]byte {
				if stalled.Load() {
					return nil // never answers
				}
				if r.typ == rtmGetLink {
					return [][]byte{linkReply(r.seq, 7, "wt0")}
				}
				return [][]byte{ackMsg(r.seq)}
			})
			c.SetDeadline(time.Now().Add(80 * time.Millisecond))
			start := time.Now()
			err := call(c)
			if !Timeout(err) || time.Since(start) > time.Second {
				t.Fatalf("%v after %v", err, time.Since(start))
			}
			stalled.Store(false)
			c.SetDeadline(time.Now().Add(time.Second))
			if err := call(c); err != nil {
				t.Fatalf("the next call, on a fresh socket: %v", err)
			}
			k.mu.Lock()
			pairs := k.pairs
			k.mu.Unlock()
			if pairs < 2 {
				t.Errorf("the cut-off socket was reused (%d sockets)", pairs)
			}
		})
	}
}

func TestInterruptEndsARequestInFlightAndTheNextOneReconnects(t *testing.T) {
	var stalled atomic.Bool
	stalled.Store(true)
	c, k := newFake(t, func(n int, r request) [][]byte {
		if stalled.Load() {
			return nil
		}
		return [][]byte{ackMsg(r.seq)}
	})
	c.SetDeadline(time.Now().Add(10 * time.Second))
	done := make(chan error, 1)
	go func() { done <- c.SetLinkUp(7) }()
	for k.count() == 0 {
		time.Sleep(time.Millisecond)
	}
	start := time.Now()
	c.Interrupt()
	select {
	case err := <-done:
		if err == nil || !IsStreamError(err) {
			t.Fatalf("%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the request outlived the interrupt")
	}
	if time.Since(start) > time.Second {
		t.Error("slow")
	}
	stalled.Store(false)
	if err := c.SetLinkUp(7); err != nil {
		t.Fatalf("after the interrupt: %v", err)
	}
}

// ---- finding: a change whose notification is late is not a stable snapshot ----

// The kernel's rule dump takes no lock, and the changer updates the list before
// it notifies: a dump can see a change whose notification reaches the
// subscription after the drain that follows the dump. Silence on the
// subscription is then not stability. Two looks that agree, and a dump that
// holds no rule twice, are.
func TestASilentChangeBetweenTwoLooksIsNotStable(t *testing.T) {
	churn := &fakeChurn{} // never says a word
	var dumps atomic.Int32
	c, _ := newFake(t, func(n int, r request) [][]byte {
		if r.flags&nlmDump == nlmDump && r.typ == rtmGetRule {
			// The first look of the first snapshot sees one rule more than the second.
			if dumps.Add(1) <= 2 {
				return [][]byte{ruleEntry(r.seq, 95, nlmMulti), ruleEntry(r.seq, 96, nlmMulti), doneMsg(r.seq, 0)}
			}
		}
		return ordinary(n, r)
	})
	c.churn = churn
	s, err := c.Take(Interest{})
	if err != nil {
		t.Fatal(err)
	}
	if s.Unstable {
		t.Fatalf("a settled kernel gave an unstable snapshot: %+v", s)
	}
	if n := len(s.Rules[V4]); n != 2 {
		t.Errorf("the snapshot is the disagreeing look, not the agreeing one: %v", s.Rules[V4])
	}
}

// A rule that is really there twice is not instability: the kernel refuses an
// identical rule only for a request with NLM_F_EXCL, and `ip rule restore`
// sends none. Both looks show it twice, so the snapshot says so and stable, and
// the owner can remove the duplicate through its deletion check.
func TestARuleReallyThereTwiceIsAStableSnapshotWithBothCopies(t *testing.T) {
	for name, churn := range map[string]*fakeChurn{"with a subscription": {}, "without": nil} {
		c, _ := newFake(t, func(n int, r request) [][]byte {
			if r.flags&nlmDump == nlmDump && r.typ == rtmGetRule {
				return [][]byte{ruleEntry(r.seq, 95, nlmMulti), ruleEntry(r.seq, 95, nlmMulti), doneMsg(r.seq, 0)}
			}
			return ordinary(n, r)
		})
		if churn != nil {
			c.churn = churn
		}
		s, err := c.Take(Interest{})
		if err != nil || s.Unstable {
			t.Fatalf("%s: %+v %v", name, s, err)
		}
		if n := len(s.Rules[V4]); n != 2 {
			t.Errorf("%s: %d rules, want the rule twice", name, n)
		}
	}
}

// A repeat shown by two looks in a row but not by the confirming ones is still
// an artifact: a rule really there twice is in every look.
func TestARepeatThatTheConfirmingLooksDoNotShowIsInstability(t *testing.T) {
	churn := &fakeChurn{}
	var v4 atomic.Int32
	c, _ := newFake(t, func(n int, r request) [][]byte {
		if r.flags&nlmDump == nlmDump && r.typ == rtmGetRule && r.data[0] == 2 {
			if v4.Add(1) <= 2 { // the first two looks
				return [][]byte{ruleEntry(r.seq, 95, nlmMulti), ruleEntry(r.seq, 95, nlmMulti), doneMsg(r.seq, 0)}
			}
			return [][]byte{ruleEntry(r.seq, 95, nlmMulti), doneMsg(r.seq, 0)}
		}
		return ordinary(n, r)
	})
	c.churn = churn
	s, err := c.Take(Interest{})
	if err != nil || s.Unstable || len(s.Rules[V4]) != 1 {
		t.Fatalf("%+v %v", s, err)
	}
}

// A repeat that is in one look and not in the other is an artifact of the dump.
func TestARepeatInOneLookOnlyIsInstability(t *testing.T) {
	churn := &fakeChurn{}
	var rules atomic.Int32
	c, _ := newFake(t, func(n int, r request) [][]byte {
		if r.flags&nlmDump == nlmDump && r.typ == rtmGetRule {
			if rules.Add(1) == 1 { // the first family of the first look repeats a rule
				return [][]byte{ruleEntry(r.seq, 95, nlmMulti), ruleEntry(r.seq, 95, nlmMulti), doneMsg(r.seq, 0)}
			}
			return [][]byte{ruleEntry(r.seq, 95, nlmMulti), doneMsg(r.seq, 0)}
		}
		return ordinary(n, r)
	})
	c.churn = churn
	s, err := c.Take(Interest{})
	if err != nil || s.Unstable {
		t.Fatalf("%+v %v", s, err)
	}
	if n := len(s.Rules[V4]); n != 1 {
		t.Errorf("the snapshot kept the repeat: %d rules", n)
	}
}

// The barrier orders late notifications before the drain: a change that is
// under way when the looks end has notified by the time the barrier is
// acknowledged, so the drain that follows sees it.
func TestALateNotificationIsSeenBecauseTheBarrierWaitsForIt(t *testing.T) {
	churn := &fakeChurn{}
	var barriers atomic.Int32
	c, k := newFake(t, func(n int, r request) [][]byte {
		if r.typ == rtmNewLink && r.flags&nlmDump != nlmDump {
			// The changer was between updating the list and notifying; the
			// barrier takes the lock after it, so its notification is queued
			// before the barrier is acknowledged.
			if barriers.Add(1) == 1 {
				churn.push(Event{Kind: EventRule, Family: V4})
			}
		}
		return ordinary(n, r)
	})
	c.churn = churn
	s, err := c.Take(Interest{})
	if err != nil || s.Unstable {
		t.Fatalf("%+v %v", s, err)
	}
	if k.barriers() != 2 || k.dumps() != 18 {
		t.Errorf("%d barriers, %d dumps: the first pair of looks should have been discarded", k.barriers(), k.dumps())
	}
	// The barrier is the no-op RTM_NEWLINK for the loopback: no attribute, no flag.
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, r := range k.requests {
		if r.typ == rtmNewLink {
			if len(r.data) != 16 || native.Uint32(r.data[4:8]) != 1 || native.Uint32(r.data[8:12]) != 0 || native.Uint32(r.data[12:16]) != 0 {
				t.Errorf("barrier payload %x", r.data)
			}
		}
	}
}

func TestAKernelThatRefusesTheBarrierGetsALongerDrainAndIsNotAskedAgain(t *testing.T) {
	churn := &fakeChurn{}
	c, k := newFake(t, func(n int, r request) [][]byte {
		if r.typ == rtmNewLink && r.flags&nlmDump != nlmDump {
			return [][]byte{frame(nlmsgError, 0, r.seq, errnoBody(syscall.EPERM))}
		}
		return ordinary(n, r)
	})
	c.churn = churn
	for i := 0; i < 3; i++ {
		if s, err := c.Take(Interest{}); err != nil || s.Unstable {
			t.Fatalf("%+v %v", s, err)
		}
	}
	if k.barriers() != 1 {
		t.Errorf("the refused barrier was sent %d times", k.barriers())
	}
}
