//go:build linux

package rtnl

import (
	"errors"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
)

type scriptedConn struct {
	replies  [][]netlink.Message
	errs     []error
	requests []netlink.Message
}

func (s *scriptedConn) Execute(m netlink.Message) ([]netlink.Message, error) {
	s.requests = append(s.requests, m)
	i := len(s.requests) - 1
	if i < len(s.errs) && s.errs[i] != nil {
		return nil, s.errs[i]
	}
	return s.replies[i], nil
}
func (s *scriptedConn) SetDeadline(time.Time) error { return nil }
func (s *scriptedConn) Close() error                { return nil }

func ruleMessage(priority uint32, flags netlink.HeaderFlags) netlink.Message {
	r := Rule{Family: V4, Priority: priority, Action: FRActUnreachable, IifName: "wt0"}
	return netlink.Message{Header: netlink.Header{Type: rtmNewRule, Flags: netlink.Multi | flags}, Data: r.Marshal()}
}

func TestAnInterruptedDumpIsDiscardedAndTakenAgain(t *testing.T) {
	sc := &scriptedConn{replies: [][]netlink.Message{
		{ruleMessage(95, 0), ruleMessage(96, netlink.DumpInterrupted), ruleMessage(97, 0)}, // the kernel says the list changed under the dump
		{ruleMessage(95, 0), ruleMessage(97, 0)},
	}}
	c := &Conn{c: sc, timeout: time.Second}
	rules, err := c.Rules(V4)
	if err != nil {
		t.Fatal(err)
	}
	if len(sc.requests) != 2 {
		t.Fatalf("%d dumps", len(sc.requests))
	}
	if len(rules) != 2 || rules[0].Priority != 95 || rules[1].Priority != 97 {
		t.Fatalf("the interrupted dump's rules leaked into the result: %v", rules)
	}
	if sc.requests[0].Header.Type != rtmGetRule || sc.requests[0].Header.Flags&netlink.Dump == 0 {
		t.Errorf("%+v", sc.requests[0].Header)
	}
}

func TestADumpThatKeepsBeingInterruptedIsAnError(t *testing.T) {
	var replies [][]netlink.Message
	for i := 0; i < maxDumpAttempts; i++ {
		replies = append(replies, []netlink.Message{ruleMessage(95, netlink.DumpInterrupted)})
	}
	sc := &scriptedConn{replies: replies}
	c := &Conn{c: sc, timeout: time.Second}
	if _, err := c.Rules(V4); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("%v", err)
	}
	if len(sc.requests) != maxDumpAttempts {
		t.Errorf("%d attempts", len(sc.requests))
	}
}

func TestKernelRefusalsAreClassified(t *testing.T) {
	sc := &scriptedConn{errs: []error{&netlink.OpError{Op: "receive", Err: syscall.EEXIST}, &netlink.OpError{Op: "receive", Err: syscall.ENOENT},
		&netlink.OpError{Op: "receive", Err: syscall.ESRCH}}, replies: [][]netlink.Message{nil, nil, nil}}
	c := &Conn{c: sc, timeout: time.Second}
	if err := c.AddRule(Rule{Family: V4, Priority: 1}); !IsExist(err) || IsNotExist(err) {
		t.Errorf("%v", err)
	}
	if err := c.DelRulePriority(V4, 1); !IsNotExist(err) {
		t.Errorf("%v", err)
	}
	if err := c.DelRoute(Route{Family: V4}); !IsNotExist(err) {
		t.Errorf("%v", err)
	}
}

func TestRequestsCarryTheRightMessageTypesAndFlags(t *testing.T) {
	sc := &scriptedConn{replies: make([][]netlink.Message, 5)}
	c := &Conn{c: sc, timeout: time.Second}
	_ = c.AddRule(Rule{Family: V4, Priority: 5, Action: FRActUnreachable})
	_ = c.DelRule(Rule{Family: V4, Priority: 5, Action: FRActUnreachable})
	_ = c.DelRulePriority(V6, 7)
	_ = c.ReplaceRoute(Route{Family: V4})
	_ = c.DelRoute(Route{Family: V4})
	want := []struct {
		typ   netlink.HeaderType
		flags netlink.HeaderFlags
	}{
		{rtmNewRule, netlink.Request | netlink.Acknowledge | netlink.Create | netlink.Excl},
		{rtmDelRule, netlink.Request | netlink.Acknowledge},
		{rtmDelRule, netlink.Request | netlink.Acknowledge},
		{rtmNewRoute, netlink.Request | netlink.Acknowledge | netlink.Create | netlink.Replace},
		{rtmDelRoute, netlink.Request | netlink.Acknowledge},
	}
	for i, w := range want {
		h := sc.requests[i].Header
		if h.Type != w.typ || h.Flags != w.flags {
			t.Errorf("request %d: type %d flags %v, want %d %v", i, h.Type, h.Flags, w.typ, w.flags)
		}
	}
}

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
