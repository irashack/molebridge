//go:build linux

package rtnl

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// receiver is the part of *netlink.Conn a Subscriber uses.
type receiver interface {
	Receive() ([]netlink.Message, error)
	SetReadDeadline(time.Time) error
	Close() error
}

// Subscriber receives rtnetlink multicast notifications.
type Subscriber struct {
	c receiver
}

// groups are the multicast groups the contract depends on: rule, route, link
// and address changes in both families.
var groups = []uint32{
	unix.RTNLGRP_IPV4_RULE, unix.RTNLGRP_IPV6_RULE,
	unix.RTNLGRP_IPV4_ROUTE, unix.RTNLGRP_IPV6_ROUTE,
	unix.RTNLGRP_LINK,
	unix.RTNLGRP_IPV4_IFADDR, unix.RTNLGRP_IPV6_IFADDR,
}

// Subscribe opens an event socket and joins every group before returning, so
// the caller's first dump (taken afterwards, on a different socket) cannot
// miss a change.
func Subscribe(o Options) (*Subscriber, error) {
	c, err := netlink.Dial(unix.NETLINK_ROUTE, &netlink.Config{NetNS: o.NetNS})
	if err != nil {
		return nil, fmt.Errorf("rtnl: open event socket: %w", err)
	}
	if o.ReadBuffer > 0 {
		_ = c.SetReadBuffer(o.ReadBuffer)
	}
	for _, g := range groups {
		if err := c.JoinGroup(g); err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("rtnl: join multicast group %d: %w", g, err)
		}
	}
	return &Subscriber{c: c}, nil
}

// Close closes the socket and unblocks a pending Next.
func (s *Subscriber) Close() error { return s.c.Close() }

// Next waits for notifications until the deadline (zero means no deadline)
// and returns everything that arrived in one read. It returns ErrOverrun when
// the kernel dropped messages, and an error satisfying Timeout when the
// deadline passes with nothing to read.
func (s *Subscriber) Next(deadline time.Time) ([]Event, error) {
	if err := s.c.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	msgs, err := s.c.Receive()
	if err != nil {
		if errors.Is(err, syscall.ENOBUFS) {
			return nil, ErrOverrun
		}
		return nil, err
	}
	return decodeEvents(msgs), nil
}

// Poll returns the notifications that are waiting, without waiting for more: a
// read that does not arm a timer (a read with a deadline wakes up on the timer's
// granularity, a millisecond or more). With nothing waiting it returns an error
// satisfying Timeout, like Next.
func (s *Subscriber) Poll() ([]Event, error) {
	conn, ok := s.c.(*netlink.Conn)
	if !ok {
		return s.Next(time.Now().Add(100 * time.Microsecond))
	}
	rc, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}
	buf := make([]byte, 1<<16)
	var n int
	var serr error
	if err := rc.Read(func(fd uintptr) bool {
		n, _, serr = unix.Recvfrom(int(fd), buf, unix.MSG_DONTWAIT|unix.MSG_TRUNC)
		return true // never wait for readiness
	}); err != nil {
		return nil, err
	}
	switch {
	case errors.Is(serr, unix.EAGAIN):
		return nil, os.ErrDeadlineExceeded
	case errors.Is(serr, unix.ENOBUFS):
		return nil, ErrOverrun
	case serr != nil:
		return nil, serr
	case n > len(buf):
		return nil, ErrOverrun // a datagram too large to read whole: treat as lost
	}
	raw, err := splitMessages(buf[:n])
	if err != nil {
		return nil, err
	}
	msgs := make([]netlink.Message, 0, len(raw))
	for _, m := range raw {
		msgs = append(msgs, netlink.Message{Header: netlink.Header{Type: netlink.HeaderType(m.typ), Flags: netlink.HeaderFlags(m.flags), Sequence: m.seq, PID: m.pid}, Data: m.data})
	}
	return decodeEvents(msgs), nil
}
