//go:build linux

package rtnl

import (
	"errors"
	"fmt"
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
