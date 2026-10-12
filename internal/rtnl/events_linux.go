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

// EventKind says which kind of object changed.
type EventKind uint8

// The kinds of change the subscription reports.
const (
	EventRule EventKind = iota + 1
	EventRoute
	EventLink
	EventAddr
)

func (k EventKind) String() string {
	switch k {
	case EventRule:
		return "rule"
	case EventRoute:
		return "route"
	case EventLink:
		return "link"
	case EventAddr:
		return "address"
	}
	return "unknown"
}

// Event is one multicast notification. The decoded object is best effort: a
// message that does not decode still counts as a change (Err is set).
type Event struct {
	Kind    EventKind
	Deleted bool
	Family  Family
	// Table is the routing table of a route event.
	Table uint32
	// Name is the interface name of a link event.
	Name string
	Err  error
}

// Subscriber receives rtnetlink multicast notifications.
type Subscriber struct {
	c *netlink.Conn
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

func decodeEvents(msgs []netlink.Message) []Event {
	var out []Event
	for _, m := range msgs {
		var e Event
		switch m.Header.Type {
		case rtmNewRule, rtmDelRule:
			e.Kind, e.Deleted = EventRule, m.Header.Type == rtmDelRule
			r, err := DecodeRule(m.Data)
			e.Err, e.Family = err, r.Family
		case rtmNewRoute, rtmDelRoute:
			e.Kind, e.Deleted = EventRoute, m.Header.Type == rtmDelRoute
			r, err := DecodeRoute(m.Data)
			e.Err, e.Family, e.Table = err, r.Family, r.Table
		case rtmNewLink, rtmDelLink:
			e.Kind, e.Deleted = EventLink, m.Header.Type == rtmDelLink
			l, err := DecodeLink(m.Data)
			e.Err, e.Name = err, l.Name
		case rtmNewAddr, rtmDelAddr:
			e.Kind, e.Deleted = EventAddr, m.Header.Type == rtmDelAddr
			a, err := DecodeAddr(m.Data)
			e.Err, e.Family = err, a.Family
		default:
			continue
		}
		out = append(out, e)
	}
	return out
}
