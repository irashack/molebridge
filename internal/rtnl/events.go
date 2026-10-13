package rtnl

import "github.com/mdlayher/netlink"

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
	// Pid is the port id of the socket whose request caused the notification
	// (nlmsg_pid, which the kernel stamps from the request); 0 for a change the
	// kernel made itself.
	Pid uint32
}

//lint:ignore U1000 linux-only: called from events_linux.go
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
		e.Pid = m.Header.PID
		out = append(out, e)
	}
	return out
}
