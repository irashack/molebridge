//go:build linux

package rtnl

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// DefaultTimeout bounds every request on a Conn unless SetTimeout says
// otherwise. The mutation owner's 10-second operation bound is built on it.
const DefaultTimeout = 10 * time.Second

// maxDumpAttempts is how many times a dump interrupted by concurrent changes
// is taken again before the caller is told.
const maxDumpAttempts = 8

// Options selects the namespace a socket lives in.
type Options struct {
	// NetNS is a file descriptor of a network namespace to operate in; zero
	// means the calling thread's namespace at the time of the call.
	NetNS int
	// ReadBuffer, when positive, sizes the socket's receive buffer. Tests
	// use a tiny one to provoke ENOBUFS.
	ReadBuffer int
}

// Conn is a NETLINK_ROUTE request socket. It is safe for concurrent use;
// requests are serialized.
type Conn struct {
	mu      sync.Mutex
	c       *netlink.Conn
	timeout time.Duration
}

// Dial opens a request socket.
func Dial(o Options) (*Conn, error) {
	c, err := netlink.Dial(unix.NETLINK_ROUTE, &netlink.Config{NetNS: o.NetNS})
	if err != nil {
		return nil, fmt.Errorf("rtnl: open netlink socket: %w", err)
	}
	// Extended acknowledgements make kernel refusals readable; older kernels
	// lack them and that is fine.
	_ = c.SetOption(netlink.ExtendedAcknowledge, true)
	if o.ReadBuffer > 0 {
		_ = c.SetReadBuffer(o.ReadBuffer)
	}
	return &Conn{c: c, timeout: DefaultTimeout}, nil
}

// Close closes the socket.
func (c *Conn) Close() error { return c.c.Close() }

// SetTimeout changes the bound on each request.
func (c *Conn) SetTimeout(d time.Duration) {
	c.mu.Lock()
	c.timeout = d
	c.mu.Unlock()
}

func (c *Conn) execute(typ netlink.HeaderType, flags netlink.HeaderFlags, data []byte) ([]netlink.Message, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.c.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return nil, err
	}
	return c.c.Execute(netlink.Message{
		Header: netlink.Header{Type: typ, Flags: flags},
		Data:   data,
	})
}

// dump runs a dump request and returns the payloads of the replies of the
// wanted type. A dump the kernel marked interrupted is discarded and taken
// again.
func (c *Conn) dump(typ netlink.HeaderType, want netlink.HeaderType, data []byte) ([][]byte, error) {
	for attempt := 0; attempt < maxDumpAttempts; attempt++ {
		msgs, err := c.execute(typ, netlink.Request|netlink.Dump, data)
		if err != nil {
			return nil, err
		}
		interrupted := false
		out := make([][]byte, 0, len(msgs))
		for _, m := range msgs {
			if m.Header.Flags&netlink.DumpInterrupted != 0 {
				interrupted = true
			}
			if m.Header.Type == want {
				out = append(out, m.Data)
			}
		}
		if !interrupted {
			return out, nil
		}
	}
	return nil, ErrInconsistent
}

// Rules dumps the rules of one family, in priority order as the kernel keeps
// them.
func (c *Conn) Rules(f Family) ([]Rule, error) {
	hdr := make([]byte, 12)
	hdr[0] = f.AF()
	payloads, err := c.dump(rtmGetRule, rtmNewRule, hdr)
	if err != nil {
		return nil, fmt.Errorf("rtnl: dump %s rules: %w", f, err)
	}
	rules := make([]Rule, 0, len(payloads))
	for _, p := range payloads {
		r, err := DecodeRule(p)
		if err != nil {
			return nil, fmt.Errorf("rtnl: dump %s rules: %w", f, err)
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// Routes dumps the routes of one family whose table the filter accepts (all
// tables when it is nil). Cached clones (RTM_F_CLONED) are skipped, as
// `ip route show` skips them.
func (c *Conn) Routes(f Family, tables func(uint32) bool) ([]Route, error) {
	hdr := make([]byte, 12)
	hdr[0] = f.AF()
	payloads, err := c.dump(rtmGetRoute, rtmNewRoute, hdr)
	if err != nil {
		return nil, fmt.Errorf("rtnl: dump %s routes: %w", f, err)
	}
	var routes []Route
	for _, p := range payloads {
		r, err := DecodeRoute(p)
		if err != nil {
			return nil, fmt.Errorf("rtnl: dump %s routes: %w", f, err)
		}
		if r.Flags&0x200 != 0 { // RTM_F_CLONED
			continue
		}
		if tables != nil && !tables(r.Table) {
			continue
		}
		routes = append(routes, r)
	}
	return routes, nil
}

// Links dumps every interface.
func (c *Conn) Links() ([]Link, error) {
	hdr := make([]byte, 16)
	payloads, err := c.dump(rtmGetLink, rtmNewLink, hdr)
	if err != nil {
		return nil, fmt.Errorf("rtnl: dump links: %w", err)
	}
	links := make([]Link, 0, len(payloads))
	for _, p := range payloads {
		l, err := DecodeLink(p)
		if err != nil {
			return nil, fmt.Errorf("rtnl: dump links: %w", err)
		}
		links = append(links, l)
	}
	return links, nil
}

// Addrs dumps the addresses of one family.
func (c *Conn) Addrs(f Family) ([]Addr, error) {
	hdr := make([]byte, 8)
	hdr[0] = f.AF()
	payloads, err := c.dump(rtmGetAddr, rtmNewAddr, hdr)
	if err != nil {
		return nil, fmt.Errorf("rtnl: dump %s addresses: %w", f, err)
	}
	var addrs []Addr
	for _, p := range payloads {
		a, err := DecodeAddr(p)
		if err != nil {
			return nil, fmt.Errorf("rtnl: dump %s addresses: %w", f, err)
		}
		addrs = append(addrs, a)
	}
	return addrs, nil
}

// AddRule installs a rule (NLM_F_EXCL: an identical rule is EEXIST).
func (c *Conn) AddRule(r Rule) error {
	_, err := c.execute(rtmNewRule, netlink.Request|netlink.Acknowledge|netlink.Create|netlink.Excl, r.Marshal())
	return wrap("add rule", err)
}

// DelRule removes the first rule that has every attribute of r.
func (c *Conn) DelRule(r Rule) error {
	_, err := c.execute(rtmDelRule, netlink.Request|netlink.Acknowledge, r.Marshal())
	return wrap("delete rule", err)
}

// DelRulePriority removes the first rule at a priority, whatever it selects.
func (c *Conn) DelRulePriority(f Family, priority uint32) error {
	_, err := c.execute(rtmDelRule, netlink.Request|netlink.Acknowledge, PriorityOnly(f, priority))
	return wrap("delete rule by priority", err)
}

// ReplaceRoute creates or replaces a route, like `ip route replace`.
func (c *Conn) ReplaceRoute(r Route) error {
	_, err := c.execute(rtmNewRoute, netlink.Request|netlink.Acknowledge|netlink.Create|netlink.Replace, r.Marshal())
	return wrap("replace route", err)
}

// DelRoute removes the route that matches r's attributes.
func (c *Conn) DelRoute(r Route) error {
	_, err := c.execute(rtmDelRoute, netlink.Request|netlink.Acknowledge, r.Marshal())
	return wrap("delete route", err)
}

func wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	var oe *netlink.OpError
	if errors.As(err, &oe) && oe.Message != "" {
		return fmt.Errorf("rtnl: %s: %w (%s)", op, err, oe.Message)
	}
	return fmt.Errorf("rtnl: %s: %w", op, err)
}

// Timeout reports whether err is a deadline expiry.
func Timeout(err error) bool {
	return errors.Is(err, os.ErrDeadlineExceeded)
}
