//go:build linux

package rtnl

import (
	"context"
	"fmt"
	"time"
)

// DefaultTimeout bounds every request on a Conn unless SetTimeout says
// otherwise. The mutation owner's 10-second operation bound is built on
// SetDeadline, which bounds a whole operation.
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

// Rules dumps the rules of one family, in priority order as the kernel keeps
// them.
func (c *Conn) Rules(f Family) ([]Rule, error) {
	return c.rulesWith(func(ctx context.Context, typ, want uint16, data []byte) ([][]byte, error) {
		return c.dumpRetry(ctx, typ, want, data)
	}, context.Background(), f)
}

func (c *Conn) rulesOnce(ctx context.Context, f Family) ([]Rule, error) {
	return c.rulesWith(c.dump, ctx, f)
}

type dumper func(ctx context.Context, typ, want uint16, data []byte) ([][]byte, error)

func (c *Conn) rulesWith(d dumper, ctx context.Context, f Family) ([]Rule, error) {
	hdr := make([]byte, 12)
	hdr[0] = f.AF()
	payloads, err := d(ctx, rtmGetRule, rtmNewRule, hdr)
	if err != nil {
		return nil, fmt.Errorf("rtnl: dump %s rules: %w", f, err)
	}
	rules := make([]Rule, 0, len(payloads))
	for _, p := range payloads {
		r, err := DecodeRule(p)
		if err != nil {
			return nil, c.malformed(fmt.Sprintf("dump %s rules", f), err)
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// malformed: a reply that does not decode means the stream cannot be trusted.
func (c *Conn) malformed(what string, err error) error {
	return c.reset(fmt.Errorf("rtnl: %s: %w", what, err))
}

// Routes dumps the routes of one family whose table the filter accepts (all
// tables when it is nil). Cached clones (RTM_F_CLONED) are skipped, as
// `ip route show` skips them.
func (c *Conn) Routes(f Family, tables func(uint32) bool) ([]Route, error) {
	return c.routesWith(func(ctx context.Context, typ, want uint16, data []byte) ([][]byte, error) {
		return c.dumpRetry(ctx, typ, want, data)
	}, context.Background(), f, tables)
}

func (c *Conn) routesOnce(ctx context.Context, f Family, tables func(uint32) bool) ([]Route, error) {
	return c.routesWith(c.dump, ctx, f, tables)
}

func (c *Conn) routesWith(d dumper, ctx context.Context, f Family, tables func(uint32) bool) ([]Route, error) {
	hdr := make([]byte, 12)
	hdr[0] = f.AF()
	payloads, err := d(ctx, rtmGetRoute, rtmNewRoute, hdr)
	if err != nil {
		return nil, fmt.Errorf("rtnl: dump %s routes: %w", f, err)
	}
	var routes []Route
	for _, p := range payloads {
		r, err := DecodeRoute(p)
		if err != nil {
			return nil, c.malformed(fmt.Sprintf("dump %s routes", f), err)
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
	return c.linksWith(func(ctx context.Context, typ, want uint16, data []byte) ([][]byte, error) {
		return c.dumpRetry(ctx, typ, want, data)
	}, context.Background())
}

func (c *Conn) linksOnce(ctx context.Context) ([]Link, error) { return c.linksWith(c.dump, ctx) }

func (c *Conn) linksWith(d dumper, ctx context.Context) ([]Link, error) {
	hdr := make([]byte, 16)
	payloads, err := d(ctx, rtmGetLink, rtmNewLink, hdr)
	if err != nil {
		return nil, fmt.Errorf("rtnl: dump links: %w", err)
	}
	links := make([]Link, 0, len(payloads))
	for _, p := range payloads {
		l, err := DecodeLink(p)
		if err != nil {
			return nil, c.malformed("dump links", err)
		}
		links = append(links, l)
	}
	return links, nil
}

// Addrs dumps the addresses of one family.
func (c *Conn) Addrs(f Family) ([]Addr, error) {
	return c.addrsWith(func(ctx context.Context, typ, want uint16, data []byte) ([][]byte, error) {
		return c.dumpRetry(ctx, typ, want, data)
	}, context.Background(), f)
}

func (c *Conn) addrsOnce(ctx context.Context, f Family) ([]Addr, error) {
	return c.addrsWith(c.dump, ctx, f)
}

func (c *Conn) addrsWith(d dumper, ctx context.Context, f Family) ([]Addr, error) {
	hdr := make([]byte, 8)
	hdr[0] = f.AF()
	payloads, err := d(ctx, rtmGetAddr, rtmNewAddr, hdr)
	if err != nil {
		return nil, fmt.Errorf("rtnl: dump %s addresses: %w", f, err)
	}
	var addrs []Addr
	for _, p := range payloads {
		a, err := DecodeAddr(p)
		if err != nil {
			return nil, c.malformed(fmt.Sprintf("dump %s addresses", f), err)
		}
		addrs = append(addrs, a)
	}
	return addrs, nil
}

// AddRule installs a rule (NLM_F_EXCL: an identical rule is EEXIST).
func (c *Conn) AddRule(r Rule) error {
	return wrap("add rule", c.request(context.Background(), rtmNewRule, nlmRequest|nlmAck|nlmCreate|nlmExcl, r.Marshal()))
}

// DelRule removes the first rule that has every attribute of r.
func (c *Conn) DelRule(r Rule) error {
	return wrap("delete rule", c.request(context.Background(), rtmDelRule, nlmRequest|nlmAck, r.Marshal()))
}

// DelRulePriority removes the first rule at a priority, whatever it selects.
func (c *Conn) DelRulePriority(f Family, priority uint32) error {
	return wrap("delete rule by priority", c.request(context.Background(), rtmDelRule, nlmRequest|nlmAck, PriorityOnly(f, priority)))
}

// ReplaceRoute creates or replaces a route, like `ip route replace`.
func (c *Conn) ReplaceRoute(r Route) error {
	return wrap("replace route", c.request(context.Background(), rtmNewRoute, nlmRequest|nlmAck|nlmCreate|nlmReplace, r.Marshal()))
}

// DelRoute removes the route that matches r's attributes.
func (c *Conn) DelRoute(r Route) error {
	return wrap("delete route", c.request(context.Background(), rtmDelRoute, nlmRequest|nlmAck, r.Marshal()))
}

func wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("rtnl: %s: %w", op, err)
}

// LinkByName reads one interface. A missing one is an error for which
// IsNotExist is true (ENODEV).
func (c *Conn) LinkByName(name string) (Link, error) {
	msgs, _, err := c.exchange(context.Background(), rtmGetLink, nlmRequest, LinkLookupRequest(name))
	if err != nil {
		return Link{}, fmt.Errorf("rtnl: look up link %s: %w", name, err)
	}
	for _, m := range msgs {
		if m.typ != rtmNewLink {
			continue
		}
		l, err := DecodeLink(m.data)
		if err != nil {
			return Link{}, c.malformed("look up link "+name, err)
		}
		return l, nil
	}
	return Link{}, c.malformed("look up link "+name, fmt.Errorf("%w: no link in the reply", ErrMalformed))
}

// AddLink creates an interface of a kind ("wireguard") with a name, like
// `ip link add NAME type KIND` (EEXIST if the name is taken).
func (c *Conn) AddLink(name, kind string) error {
	return wrap("add link", c.request(context.Background(), rtmNewLink, nlmRequest|nlmAck|nlmCreate|nlmExcl, LinkCreateRequest(name, kind)))
}

// DelLink removes an interface by index.
func (c *Conn) DelLink(index uint32) error {
	return wrap("delete link", c.request(context.Background(), rtmDelLink, nlmRequest|nlmAck, LinkDeleteRequest(index)))
}

// SetLinkMTU sets an interface's MTU.
func (c *Conn) SetLinkMTU(index, mtu uint32) error {
	return wrap("set link MTU", c.request(context.Background(), rtmNewLink, nlmRequest|nlmAck, LinkMTURequest(index, mtu)))
}

// SetLinkUp brings an interface administratively up.
func (c *Conn) SetLinkUp(index uint32) error {
	return wrap("set link up", c.request(context.Background(), rtmNewLink, nlmRequest|nlmAck, LinkUpRequest(index)))
}

// AddAddr assigns an address (EEXIST if it is already there).
func (c *Conn) AddAddr(a Addr) error {
	return wrap("add address", c.request(context.Background(), rtmNewAddr, nlmRequest|nlmAck|nlmCreate|nlmExcl, a.Marshal()))
}

// DelAddr removes an address.
func (c *Conn) DelAddr(a Addr) error {
	return wrap("delete address", c.request(context.Background(), rtmDelAddr, nlmRequest|nlmAck, a.Marshal()))
}
