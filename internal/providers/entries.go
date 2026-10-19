package providers

import "github.com/irashack/molebridge/internal/validate"

// Shape says which provider's catalogue an entry came from. It decides which
// Relay fields exist and the member order the entry has in relays.json (the
// order Python's dicts gave them), nothing else.
type Shape int

// The entry shapes.
const (
	ShapeMullvad Shape = iota // also the shape of a snapshot written before providers existed
	ShapePIA
	ShapeNordVPN
	ShapeGluetun
)

// Server is one of a PIA region's WireGuard servers: the address and the TLS
// name the applier verifies against PIA's CA.
type Server struct {
	IP string
	CN string
}

// JSONObject implements validate.ObjectMarshaler.
func (s Server) JSONObject() validate.Obj { return validate.Members("ip", s.IP, "cn", s.CN) }

// Relay is one entry of a provider's catalogue (a Mullvad relay, a PIA region,
// a NordVPN server, a gluetun server). Which fields are set depends on Shape;
// the parsers and ValidateEntry never set the others. Pointer fields and the
// slices distinguish "absent" (nil) from a present zero value.
type Relay struct {
	Shape        Shape
	Hostname     string // the selectable name: a relay hostname or a region id
	PublicKey    string
	IPv4AddrIn   string // the address the key's peer is reached at; PIA: the latency target
	City         string
	Country      string
	LocationCode string
	CountryCode  string // NordVPN

	// Mullvad: display attributes, kept only when well formed.
	Owned           *bool
	Stboot          *bool
	HostingProvider string // JSON "provider"

	// PIA
	PortForward bool
	Geo         bool
	Servers     []Server

	// NordVPN
	Load    *int64
	Virtual bool

	// gluetun: ID is the identifier the selection filter matches, which for
	// every supported provider is the hostname.
	ID              string
	SelectionFilter string
	IPv4Addrs       []string // nil when absent
	IPv6Addrs       []string // always present, possibly empty
	Region          *string
	Categories      []string // nil when absent
}

func anyStrings(list []string) []any {
	out := make([]any, len(list))
	for i, s := range list {
		out[i] = s
	}
	return out
}

// memberWriter receives an entry's members in order (Relay.members): the
// object JSONObject builds, or the bound SnapshotTooLarge counts without
// building it.
type memberWriter interface {
	text(key, value string)
	flag(key string, value bool)
	number(key string, value int64)
	texts(key string, values []string)
	servers(key string, values []Server)
}

// objectWriter builds the object.
type objectWriter struct{ o validate.Obj }

func (w *objectWriter) add(key string, value any) {
	w.o = append(w.o, validate.Pair{Key: key, Value: value})
}
func (w *objectWriter) text(key, value string)            { w.add(key, value) }
func (w *objectWriter) flag(key string, value bool)       { w.add(key, value) }
func (w *objectWriter) number(key string, value int64)    { w.add(key, value) }
func (w *objectWriter) texts(key string, values []string) { w.add(key, anyStrings(values)) }
func (w *objectWriter) servers(key string, values []Server) {
	list := make([]any, len(values))
	for i, s := range values {
		list[i] = s
	}
	w.add(key, list)
}

// JSONObject implements validate.ObjectMarshaler: the entry as it is stored in
// relays.json, members in the order Python wrote them.
func (r *Relay) JSONObject() validate.Obj {
	w := &objectWriter{o: make(validate.Obj, 0, 12)}
	r.members(w)
	return w.o
}

// members writes the entry's members, in the order JSONObject has them.
func (r *Relay) members(w memberWriter) {
	switch r.Shape {
	case ShapePIA:
		w.text("hostname", r.Hostname)
		w.text("city", r.City)
		w.text("country", r.Country)
		w.text("location_code", r.LocationCode)
		w.text("ipv4_addr_in", r.IPv4AddrIn)
		w.flag("port_forward", r.PortForward)
		w.flag("geo", r.Geo)
		w.servers("servers", r.Servers)
		return
	case ShapeNordVPN:
		w.text("hostname", r.Hostname)
		w.text("public_key", r.PublicKey)
		w.text("ipv4_addr_in", r.IPv4AddrIn)
		w.text("city", r.City)
		w.text("country", r.Country)
		w.text("country_code", r.CountryCode)
		w.text("location_code", r.LocationCode)
		if r.Load != nil {
			w.number("load", *r.Load)
		}
		w.flag("virtual", r.Virtual)
		return
	case ShapeGluetun:
		w.text("hostname", r.Hostname)
		w.text("public_key", r.PublicKey)
		w.text("ipv4_addr_in", r.IPv4AddrIn)
		if r.IPv4Addrs != nil {
			w.texts("ipv4_addrs", r.IPv4Addrs)
		}
		w.texts("ipv6_addrs", r.IPv6Addrs) // nil is []
		w.text("city", r.City)
		w.text("country", r.Country)
		if r.Region != nil {
			w.text("region", *r.Region)
		}
		if r.Categories != nil {
			w.texts("categories", r.Categories)
		}
		w.text("id", r.ID)
		w.text("selection_filter", r.SelectionFilter)
		return
	}
	w.text("hostname", r.Hostname)
	w.text("public_key", r.PublicKey)
	w.text("ipv4_addr_in", r.IPv4AddrIn)
	w.text("city", r.City)
	w.text("country", r.Country)
	w.text("location_code", r.LocationCode)
	if r.Owned != nil {
		w.flag("owned", *r.Owned)
	}
	if r.Stboot != nil {
		w.flag("stboot", *r.Stboot)
	}
	if r.HostingProvider != "" {
		w.text("provider", r.HostingProvider)
	}
}

// Flag reads one of the boolean attributes the panel filters and badges on
// ("owned", "stboot", "port_forward", "geo", "virtual"): its value and whether
// the entry has it at all.
func (r *Relay) Flag(name string) (value, present bool) {
	switch name {
	case "owned":
		if r.Owned != nil {
			return *r.Owned, true
		}
	case "stboot":
		if r.Stboot != nil {
			return *r.Stboot, true
		}
	case "port_forward":
		return r.PortForward, r.Shape == ShapePIA
	case "geo":
		return r.Geo, r.Shape == ShapePIA
	case "virtual":
		return r.Virtual, r.Shape == ShapeNordVPN
	}
	return false, false
}

// Copy returns a deep copy.
func (r *Relay) Copy() *Relay {
	c := *r
	c.Servers = append([]Server(nil), r.Servers...)
	if r.IPv4Addrs != nil {
		c.IPv4Addrs = append([]string{}, r.IPv4Addrs...)
	}
	if r.IPv6Addrs != nil {
		c.IPv6Addrs = append([]string{}, r.IPv6Addrs...)
	}
	if r.Categories != nil {
		c.Categories = append([]string{}, r.Categories...)
	}
	for _, p := range []**bool{&c.Owned, &c.Stboot} {
		if *p != nil {
			v := **p
			*p = &v
		}
	}
	if c.Load != nil {
		v := *c.Load
		c.Load = &v
	}
	if c.Region != nil {
		v := *c.Region
		c.Region = &v
	}
	return &c
}

// Entries is a catalogue: entries by name in the order they were added, like a
// Python dict. The zero value and nil are empty.
type Entries struct {
	order []string
	index map[string]*Relay
}

// NewEntries returns an empty catalogue.
func NewEntries() *Entries { return &Entries{index: map[string]*Relay{}} }

// Len is the number of entries.
func (e *Entries) Len() int {
	if e == nil {
		return 0
	}
	return len(e.order)
}

// Names lists the names in insertion order.
func (e *Entries) Names() []string {
	if e == nil {
		return nil
	}
	return append([]string(nil), e.order...)
}

// Get returns the entry named name.
func (e *Entries) Get(name string) (*Relay, bool) {
	if e == nil {
		return nil, false
	}
	r, ok := e.index[name]
	return r, ok
}

// Has reports whether an entry has this name.
func (e *Entries) Has(name string) bool { _, ok := e.Get(name); return ok }

// Set adds an entry, or replaces the one with that name keeping its position.
func (e *Entries) Set(name string, r *Relay) {
	if e.index == nil {
		e.index = map[string]*Relay{}
	}
	if _, ok := e.index[name]; !ok {
		e.order = append(e.order, name)
	}
	e.index[name] = r
}

// Each calls fn for every entry in order until fn returns false.
func (e *Entries) Each(fn func(name string, r *Relay) bool) {
	if e == nil {
		return
	}
	for _, name := range e.order {
		if !fn(name, e.index[name]) {
			return
		}
	}
}

// Filter returns the entries for which keep is true, in order.
func (e *Entries) Filter(keep func(name string, r *Relay) bool) *Entries {
	out := NewEntries()
	e.Each(func(name string, r *Relay) bool {
		if keep(name, r) {
			out.Set(name, r)
		}
		return true
	})
	return out
}

// JSONObject implements validate.ObjectMarshaler.
func (e *Entries) JSONObject() validate.Obj {
	o := make(validate.Obj, 0, e.Len())
	e.Each(func(name string, r *Relay) bool {
		o = append(o, validate.Pair{Key: name, Value: r})
		return true
	})
	return o
}
