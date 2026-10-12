package rtnl

import "net/netip"

// Snapshot is a consistent-as-possible copy of the kernel state the contract
// is judged on. Routes hold only the tables a caller asked for.
type Snapshot struct {
	Rules  map[Family][]Rule
	Routes map[Family][]Route
	Links  []Link
	Addrs  map[Family][]Addr
}

// Interest says which parts of the routing state a snapshot needs.
type Interest struct {
	// Tables are the routing tables whose routes are kept.
	Tables []uint32
}

// NewSnapshot returns an empty snapshot with its maps made.
func NewSnapshot() *Snapshot {
	return &Snapshot{
		Rules:  map[Family][]Rule{},
		Routes: map[Family][]Route{},
		Addrs:  map[Family][]Addr{},
	}
}

// Link returns the interface called name.
func (s *Snapshot) Link(name string) (Link, bool) {
	for _, l := range s.Links {
		if l.Name == name {
			return l, true
		}
	}
	return Link{}, false
}

// RoutesInTable returns the routes of one family and table.
func (s *Snapshot) RoutesInTable(f Family, table uint32) []Route {
	var out []Route
	for _, r := range s.Routes[f] {
		if r.Table == table {
			out = append(out, r)
		}
	}
	return out
}

// GlobalAddr returns the first global-scope address of the family on the
// named interface (what `ip -o -4 addr show dev X scope global` lists first).
func (s *Snapshot) GlobalAddr(name string, f Family) (netip.Addr, bool) {
	l, ok := s.Link(name)
	if !ok {
		return netip.Addr{}, false
	}
	for _, a := range s.Addrs[f] {
		if a.Index == l.Index && a.Global() {
			return a.Local.Addr(), true
		}
	}
	return netip.Addr{}, false
}
