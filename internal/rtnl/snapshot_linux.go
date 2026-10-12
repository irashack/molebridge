//go:build linux

package rtnl

// Take dumps the rules, the routes of the wanted tables, the links and the
// addresses. Callers that watch for changes must have joined the multicast
// groups (Subscribe) before calling it.
func (c *Conn) Take(in Interest) (*Snapshot, error) {
	s := NewSnapshot()
	want := func(t uint32) bool {
		for _, w := range in.Tables {
			if w == t {
				return true
			}
		}
		return false
	}
	for _, f := range []Family{V4, V6} {
		rules, err := c.Rules(f)
		if err != nil {
			return nil, err
		}
		s.Rules[f] = rules
		routes, err := c.Routes(f, want)
		if err != nil {
			return nil, err
		}
		s.Routes[f] = routes
		addrs, err := c.Addrs(f)
		if err != nil {
			return nil, err
		}
		s.Addrs[f] = addrs
	}
	links, err := c.Links()
	if err != nil {
		return nil, err
	}
	s.Links = links
	return s, nil
}
