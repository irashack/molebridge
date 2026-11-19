package tunnel

import (
	"net/netip"

	"github.com/irashack/molebridge/internal/rtnl"
	"github.com/irashack/molebridge/internal/tunnelconf"
)

// TunnelSource is the tunnel configuration recovery rebuilds: the current
// provider's config and the last peer set for it. The applier updates it
// before it queues a Replace, so a tunnel lost during or after a provider
// change comes back as the new provider's.
type TunnelSource interface {
	Current() (provider string, conf *tunnelconf.Conf)
}

// ReturnPathOf is the return path the routing contract expects for a tunnel
// config: per family, the config's address, whose rules 94 and 98 are
// expected; a config with no address at all (PIA's) leaves both families'
// pairs to the transaction that sets the address. The worker's starting
// expected state and Replace both take it from here.
func ReturnPathOf(c *tunnelconf.Conf) (map[rtnl.Family][]netip.Addr, map[rtnl.Family]bool) {
	rp, leave := map[rtnl.Family][]netip.Addr{}, map[rtnl.Family]bool{}
	if c == nil {
		return rp, leave
	}
	if c.Addr4.IsValid() {
		rp[rtnl.V4] = []netip.Addr{c.Addr4}
	}
	if c.Addr6.IsValid() {
		rp[rtnl.V6] = []netip.Addr{c.Addr6}
	}
	if c.RuleOwner() == "applier" {
		leave[rtnl.V4], leave[rtnl.V6] = true, true
	}
	return rp, leave
}
