package applier

import (
	"context"
	"net/netip"

	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/rtnl"
)

// System is everything the applier needs from the machine. The applier never
// executes anything: the Python applier shelled out through `self.run([...])`
// (ip, wg, nft, curl, cat) and each kind of call is one method here.
//
// The exit worker implements the kernel methods (netlink, wgctrl, nftables);
// HTTP is implemented by netx.Client, which satisfies Fetch as it is. Every
// method returns an error for a failure, a missing interface or an answer
// that makes no sense; the applier treats any error as "no usable answer"
// exactly as it treated the Python RuntimeError and ValueError. Methods are
// called from the applier's goroutine (Tick) except those Healthy uses, which
// may run on another; implementations must be safe for that.
//
// Kernel changes (ReplacePeer, ChangePIAAddress, the PIA primitives and the
// nftables methods) are the exit worker's mutation owner's to serialize: each
// call is one queued job, and the expected state the routing repairer keeps is
// updated before the kernel is.
//
// The mapping from the Python calls:
//
//	ip link show dev <overlay>                  LinkExists
//	ip -j address show dev <exit>               TunnelAddresses
//	ip -j -N rule/route show + family_status    RoutingStatus
//	cat <sysctl>                                ReadSysctl
//	ip -d -j link show dev <overlay>            OverlayKernelWireGuard
//	nft -j list chains                          NetbirdFirewallPresent
//	ip -j -6 route show table all, ... address  IPv6Evidence
//	wg show <exit> peers                        Peers
//	wg show <exit> latest-handshakes            LatestHandshakes
//	wg show <exit> endpoints                    Endpoints
//	wg show <exit> public-key                   PublicKey
//	wg set <exit> peer ... remove / endpoint    ReplacePeer
//	ip -j -4 address show (every interface)     NamespaceIPv4Prefixes
//	the PIA rule 94/98, address and route calls PIAKernel and ChangePIAAddress
//	nft -f (the ingress guard)                  InstallIngressGuard
//	nft -f (the forwarding table)               ApplyForwardRules, RemoveForwardRules
//	curl                                        Fetch
type System interface {
	// LinkExists is nil when the interface exists.
	LinkExists(ctx context.Context, name string) error
	// RoutingStatus is the routing contract's verdict for one family (4 or 6):
	// whether the rules and routes protect traffic (protected) and whether the
	// exit table's unreachable fallback holds (fallback). tunnelAddress is the
	// tunnel's address in that family ("" when it has none), against which the
	// return-path rules 94 and 98 are judged. The owner record is not part of
	// it: the supervisor's lease is (decision D7).
	RoutingStatus(ctx context.Context, family int, tunnelAddress string) (protected, fallback bool, err error)
	// ReadSysctl returns the text of a /proc/sys file.
	ReadSysctl(ctx context.Context, path string) (string, error)
	// OverlayKernelWireGuard is whether the overlay interface exists and is a
	// kernel WireGuard link (exactly one, with that name).
	OverlayKernelWireGuard(ctx context.Context) (bool, error)
	// NetbirdFirewallPresent is whether NetBird's own kernel-firewall chains
	// are in the ruleset.
	NetbirdFirewallPresent(ctx context.Context) (bool, error)
	// IPv6Evidence are the namespace's IPv6 routes (every table) and its
	// global-scope IPv6 addresses, in the shape of `ip -j` output ([]any of
	// map[string]any) that internal/egress.HostLacksIPv6 judges.
	IPv6Evidence(ctx context.Context) (routes, links any, err error)
	// OwnerGeneration is the native exit's current owner generation (a
	// restarted exit starts a new one), or "" when there is none, as for the
	// gluetun backend.
	OwnerGeneration(ctx context.Context) string

	// Peers are the tunnel's peer public keys (wg show peers). An error is a
	// missing or non-WireGuard interface.
	Peers(ctx context.Context) ([]string, error)
	// LatestHandshakes are the peers' last handshake times in Unix seconds, 0
	// for none yet. A peer absent from the map is unknown.
	LatestHandshakes(ctx context.Context) (map[string]int64, error)
	// Endpoints are the peers' endpoints as "ip:port" (or "(none)"). A listing
	// with an invalid key, a duplicate key or a malformed line is an error.
	Endpoints(ctx context.Context) (map[string]string, error)
	// PublicKey is the interface's own public key. The private key is never
	// read.
	PublicKey(ctx context.Context) (string, error)
	// ReplacePeer removes the peers in remove, one after another (a failure
	// stops before anything else changes), then sets add; an add with no
	// public key sets nothing.
	ReplacePeer(ctx context.Context, remove []string, add PeerConfig) error

	// NamespaceIPv4Prefixes are the IPv4 prefixes on every interface but
	// exclude: a PIA registration landing inside one would shadow the
	// namespace's own routes.
	NamespaceIPv4Prefixes(ctx context.Context, exclude string) ([]netip.Prefix, error)
	// PIAKernel is the rules, address and route calls PIA's per-server tunnel
	// address needs. Every method is a single idempotent kernel change.
	PIAKernel
	// ChangePIAAddress is PIA's address-change transaction, ONE job on the
	// exit worker's mutation owner: install and confirm the new 94/98 pair,
	// change the address (new first, then the old one removed), restore the
	// exit-table default route, remove the old pair, with the expected state
	// carrying both pairs meanwhile. old is the invalid address when the
	// tunnel has no IPv4 address yet. The function ChangePIAAddress in this
	// package is the ordering to follow and the one the tests run: the worker
	// implements this method by calling it over its own PIAKernel.
	ChangePIAAddress(ctx context.Context, old, new netip.Addr) error
	// InstallIngressGuard installs the forward-path guard: forwarded tunnel
	// ingress may leave only over the overlay (`table inet molebridge_guard`,
	// chain forward, `iifname <exit> oifname != <overlay> drop`), replacing any
	// earlier table of that name atomically. It is never removed.
	InstallIngressGuard(ctx context.Context) error
	// ApplyForwardRules atomically replaces `table ip molebridge_forward`: in
	// prerouting (dstnat) `iifname <exit> meta l4proto {tcp, udp} th dport
	// <port> dnat to <target>`, and in postrouting (srcnat) `oifname <overlay>
	// ct status dnat ip daddr <target> masquerade`.
	ApplyForwardRules(ctx context.Context, port int, target netip.Addr) error
	// RemoveForwardRules deletes `table ip molebridge_forward` whether or not
	// it exists.
	RemoveForwardRules(ctx context.Context) error

	// Fetch sends one HTTP request (netx.Client satisfies it).
	Fetch(ctx context.Context, req netx.Request) (netx.Response, error)
}

// PeerConfig is the peer ReplacePeer sets.
type PeerConfig struct {
	PublicKey  string
	Endpoint   string   // "ip:port"
	AllowedIPs []string // CIDRs, as wg takes them
	// KeepaliveSec is the persistent keepalive interval in seconds.
	KeepaliveSec int
}

// Rule is an IPv4 policy rule as far as the return-path rules 94 and 98 are
// concerned.
type Rule struct {
	Priority int
	// Src is the source address or prefix, "" for "all".
	Src string
	// SrcLen is the source prefix length, -1 when the rule states none.
	SrcLen int
	// IPProto is the IP protocol number selector, 0 for none (1 is ICMP).
	IPProto int
	// Table is the routing table the rule looks up, 0 for none.
	Table int
	// Action is "unreachable" for that action, "" for none.
	Action string
	// Other is true when the rule carries anything this exit's return-path
	// rules never do (iif, oif, fwmark, dst, a negation ...).
	Other bool
}

// PIAKernel is the kernel calls PIA's return-path handling is built from. Rule
// 94 is `ip -4 rule add from <addr> ipproto icmp lookup <table> priority 94`
// and rule 98 `... unreachable priority 98`.
type PIAKernel interface {
	// IPv4Rules are the IPv4 rules now installed at priority.
	IPv4Rules(ctx context.Context, priority int) ([]Rule, error)
	// TunnelAddresses are the exit interface's global-scope addresses (an
	// error means there is no such interface).
	TunnelAddresses(ctx context.Context) ([]netip.Addr, error)
	// AddReturnPathRule installs rule 94 or 98 for addr.
	AddReturnPathRule(ctx context.Context, priority int, addr netip.Addr) error
	// DeleteReturnPathRule deletes the rule at priority from src; with an
	// invalid src it deletes whichever rule is at that priority.
	DeleteReturnPathRule(ctx context.Context, priority int, src netip.Addr) error
	// ReplaceTunnelAddress is `ip -4 address replace <addr>/32 dev <exit>`.
	ReplaceTunnelAddress(ctx context.Context, addr netip.Addr) error
	// DeleteTunnelAddress is `ip -4 address del <addr>/32 dev <exit>`.
	DeleteTunnelAddress(ctx context.Context, addr netip.Addr) error
	// ReplaceExitDefaultRoute is `ip -4 route replace default dev <exit> table
	// <table>`.
	ReplaceExitDefaultRoute(ctx context.Context) error
}

// GluetunKernel is what the gluetun backend reads of the namespace beyond
// System: the tunnel interface's flags and index, the host interface's index,
// and the rules and the exit, host and main tables as typed values. The Python
// applier read them with `ip -j link/rule/route show`; the exit worker
// implements this over its netlink connection, and the applier never executes
// anything for it. A System that serves the gluetun backend implements it too
// (CheckSystem refuses a provider on one that does not).
//
// The mapping from the Python calls:
//
//	ip -j link show dev <exit>                          GluetunLinks (Tunnel)
//	ip -j -N rule show                                  GluetunTables (Rules)
//	ip -j -N route show table <exit, host, main>        GluetunTables (Exit, Host, Main)
type GluetunKernel interface {
	// GluetunLinks reads the tunnel interface (EXIT_IF) and the host
	// interface (HOST_IF). gluetun's interface coming and going is routine: a
	// missing tunnel is Present false with no error. An error is a failure to
	// read, or an answer that makes no sense (the Python "invalid tunnel
	// interface").
	GluetunLinks(ctx context.Context) (GluetunLinks, error)
	// GluetunTables reads one family's (4 or 6) rules and routes.
	GluetunTables(ctx context.Context, family int) (GluetunTables, error)
}

// GluetunSystem is a System that also serves the gluetun backend.
type GluetunSystem interface {
	System
	GluetunKernel
}

// TunnelLink is the tunnel interface as the gluetun backend sees it.
type TunnelLink struct {
	Present, Up bool
	// Index is the interface index, 0 when it is absent. gluetun makes a new
	// interface on every settings change, so a changed index is a new one.
	Index uint32
}

// GluetunLinks are the interfaces the gluetun predicates read.
type GluetunLinks struct {
	Tunnel TunnelLink
	// HostIndex is the host interface's index, 0 when it is absent.
	HostIndex uint32
}

// GluetunTables are one family's rules and the routes of the exit table, the
// host table and the main table.
type GluetunTables struct {
	Rules            []rtnl.Rule
	Exit, Host, Main []rtnl.Route
}
