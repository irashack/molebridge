//go:build linux

package nft

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"

	"github.com/irashack/molebridge/internal/rtnl"
)

// The tables the exit's pipeline owns (applier/pia.py NFT_TABLE, GUARD_TABLE).
const (
	ForwardTable = "molebridge_forward"
	GuardTable   = "molebridge_guard"
)

// MutationBudget bounds a change whose context has no deadline.
const MutationBudget = 10 * time.Second

// extraConnOptions, when set, adds connection options to every mutation (tests
// replace the netlink dial through it).
var extraConnOptions func() []nftables.ConnOption

// withConn opens a lasting nftables connection for one change and runs fn on
// it. The connection owns exactly one netlink socket, which carries the
// context's absolute deadline from the moment it is created (see owned) and
// is closed directly when the context ends: Flush holds the library's mutex
// for the whole acknowledgement read, so CloseLasting cannot be the way to
// cancel it. The change runs under rtnl.RunBounded, which reports a call that
// outlasts even the closed socket. The connection is never reused. netns is a
// file descriptor of a network namespace, 0 for the caller's.
func withConn(ctx context.Context, netns int, fn func(*nftables.Conn) error) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, MutationBudget)
		defer cancel()
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("nft: %w", boundedErr(err))
	}
	dl, _ := ctx.Deadline()
	sock := &owned{dl: dl}
	opts := []nftables.ConnOption{nftables.AsLasting(), nftables.WithSockOptions(sock.option)}
	if netns != 0 {
		opts = append(opts, nftables.WithNetNSFd(netns))
	}
	if extraConnOptions != nil {
		opts = append(opts, extraConnOptions()...)
	}
	c, err := nftables.New(opts...)
	defer sock.close()
	if err != nil {
		return fmt.Errorf("nft: open netlink: %w", err)
	}
	return rtnl.RunBounded(ctx, rtnl.DefaultAbortGrace, sock.close, func() error { return fn(c) })
}

// ifname is an interface name as nft compares it: NUL-padded to IFNAMSIZ.
func ifname(name string) []byte {
	b := make([]byte, unix.IFNAMSIZ)
	copy(b, name)
	return b
}

// replaceTable queues "table X; delete table X; table X { ... }": the new
// table replaces any earlier one in one batch.
func replaceTable(c *nftables.Conn, family nftables.TableFamily, name string) *nftables.Table {
	t := &nftables.Table{Family: family, Name: name}
	c.AddTable(t)
	c.DelTable(t)
	return c.AddTable(t)
}

// EnsureIngressGuard keeps the forward-path guard in place: forwarded tunnel
// ingress may leave only over the overlay.
//
//	table inet molebridge_guard {
//	  chain forward {
//	    type filter hook forward priority filter; policy accept;
//	    iifname "<exit>" oifname != "<overlay>" drop
//	  }
//	}
//
// It reads the table back first and replaces it, atomically, only when it is
// missing or differs; an intact guard is left alone, so a check makes no
// change and announces nothing to other nftables listeners. (NetBird's client
// watches for new tables and chains and, half a second after each, inserts
// its accept rules into every filter chain it finds: replacing the table on
// every pass kept it doing that every pass.) Rules that match only the
// overlay, `iifname "<overlay>" ...` or `oifname "<overlay>" ...` (the ones
// NetBird inserts), cannot let tunnel ingress out anywhere else and are
// tolerated; any other difference is repaired. It returns why it installed
// the table, "" when the guard was already in place. Nothing removes it.
func EnsureIngressGuard(ctx context.Context, netns int, exitIf, overlayIf string) (string, error) {
	var why string
	err := withSidecarReadConn(ctx, netns, func(c *nftables.Conn, raw *netlink.Conn) error {
		reason, err := ingressGuardDifference(c, raw, exitIf, overlayIf)
		if err != nil {
			return fmt.Errorf("read back: %w", err)
		}
		if reason == "" {
			return nil
		}
		why = reason
		return installIngressGuard(c, exitIf, overlayIf)
	})
	if err != nil {
		return "", fmt.Errorf("nft: ensure the ingress guard: %w", err)
	}
	return why, nil
}

// InstallIngressGuard replaces the guard unconditionally (tests and drills;
// the exit calls EnsureIngressGuard).
func InstallIngressGuard(ctx context.Context, netns int, exitIf, overlayIf string) error {
	err := withConn(ctx, netns, func(c *nftables.Conn) error { return installIngressGuard(c, exitIf, overlayIf) })
	if err != nil {
		return fmt.Errorf("nft: install the ingress guard: %w", err)
	}
	return nil
}

func guardChain(t *nftables.Table) *nftables.Chain {
	policy := nftables.ChainPolicyAccept
	return &nftables.Chain{Name: "forward", Table: t, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter, Policy: &policy}
}

func guardDrop(exitIf, overlayIf string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(exitIf)},
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: ifname(overlayIf)},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
}

// overlayOnly is the start of a rule that matches only packets arriving on,
// or leaving by, the overlay.
func overlayOnly(key expr.MetaKey, overlayIf string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(overlayIf)},
	}
}

func installIngressGuard(c *nftables.Conn, exitIf, overlayIf string) error {
	t := replaceTable(c, nftables.TableFamilyINet, GuardTable)
	chain := c.AddChain(guardChain(t))
	c.AddRule(&nftables.Rule{Table: t, Chain: chain, Exprs: guardDrop(exitIf, overlayIf)})
	return c.Flush()
}

// ingressGuardDifference reads the live guard back: "" when it holds, or what
// is wrong with it.
func ingressGuardDifference(c *nftables.Conn, raw *netlink.Conn, exitIf, overlayIf string) (string, error) {
	want := &nftables.Table{Family: nftables.TableFamilyINet, Name: GuardTable}
	tables, err := c.ListTablesOfFamily(want.Family)
	if err != nil {
		return "", err
	}
	found := false
	for _, live := range tables {
		if live.Name == want.Name && live.Family == want.Family {
			found = true
			if live.Flags != 0 {
				return "table flags differ", nil
			}
		}
	}
	if !found {
		return "no table inet " + GuardTable, nil
	}
	chains, err := c.ListChainsOfTableFamily(want.Family)
	if err != nil {
		return "", err
	}
	wantChain := guardChain(want)
	var live *nftables.Chain
	for _, chain := range chains {
		if chain.Table == nil || chain.Table.Name != want.Name || chain.Table.Family != want.Family {
			continue
		}
		if chain.Name != wantChain.Name {
			return "extra chain " + chain.Name, nil
		}
		live = chain
	}
	if live == nil {
		return "no chain forward", nil
	}
	if reason := sidecarChainDifference(live, wantChain); reason != "" {
		return "chain forward: " + reason, nil
	}
	rules, err := readRules(raw, want, live)
	if err != nil {
		return "", err
	}
	drop := false
	for i, r := range rules {
		switch {
		case !r.userData && sidecarExpressionsEqual(r.exprs, guardDrop(exitIf, overlayIf)):
			drop = true
		case expressionsPrefixEqual(r.exprs, overlayOnly(expr.MetaKeyIIFNAME, overlayIf)),
			expressionsPrefixEqual(r.exprs, overlayOnly(expr.MetaKeyOIFNAME, overlayIf)):
			// Matches only overlay traffic, which the guard does not hold.
		default:
			return fmt.Sprintf("chain forward: rule %d is not the guard's", i+1), nil
		}
	}
	if !drop {
		return "chain forward: no drop rule", nil
	}
	return "", nil
}

// ApplyForwardRules atomically replaces `table ip molebridge_forward`:
//
//	chain prerouting {
//	  type nat hook prerouting priority dstnat; policy accept;
//	  iifname "<exit>" meta l4proto { tcp, udp } th dport <port> dnat to <target>
//	}
//	chain postrouting {
//	  type nat hook postrouting priority srcnat; policy accept;
//	  oifname "<overlay>" ct status dnat ip daddr <target> masquerade
//	}
//
// (The target's WireGuard peer accepts only the exit's overlay address from
// this peer, so forwarded connections carry it.)
func ApplyForwardRules(ctx context.Context, netns int, exitIf, overlayIf string, port int, target netip.Addr) error {
	if !target.Is4() || port < 1 || port > 65535 {
		return fmt.Errorf("nft: invalid forward target")
	}
	err := withConn(ctx, netns, func(c *nftables.Conn) error { return applyForwardRules(c, exitIf, overlayIf, port, target) })
	if err != nil {
		return fmt.Errorf("nft: apply the forward rules: %w", err)
	}
	return nil
}

func applyForwardRules(c *nftables.Conn, exitIf, overlayIf string, port int, target netip.Addr) error {
	t := replaceTable(c, nftables.TableFamilyIPv4, ForwardTable)
	accept := nftables.ChainPolicyAccept
	pre := c.AddChain(&nftables.Chain{Name: "prerouting", Table: t, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityNATDest, Policy: &accept})
	post := c.AddChain(&nftables.Chain{Name: "postrouting", Table: t, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource, Policy: &accept})

	set := &nftables.Set{Table: t, Anonymous: true, Constant: true, KeyType: nftables.TypeInetProto}
	if err := c.AddSet(set, []nftables.SetElement{{Key: []byte{unix.IPPROTO_TCP}}, {Key: []byte{unix.IPPROTO_UDP}}}); err != nil {
		return err
	}
	dport := make([]byte, 2)
	binary.BigEndian.PutUint16(dport, uint16(port))
	addr := target.As4()
	c.AddRule(&nftables.Rule{Table: t, Chain: pre, Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(exitIf)},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: dport},
		&expr.Immediate{Register: 1, Data: addr[:]},
		&expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: 1},
	}})
	// ct status & dnat != 0
	dnat := make([]byte, 4)
	binary.NativeEndian.PutUint32(dnat, 0x20) // IPS_DST_NAT
	c.AddRule(&nftables.Rule{Table: t, Chain: post, Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(overlayIf)},
		&expr.Ct{Key: expr.CtKeySTATUS, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: dnat, Xor: make([]byte, 4)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr[:]},
		&expr.Masq{},
	}})
	return c.Flush()
}

// RemoveForwardRules deletes the forwarding table whether or not it exists.
func RemoveForwardRules(ctx context.Context, netns int) error {
	err := withConn(ctx, netns, func(c *nftables.Conn) error {
		t := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: ForwardTable}
		c.AddTable(t) // so that deleting a missing table is not an error
		c.DelTable(t)
		return c.Flush()
	})
	if err != nil {
		return fmt.Errorf("nft: remove the forward rules: %w", err)
	}
	return nil
}
