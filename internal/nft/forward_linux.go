//go:build linux

package nft

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"

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

// withConn opens a lasting nftables connection for one change and runs fn on
// it. Every socket the connection opens carries the context's absolute
// deadline from the start (WithSockOptions), the whole change also runs under
// rtnl.RunBounded, which closes the connection at the deadline (a kernel that
// never answers cannot hold the caller), and the connection is never reused:
// it is closed when fn returns, and one delivered after the caller gave up on
// it is closed by the goroutine that opened it. netns is a file descriptor of
// a network namespace, 0 for the caller's.
func withConn(ctx context.Context, netns int, fn func(*nftables.Conn) error) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("nft: %w", rtnl.ErrDeadline)
	}
	opts := []nftables.ConnOption{nftables.AsLasting()}
	if dl, ok := ctx.Deadline(); ok {
		opts = append(opts, nftables.WithSockOptions(func(c *netlink.Conn) error { return c.SetDeadline(dl) }))
	}
	if netns != 0 {
		opts = append(opts, nftables.WithNetNSFd(netns))
	}
	var (
		mu        sync.Mutex
		c         *nftables.Conn
		abandoned bool
	)
	err := rtnl.RunBounded(ctx, rtnl.DefaultAbortGrace, func() {
		mu.Lock()
		abandoned = true
		cc := c
		mu.Unlock()
		if cc != nil {
			_ = cc.CloseLasting()
		}
	}, func() error {
		opened, err := nftables.New(opts...)
		if err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		if abandoned {
			_ = opened.CloseLasting()
			return rtnl.ErrDeadline
		}
		c = opened
		return nil
	})
	if err != nil {
		return fmt.Errorf("nft: open netlink: %w", err)
	}
	defer c.CloseLasting()
	return rtnl.RunBounded(ctx, rtnl.DefaultAbortGrace, func() { _ = c.CloseLasting() }, func() error { return fn(c) })
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

// InstallIngressGuard installs the forward-path guard: forwarded tunnel
// ingress may leave only over the overlay.
//
//	table inet molebridge_guard {
//	  chain forward {
//	    type filter hook forward priority filter; policy accept;
//	    iifname "<exit>" oifname != "<overlay>" drop
//	  }
//	}
//
// An earlier table of that name is replaced atomically. Nothing removes it.
func InstallIngressGuard(ctx context.Context, netns int, exitIf, overlayIf string) error {
	err := withConn(ctx, netns, func(c *nftables.Conn) error { return installIngressGuard(c, exitIf, overlayIf) })
	if err != nil {
		return fmt.Errorf("nft: install the ingress guard: %w", err)
	}
	return nil
}

func installIngressGuard(c *nftables.Conn, exitIf, overlayIf string) error {
	t := replaceTable(c, nftables.TableFamilyINet, GuardTable)
	policy := nftables.ChainPolicyAccept
	chain := c.AddChain(&nftables.Chain{Name: "forward", Table: t, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter, Policy: &policy})
	c.AddRule(&nftables.Rule{Table: t, Chain: chain, Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(exitIf)},
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: ifname(overlayIf)},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}})
	return c.Flush()
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
