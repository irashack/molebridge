//go:build linux

package nft

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// The tables the exit's pipeline owns (applier/pia.py NFT_TABLE, GUARD_TABLE).
const (
	ForwardTable = "molebridge_forward"
	GuardTable   = "molebridge_guard"
)

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
func InstallIngressGuard(exitIf, overlayIf string) error {
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nft: open netlink: %w", err)
	}
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
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nft: install the ingress guard: %w", err)
	}
	return nil
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
func ApplyForwardRules(exitIf, overlayIf string, port int, target netip.Addr) error {
	if !target.Is4() || port < 1 || port > 65535 {
		return fmt.Errorf("nft: invalid forward target")
	}
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nft: open netlink: %w", err)
	}
	t := replaceTable(c, nftables.TableFamilyIPv4, ForwardTable)
	accept := nftables.ChainPolicyAccept
	pre := c.AddChain(&nftables.Chain{Name: "prerouting", Table: t, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityNATDest, Policy: &accept})
	post := c.AddChain(&nftables.Chain{Name: "postrouting", Table: t, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource, Policy: &accept})

	set := &nftables.Set{Table: t, Anonymous: true, Constant: true, KeyType: nftables.TypeInetProto}
	if err := c.AddSet(set, []nftables.SetElement{{Key: []byte{unix.IPPROTO_TCP}}, {Key: []byte{unix.IPPROTO_UDP}}}); err != nil {
		return fmt.Errorf("nft: build the forward rules: %w", err)
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
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nft: apply the forward rules: %w", err)
	}
	return nil
}

// RemoveForwardRules deletes the forwarding table whether or not it exists.
func RemoveForwardRules() error {
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nft: open netlink: %w", err)
	}
	t := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: ForwardTable}
	c.AddTable(t) // so that deleting a missing table is not an error
	c.DelTable(t)
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nft: remove the forward rules: %w", err)
	}
	return nil
}

