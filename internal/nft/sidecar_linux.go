//go:build linux

package nft

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"reflect"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
)

// SidecarTable is the native sidecar's table, in family inet.
const SidecarTable = "molebridge_sidecar"

// SidecarBackstopTable independently enforces output if SidecarTable is lost.
const SidecarBackstopTable = "molebridge_sidecar_backstop"

const sidecarAttrTypeMask = ^uint16(unix.NLA_F_NESTED | unix.NLA_F_NET_BYTEORDER)

// SidecarFirewall describes the namespace's native sidecar firewall.
type SidecarFirewall struct {
	ExitIf        string
	TunnelMark    uint32
	ControlMark   uint32
	LAN4          []netip.Prefix
	LAN6          []netip.Prefix
	ForwardedPort uint16 // 0 admits no new connections from the tunnel
}

func (f SidecarFirewall) validate() error {
	if !contract.ValidInterfaceName(f.ExitIf) || f.ExitIf == "lo" {
		return fmt.Errorf("nft: invalid sidecar tunnel interface")
	}
	if f.TunnelMark == 0 || f.ControlMark == 0 || f.TunnelMark == f.ControlMark {
		return fmt.Errorf("nft: sidecar marks must be non-zero and different")
	}
	if len(f.LAN4)+len(f.LAN6) > 16 {
		return fmt.Errorf("nft: sidecar LAN prefixes exceed 16")
	}
	seen := make(map[netip.Prefix]bool)
	for i, prefixes := range [][]netip.Prefix{f.LAN4, f.LAN6} {
		for _, p := range prefixes {
			if !p.IsValid() || p.Bits() == 0 || p != p.Masked() || p.Addr().Is4In6() || p.Addr().Is4() != (i == 0) {
				return fmt.Errorf("nft: invalid sidecar LAN%d prefix", 4+2*i)
			}
			if seen[p] {
				return fmt.Errorf("nft: duplicate sidecar LAN prefix")
			}
			seen[p] = true
		}
	}
	// ForwardedPort is uint16: every representable value is valid, including 0.
	return nil
}

// InstallSidecar replaces both tables in one atomic batch and verifies the
// committed chains and rules. netns is a namespace fd, or 0 for the caller's.
func InstallSidecar(ctx context.Context, netns int, f SidecarFirewall) error {
	if err := f.validate(); err != nil {
		return err
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, MutationBudget)
		defer cancel()
	}
	err := withConn(ctx, netns, func(c *nftables.Conn) error {
		for _, name := range []string{SidecarTable, SidecarBackstopTable} {
			table, chains, rules := sidecarRules(f, name)
			replaceTable(c, table.Family, table.Name)
			for _, chain := range chains {
				c.AddChain(chain)
				for _, rule := range rules[chain.Name] {
					c.AddRule(rule)
				}
			}
		}
		return c.Flush()
	})
	if err == nil {
		var ok bool
		var reason string
		ok, reason, err = VerifySidecar(ctx, netns, f)
		if err == nil && !ok {
			err = fmt.Errorf("readback: %s", reason)
		}
	}
	if err != nil {
		return fmt.Errorf("nft: install the sidecar firewall: %w", err)
	}
	return nil
}

// VerifySidecar reports whether both live tables have exactly f's chains and
// rules, in order. Runtime counters and kernel-assigned handles may differ.
func VerifySidecar(ctx context.Context, netns int, f SidecarFirewall) (ok bool, reason string, err error) {
	if err = f.validate(); err != nil {
		return false, "", err
	}
	err = withSidecarReadConn(ctx, netns, func(c *nftables.Conn, raw *netlink.Conn) error {
		var err error
		ok, reason, err = verifySidecar(c, raw, f)
		return err
	})
	if err != nil {
		return false, "", fmt.Errorf("nft: verify the sidecar firewall: %w", err)
	}
	return ok, reason, nil
}

func sidecarRules(f SidecarFirewall, tableName string) (*nftables.Table, []*nftables.Chain, map[string][]*nftables.Rule) {
	table := &nftables.Table{Name: tableName, Family: nftables.TableFamilyINet}
	drop, accept := nftables.ChainPolicyDrop, nftables.ChainPolicyAccept
	chains := []*nftables.Chain{
		{Name: "output", Table: table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityFilter, Policy: &drop},
		{Name: "input", Table: table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter, Policy: &accept},
		{Name: "forward", Table: table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter, Policy: &drop},
	}
	rules := make(map[string][]*nftables.Rule)
	add := func(chain *nftables.Chain, es ...expr.Any) {
		rules[chain.Name] = append(rules[chain.Name], &nftables.Rule{Table: table, Chain: chain, Exprs: es})
	}
	out, in := chains[0], chains[1]
	for _, name := range []string{"lo", f.ExitIf} {
		add(out, append(sidecarInterface(expr.MetaKeyOIFNAME, name), &expr.Verdict{Kind: expr.VerdictAccept})...)
	}
	for _, mark := range []uint32{f.TunnelMark, f.ControlMark} {
		b := make([]byte, 4)
		binary.NativeEndian.PutUint32(b, mark)
		add(out, &expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: b}, &expr.Verdict{Kind: expr.VerdictAccept})
	}
	// One rule per prefix avoids anonymous interval set IDs and preserves the
	// input order when comparing kernel answers. Validation caps this at 16.
	for _, prefixes := range [][]netip.Prefix{f.LAN4, f.LAN6} {
		for _, p := range prefixes {
			add(out, sidecarPrefix(p)...)
		}
	}
	// Only the kernel's link maintenance messages bypass the LAN allowlist.
	// ICMPv6 datagram sockets cannot send these types; raw sockets require
	// CAP_NET_RAW. In particular, UDP multicast/link-local is not exempt.
	for _, typ := range []byte{133, 135, 136, 143} { // RS, NS, NA, MLDv2 report
		add(out, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMPV6}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{typ}}, &expr.Verdict{Kind: expr.VerdictAccept})
	}
	add(out, &expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop})
	// Both base chains must accept output. Keep their rules identical and
	// independent, so either table alone survives deletion of the other.
	if tableName == SidecarBackstopTable {
		return table, chains[:1], rules
	}

	es := sidecarInterface(expr.MetaKeyIIFNAME, f.ExitIf)
	mask := make([]byte, 4)
	binary.NativeEndian.PutUint32(mask, expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED)
	es = append(es, &expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask, Xor: make([]byte, 4)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)}, &expr.Verdict{Kind: expr.VerdictAccept})
	add(in, es...)
	if f.ForwardedPort != 0 {
		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, f.ForwardedPort)
		for _, proto := range []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
			es := sidecarInterface(expr.MetaKeyIIFNAME, f.ExitIf)
			es = append(es, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: port}, &expr.Verdict{Kind: expr.VerdictAccept})
			add(in, es...)
		}
	}
	add(in, append(sidecarInterface(expr.MetaKeyIIFNAME, f.ExitIf), &expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop})...)
	return table, chains, rules
}

func sidecarInterface(key expr.MetaKey, name string) []expr.Any {
	return []expr.Any{&expr.Meta{Key: key, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(name)}}
}

func sidecarPrefix(p netip.Prefix) []expr.Any {
	family, offset := byte(unix.NFPROTO_IPV6), uint32(24)
	if p.Addr().Is4() {
		family, offset = unix.NFPROTO_IPV4, 16
	}
	addr := p.Addr().AsSlice()
	mask := make([]byte, len(addr))
	for bit := 0; bit < p.Bits(); bit++ {
		mask[bit/8] |= 0x80 >> (bit % 8)
	}
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{family}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: uint32(len(addr))},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: uint32(len(addr)), Mask: mask, Xor: make([]byte, len(addr))},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr}, &expr.Verdict{Kind: expr.VerdictAccept},
	}
}

func verifySidecar(c *nftables.Conn, raw *netlink.Conn, f SidecarFirewall) (bool, string, error) {
	for _, name := range []string{SidecarTable, SidecarBackstopTable} {
		ok, reason, err := verifySidecarTable(c, raw, f, name)
		if err != nil {
			return false, "", fmt.Errorf("%s: %w", name, err)
		}
		if !ok {
			return false, reason, nil
		}
	}
	return true, "", nil
}

func verifySidecarTable(c *nftables.Conn, raw *netlink.Conn, f SidecarFirewall, name string) (bool, string, error) {
	table, wantChains, wantRules := sidecarRules(f, name)
	tables, err := c.ListTablesOfFamily(table.Family)
	if err != nil {
		return false, "", err
	}
	found := false
	for _, live := range tables {
		if live.Name == table.Name && live.Family == table.Family {
			found = true
			if live.Flags != 0 {
				return false, name + ": table flags differ", nil
			}
		}
	}
	if !found {
		return false, "no table inet " + name, nil
	}
	chains, err := c.ListChainsOfTableFamily(table.Family)
	if err != nil {
		return false, "", err
	}
	expectedChains := make(map[string]bool)
	for _, chain := range wantChains {
		expectedChains[chain.Name] = true
	}
	liveChains := make(map[string]*nftables.Chain)
	for _, chain := range chains {
		if chain.Table != nil && chain.Table.Name == table.Name && chain.Table.Family == table.Family {
			if !expectedChains[chain.Name] {
				return false, name + ": extra chain " + chain.Name, nil
			}
			liveChains[chain.Name] = chain
		}
	}
	for _, want := range wantChains {
		live := liveChains[want.Name]
		if live == nil {
			return false, name + ": no chain " + want.Name, nil
		}
		if reason := sidecarChainDifference(live, want); reason != "" {
			return false, name + ": chain " + want.Name + ": " + reason, nil
		}
		rules, err := sidecarReadRules(raw, table, live)
		if err != nil {
			return false, "", err
		}
		expected := wantRules[want.Name]
		for i := 0; i < len(rules) && i < len(expected); i++ {
			if !sidecarExpressionsEqual(rules[i], expected[i].Exprs) {
				return false, fmt.Sprintf("%s: chain %s: rule %d differs", name, want.Name, i+1), nil
			}
		}
		if len(rules) != len(expected) {
			return false, fmt.Sprintf("%s: chain %s: %d rules, want %d", name, want.Name, len(rules), len(expected)), nil
		}
	}
	return true, "", nil
}

func sidecarChainDifference(live, want *nftables.Chain) string {
	if !reflect.DeepEqual(live.Hooknum, want.Hooknum) {
		return "hook differs"
	}
	if !reflect.DeepEqual(live.Priority, want.Priority) {
		return "priority differs"
	}
	if !reflect.DeepEqual(live.Policy, want.Policy) {
		if live.Policy == nil {
			return "no policy"
		}
		if *live.Policy == nftables.ChainPolicyAccept {
			return "policy accept"
		}
		if *live.Policy == nftables.ChainPolicyDrop {
			return "policy drop"
		}
		return "policy differs"
	}
	if live.Type != want.Type {
		return "type differs"
	}
	if live.Device != want.Device {
		return "device differs"
	}
	return ""
}

// withSidecarReadConn uses the same owned socket, budget, cancellation and
// namespace handling as withConn. The raw socket is needed because the vendored
// GetRules silently discards expressions it does not recognize. Mutations still
// use withConn; this read connection also serves the library's table/chain dumps.
func withSidecarReadConn(ctx context.Context, netns int, fn func(*nftables.Conn, *netlink.Conn) error) error {
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
	var raw *netlink.Conn
	opts := []nftables.ConnOption{nftables.AsLasting(), nftables.WithSockOptions(func(c *netlink.Conn) error {
		raw = c
		return sock.option(c)
	})}
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
	return rtnl.RunBounded(ctx, rtnl.DefaultAbortGrace, sock.close, func() error { return fn(c, raw) })
}

// sidecarReadRules retains raw expression attributes, including unknown ones.
// Handles, transaction IDs and positions identify rules, rather than policy.
func sidecarReadRules(c *netlink.Conn, table *nftables.Table, chain *nftables.Chain) ([][]byte, error) {
	attrs, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_RULE_TABLE, Data: []byte(table.Name + "\x00")},
		{Type: unix.NFTA_RULE_CHAIN, Data: []byte(chain.Name + "\x00")},
	})
	if err != nil {
		return nil, err
	}
	messages, err := c.Execute(netlink.Message{
		Header: netlink.Header{Type: unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_GETRULE, Flags: netlink.Request | netlink.Dump},
		Data:   append([]byte{byte(table.Family), 0, 0, 0}, attrs...),
	})
	if err != nil {
		return nil, err
	}
	var rules [][]byte
	for _, m := range messages {
		if m.Header.Type != unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_NEWRULE || len(m.Data) < 4 || m.Data[0] != byte(table.Family) {
			return nil, fmt.Errorf("unexpected sidecar rule reply")
		}
		ad, err := netlink.NewAttributeDecoder(m.Data[4:])
		if err != nil {
			return nil, err
		}
		var expressions []byte
		changed := false
		var tableName, chainName string
		for ad.Next() {
			switch ad.Type() {
			case unix.NFTA_RULE_TABLE:
				tableName = ad.String()
			case unix.NFTA_RULE_CHAIN:
				chainName = ad.String()
			case unix.NFTA_RULE_EXPRESSIONS:
				expressions = ad.Bytes()
			case unix.NFTA_RULE_USERDATA:
				changed = len(ad.Bytes()) != 0
			}
		}
		if err := ad.Err(); err != nil {
			return nil, err
		}
		if tableName != table.Name || chainName != chain.Name {
			return nil, fmt.Errorf("unexpected sidecar rule location")
		}
		if changed {
			// A comment is still a change to the installed rule.
			expressions = nil
		}
		rules = append(rules, expressions)
	}
	return rules, nil
}

func sidecarExpressionsEqual(live []byte, want []expr.Any) bool {
	attrs, err := netlink.UnmarshalAttributes(live)
	if err != nil || len(attrs) != len(want) {
		return false
	}
	for i, e := range want {
		if attrs[i].Type&sidecarAttrTypeMask != unix.NFTA_LIST_ELEM {
			return false
		}
		encoded, err := expr.Marshal(unix.NFPROTO_INET, e)
		if err != nil {
			return false
		}
		got, err := netlink.UnmarshalAttributes(attrs[i].Data)
		if err != nil || len(got) != 2 {
			return false
		}
		for j := range got {
			if got[j].Type&sidecarAttrTypeMask != unix.NFTA_EXPR_DATA {
				continue
			}
			data, err := netlink.UnmarshalAttributes(got[j].Data)
			if err != nil {
				return false
			}
			if _, ok := e.(*expr.Counter); ok {
				var normalized []netlink.Attribute
				for _, a := range data {
					key := a.Type & sidecarAttrTypeMask
					// Some architectures pad 64-bit counters for alignment.
					if key == unix.NFTA_COUNTER_PAD && len(a.Data) == 0 {
						continue
					}
					if len(a.Data) != 8 || (key != unix.NFTA_COUNTER_BYTES && key != unix.NFTA_COUNTER_PACKETS) {
						return false
					}
					a.Data = make([]byte, 8)
					normalized = append(normalized, a)
				}
				data = normalized
			}
			if _, ok := e.(*expr.Bitwise); ok {
				// Newer kernels dump an explicit boolean operation (attribute 6)
				// although the older vendored encoder leaves it implicit.
				for k := 0; k < len(data); k++ {
					if data[k].Type&sidecarAttrTypeMask == 6 && bytes.Equal(data[k].Data, []byte{0, 0, 0, 0}) {
						data = append(data[:k:k], data[k+1:]...)
						break
					}
				}
			}
			got[j].Length = 0 // normalization may change the nested attribute length
			got[j].Data, err = netlink.MarshalAttributes(data)
			if err != nil {
				return false
			}
		}
		actual, err := netlink.MarshalAttributes(got)
		if err != nil || !sidecarAttributesEqual(actual, encoded) {
			return false
		}
	}
	return true
}

// Attribute order and NLA_F_NESTED flags vary between kernel and encoder;
// nested data is compared as a tree, while expression order stays significant.
// Unknown and duplicate attributes fail the comparison rather than disappearing.
func sidecarAttributesEqual(live, want []byte) bool {
	got, err := netlink.UnmarshalAttributes(live)
	if err != nil {
		return false
	}
	expected, err := netlink.UnmarshalAttributes(want)
	if err != nil || len(got) != len(expected) {
		return false
	}
	byType := make(map[uint16]netlink.Attribute, len(got))
	for _, a := range got {
		key := a.Type & sidecarAttrTypeMask
		if _, exists := byType[key]; exists {
			return false
		}
		byType[key] = a
	}
	for _, a := range expected {
		b, exists := byType[a.Type&sidecarAttrTypeMask]
		if !exists {
			return false
		}
		if a.Type&unix.NLA_F_NESTED != 0 {
			if !sidecarAttributesEqual(b.Data, a.Data) {
				return false
			}
		} else if !bytes.Equal(b.Data, a.Data) {
			return false
		}
	}
	return true
}
