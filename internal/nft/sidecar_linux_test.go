//go:build linux

package nft

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

func sidecarFixture() SidecarFirewall {
	return SidecarFirewall{ExitIf: "tun0", TunnelMark: 51821, ControlMark: 0x1bd00}
}

func TestSidecarRuleEncoding(t *testing.T) {
	for _, lan := range []bool{false, true} {
		for _, port := range []uint16{0, 1, 41234, 65535} {
			t.Run(fmt.Sprintf("lan=%t/port=%d", lan, port), func(t *testing.T) {
				f := sidecarFixture()
				f.ForwardedPort = port
				if lan {
					f.LAN4 = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.128/25")}
					f.LAN6 = []netip.Prefix{netip.MustParsePrefix("2001:db8::/33")}
				}
				table, chains, rules := sidecarRules(f, SidecarTable)
				if table.Name != SidecarTable || table.Family != nftables.TableFamilyINet || len(chains) != 3 {
					t.Fatalf("table %+v, chains %+v", table, chains)
				}
				for i, hook := range []*nftables.ChainHook{nftables.ChainHookOutput, nftables.ChainHookInput, nftables.ChainHookForward} {
					policy := nftables.ChainPolicyDrop
					if i == 1 {
						policy = nftables.ChainPolicyAccept
					}
					ch := chains[i]
					if *ch.Hooknum != *hook || *ch.Priority != 0 || *ch.Policy != policy || ch.Type != nftables.ChainTypeFilter {
						t.Fatalf("chain %+v", ch)
					}
				}
				accept := &expr.Verdict{Kind: expr.VerdictAccept}
				iface := func(key expr.MetaKey, name string) []expr.Any {
					b := make([]byte, 16)
					copy(b, name)
					return []expr.Any{&expr.Meta{Key: key, Register: 1}, &expr.Cmp{Register: 1, Data: b}}
				}
				wantOut := [][]expr.Any{append(iface(expr.MetaKeyOIFNAME, "lo"), accept), append(iface(expr.MetaKeyOIFNAME, "tun0"), accept)}
				for _, mark := range []uint32{51821, 0x1bd00} {
					data := make([]byte, 4)
					binary.NativeEndian.PutUint32(data, mark)
					wantOut = append(wantOut, []expr.Any{&expr.Meta{Key: expr.MetaKeyMARK, Register: 1}, &expr.Cmp{Register: 1, Data: data}, accept})
				}
				// Literal offsets and masks make these independent of the encoder.
				prefix := func(family byte, offset uint32, addr, mask []byte) []expr.Any {
					return []expr.Any{&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, &expr.Cmp{Register: 1, Data: []byte{family}},
						&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: uint32(len(addr))},
						&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: uint32(len(addr)), Mask: mask, Xor: make([]byte, len(addr))},
						&expr.Cmp{Register: 1, Data: addr}, accept}
				}
				if lan {
					wantOut = append(wantOut,
						prefix(unix.NFPROTO_IPV4, 16, []byte{192, 0, 2, 0}, []byte{255, 255, 255, 0}),
						prefix(unix.NFPROTO_IPV4, 16, []byte{198, 51, 100, 128}, []byte{255, 255, 255, 128}),
						prefix(unix.NFPROTO_IPV6, 24, []byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, []byte{255, 255, 255, 255, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}))
				}
				for _, typ := range []byte{133, 135, 136, 143} {
					wantOut = append(wantOut, []expr.Any{
						&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
						&expr.Cmp{Register: 1, Data: []byte{58}},
						&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
						&expr.Cmp{Register: 1, Data: []byte{typ}}, accept})
				}
				wantOut = append(wantOut, []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}})
				mask := make([]byte, 4)
				binary.NativeEndian.PutUint32(mask, 6)
				wantIn := [][]expr.Any{append(iface(expr.MetaKeyIIFNAME, "tun0"), &expr.Ct{Key: expr.CtKeySTATE, Register: 1},
					&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask, Xor: make([]byte, 4)},
					&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)}, accept)}
				if port != 0 {
					for _, proto := range []byte{6, 17} {
						wantIn = append(wantIn, append(iface(expr.MetaKeyIIFNAME, "tun0"), &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
							&expr.Cmp{Register: 1, Data: []byte{proto}}, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
							&expr.Cmp{Register: 1, Data: []byte{byte(port >> 8), byte(port)}}, accept))
					}
				}
				wantIn = append(wantIn, append(iface(expr.MetaKeyIIFNAME, "tun0"), &expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}))
				backstop, backChains, backRules := sidecarRules(f, SidecarBackstopTable)
				if backstop.Name != SidecarBackstopTable || backstop.Family != table.Family || len(backChains) != 1 || len(backRules) != 1 {
					t.Fatalf("backstop: %+v, chains %+v, rules %+v", backstop, backChains, backRules)
				}
				wantChain := *chains[0]
				wantChain.Table = backstop
				if !reflect.DeepEqual(backChains[0], &wantChain) || len(backRules["output"]) != len(wantOut) {
					t.Fatal("backstop output chain differs")
				}
				for i, rule := range backRules["output"] {
					if rule.Table != backstop || rule.Chain != backChains[0] || !reflect.DeepEqual(rule.Exprs, wantOut[i]) {
						t.Errorf("backstop output rule %d differs", i+1)
					}
				}
				for name, want := range map[string][][]expr.Any{"output": wantOut, "input": wantIn, "forward": nil} {
					got := rules[name]
					if len(got) != len(want) {
						t.Fatalf("%s: %d rules, want %d", name, len(got), len(want))
					}
					for i := range got {
						if !reflect.DeepEqual(got[i].Exprs, want[i]) {
							t.Errorf("%s rule %d: got %#v, want %#v", name, i+1, got[i].Exprs, want[i])
						}
					}
				}
			})
		}
	}
}

func TestSidecarValidationBeforeOpeningASocket(t *testing.T) {
	cases := []struct {
		name string
		edit func(*SidecarFirewall)
		want string
	}{
		{"empty interface", func(f *SidecarFirewall) { f.ExitIf = "" }, "nft: invalid sidecar tunnel interface"},
		{"long interface", func(f *SidecarFirewall) { f.ExitIf = "abcdefghijklmnop" }, "nft: invalid sidecar tunnel interface"},
		{"bad interface", func(f *SidecarFirewall) { f.ExitIf = "a/b" }, "nft: invalid sidecar tunnel interface"},
		{"loopback", func(f *SidecarFirewall) { f.ExitIf = "lo" }, "nft: invalid sidecar tunnel interface"},
		{"zero tunnel mark", func(f *SidecarFirewall) { f.TunnelMark = 0 }, "nft: sidecar marks must be non-zero and different"},
		{"zero control mark", func(f *SidecarFirewall) { f.ControlMark = 0 }, "nft: sidecar marks must be non-zero and different"},
		{"same marks", func(f *SidecarFirewall) { f.ControlMark = f.TunnelMark }, "nft: sidecar marks must be non-zero and different"},
		{"too many", func(f *SidecarFirewall) { f.LAN4 = make([]netip.Prefix, 17) }, "nft: sidecar LAN prefixes exceed 16"},
		{"invalid prefix", func(f *SidecarFirewall) { f.LAN4 = []netip.Prefix{{}} }, "nft: invalid sidecar LAN4 prefix"},
		{"host bits", func(f *SidecarFirewall) { f.LAN4 = []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")} }, "nft: invalid sidecar LAN4 prefix"},
		{"default", func(f *SidecarFirewall) { f.LAN4 = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")} }, "nft: invalid sidecar LAN4 prefix"},
		{"wrong family", func(f *SidecarFirewall) { f.LAN6 = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")} }, "nft: invalid sidecar LAN6 prefix"},
		{"mapped", func(f *SidecarFirewall) { f.LAN6 = []netip.Prefix{netip.MustParsePrefix("::ffff:192.0.2.0/120")} }, "nft: invalid sidecar LAN6 prefix"},
		{"duplicate", func(f *SidecarFirewall) {
			p := netip.MustParsePrefix("2001:db8::/32")
			f.LAN6 = []netip.Prefix{p, p}
		}, "nft: duplicate sidecar LAN prefix"},
	}
	extraConnOptions = func() []nftables.ConnOption { t.Error("opened a socket for invalid input"); return nil }
	t.Cleanup(func() { extraConnOptions = nil })
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := sidecarFixture()
			tc.edit(&f)
			if err := InstallSidecar(t.Context(), 0, f); err == nil || err.Error() != tc.want {
				t.Errorf("install: %v, want %q", err, tc.want)
			}
			if ok, reason, err := VerifySidecar(t.Context(), 0, f); ok || reason != "" || err == nil || err.Error() != tc.want {
				t.Errorf("verify: %t %q %v", ok, reason, err)
			}
		})
	}
	f := sidecarFixture()
	for i := 0; i < 8; i++ {
		f.LAN4 = append(f.LAN4, netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), 32))
		f.LAN6 = append(f.LAN6, netip.PrefixFrom(netip.AddrFrom16([16]byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i)}), 128))
	}
	if err := f.validate(); err != nil {
		t.Fatalf("16 mixed prefixes: %v", err)
	}
	f.LAN6 = append(f.LAN6, netip.MustParsePrefix("2001:db8:1::/48"))
	if err := f.validate(); err == nil {
		t.Fatal("17 mixed prefixes accepted")
	}
}

// Synthetic answers go through the library's real chain/rule decoders, not
// just a comparison of the encoder's objects with themselves.
type sidecarKernelTable struct {
	table  *nftables.Table
	chains []*nftables.Chain
	rules  map[string][]*nftables.Rule
}

type sidecarKernel struct {
	*sidecarKernelTable
	backstop *sidecarKernelTable
	batches  int
	batch    []netlink.Message
	fail     uint16
	wireEdit func([]byte) []byte
}

func newSidecarKernel(f SidecarFirewall) *sidecarKernel {
	table, chains, rules := sidecarRules(f, SidecarTable)
	backstop, backChains, backRules := sidecarRules(f, SidecarBackstopTable)
	return &sidecarKernel{
		sidecarKernelTable: &sidecarKernelTable{table: table, chains: chains, rules: rules},
		backstop:           &sidecarKernelTable{table: backstop, chains: backChains, rules: backRules},
	}
}

func sidecarAttrs(attrs ...netlink.Attribute) []byte {
	for i := range attrs {
		attrs[i].Length = 0
	}
	return nltest.MustMarshalAttributes(attrs)
}
func sidecarBE(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }
func sidecarString(typ uint16, value string) netlink.Attribute {
	return netlink.Attribute{Type: typ, Data: []byte(value + "\x00")}
}
func sidecarMessage(kind uint16, attrs []byte) netlink.Message {
	return netlink.Message{Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | kind)}, Data: append([]byte{unix.NFPROTO_INET, 0, 0, 0}, attrs...)}
}

func (k *sidecarKernel) dial(req []netlink.Message) ([]netlink.Message, error) {
	if len(req) == 0 {
		return nil, io.EOF
	}
	if req[0].Header.Type == unix.NFNL_MSG_BATCH_BEGIN {
		k.batches++
		k.batch = req
		var ack []netlink.Message
		for _, m := range req {
			if m.Header.Flags&netlink.Acknowledge != 0 {
				ack = append(ack, netlink.Message{Header: netlink.Header{Type: netlink.Error}, Data: make([]byte, 4)})
			}
		}
		return ack, nil
	}
	kind := uint16(req[0].Header.Type) & 0xff
	if k.fail == kind {
		return nil, errors.New("synthetic read failure")
	}
	var reply []netlink.Message
	switch kind {
	case unix.NFT_MSG_GETTABLE:
		for _, state := range []*sidecarKernelTable{k.sidecarKernelTable, k.backstop} {
			if state.table != nil {
				reply = append(reply, sidecarMessage(unix.NFT_MSG_NEWTABLE, sidecarAttrs(sidecarString(unix.NFTA_TABLE_NAME, state.table.Name), netlink.Attribute{Type: unix.NFTA_TABLE_FLAGS, Data: sidecarBE(state.table.Flags)})))
			}
		}
	case unix.NFT_MSG_GETCHAIN:
		for _, ch := range append(append([]*nftables.Chain{}, k.chains...), k.backstop.chains...) {
			attrs := []netlink.Attribute{sidecarString(unix.NFTA_CHAIN_TABLE, ch.Table.Name), sidecarString(unix.NFTA_CHAIN_NAME, ch.Name), sidecarString(unix.NFTA_CHAIN_TYPE, string(ch.Type))}
			if ch.Hooknum != nil && ch.Priority != nil {
				attrs = append(attrs, netlink.Attribute{Type: unix.NFTA_CHAIN_HOOK | unix.NLA_F_NESTED, Data: sidecarAttrs(
					netlink.Attribute{Type: unix.NFTA_HOOK_HOOKNUM, Data: sidecarBE(uint32(*ch.Hooknum))}, netlink.Attribute{Type: unix.NFTA_HOOK_PRIORITY, Data: sidecarBE(uint32(*ch.Priority))})})
			}
			if ch.Policy != nil {
				attrs = append(attrs, netlink.Attribute{Type: unix.NFTA_CHAIN_POLICY, Data: sidecarBE(uint32(*ch.Policy))})
			}
			reply = append(reply, sidecarMessage(unix.NFT_MSG_NEWCHAIN, sidecarAttrs(attrs...)))
		}
	case unix.NFT_MSG_GETRULE:
		ad, err := netlink.NewAttributeDecoder(req[0].Data[4:])
		if err != nil {
			return nil, err
		}
		var name, tableName string
		for ad.Next() {
			switch ad.Type() {
			case unix.NFTA_RULE_CHAIN:
				name = ad.String()
			case unix.NFTA_RULE_TABLE:
				tableName = ad.String()
			}
		}
		state := k.sidecarKernelTable
		if tableName == SidecarBackstopTable {
			state = k.backstop
		} else if tableName != SidecarTable {
			return nil, fmt.Errorf("unexpected table %q", tableName)
		}
		for _, r := range state.rules[name] {
			var es []netlink.Attribute
			for _, e := range r.Exprs {
				b, err := expr.Marshal(unix.NFPROTO_INET, e)
				if err != nil {
					return nil, err
				}
				es = append(es, netlink.Attribute{Type: unix.NFTA_LIST_ELEM | unix.NLA_F_NESTED, Data: b})
			}
			encodedExprs := sidecarAttrs(es...)
			if k.wireEdit != nil {
				encodedExprs = k.wireEdit(encodedExprs)
			}
			attrs := []netlink.Attribute{sidecarString(unix.NFTA_RULE_TABLE, tableName), sidecarString(unix.NFTA_RULE_CHAIN, name),
				{Type: unix.NFTA_RULE_EXPRESSIONS | unix.NLA_F_NESTED, Data: encodedExprs}, {Type: unix.NFTA_RULE_USERDATA, Data: r.UserData},
				{Type: unix.NFTA_RULE_HANDLE, Data: []byte{0, 0, 0, 0, 0, 0, 0, 42}}}
			reply = append(reply, sidecarMessage(unix.NFT_MSG_NEWRULE, sidecarAttrs(attrs...)))
		}
	default:
		return nil, fmt.Errorf("unexpected request %d", kind)
	}
	if len(reply) == 0 {
		return nil, io.EOF
	}
	for i := range reply {
		reply[i].Header.Sequence = req[0].Header.Sequence
		reply[i].Header.PID = req[0].Header.PID
	}
	reply = append(reply, netlink.Message{Header: netlink.Header{Type: netlink.Done, Sequence: req[0].Header.Sequence, PID: req[0].Header.PID}})
	return nltest.Multipart(reply)
}

func fakeSidecar(t *testing.T, k *sidecarKernel) {
	t.Helper()
	extraConnOptions = func() []nftables.ConnOption { return []nftables.ConnOption{nftables.WithTestDial(k.dial)} }
	setSocketDeadline = func(*netlink.Conn, time.Time) error { return nil }
	t.Cleanup(func() {
		extraConnOptions = nil
		setSocketDeadline = func(c *netlink.Conn, dl time.Time) error { return c.SetDeadline(dl) }
	})
}

func TestVerifySidecarKernelAnswers(t *testing.T) {
	cases := []struct {
		name   string
		edit   func(*sidecarKernel)
		reason string
	}{
		{"correct", func(*sidecarKernel) {}, ""},
		{"counters", func(k *sidecarKernel) {
			k.rules["output"][9].Exprs[0] = &expr.Counter{Packets: 12, Bytes: 345}
			k.rules["input"][3].Exprs[2] = &expr.Counter{Packets: 56, Bytes: 789}
		}, ""},
		{"missing table", func(k *sidecarKernel) { k.table = nil }, "no table inet molebridge_sidecar"},
		{"dormant table", func(k *sidecarKernel) { k.table.Flags = unix.NFT_TABLE_F_DORMANT }, "table flags differ"},
		{"missing chain", func(k *sidecarKernel) { k.chains = k.chains[1:] }, "no chain output"},
		{"extra chain", func(k *sidecarKernel) { k.chains = append(k.chains, &nftables.Chain{Table: k.table, Name: "extra"}) }, "extra chain extra"},
		{"other table ignored", func(k *sidecarKernel) {
			k.chains = append(k.chains, &nftables.Chain{Table: &nftables.Table{Name: "unrelated"}, Name: "extra"})
		}, ""},
		{"output policy", func(k *sidecarKernel) { p := nftables.ChainPolicyAccept; k.chains[0].Policy = &p }, "chain output: policy accept"},
		{"input policy", func(k *sidecarKernel) { p := nftables.ChainPolicyDrop; k.chains[1].Policy = &p }, "chain input: policy drop"},
		{"no policy", func(k *sidecarKernel) { k.chains[0].Policy = nil }, "chain output: no policy"},
		{"hook", func(k *sidecarKernel) { k.chains[0].Hooknum = nftables.ChainHookInput }, "chain output: hook differs"},
		{"priority", func(k *sidecarKernel) { k.chains[0].Priority = nftables.ChainPriorityRaw }, "chain output: priority differs"},
		{"type", func(k *sidecarKernel) { k.chains[0].Type = nftables.ChainTypeRoute }, "chain output: type differs"},
		{"rule order", func(k *sidecarKernel) {
			k.rules["output"][0], k.rules["output"][1] = k.rules["output"][1], k.rules["output"][0]
		}, "chain output: rule 1 differs"},
		{"expression order", func(k *sidecarKernel) { es := k.rules["output"][2].Exprs; es[0], es[1] = es[1], es[0] }, "chain output: rule 3 differs"},
		{"expression missing", func(k *sidecarKernel) { r := k.rules["output"][2]; r.Exprs = r.Exprs[:2] }, "chain output: rule 3 differs"},
		{"expression extra", func(k *sidecarKernel) { r := k.rules["output"][2]; r.Exprs = append(r.Exprs, &expr.Counter{}) }, "chain output: rule 3 differs"},
		{"mark", func(k *sidecarKernel) { k.rules["output"][2].Exprs[1].(*expr.Cmp).Data[0] ^= 1 }, "chain output: rule 3 differs"},
		{"verdict", func(k *sidecarKernel) { k.rules["output"][2].Exprs[2] = &expr.Verdict{Kind: expr.VerdictDrop} }, "chain output: rule 3 differs"},
		{"comment", func(k *sidecarKernel) { k.rules["output"][2].UserData = []byte("changed") }, "chain output: rule 3 differs"},
		{"missing rule", func(k *sidecarKernel) { k.rules["output"] = k.rules["output"][:7] }, "chain output: 7 rules, want 10"},
		{"extra rule", func(k *sidecarKernel) {
			k.rules["forward"] = []*nftables.Rule{{Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}}}
		}, "chain forward: 1 rules, want 0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := sidecarFixture()
			f.ForwardedPort = 41234
			f.LAN4 = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
			k := newSidecarKernel(f)
			tc.edit(k)
			fakeSidecar(t, k)
			ok, reason, err := VerifySidecar(t.Context(), 0, f)
			want := tc.reason
			if want != "" && !strings.HasPrefix(want, "no table ") {
				want = SidecarTable + ": " + want
			}
			if err != nil || ok != (want == "") || reason != want {
				t.Fatalf("got %t %q %v, want reason %q", ok, reason, err, want)
			}
		})
	}
}

// Mutate one table at a time while the other remains correct. The backstop
// must be checked just as strictly as the main output chain.
func TestVerifySidecarEachTableIndependently(t *testing.T) {
	cases := []struct {
		name   string
		edit   func(*sidecarKernelTable)
		reason string
	}{
		{"missing table", func(k *sidecarKernelTable) { k.table = nil }, "missing"},
		{"flags", func(k *sidecarKernelTable) { k.table.Flags = unix.NFT_TABLE_F_DORMANT }, "table flags differ"},
		{"missing output", func(k *sidecarKernelTable) { k.chains = k.chains[1:] }, "no chain output"},
		{"extra chain", func(k *sidecarKernelTable) {
			k.chains = append(k.chains, &nftables.Chain{Table: k.table, Name: "extra"})
		}, "extra chain extra"},
		{"policy", func(k *sidecarKernelTable) { p := nftables.ChainPolicyAccept; k.chains[0].Policy = &p }, "chain output: policy accept"},
		{"no policy", func(k *sidecarKernelTable) { k.chains[0].Policy = nil }, "chain output: no policy"},
		{"hook", func(k *sidecarKernelTable) { k.chains[0].Hooknum = nftables.ChainHookInput }, "chain output: hook differs"},
		{"priority", func(k *sidecarKernelTable) { k.chains[0].Priority = nftables.ChainPriorityRaw }, "chain output: priority differs"},
		{"type", func(k *sidecarKernelTable) { k.chains[0].Type = nftables.ChainTypeRoute }, "chain output: type differs"},
		{"rule order", func(k *sidecarKernelTable) {
			k.rules["output"][0], k.rules["output"][1] = k.rules["output"][1], k.rules["output"][0]
		}, "chain output: rule 1 differs"},
		{"mark", func(k *sidecarKernelTable) { k.rules["output"][2].Exprs[1].(*expr.Cmp).Data[0] ^= 1 }, "chain output: rule 3 differs"},
		{"ICMPv6 protocol", func(k *sidecarKernelTable) { k.rules["output"][4].Exprs[1].(*expr.Cmp).Data[0] = unix.IPPROTO_UDP }, "chain output: rule 5 differs"},
		{"ICMPv6 type", func(k *sidecarKernelTable) { k.rules["output"][4].Exprs[3].(*expr.Cmp).Data[0] = 128 }, "chain output: rule 5 differs"},
		{"comment", func(k *sidecarKernelTable) { k.rules["output"][2].UserData = []byte("changed") }, "chain output: rule 3 differs"},
		{"missing final drop", func(k *sidecarKernelTable) { k.rules["output"] = k.rules["output"][:8] }, "chain output: 8 rules, want 9"},
		{"extra rule", func(k *sidecarKernelTable) {
			k.rules["output"] = append(k.rules["output"], &nftables.Rule{Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}})
		}, "chain output: 10 rules, want 9"},
		{"runtime counters", func(k *sidecarKernelTable) { k.rules["output"][8].Exprs[0] = &expr.Counter{Packets: 42, Bytes: 1234} }, ""},
	}
	for _, name := range []string{SidecarTable, SidecarBackstopTable} {
		for _, tc := range cases {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				f := sidecarFixture()
				k := newSidecarKernel(f)
				state := k.sidecarKernelTable
				if name == SidecarBackstopTable {
					state = k.backstop
				}
				tc.edit(state)
				fakeSidecar(t, k)
				want := tc.reason
				if want == "missing" {
					want = "no table inet " + name
				} else if want != "" {
					want = name + ": " + want
				}
				ok, reason, err := VerifySidecar(t.Context(), 0, f)
				if err != nil || ok != (want == "") || reason != want {
					t.Fatalf("got %t %q %v, want reason %q", ok, reason, err, want)
				}
			})
		}
	}
	t.Run("backstop has no input", func(t *testing.T) {
		f := sidecarFixture()
		k := newSidecarKernel(f)
		k.backstop.chains = append(k.backstop.chains, &nftables.Chain{Table: k.backstop.table, Name: "input"})
		fakeSidecar(t, k)
		ok, reason, err := VerifySidecar(t.Context(), 0, f)
		if err != nil || ok || reason != "molebridge_sidecar_backstop: extra chain input" {
			t.Fatalf("got %t %q %v", ok, reason, err)
		}
	})
}

func TestInstallSidecarIsOneBatchAndReadsBack(t *testing.T) {
	f := sidecarFixture()
	k := newSidecarKernel(f)
	fakeSidecar(t, k)
	if err := InstallSidecar(t.Context(), 0, f); err != nil {
		t.Fatal(err)
	}
	if k.batches != 1 {
		t.Fatalf("%d batches", k.batches)
	}
	batch := k.batch
	if batch[0].Header.Type != unix.NFNL_MSG_BATCH_BEGIN || batch[len(batch)-1].Header.Type != unix.NFNL_MSG_BATCH_END {
		t.Fatal("missing batch boundary")
	}
	tableOps := make(map[string][]uint16)
	chainNames := make(map[string][]string)
	ruleCounts := make(map[string]int)
	for _, msg := range batch[1 : len(batch)-1] {
		kind := uint16(msg.Header.Type) & 0xff
		attrs, err := netlink.UnmarshalAttributes(msg.Data[4:])
		if err != nil {
			t.Fatal(err)
		}
		values := make(map[uint16][]byte)
		for _, a := range attrs {
			values[a.Type&sidecarAttrTypeMask] = a.Data
		}
		str := func(key uint16) string { return strings.TrimRight(string(values[key]), "\x00") }
		switch kind {
		case unix.NFT_MSG_NEWTABLE, unix.NFT_MSG_DELTABLE:
			name := str(unix.NFTA_TABLE_NAME)
			tableOps[name] = append(tableOps[name], kind)
		case unix.NFT_MSG_NEWCHAIN:
			name := str(unix.NFTA_CHAIN_TABLE)
			chainNames[name] = append(chainNames[name], str(unix.NFTA_CHAIN_NAME))
		case unix.NFT_MSG_NEWRULE:
			name, chain := str(unix.NFTA_RULE_TABLE), str(unix.NFTA_RULE_CHAIN)
			if name == SidecarBackstopTable && chain != "output" {
				t.Fatalf("backstop contains chain %s", chain)
			}
			_, _, expected := sidecarRules(f, name)
			if name == SidecarBackstopTable && !sidecarExpressionsEqual(values[unix.NFTA_RULE_EXPRESSIONS], expected["output"][ruleCounts[name]].Exprs) {
				t.Fatal("backstop batch rule differs")
			}
			ruleCounts[name]++
		default:
			t.Fatalf("unexpected batch operation %d", kind)
		}
	}
	for _, name := range []string{SidecarTable, SidecarBackstopTable} {
		if !reflect.DeepEqual(tableOps[name], []uint16{unix.NFT_MSG_NEWTABLE, unix.NFT_MSG_DELTABLE, unix.NFT_MSG_NEWTABLE}) {
			t.Fatalf("%s replacement operations: %v", name, tableOps[name])
		}
		_, chains, rules := sidecarRules(f, name)
		var names []string
		count := 0
		for _, chain := range chains {
			names = append(names, chain.Name)
			count += len(rules[chain.Name])
		}
		if !reflect.DeepEqual(chainNames[name], names) || ruleCounts[name] != count {
			t.Fatalf("%s: chains %v, rules %d; want %v, %d", name, chainNames[name], ruleCounts[name], names, count)
		}
	}
	if len(tableOps) != 2 || len(chainNames) != 2 || len(ruleCounts) != 2 {
		t.Fatal("batch contains unexpected tables")
	}
	// Acknowledging the batch alone is insufficient: both readbacks must match.
	for _, name := range []string{SidecarTable, SidecarBackstopTable} {
		t.Run("missing "+name, func(t *testing.T) {
			k := newSidecarKernel(f)
			if name == SidecarTable {
				k.table = nil
			} else {
				k.backstop.table = nil
			}
			fakeSidecar(t, k)
			if err := InstallSidecar(t.Context(), 0, f); err == nil || err.Error() != "nft: install the sidecar firewall: readback: no table inet "+name {
				t.Fatalf("%v", err)
			}
		})
	}
}

func TestSidecarReadErrorsAndCancelledContext(t *testing.T) {
	for _, kind := range []uint16{unix.NFT_MSG_GETTABLE, unix.NFT_MSG_GETCHAIN, unix.NFT_MSG_GETRULE} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			k := newSidecarKernel(sidecarFixture())
			k.fail = kind
			fakeSidecar(t, k)
			if ok, reason, err := VerifySidecar(t.Context(), 0, sidecarFixture()); ok || reason != "" || err == nil {
				t.Fatalf("%t %q %v", ok, reason, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := InstallSidecar(ctx, 0, sidecarFixture()); err == nil {
		t.Fatal("cancelled install succeeded")
	}
	if ok, _, err := VerifySidecar(ctx, 0, sidecarFixture()); ok || err == nil {
		t.Fatal("cancelled verify succeeded")
	}
}

func TestSidecarRawExpressionComparison(t *testing.T) {
	unknown := sidecarAttrs(sidecarString(unix.NFTA_EXPR_NAME, "future-expression"), netlink.Attribute{Type: unix.NFTA_EXPR_DATA | unix.NLA_F_NESTED, Data: sidecarAttrs(netlink.Attribute{Type: 1, Data: sidecarBE(1)})})
	cases := []struct {
		name string
		edit func([]byte) []byte
		want bool
	}{
		{"unknown expression", func(b []byte) []byte {
			return append(sidecarAttrs(netlink.Attribute{Type: unix.NFTA_LIST_ELEM | unix.NLA_F_NESTED, Data: unknown}), b...)
		}, false},
		{"attribute order and nested flags", func(b []byte) []byte {
			return sidecarRewriteAttrs(b, func(a netlink.Attribute) (netlink.Attribute, bool) { a.Type &^= unix.NLA_F_NESTED; return a, true }, true)
		}, true},
		{"boolean bitwise op", func(b []byte) []byte {
			return sidecarEditExpressionData(b, "bitwise", func(attrs []netlink.Attribute) []netlink.Attribute {
				return append(attrs, netlink.Attribute{Type: 6, Data: sidecarBE(0)})
			})
		}, true},
		{"changed bitwise op", func(b []byte) []byte {
			return sidecarEditExpressionData(b, "bitwise", func(attrs []netlink.Attribute) []netlink.Attribute {
				return append(attrs, netlink.Attribute{Type: 6, Data: sidecarBE(1)})
			})
		}, false},
		{"unknown meta attribute", func(b []byte) []byte {
			return sidecarEditExpressionData(b, "meta", func(attrs []netlink.Attribute) []netlink.Attribute {
				return append(attrs, netlink.Attribute{Type: 1234, Data: sidecarBE(1)})
			})
		}, false},
		{"duplicate meta attribute", func(b []byte) []byte {
			return sidecarEditExpressionData(b, "meta", func(attrs []netlink.Attribute) []netlink.Attribute { return append(attrs, attrs[0]) })
		}, false},
		{"meta store instead of load", func(b []byte) []byte {
			return sidecarEditExpressionData(b, "meta", func(attrs []netlink.Attribute) []netlink.Attribute {
				for i := range attrs {
					if attrs[i].Type == unix.NFTA_META_DREG {
						attrs[i].Type = unix.NFTA_META_SREG
					}
				}
				return attrs
			})
		}, false},
		{"ct store instead of load", func(b []byte) []byte {
			return sidecarEditExpressionData(b, "ct", func(attrs []netlink.Attribute) []netlink.Attribute {
				for i := range attrs {
					if attrs[i].Type == unix.NFTA_CT_DREG {
						attrs[i].Type = unix.NFTA_CT_SREG
					}
				}
				return attrs
			})
		}, false},
		{"counter alignment padding", func(b []byte) []byte {
			return sidecarEditExpressionData(b, "counter", func(attrs []netlink.Attribute) []netlink.Attribute {
				return append(attrs, netlink.Attribute{Type: unix.NFTA_COUNTER_PAD})
			})
		}, true},
		{"counter unknown attribute", func(b []byte) []byte {
			return sidecarEditExpressionData(b, "counter", func(attrs []netlink.Attribute) []netlink.Attribute {
				return append(attrs, netlink.Attribute{Type: 1234, Data: make([]byte, 8)})
			})
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := sidecarFixture()
			f.ForwardedPort = 41234
			k := newSidecarKernel(f)
			k.wireEdit = tc.edit
			fakeSidecar(t, k)
			ok, reason, err := VerifySidecar(t.Context(), 0, f)
			if err != nil || ok != tc.want || (!ok && reason == "") {
				t.Fatalf("%t %q %v, want %t", ok, reason, err, tc.want)
			}
		})
	}
}

// Rewrite only attribute order and flags, preserving rule/expression order.
func sidecarRewriteAttrs(b []byte, edit func(netlink.Attribute) (netlink.Attribute, bool), expressions bool) []byte {
	attrs, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		panic(err)
	}
	var result []netlink.Attribute
	for _, a := range attrs {
		if a.Type&unix.NLA_F_NESTED != 0 {
			a.Data = sidecarRewriteAttrs(a.Data, edit, false)
		}
		a, keep := edit(a)
		if keep {
			result = append(result, a)
		}
	}
	if !expressions {
		for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
			result[i], result[j] = result[j], result[i]
		}
	}
	return sidecarAttrs(result...)
}

func sidecarEditExpressionData(b []byte, name string, edit func([]netlink.Attribute) []netlink.Attribute) []byte {
	list, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		panic(err)
	}
	for i := range list {
		attrs, err := netlink.UnmarshalAttributes(list[i].Data)
		if err != nil {
			panic(err)
		}
		found := false
		for _, a := range attrs {
			if a.Type&sidecarAttrTypeMask == unix.NFTA_EXPR_NAME && string(a.Data) == name+"\x00" {
				found = true
			}
		}
		if !found {
			continue
		}
		for j := range attrs {
			if attrs[j].Type&sidecarAttrTypeMask != unix.NFTA_EXPR_DATA {
				continue
			}
			data, err := netlink.UnmarshalAttributes(attrs[j].Data)
			if err != nil {
				panic(err)
			}
			attrs[j].Data = sidecarAttrs(edit(data)...)
		}
		list[i].Data = sidecarAttrs(attrs...)
	}
	return sidecarAttrs(list...)
}
