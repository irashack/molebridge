package mutator

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
)

func sidecarSpec() contract.Spec {
	c := contract.Config{Kind: contract.Sidecar, Backend: contract.Native, ExitIf: "mullvad", Table: 51821, HostIf: "eth0", ControlMark: 0x1bd00,
		LAN:  []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/28"), netip.MustParsePrefix("203.0.113.10/32")},
		LAN6: []netip.Prefix{netip.MustParsePrefix("2001:db8:1::/64"), netip.MustParsePrefix("2001:db8:2::/64"), netip.MustParsePrefix("2001:db8:3::10/128")}}
	return contract.Spec{Config: c, ReturnPath: nativeSpec().ReturnPath}
}

func sidecarKernel(spec contract.Spec, tunnel bool) *fakeKernel {
	k := newFakeKernel()
	k.links = k.links[:2] // no overlay, as in a shared application namespace
	if tunnel {
		k.links = append(k.links, rtnl.Link{Index: 7, Name: spec.Config.ExitIf, Flags: rtnl.IFFUp, Kind: "wireguard"})
	}
	for _, f := range families {
		prefix := "0.0.0.0/0"
		if f == rtnl.V6 {
			prefix = "::/0"
		}
		k.routes[f] = []rtnl.Route{{Family: f, Dst: netip.MustParsePrefix(prefix), Table: rtnl.TableMain, Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(2))}}
	}
	return k
}

func TestNativeSidecarInstallAndRestart(t *testing.T) {
	for _, tunnel := range []bool{false, true} {
		t.Run(fmt.Sprintf("tunnel=%v", tunnel), func(t *testing.T) {
			spec := sidecarSpec()
			k := sidecarKernel(spec, tunnel)
			m := start(t, k, spec)
			if m.o.GuardRepairs {
				t.Fatal("native sidecar must never use GuardRepairs")
			}
			if err := m.Install(context.Background()); err != nil {
				t.Fatal(err)
			}
			expectHealthy(t, k, spec)
			for _, f := range families {
				p97, p96 := index(k.log, fmt.Sprintf("add %d 97", f.AF())), index(k.log, fmt.Sprintf("add %d 96", f.AF()))
				if p97 < 0 || p96 <= p97 {
					t.Fatalf("install order: %v", k.log)
				}
				for _, p := range []uint32{88, 89, 90, 93, 94, 98} {
					if i := index(k.log, fmt.Sprintf("add %d %d", f.AF(), p)); i <= p96 {
						t.Fatalf("exception before 96: %v", k.log)
					}
				}
				if len(priorities(k, f)) != 11 || priorities(k, f)[0] != 1 {
					t.Fatalf("priorities (including kernel rules): %v", priorities(k, f))
				}
			}
			for _, op := range k.log {
				if strings.HasSuffix(op, " 80") || strings.HasSuffix(op, " 1") || strings.HasPrefix(op, "del 2 0") || strings.HasPrefix(op, "del 10 0") {
					t.Fatalf("overlay guard or priority-0 mutation: %s", op)
				}
			}
			// A new owner sees exactly the namespace retained after a container
			// restart. Installing again must neither duplicate nor replace rules.
			m.Close()
			before := len(k.log)
			m = start(t, k, spec)
			if err := m.Install(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(k.log) != before || !m.Ready() {
				t.Fatalf("restart changed an exact namespace: %v", k.log[before:])
			}
		})
	}
}

func TestNativeSidecarRepairsEachRuleAndForeignMainLookup(t *testing.T) {
	spec := sidecarSpec()
	k := sidecarKernel(spec, true)
	m := start(t, k, spec)
	if err := m.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		for _, r := range spec.Rules(f) {
			if err := k.DelRule(r); err != nil {
				t.Fatal(err)
			}
			if res, err := m.ReconcileNow(context.Background(), "rule deletion"); err != nil || !res.Verified || !res.Repaired {
				t.Fatalf("rule %s: %+v, %v", r, res, err)
			}
			expectHealthy(t, k, spec)
		}
		if err := k.AddRule(rtnl.Rule{Family: f, Priority: 50, Action: rtnl.FRActToTbl, Table: rtnl.TableMain}); err != nil {
			t.Fatal(err)
		}
		if res, err := m.ReconcileNow(context.Background(), "foreign main lookup"); err != nil || !res.Verified {
			t.Fatalf("main lookup: %+v, %v", res, err)
		}
	}
	expectHealthy(t, k, spec)
	for _, op := range k.log {
		if strings.HasSuffix(op, " 80") {
			t.Fatalf("temporary guard in repair: %s", op)
		}
	}
}

func TestNativeSidecarDeletionApproval(t *testing.T) {
	for _, f := range families {
		spec := sidecarSpec()
		k := sidecarKernel(spec, false)
		m := start(t, k, spec)
		if err := m.Install(context.Background()); err != nil {
			t.Fatal(err)
		}
		err := m.Do(context.Background(), "delete backed-up rules", func(tx *Tx) error {
			if err := tx.DelRule(spec.RulesAt(f, 88)[0]); err != nil {
				return fmt.Errorf("89 backs up 88: %w", err)
			}
			if err := tx.DelRule(spec.RulesAt(f, 96)[0]); err != nil {
				return fmt.Errorf("97 backs up 96: %w", err)
			}
			return tx.DelRule(spec.RulesAt(f, 97)[0])
		})
		if !errors.Is(err, ErrUnsafeDeletion) {
			t.Fatalf("97 without 96: %v", err)
		}
		if priorities(k, f)[97] != 1 {
			t.Fatal("97 was removed")
		}
		if res, err := m.ReconcileNow(context.Background(), "restore"); err != nil || !res.Verified {
			t.Fatalf("restore: %+v, %v", res, err)
		}
	}
}

func TestNativeSidecarFailedInstallKeepsTerminalRule(t *testing.T) {
	spec := sidecarSpec()
	k := sidecarKernel(spec, false)
	k.fail = func(op string) error {
		if op == "add 2 96" {
			return syscall.EPERM
		}
		return nil
	}
	m := start(t, k, spec)
	if err := m.Install(context.Background()); err == nil || !strings.HasPrefix(err.Error(), "the routing contract could not be installed:") {
		t.Fatalf("install: %v", err)
	}
	if m.Ready() || priorities(k, rtnl.V4)[97] != 1 || priorities(k, rtnl.V4)[80] != 0 {
		t.Fatal("failed install lost its terminal rule or used an overlay guard")
	}
}

func TestNativeSidecarReturnPathTransactionAndRetirement(t *testing.T) {
	for _, f := range families {
		spec := sidecarSpec()
		spec.ReturnPath = nil
		spec.LeaveReturnPath = map[rtnl.Family]bool{rtnl.V4: true, rtnl.V6: true}
		k := sidecarKernel(spec, true)
		m := start(t, k, spec)
		if err := m.Install(context.Background()); err != nil {
			t.Fatal(err)
		}
		addrs := []netip.Addr{netip.MustParseAddr("203.0.113.11"), netip.MustParseAddr("203.0.113.12")}
		if f == rtnl.V6 {
			addrs = []netip.Addr{netip.MustParseAddr("2001:db8:3::11"), netip.MustParseAddr("2001:db8:3::12")}
		}
		old := netip.Addr{}
		for _, next := range addrs {
			if err := m.ChangeReturnPath(context.Background(), f, old, next, func(tx *Tx) error {
				both := tx.Spec()
				count := 1
				if old.IsValid() {
					count = 2
				}
				if len(both.ReturnPath[f]) != count {
					return fmt.Errorf("expected pairs: %v", both.ReturnPath[f])
				}
				if err := tx.confirmed(f, append(both.RulesAt(f, 94), both.RulesAt(f, 98)...)...); err != nil {
					return err
				}
				k.setAddr(f, spec.Config.ExitIf, old, false)
				k.setAddr(f, spec.Config.ExitIf, next, true)
				// Address replacement drops the tunnel route, as in PIA.
				return k.DelRoute(contract.TunnelRoute(f, spec.Config.Table, 7))
			}); err != nil {
				t.Fatal(err)
			}
			if got := m.Expected().ReturnPath[f]; !reflect.DeepEqual(got, []netip.Addr{next}) {
				t.Fatalf("settled pairs: %v", got)
			}
			expectHealthy(t, k, m.Expected())
			old = next
		}
		if err := m.RetireReturnPath(context.Background(), f, old); !errors.Is(err, ErrReturnPathLive) {
			t.Fatalf("retired a live address: %v", err)
		}
		k.setAddr(f, spec.Config.ExitIf, old, false)
		if err := m.RetireReturnPath(context.Background(), f, old); err != nil {
			t.Fatal(err)
		}
		if got := m.Expected(); !got.LeaveReturnPath[f] || len(got.ReturnPath[f]) != 0 {
			t.Fatalf("retired state: %+v", got)
		}
		for _, r := range k.rules[f] {
			if r.Priority == 94 || r.Priority == 98 {
				t.Fatalf("retired pair stays: %s", r)
			}
		}
		expectHealthy(t, k, m.Expected())
	}
}

func TestNativeSidecarRebuildKeepsEveryLANPrefix(t *testing.T) {
	for _, priority := range []uint32{90, 96, 97} {
		t.Run(fmt.Sprint(priority), func(t *testing.T) {
			spec := sidecarSpec()
			k := sidecarKernel(spec, true)
			m := start(t, k, spec)
			if err := m.Install(context.Background()); err != nil {
				t.Fatal(err)
			}
			for _, f := range families {
				broad := spec.RulesAt(f, priority)[0]
				broad.IifName, broad.Dst = "", netip.Prefix{}
				if err := k.AddRule(broad); err != nil {
					t.Fatal(err)
				}
				if res, err := m.ReconcileNow(context.Background(), "fewer selectors"); err != nil || !res.Verified || !res.Repaired {
					t.Fatalf("rebuild %s %d: %+v, %v", f, priority, res, err)
				}
				expectHealthy(t, k, spec)
			}
			for _, op := range k.log {
				if strings.HasSuffix(op, " 80") {
					t.Fatalf("temporary guard during rebuild: %s", op)
				}
			}
		})
	}
}
