//go:build drill && linux

package nft_test

import (
	"context"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"github.com/irashack/molebridge/internal/nft"
	"github.com/irashack/molebridge/internal/nstest"
)

func list(t *testing.T, ns *nstest.NS, args ...string) string {
	t.Helper()
	out, err := ns.Exec("nft", args...)
	if err != nil {
		t.Fatalf("nft %v: %v\n%s", args, err, out)
	}
	return out
}

// The ingress guard and the port-forwarding table are what applier/pia.py
// installed with `nft -f`: same tables, chains, hooks and rules.
func TestIngressGuardAndForwardRules(t *testing.T) {
	ns := nstest.New(t, "fwd")
	bound, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := ns.Exec("nft", "list", "ruleset"); err != nil {
		t.Skip("nft is unavailable here")
	}
	do := func(fn func() error) {
		t.Helper()
		if err := ns.Do(fn); err != nil {
			t.Fatal(err)
		}
	}
	do(func() error { return nft.InstallIngressGuard(bound, ns.Fd(), "mullvad", "wt0") })
	guard := list(t, ns, "list", "table", "inet", "molebridge_guard")
	for _, want := range []string{"chain forward", "type filter hook forward priority filter; policy accept;", `iifname "mullvad" oifname != "wt0" drop`} {
		if !strings.Contains(guard, want) {
			t.Errorf("guard lacks %q:\n%s", want, guard)
		}
	}
	// Installing again replaces the table; it does not stack rules.
	do(func() error { return nft.InstallIngressGuard(bound, ns.Fd(), "mullvad", "wt0") })
	if n := strings.Count(list(t, ns, "list", "table", "inet", "molebridge_guard"), "drop"); n != 1 {
		t.Errorf("the guard has %d drop rules after a second install", n)
	}

	target := netip.MustParseAddr("100.64.0.9")
	do(func() error { return nft.ApplyForwardRules(bound, ns.Fd(), "mullvad", "wt0", 41234, target) })
	fwd := list(t, ns, "list", "table", "ip", "molebridge_forward")
	for _, want := range []string{
		"type nat hook prerouting priority dstnat; policy accept;",
		`iifname "mullvad" meta l4proto { tcp, udp } th dport 41234 dnat to 100.64.0.9`,
		"type nat hook postrouting priority srcnat; policy accept;",
		`oifname "wt0" ct status dnat ip daddr 100.64.0.9 masquerade`,
	} {
		if !strings.Contains(fwd, want) {
			t.Errorf("forward table lacks %q:\n%s", want, fwd)
		}
	}
	do(func() error { return nft.ApplyForwardRules(bound, ns.Fd(), "mullvad", "wt0", 50000, target) })
	fwd = list(t, ns, "list", "table", "ip", "molebridge_forward")
	if strings.Contains(fwd, "41234") || !strings.Contains(fwd, "th dport 50000") || strings.Count(fwd, "dnat to") != 1 {
		t.Errorf("a new port must replace the old rules:\n%s", fwd)
	}
	do(func() error { return nft.RemoveForwardRules(bound, ns.Fd()) })
	if out, err := ns.Exec("nft", "list", "table", "ip", "molebridge_forward"); err == nil {
		t.Errorf("the table is still there:\n%s", out)
	}
	// Removing a table that is not there is not an error.
	do(func() error { return nft.RemoveForwardRules(bound, ns.Fd()) })
	if !strings.Contains(list(t, ns, "list", "ruleset"), "molebridge_guard") {
		t.Error("the guard is never removed")
	}
}

// molebridge#180: EnsureIngressGuard reads the guard back and leaves an intact
// one alone, so a check announces no new table or chain to nftables
// listeners (NetBird's client reconciles its firewall after each one). The
// accept rules NetBird inserts, which match only overlay traffic, are
// tolerated; a rule that could pass tunnel ingress elsewhere, a missing drop
// rule or a deleted table is repaired at once.
func TestEnsureIngressGuardLeavesAnIntactGuardAlone(t *testing.T) {
	ns := nstest.New(t, "ensure")
	bound, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	if _, err := ns.Exec("nft", "list", "ruleset"); err != nil {
		t.Skip("nft is unavailable here")
	}
	ensure := func() string {
		t.Helper()
		var why string
		if err := ns.Do(func() error {
			var err error
			why, err = nft.EnsureIngressGuard(bound, ns.Fd(), "mullvad", "wt0")
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return why
	}
	if why := ensure(); why != "no table inet molebridge_guard" {
		t.Fatalf("first install: %q", why)
	}

	// What NetBird 0.82 inserts into every external filter forward chain.
	c, err := nftables.New(nftables.WithNetNSFd(ns.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: nft.GuardTable}
	chain := &nftables.Chain{Name: "forward", Table: table}
	wt0 := make([]byte, 16)
	copy(wt0, "wt0")
	c.InsertRule(&nftables.Rule{Table: table, Chain: chain, UserData: []byte("netbird-fwd-iif"), Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: wt0},
		&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictAccept},
	}})
	c.InsertRule(&nftables.Rule{Table: table, Chain: chain, UserData: []byte("netbird-fwd-oif"), Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: wt0},
		&expr.Ct{Key: expr.CtKeySTATE, Register: 2},
		&expr.Bitwise{SourceRegister: 2, DestRegister: 2, Len: 4, Mask: []byte{6, 0, 0, 0}, Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 2, Data: []byte{0, 0, 0, 0}},
		&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictAccept},
	}})
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}

	mon := nftables.NewMonitor(nftables.WithMonitorAction(nftables.MonitorActionNew),
		nftables.WithMonitorObject(nftables.MonitorObjectChains|nftables.MonitorObjectTables))
	events, err := c.AddMonitor(mon)
	if err != nil {
		t.Fatal(err)
	}
	defer mon.Close()
	var seen atomic.Int32
	go func() {
		for ev := range events {
			if ev.Type == nftables.MonitorEventTypeNewTable || ev.Type == nftables.MonitorEventTypeNewChain {
				seen.Add(1)
			}
		}
	}()
	for i := 0; i < 5; i++ {
		if why := ensure(); why != "" {
			t.Fatalf("check %d replaced an intact guard: %q\n%s", i, why, list(t, ns, "list", "table", "inet", "molebridge_guard"))
		}
	}
	time.Sleep(300 * time.Millisecond)
	if n := seen.Load(); n != 0 {
		t.Fatalf("checks of an intact guard announced %d new tables or chains", n)
	}

	for name, damage := range map[string][]string{
		"a rule passing tunnel ingress": {"insert", "rule", "inet", "molebridge_guard", "forward", "iifname", "mullvad", "accept"},
		"the drop rule flushed":         {"flush", "chain", "inet", "molebridge_guard", "forward"},
		"the table deleted":             {"delete", "table", "inet", "molebridge_guard"},
	} {
		list(t, ns, damage...)
		if why := ensure(); why == "" {
			t.Errorf("%s: not repaired", name)
		}
		guard := list(t, ns, "list", "table", "inet", "molebridge_guard")
		if !strings.Contains(guard, `iifname "mullvad" oifname != "wt0" drop`) || strings.Contains(guard, `iifname "mullvad" accept`) {
			t.Errorf("%s: after the repair:\n%s", name, guard)
		}
		if why := ensure(); why != "" {
			t.Errorf("%s: the repaired guard is replaced again: %q", name, why)
		}
	}
}
