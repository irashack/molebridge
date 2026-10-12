//go:build drill && linux

package nft_test

import (
	"net/netip"
	"strings"
	"testing"

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
	if _, err := ns.Exec("nft", "list", "ruleset"); err != nil {
		t.Skip("nft is unavailable here")
	}
	do := func(fn func() error) {
		t.Helper()
		if err := ns.Do(fn); err != nil {
			t.Fatal(err)
		}
	}
	do(func() error { return nft.InstallIngressGuard("mullvad", "wt0") })
	guard := list(t, ns, "list", "table", "inet", "molebridge_guard")
	for _, want := range []string{"chain forward", "type filter hook forward priority filter; policy accept;", `iifname "mullvad" oifname != "wt0" drop`} {
		if !strings.Contains(guard, want) {
			t.Errorf("guard lacks %q:\n%s", want, guard)
		}
	}
	// Installing again replaces the table; it does not stack rules.
	do(func() error { return nft.InstallIngressGuard("mullvad", "wt0") })
	if n := strings.Count(list(t, ns, "list", "table", "inet", "molebridge_guard"), "drop"); n != 1 {
		t.Errorf("the guard has %d drop rules after a second install", n)
	}

	target := netip.MustParseAddr("100.64.0.9")
	do(func() error { return nft.ApplyForwardRules("mullvad", "wt0", 41234, target) })
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
	do(func() error { return nft.ApplyForwardRules("mullvad", "wt0", 50000, target) })
	fwd = list(t, ns, "list", "table", "ip", "molebridge_forward")
	if strings.Contains(fwd, "41234") || !strings.Contains(fwd, "th dport 50000") || strings.Count(fwd, "dnat to") != 1 {
		t.Errorf("a new port must replace the old rules:\n%s", fwd)
	}
	do(func() error { return nft.RemoveForwardRules() })
	if out, err := ns.Exec("nft", "list", "table", "ip", "molebridge_forward"); err == nil {
		t.Errorf("the table is still there:\n%s", out)
	}
	// Removing a table that is not there is not an error.
	do(func() error { return nft.RemoveForwardRules() })
	if !strings.Contains(list(t, ns, "list", "ruleset"), "molebridge_guard") {
		t.Error("the guard is never removed")
	}
}
