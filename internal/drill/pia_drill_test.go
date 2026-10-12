//go:build drill && linux

package drill

// PIA: an addressless config, so the provider transaction owns rules 94 and 98.
// The address changes the way the applier does it: the new pair first, then the
// address, then the old pair.

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/mutator"
	"github.com/irashack/molebridge/internal/rtnl"
)

func piaRig(t *testing.T) *rig {
	return newRig(t, func(o *rigOptions) {
		o.spec = func(s contract.Spec) contract.Spec {
			return contract.Spec{Config: s.Config, LeaveReturnPath: map[rtnl.Family]bool{rtnl.V4: true, rtnl.V6: true}}
		}
	})
}

func TestPIAInitializationInstallsNoReturnPathRuleAndBlocksIPv6(t *testing.T) { // PIA initialization without an address keeps every guard and blocks IPv6
	r := piaRig(t)
	for _, f := range []string{"-4", "-6"} {
		out, _ := r.exit.TryIP(f, "rule", "show")
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, "94:") || strings.HasPrefix(l, "98:") {
				t.Errorf("%s: an addressless config installed %q", f, l)
			}
		}
	}
	// The tunnel carries IPv4 only: the IPv6 table holds the fallback alone.
	out, _ := r.exit.TryIP("-6", "route", "show", "table", fmt.Sprint(table))
	if strings.Contains(out, "default dev "+exitIf) {
		t.Errorf("IPv6 exit table: %q", out)
	}
	if r.ping("-6") {
		t.Error("IPv6 escaped through an IPv4-only PIA tunnel")
	}
	if ok := r.ping("-4"); !ok {
		t.Error("IPv4 does not forward")
	}
}

func TestPIAAddressChangesAreOneTransaction(t *testing.T) { // PIA's rules 94 and 98 through three address changes
	r := piaRig(t)
	r.flood()
	resetCounter(t, r.outside)
	old := netip.Addr{}
	current := "203.0.113.1/24"
	for round := 1; round <= 3; round++ {
		next := fmt.Sprintf("203.0.113.%d", 10+round)
		err := r.mut.ChangeReturnPath(context.Background(), rtnl.V4, old, netip.MustParseAddr(next), func(tx *mutator.Tx) error {
			// The applier's order: the new address first, then the old one goes,
			// then the tunnel default is re-asserted (the transaction does that
			// last). Removing the last address first would delete every route
			// through the interface.
			for _, step := range [][]string{
				{"-n", r.exit.Name, "-4", "addr", "replace", next + "/32", "dev", exitIf},
				{"-n", r.exit.Name, "-4", "addr", "del", current, "dev", exitIf},
				{"-n", r.tun.Name, "route", "replace", "192.0.2.0/24", "via", next},
			} {
				if out, err := exec.Command("ip", step...).CombinedOutput(); err != nil {
					return fmt.Errorf("ip %v: %v\n%s", step, err, out)
				}
			}
			pinNeighbors(r.exit)
			return nil
		})
		if err != nil {
			t.Fatalf("round %d: %v\n%s", round, err, r.logs.text())
		}
		current = next + "/32"
		old = netip.MustParseAddr(next)
		out, _ := r.exit.TryIP("-4", "rule", "show")
		n94, n98 := strings.Count(out, "94:"), strings.Count(out, "98:")
		if n94 != 1 || n98 != 1 || !strings.Contains(out, "from "+next+" ipproto icmp lookup") {
			t.Errorf("round %d: rules after the change:\n%s", round, out)
		}
		if ok := r.ping("-4"); !ok {
			t.Errorf("round %d: IPv4 did not forward after the address change", round)
		}
		if r.ping("-6") {
			t.Errorf("round %d: IPv6 escaped after the address change", round)
		}
		if !r.tooBigReported("-4") {
			t.Errorf("round %d: the ICMP return path broke after the address change", round)
		}
		time.Sleep(30 * time.Millisecond)
		if !r.healthy() {
			t.Errorf("round %d: the contract does not hold after the transaction (the repairer may have undone it)", round)
		}
	}
	r.held("PIA's address changes")
	// The repairer compares the new pair from now on: delete it, it comes back.
	r.exit.IP("-4", "rule", "del", "priority", "98")
	r.waitHealthy(time.Second)
	out, _ := r.exit.TryIP("-4", "rule", "show", "priority", "98")
	if !strings.Contains(out, "unreachable") {
		t.Errorf("rule 98 was not repaired after the transaction: %q", out)
	}
}
