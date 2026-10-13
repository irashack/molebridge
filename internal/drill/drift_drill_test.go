//go:build drill && linux

package drill

// The drift table of tools/check-routing.sh against the live repairer: every
// single fault, in both families, is repaired within 250 ms of the outside
// change (D10), nothing from the overlay leaves through the host interface
// while it is, and the client is connected again afterwards.

import (
	"fmt"
	"sort"
	"testing"
	"time"
)

const repairBudget = 250 * time.Millisecond

type fault struct {
	name string
	// apply injects the fault with ip, in the exit namespace.
	apply func(r *rig, family string)
	// opensTheNamespace: the fault itself lets overlay traffic out (a foreign
	// rule that routes it to the host), so containment cannot be asserted
	// while it lasts.
	opensTheNamespace bool
	// blockedWhileHeld: with the repairer held, the client cannot reach the
	// destination (the contract fails closed), rather than being unaffected.
	blockedWhileHeld bool
}

func ipf(r *rig, family string, args ...string) { r.exit.IP(append([]string{family}, args...)...) }

func faults() []fault {
	var out []fault
	for _, p := range []string{"1", "90", "94", "95", "96", "97", "98"} {
		p := p
		out = append(out, fault{name: "rule " + p + " deleted", blockedWhileHeld: p == "95",
			apply: func(r *rig, f string) { ipf(r, f, "rule", "del", "priority", p) }})
	}
	out = append(out,
		fault{name: "tunnel route deleted", blockedWhileHeld: true,
			apply: func(r *rig, f string) {
				ipf(r, f, "route", "del", "default", "dev", exitIf, "table", fmt.Sprint(table))
			}},
		fault{name: "unreachable fallback deleted",
			apply: func(r *rig, f string) {
				ipf(r, f, "route", "del", "unreachable", "default", "metric", "4096", "table", fmt.Sprint(table))
			}},
		fault{name: "all exit-table routes deleted", blockedWhileHeld: true,
			apply: func(r *rig, f string) { ipf(r, f, "route", "flush", "table", fmt.Sprint(table)) }},
		fault{name: "foreign exit-table route", blockedWhileHeld: false,
			apply: func(r *rig, f string) {
				dst := "203.0.113.99/32"
				if f == "-6" {
					dst = "2001:db8:3::99/128"
				}
				ipf(r, f, "route", "add", dst, "dev", "eth0", "table", fmt.Sprint(table))
			}},
		fault{name: "rule 97 replaced by a prohibit",
			apply: func(r *rig, f string) {
				ipf(r, f, "rule", "add", "iif", overlayIf, "prohibit", "priority", "97")
				ipf(r, f, "rule", "del", "iif", overlayIf, "unreachable", "priority", "97")
			}},
		fault{name: "rule 95 replaced by an unreachable", blockedWhileHeld: true,
			apply: func(r *rig, f string) {
				ipf(r, f, "rule", "add", "iif", overlayIf, "unreachable", "priority", "95")
				ipf(r, f, "rule", "del", "iif", overlayIf, "lookup", fmt.Sprint(table), "priority", "95")
			}},
		fault{name: "extra fwmark selector on a copy of rule 95",
			apply: func(r *rig, f string) {
				ipf(r, f, "rule", "add", "iif", overlayIf, "fwmark", "5", "lookup", fmt.Sprint(table), "priority", "95")
			}},
		fault{name: "extra ipproto selector on a copy of rule 96",
			apply: func(r *rig, f string) {
				ipf(r, f, "rule", "add", "oif", exitIf, "ipproto", "tcp", "lookup", fmt.Sprint(table), "priority", "96")
			}},
		fault{name: "extra sport selector on a copy of rule 97",
			apply: func(r *rig, f string) {
				ipf(r, f, "rule", "add", "iif", overlayIf, "sport", "1-2", "unreachable", "priority", "97")
			}},
		fault{name: "rule 95 with fewer selectors",
			apply: func(r *rig, f string) { ipf(r, f, "rule", "add", "lookup", fmt.Sprint(table), "priority", "95") }},
		fault{name: "rule 96 with fewer selectors",
			apply: func(r *rig, f string) { ipf(r, f, "rule", "add", "lookup", fmt.Sprint(table), "priority", "96") }},
		fault{name: "rule 90 for another destination",
			apply: func(r *rig, f string) {
				dst := "192.0.0.0/8"
				if f == "-6" {
					dst = "2001:db8::/32"
				}
				ipf(r, f, "rule", "add", "iif", exitIf, "to", dst, "lookup", "main", "priority", "90")
			}},
		fault{name: "inserted lookup main at 50", opensTheNamespace: true,
			apply: func(r *rig, f string) { ipf(r, f, "rule", "add", "lookup", "main", "priority", "50") }},
		fault{name: "kernel rule 0 back", opensTheNamespace: true,
			apply: func(r *rig, f string) { ipf(r, f, "rule", "add", "lookup", "local", "priority", "0") }},
		fault{name: "inserted blackhole at 3",
			apply: func(r *rig, f string) { ipf(r, f, "rule", "add", "blackhole", "priority", "3") }},
	)
	return out
}

// logSlowest reports the slowest repairs of a table of faults.
func logSlowest(t *testing.T, rows map[string]time.Duration) {
	t.Helper()
	type row struct {
		name string
		d    time.Duration
	}
	var all []row
	for n, d := range rows {
		all = append(all, row{n, d})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].d > all[j].d })
	for i := 0; i < len(all) && i < 5; i++ {
		t.Logf("slow row %d: %-50s %v", i+1, all[i].name, all[i].d)
	}
}

func TestEverySingleFaultIsRepairedWithin250ms(t *testing.T) { // the drift table, with D10's assertion
	var worst time.Duration
	rows := map[string]time.Duration{}
	defer func() { logSlowest(t, rows) }()
	for _, fl := range faults() {
		for _, family := range []string{"-4", "-6"} {
			fl, family := fl, family
			t.Run(fl.name+" "+family, func(t *testing.T) {
				r := newRig(t)
				if !fl.opensTheNamespace {
					r.flood()
				}
				resetCounter(t, r.outside)
				before := r.mut.Stats().Repairs
				fl.apply(r, family)
				took := r.waitHealthy(2 * time.Second)
				rows[fl.name+" "+family] = took
				if took > repairBudget {
					t.Errorf("repaired %v after the change, budget %v", took, repairBudget)
				}
				if took > worst {
					worst = took
				}
				// The pass records itself a moment after its last change.
				for i := 0; i < 100 && r.mut.Stats().Repairs == before; i++ {
					time.Sleep(5 * time.Millisecond)
				}
				if r.mut.Stats().Repairs == before {
					t.Errorf("the repairer did not count a repair for %s", fl.name)
				}
				if !fl.opensTheNamespace {
					// The flood has been running through the repair.
					time.Sleep(30 * time.Millisecond)
					r.held(fl.name)
				}
				if ok, f := r.connected(); !ok {
					t.Errorf("%s: not connected after the repair", f)
				}
			})
		}
	}
	t.Logf("slowest repair: %v", worst)
}

// With the repairer held, the fault's own effect is contained: the overlay is
// blocked or still goes through the tunnel, never to the host.
func TestFaultsAreContainedUntilRepaired(t *testing.T) { // 'blocked' rows of check-routing.sh
	for _, fl := range faults() {
		if fl.opensTheNamespace {
			continue
		}
		for _, family := range []string{"-4", "-6"} {
			fl, family := fl, family
			t.Run(fl.name+" "+family, func(t *testing.T) {
				r := newRig(t)
				resume := r.pause()
				defer resume()
				resetCounter(t, r.outside)
				fl.apply(r, family)
				time.Sleep(20 * time.Millisecond)
				reached := r.ping(family)
				if fl.blockedWhileHeld && reached {
					t.Errorf("the client reached the destination with %s", fl.name)
				}
				if n := counter(t, r.outside); n != 0 {
					t.Errorf("%d packets left through the host interface while the fault stood", n)
				}
				resume()
				r.waitHealthy(2 * time.Second)
				if ok, f := r.connected(); !ok {
					t.Errorf("%s: not connected after the repair", f)
				}
			})
		}
	}
}
