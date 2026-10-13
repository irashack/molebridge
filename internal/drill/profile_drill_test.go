//go:build drill && linux

package drill

// A profile of what a repair costs on the real kernel: how many snapshots,
// barriers and requests, and how long each kind takes. Run with
// MOLEBRIDGE_PROFILE=1; it asserts nothing.

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/mutator"
	"github.com/irashack/molebridge/internal/rtnl"
)

type timingKernel struct {
	*rtnl.Conn
	mu    sync.Mutex
	count map[string]int
	total map[string]time.Duration
	// log is every call with its start and end, relative to origin.
	origin time.Time
	log    []string
}

func (k *timingKernel) note(op string, start time.Time) {
	k.mu.Lock()
	k.count[op]++
	k.total[op] += time.Since(start)
	if !k.origin.IsZero() {
		k.log = append(k.log, fmt.Sprintf("%8.2f..%8.2f ms  %s", float64(start.Sub(k.origin))/1e6, float64(time.Since(k.origin))/1e6, op))
	}
	k.mu.Unlock()
}

func (k *timingKernel) TakeContext(ctx context.Context, in rtnl.Interest) (*rtnl.Snapshot, error) {
	defer k.note("snapshot", time.Now())
	return k.Conn.TakeContext(ctx, in)
}
func (k *timingKernel) Take(in rtnl.Interest) (*rtnl.Snapshot, error) {
	defer k.note("snapshot", time.Now())
	return k.Conn.Take(in)
}
func (k *timingKernel) RulesStable(ctx context.Context, f rtnl.Family) ([]rtnl.Rule, bool, error) {
	defer k.note("read back rules", time.Now())
	return k.Conn.RulesStable(ctx, f)
}
func (k *timingKernel) ForeignChange(ctx context.Context, in rtnl.Interest) (bool, error) {
	defer k.note("foreign check", time.Now())
	return k.Conn.ForeignChange(ctx, in)
}
func (k *timingKernel) AddRule(r rtnl.Rule) error {
	defer k.note("add rule", time.Now())
	return k.Conn.AddRule(r)
}
func (k *timingKernel) DelRule(r rtnl.Rule) error {
	defer k.note("del rule", time.Now())
	return k.Conn.DelRule(r)
}
func (k *timingKernel) DelRulePriority(f rtnl.Family, p uint32) error {
	defer k.note("del rule by priority", time.Now())
	return k.Conn.DelRulePriority(f, p)
}
func (k *timingKernel) ReplaceRoute(r rtnl.Route) error {
	defer k.note("replace route", time.Now())
	return k.Conn.ReplaceRoute(r)
}
func (k *timingKernel) DelRoute(r rtnl.Route) error {
	defer k.note("del route", time.Now())
	return k.Conn.DelRoute(r)
}

func TestProfileOfARepair(t *testing.T) {
	if os.Getenv("MOLEBRIDGE_PROFILE") == "" {
		t.Skip("set MOLEBRIDGE_PROFILE=1")
	}
	for _, fl := range []struct {
		name  string
		apply func(r *rig)
	}{
		{"rule 95 with fewer selectors -6", func(r *rig) {
			r.exit.IP("-6", "rule", "add", "lookup", fmt.Sprint(table), "priority", "95")
			r.exit.IP("-6", "rule", "del", "iif", overlayIf, "lookup", fmt.Sprint(table), "priority", "95")
		}},
		{"rule 90 deleted -6", func(r *rig) { r.exit.IP("-6", "rule", "del", "priority", "90") }},
		{"rule 97 deleted -4", func(r *rig) { r.exit.IP("-4", "rule", "del", "priority", "97") }},
	} {
		t.Run(fl.name, func(t *testing.T) {
			var tk *timingKernel
			r := newRig(t, func(o *rigOptions) {
				o.wrap = func(c *rtnl.Conn) mutator.Kernel {
					tk = &timingKernel{Conn: c, count: map[string]int{}, total: map[string]time.Duration{}}
					return tk
				}
			})
			tk.mu.Lock()
			tk.count, tk.total = map[string]int{}, map[string]time.Duration{}
			tk.mu.Unlock()
			start := time.Now()
			fl.apply(r)
			took := r.waitHealthy(2 * time.Second)
			tk.mu.Lock()
			defer tk.mu.Unlock()
			var ops []string
			for op := range tk.count {
				ops = append(ops, op)
			}
			sort.Strings(ops)
			t.Logf("repaired %v after the change (measured from %v)", took, time.Since(start))
			for _, op := range ops {
				t.Logf("  %-22s x%-3d %v", op, tk.count[op], tk.total[op])
			}
		})
	}
}

func TestProfileOfTheKernelCalls(t *testing.T) {
	if os.Getenv("MOLEBRIDGE_PROFILE") == "" {
		t.Skip("set MOLEBRIDGE_PROFILE=1")
	}
	r := newRig(t)
	c, err := rtnl.Dial(rtnl.Options{NetNS: r.exit.Fd()})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	in := r.spec.Interest()
	avg := func(name string, n int, f func()) {
		start := time.Now()
		for i := 0; i < n; i++ {
			f()
		}
		t.Logf("%-28s %v", name, time.Since(start)/time.Duration(n))
	}
	ctx := context.Background()
	avg("snapshot", 100, func() { _, _ = c.TakeContext(ctx, in) })
	avg("foreign check (barrier+drain)", 100, func() { _, _ = c.ForeignChange(ctx, in) })
	avg("rules read back", 100, func() { _, _, _ = c.RulesStable(ctx, rtnl.V4) })
	avg("rules dump v4", 100, func() { _, _ = c.Rules(rtnl.V4) })
	avg("routes dump v4", 100, func() { _, _ = c.Routes(rtnl.V4, nil) })
	avg("links dump", 100, func() { _, _ = c.Links() })
	avg("addrs dump v4", 100, func() { _, _ = c.Addrs(rtnl.V4) })
}

func TestProfileOfTheDrain(t *testing.T) {
	if os.Getenv("MOLEBRIDGE_PROFILE") == "" {
		t.Skip("set MOLEBRIDGE_PROFILE=1")
	}
	r := newRig(t)
	sub, err := rtnl.Subscribe(rtnl.Options{NetNS: r.exit.Fd()})
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	for _, d := range []time.Duration{0, 50 * time.Microsecond, 200 * time.Microsecond, time.Millisecond} {
		start := time.Now()
		n := 200
		for i := 0; i < n; i++ {
			_, _ = sub.Next(time.Now().Add(d))
		}
		t.Logf("an empty read with a deadline %v ahead takes %v", d, time.Since(start)/time.Duration(n))
	}
	c, err := rtnl.Dial(rtnl.Options{NetNS: r.exit.Fd()})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	for i := 0; i < 200; i++ {
		_ = c.SetLinkUp(1)
	}
	t.Logf("a no-op link request (what the barrier sends) takes %v", time.Since(start)/200)
}

func TestProfileOfAGluetunRepair(t *testing.T) {
	if os.Getenv("MOLEBRIDGE_PROFILE") == "" {
		t.Skip("set MOLEBRIDGE_PROFILE=1")
	}
	for _, fl := range []struct {
		name  string
		apply func(g *glRig)
	}{
		{"rule 91 without its suppressor -4", func(g *glRig) {
			g.ipx("-4", "rule", "add", "iif", "lo", "to", "192.0.2.0/24", "lookup", "main", "priority", "91")
			g.ipx("-4", "rule", "del", "iif", "lo", "to", "192.0.2.0/24", "lookup", "main", "suppress_prefixlength", "0", "priority", "91")
		}},
		{"a stray host-table route -6", func(g *glRig) { g.ipx("-6", "route", "add", "2001:db8:99::/64", "dev", glExitIf, "table", "51822") }},
		{"rule 88 without iif lo -4", func(g *glRig) {
			g.ipx("-4", "rule", "add", "fwmark", "0x1bd00/0xffffffff", "lookup", "51822", "priority", "88")
			g.ipx("-4", "rule", "del", "iif", "lo", "fwmark", "0x1bd00/0xffffffff", "lookup", "51822", "priority", "88")
		}},
	} {
		t.Run(fl.name, func(t *testing.T) {
			var tk *timingKernel
			g := newGluetunRigWith(t, func(c *rtnl.Conn) mutator.Kernel {
				tk = &timingKernel{Conn: c, count: map[string]int{}, total: map[string]time.Duration{}}
				return tk
			})
			tk.mu.Lock()
			tk.count, tk.total = map[string]int{}, map[string]time.Duration{}
			tk.mu.Unlock()
			tk.mu.Lock()
			tk.origin = time.Now()
			tk.mu.Unlock()
			fl.apply(g)
			t.Logf("the fault was applied %v after the start", time.Since(tk.origin))
			took := g.rig.waitHealthy(2 * time.Second)
			tk.mu.Lock()
			defer tk.mu.Unlock()
			for _, l := range tk.log {
				t.Log(l)
			}
			var ops []string
			for op := range tk.count {
				ops = append(ops, op)
			}
			sort.Strings(ops)
			t.Logf("repaired %v after the change", took)
			for _, op := range ops {
				t.Logf("  %-22s x%-3d %v", op, tk.count[op], tk.total[op])
			}
		})
	}
}
