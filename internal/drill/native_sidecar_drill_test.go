//go:build drill && linux

package drill

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
	"golang.org/x/sys/unix"
)

func TestNativeSidecarInstallCleanAndRetainedNamespace(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(fmt.Sprintf("restart=%v", restart), func(t *testing.T) {
			r := newNativeSidecarRig(t, restart)
			snap, err := r.obs.Take(r.spec.Interest())
			if err != nil {
				t.Fatal(err)
			}
			if holds, fallback := contract.RoutingStatus(r.spec, snap, contract.RoutingOptions{RequireAddress: true}); !holds || !fallback {
				t.Fatalf("strict status: holds=%v fallback=%v", holds, fallback)
			}
			for _, f := range []rtnl.Family{rtnl.V4, rtnl.V6} {
				zero := 0
				for _, rule := range snap.Rules[f] {
					if rule.Priority == 0 {
						zero++
					}
					if rule.Priority == 1 || rule.Priority == 80 {
						t.Fatalf("sidecar has an overlay guard: %s", rule)
					}
				}
				if zero != 1 {
					t.Fatalf("%s kernel local rule count %d", f, zero)
				}
			}
		})
	}
}

func TestNativeSidecarEachRuleAndForeignMainLookupRepairedWithin250ms(t *testing.T) {
	r := newNativeSidecarRig(t, true)
	rows := map[string]time.Duration{}
	defer func() { logSlowest(t, rows) }()
	for _, f := range []rtnl.Family{rtnl.V4, rtnl.V6} {
		for _, rule := range r.spec.Rules(f) {
			start := time.Now()
			if err := r.obs.DelRule(rule); err != nil {
				t.Fatal(err)
			}
			r.waitHealthy(2 * time.Second)
			took := time.Since(start)
			rows[rule.String()] = took
			if took > repairBudget {
				t.Errorf("%s repaired after %v, budget %v", rule, took, repairBudget)
			}
		}
		start := time.Now()
		if err := r.obs.AddRule(rtnl.Rule{Family: f, Priority: 50, Action: rtnl.FRActToTbl, Table: rtnl.TableMain}); err != nil {
			t.Fatal(err)
		}
		r.waitHealthy(2 * time.Second)
		if took := time.Since(start); took > repairBudget {
			t.Errorf("%s lookup main at 50 repaired after %v, budget %v", f, took, repairBudget)
		}
	}
}

func TestNativeSidecarPacketsWithoutTunnelRoute(t *testing.T) {
	r := newNativeSidecarRig(t, false)
	resume := r.pause()
	defer resume()
	link := uint32(0)
	if snap, err := r.obs.Take(r.spec.Interest()); err != nil {
		t.Fatal(err)
	} else if l, ok := snap.Link(exitIf); ok {
		link = l.Index
	}
	if link == 0 {
		t.Fatal("the tunnel interface is missing")
	}
	for _, f := range []rtnl.Family{rtnl.V4, rtnl.V6} {
		if err := r.obs.DelRoute(contract.TunnelRoute(f, table, link)); err != nil {
			t.Fatal(err)
		}
		dst, lan := target4, sidecarLAN4
		if f == rtnl.V6 {
			dst, lan = target6, sidecarLAN6
		}
		err := sidecarSend(r.exit, f, 0, dst, 9)
		if !errors.Is(err, unix.EHOSTUNREACH) && !errors.Is(err, unix.ENETUNREACH) {
			t.Fatalf("%s unmarked UDP with no tunnel route: %v", f, err)
		}
		for _, tc := range []struct {
			name string
			dst  string
			mark uint32
		}{{"LAN", lan, 0}, {"control", dst, r.spec.Config.ControlMark}} {
			c := sidecarReceiver(t, r.outside, f, tc.dst)
			if err := sidecarSend(r.exit, f, tc.mark, tc.dst, c.LocalAddr().(*net.UDPAddr).Port); err != nil {
				t.Fatalf("%s %s send: %v", f, tc.name, err)
			}
			if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 128)
			if _, _, err := c.ReadFromUDP(buf); err != nil {
				t.Fatalf("%s %s did not arrive through the host interface: %v", f, tc.name, err)
			}
			_ = c.Close()
		}
	}
}
