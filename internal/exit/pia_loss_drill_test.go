//go:build drill && linux

package exit

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/applier"
	"github.com/irashack/molebridge/internal/mutator"
	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/tunnel"
)

// offlineSystem is the exit's real System with the network taken away: the
// pipeline's HTTP goes nowhere. The sysctl the exit's namespace has is set in
// the rig's namespace, but ReadSysctl reads the process's own, so the rig says
// what the exit's namespace holds.
type offlineSystem struct{ *KernelSystem }

func (offlineSystem) ReadSysctl(context.Context, string) (string, error) { return "1\n", nil }

func (offlineSystem) Fetch(context.Context, netx.Request) (netx.Response, error) {
	return netx.Response{}, errors.New("offline")
}

// A PIA exit registered an address; the tunnel interface is deleted and the
// worker recreates it from the addressless config. The provider's per-tick
// reconcile and the mutation owner must settle, not fight: the lost address's
// pair goes, the owner stops expecting it, nothing is added or deleted again,
// the exit is judged intact (as 0.7.0 judged an addressless config) so the
// pipeline can register, and the new registration gets its pair.
func TestDrillPIATunnelLossDoesNotMakeTheOwnerFight(t *testing.T) {
	ks, ns, logs := sysRigLogged(t)
	ns.Sysctl("net.ipv4.icmp_errors_use_inbound_ifaddr=1")
	ctx := context.Background()
	lost, fresh := netip.MustParseAddr("203.0.113.11"), netip.MustParseAddr("203.0.113.12")

	// The provider's pipeline over the real System.
	exit := applier.Exit{ExitIf: "mullvad", OverlayIf: "wt0", Table: "51821", Overlay: "192.0.2.0/24", Kind: "overlay"}
	prov, err := applier.NewPIAFromEnv(exit, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	a, err := applier.New(applier.Config{StateDir: t.TempDir(), Exit: exit, Provider: prov, System: offlineSystem{ks},
		Publish: func(*applier.Record) error { return nil }, Log: func(string) {}})
	if err != nil {
		t.Fatal(err)
	}

	// A registration: the address and its pair, by the address transaction.
	if err := ks.ChangePIAAddress(ctx, netip.Addr{}, lost); err != nil {
		t.Fatal(err)
	}
	pair := func() string {
		out, _ := ns.TryIP("-4", "rule", "show")
		var lines []string
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, "94:") || strings.HasPrefix(l, "98:") {
				lines = append(lines, strings.Join(strings.Fields(l), " "))
			}
		}
		return strings.Join(lines, "; ")
	}
	if p := pair(); !strings.Contains(p, "94: from 203.0.113.11") || !strings.Contains(p, "98: from 203.0.113.11") {
		t.Fatalf("the registration's pair: %q", p)
	}
	if protected, _ := a.DefaultRoutingStatus(ctx, true); !protected {
		t.Fatal("a registered exit is not intact")
	}

	// `ip link del`, and the worker's recreation from the addressless config.
	ns.IP("link", "del", "mullvad")
	if err := ks.Mut.Do(ctx, "bring the tunnel up", func(tx *mutator.Tx) error {
		return ks.Tun.UpContext(tx.Context(), tunnel.Params{ExitIf: "mullvad", Conf: ks.S.Conf})
	}); err != nil {
		t.Fatal(err)
	}
	ks.invalidate()
	if addrs, err := ks.TunnelAddresses(ctx); err != nil || len(addrs) != 0 {
		t.Fatalf("the recreated tunnel has addresses %v %v", addrs, err)
	}

	// The provider's ticks. The first retires; none after it does anything.
	if _, err := a.Tick(ctx); err != nil {
		t.Logf("tick: %v", err)
	}
	if p := pair(); p != "" {
		t.Fatalf("the lost address's pair survived a tick: %q", p)
	}
	if got := ks.Mut.Expected().ReturnPath[4]; len(got) != 0 {
		t.Fatalf("the owner still expects %v", got)
	}
	marks := logs.len()
	adds, dels := logs.count("added IPv4 rule 9"), logs.count("removed IPv4 rule 9")
	for i := 0; i < 8; i++ {
		if _, err := a.Tick(ctx); err != nil {
			t.Logf("tick: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
		if res, err := ks.Mut.ReconcileNow(ctx, "tick"); err != nil || !res.Verified {
			t.Fatalf("pass %d: %+v %v", i, res, err)
		}
	}
	if logs.count("added IPv4 rule 9") != adds || logs.count("removed IPv4 rule 9") != dels {
		logs.mu.Lock()
		t.Errorf("rules were added or removed again after the retirement: %v", logs.lines[marks:])
		logs.mu.Unlock()
	}
	if p := pair(); p != "" {
		t.Errorf("a pair came back: %q", p)
	}
	// The gate's judgment (no address required, as for an addressless config)
	// passes, so the pipeline goes on to register; the strict one with an
	// address required cannot, there is none.
	if protected, fallback := a.DefaultRoutingStatus(ctx, false); !protected || !fallback {
		p6, f6, err6 := ks.RoutingStatus(ctx, 6, "")
		out4, _ := ns.TryIP("-4", "rule", "show")
		out6, _ := ns.TryIP("-6", "rule", "show")
		rt4, _ := ns.TryIP("-4", "route", "show", "table", "51821")
		t.Errorf("the addressless exit is not intact: protected=%v fallback=%v; v6 %v %v %v\nv4 rules:\n%s\nv6 rules:\n%s\nv4 table:\n%s", protected, fallback, p6, f6, err6, out4, out6, rt4)
	}
	if protected, _ := a.DefaultRoutingStatus(ctx, true); protected {
		t.Error("with an address required there is none")
	}
	if p, f, err := ks.RoutingStatus(ctx, 4, ""); err != nil || !p || !f {
		t.Errorf("RoutingStatus without an address: %v %v %v", p, f, err)
	}

	// The registration that follows gets its pair by the address transaction.
	if err := ks.ChangePIAAddress(ctx, netip.Addr{}, fresh); err != nil {
		t.Fatal(err)
	}
	if p := pair(); !strings.Contains(p, "94: from 203.0.113.12") || !strings.Contains(p, "98: from 203.0.113.12") || strings.Contains(p, "203.0.113.11") {
		t.Errorf("after the new registration: %q", p)
	}
	if protected, _ := a.DefaultRoutingStatus(ctx, true); !protected {
		t.Error("the re-registered exit is not intact")
	}
	// And a live address is never retired by the provider's tick.
	if _, err := a.Tick(ctx); err != nil {
		t.Logf("tick: %v", err)
	}
	if p := pair(); !strings.Contains(p, "203.0.113.12") {
		t.Errorf("a live address's pair went: %q", p)
	}
}
