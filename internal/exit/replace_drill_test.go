//go:build drill && linux

package exit

// tunnel.Manager.Replace in a real namespace (docs/design/multi-provider.md
// step 1): a watcher judges every stable look at the namespace with the
// policy model while the replacement runs, and a failure leaves no link and
// is recovered by the next bring-up on the new config.

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/mutator"
	"github.com/irashack/molebridge/internal/nstest"
	"github.com/irashack/molebridge/internal/policy"
	"github.com/irashack/molebridge/internal/rtnl"
	"github.com/irashack/molebridge/internal/tunnel"
	"github.com/irashack/molebridge/internal/tunnelconf"
)

func drillConf(t *testing.T, provider tunnelconf.Provider, addresses string) *tunnelconf.Conf {
	t.Helper()
	post := "ip route replace default dev %i table 51821"
	pre := "ip route del default dev %i table 51821"
	allowed := "0.0.0.0/0"
	if strings.Contains(addresses, ":") {
		post += "; ip -6 route replace default dev %i table 51821"
		pre += "; ip -6 route del default dev %i table 51821"
		allowed += ", ::/0"
	}
	text := "[Interface]\nPrivateKey = " + zeroKey + "\nAddress = " + addresses + "\nMTU = 1380\nTable = off\nPostUp = " + post + "\nPreDown = " + pre + "\n"
	if provider == tunnelconf.Mullvad {
		text += "\n[Peer]\nPublicKey = " + zeroKey + "\nEndpoint = 198.51.100.10:51820\nAllowedIPs = " + allowed + "\n"
	}
	c, err := tunnelconf.Parse(text, provider, 51821)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type replaceDrill struct {
	t   *testing.T
	ns  *nstest.NS
	mut *mutator.Mutator
	tun *tunnel.Manager
	obs *rtnl.Conn

	mu         sync.Mutex
	violations []string
	looks      int
}

func newReplaceDrill(t *testing.T, from *tunnelconf.Conf) *replaceDrill {
	t.Helper()
	ns := nstest.New(t, "replace")
	if _, err := ns.TryIP("link", "add", "wt0", "type", "wireguard"); err != nil {
		t.Skipf("no WireGuard: %v", err)
	}
	ns.Sysctl("net.ipv6.conf.all.disable_ipv6=0", "net.ipv6.conf.default.disable_ipv6=0")
	cfg, err := contract.ConfigFromEnv(func(k string) string {
		return map[string]string{"OVERLAY_CIDR": "192.0.2.0/24", "OVERLAY6_CIDR": "2001:db8:1::/64", "OVERLAY_IF": "wt0",
			"EXIT_IF": "mullvad", "EXIT_TABLE": "51821"}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	w := &worker{s: &Settings{Routing: cfg, Provider: string(from.Provider), Conf: from, Env: map[string]string{}}}
	conn, err := rtnl.Dial(rtnl.Options{NetNS: ns.Fd()})
	if err != nil {
		t.Fatal(err)
	}
	obs, err := rtnl.Dial(rtnl.Options{NetNS: ns.Fd()})
	if err != nil {
		t.Fatal(err)
	}
	tun, err := tunnel.Open(tunnel.Options{NetNS: ns.Fd()})
	if err != nil {
		t.Fatal(err)
	}
	mut := mutator.New(mutator.Options{Kernel: conn, Spec: w.spec(), GuardRepairs: true, Logf: t.Logf})
	mut.Start()
	t.Cleanup(func() { mut.Close(); conn.Close(); obs.Close(); tun.Close() })
	d := &replaceDrill{t: t, ns: ns, mut: mut, tun: tun, obs: obs}
	if err := mut.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	d.up(w.tunnelParams())
	return d
}

func (d *replaceDrill) up(p tunnel.Params) {
	d.t.Helper()
	ctx := context.Background()
	if err := d.mut.Do(ctx, "bring the tunnel up", func(tx *mutator.Tx) error { return d.tun.UpContext(tx.Context(), p) }); err != nil {
		d.t.Fatalf("bring-up: %v", err)
	}
	if res, err := d.mut.ReconcileNow(ctx, "tunnel up"); err != nil || !res.Verified {
		d.t.Fatalf("not verified with the tunnel up: %v %+v", err, res)
	}
}

// judge is one look: a stable snapshot judged with the live tunnel addresses
// as the only protected return-path addresses.
func (d *replaceDrill) judge(label string) {
	spec := d.mut.Expected()
	spec.ReturnPath = map[rtnl.Family][]netip.Addr{}
	snap, err := d.obs.Take(spec.Interest())
	if err != nil || snap.Unstable {
		return
	}
	v := policy.FromSnapshot(spec, snap).Violations()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.looks++
	if len(v) > 0 {
		d.violations = append(d.violations, fmt.Sprintf("%s: %v", label, v))
	}
}

// replace runs Replace while a watcher judges the namespace.
func (d *replaceDrill) replace(from, to tunnel.Params) error {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				d.judge("during the replacement")
			}
		}
	}()
	err := d.tun.Replace(context.Background(), d.mut, from, to)
	close(stop)
	<-done
	d.judge("after the replacement")
	d.mu.Lock()
	defer d.mu.Unlock()
	d.t.Logf("%d stable looks judged", d.looks)
	for _, v := range d.violations {
		d.t.Error(v)
	}
	d.violations = nil
	return err
}

func (d *replaceDrill) rules(family string) string {
	return strings.ReplaceAll(d.ns.IP(family, "rule", "show"), "\t", " ")
}

func TestReplaceSwapsTheTunnelInANamespace(t *testing.T) {
	from := tunnel.Params{ExitIf: "mullvad", Conf: drillConf(t, tunnelconf.Mullvad, "203.0.113.2/32, 2001:db8:3::2/128")}
	d := newReplaceDrill(t, from.Conf)
	to := tunnel.Params{ExitIf: "mullvad", Conf: drillConf(t, tunnelconf.NordVPN, "203.0.113.7/32")}
	if err := d.replace(from, to); err != nil {
		t.Fatal(err)
	}
	r4, r6 := d.rules("-4"), d.rules("-6")
	if strings.Contains(r4, "203.0.113.2") || strings.Contains(r6, "2001:db8:3::2") {
		t.Errorf("an old pair survived:\n%s\n%s", r4, r6)
	}
	for _, want := range []string{"94: from 203.0.113.7 ipproto icmp lookup 51821", "98: from 203.0.113.7 ipproto icmp unreachable"} {
		if !strings.Contains(r4, want) {
			t.Errorf("rules lack %q:\n%s", want, r4)
		}
	}
	if a := d.ns.IP("addr", "show", "dev", "mullvad"); !strings.Contains(a, "203.0.113.7/32") || strings.Contains(a, "203.0.113.2") {
		t.Errorf("addresses: %s", a)
	}
	if r := d.ns.IP("-4", "route", "show", "table", "51821"); !strings.Contains(r, "default dev mullvad") || !strings.Contains(r, "unreachable default metric 4096") {
		t.Errorf("IPv4 exit table: %s", r)
	}
	if r := d.ns.IP("-6", "route", "show", "table", "51821"); strings.Contains(r, "dev mullvad") || !strings.Contains(r, "unreachable default") {
		t.Errorf("IPv6 exit table: %s", r)
	}
	if res, err := d.mut.ReconcileNow(context.Background(), "after"); err != nil || res.Repaired || !res.Verified {
		t.Errorf("pass after the replacement: %+v %v", res, err)
	}
}

func TestAFailedReplaceInANamespaceFailsClosedAndRecovers(t *testing.T) {
	from := tunnel.Params{ExitIf: "mullvad", Conf: drillConf(t, tunnelconf.NordVPN, "203.0.113.2/32")}
	d := newReplaceDrill(t, from.Conf)
	to := tunnel.Params{ExitIf: "mullvad", Conf: drillConf(t, tunnelconf.Mullvad, "203.0.113.7/32, 2001:db8:3::7/128")}
	// The new link gets IPv6 disabled: its IPv6 address fails after the link,
	// the key and the IPv4 address are in.
	d.ns.Sysctl("net.ipv6.conf.default.disable_ipv6=1")
	err := d.replace(from, to)
	if err == nil {
		t.Skip("this kernel accepted an IPv6 address on an interface with IPv6 disabled")
	}
	if strings.Contains(err.Error(), zeroKey) {
		t.Error("the key in an error")
	}
	if _, lerr := d.ns.TryIP("link", "show", "dev", "mullvad"); lerr == nil {
		t.Error("a link survived the failure")
	}
	for _, f := range []string{"-4", "-6"} {
		if r := d.ns.IP(f, "route", "show", "table", "51821"); !strings.Contains(r, "unreachable default metric 4096") {
			t.Errorf("%s: no fallback: %s", f, r)
		}
	}
	if !strings.Contains(d.rules("-4"), "from 203.0.113.7") || !strings.Contains(d.rules("-6"), "from 2001:db8:3::7") {
		t.Errorf("the new pairs are not in:\n%s\n%s", d.rules("-4"), d.rules("-6"))
	}
	// Recovery, with the fault gone, on the new config.
	d.ns.Sysctl("net.ipv6.conf.default.disable_ipv6=0")
	d.up(to)
	d.judge("after recovery")
	if a := d.ns.IP("addr", "show", "dev", "mullvad"); !strings.Contains(a, "203.0.113.7/32") || !strings.Contains(a, "2001:db8:3::7/128") {
		t.Errorf("recovered with: %s", a)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, v := range d.violations {
		t.Error(v)
	}
}
