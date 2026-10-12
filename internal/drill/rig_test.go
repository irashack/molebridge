//go:build drill && linux

package drill

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/bootclock"
	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/mutator"
	"github.com/irashack/molebridge/internal/nstest"
	"github.com/irashack/molebridge/internal/rtnl"
	"github.com/irashack/molebridge/internal/watch"
)

// The topology of tools/check-routing.sh: a client behind the overlay
// interface, the host's route to the outside, and the tunnel's far end, with
// the same fictitious destination reachable by both paths so that a leak
// shows as success where failure is expected. The documentation ranges only.
const (
	overlayIf = "wt0"
	exitIf    = "mullvad"
	table     = 51821

	target4 = "198.51.100.100"
	target6 = "2001:db8:2::100"
)

var (
	tunnel4 = netip.MustParseAddr("203.0.113.1")
	tunnel6 = netip.MustParseAddr("2001:db8:3::1")
)

type rig struct {
	t                          *testing.T
	client, exit, outside, tun *nstest.NS
	spec                       contract.Spec
	mut                        *mutator.Mutator
	watcher                    *watch.Watcher
	sub                        *rtnl.Subscriber
	obs                        *rtnl.Conn
	logs                       *logs
	cancel                     context.CancelFunc
	wg                         sync.WaitGroup
}

type logs struct {
	mu    sync.Mutex
	lines []string
}

func (l *logs) logf(format string, a ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, fmt.Sprintf(format, a...))
	l.mu.Unlock()
}

func (l *logs) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func configure(ns *nstest.NS, dev, v4, v6 string) {
	ns.IP("addr", "add", v4, "dev", dev)
	ns.IP("-6", "addr", "add", v6, "dev", dev, "nodad")
	ns.IP("link", "set", dev, "up")
}

// topology builds the four namespaces and wires them; the exit has no routing
// contract yet.
func topology(t *testing.T) (client, exit, outside, tun *nstest.NS) {
	t.Helper()
	client = nstest.New(t, "client")
	exit = nstest.New(t, "exit")
	outside = nstest.New(t, "outside")
	tun = nstest.New(t, "tunnel")
	for _, ns := range []*nstest.NS{client, exit, outside, tun} {
		ns.Sysctl("net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0", "net.ipv6.conf.default.accept_dad=0")
	}
	exit.Veth(overlayIf, client, "client0")
	exit.Veth("eth0", outside, "outside0")
	exit.Veth(exitIf, tun, "tunnel0")
	exit.IP("link", "set", overlayIf, "address", "02:00:00:00:01:01")
	client.IP("link", "set", "client0", "address", "02:00:00:00:01:02")
	configure(exit, overlayIf, "192.0.2.1/24", "2001:db8:1::1/64")
	configure(client, "client0", "192.0.2.2/24", "2001:db8:1::2/64")
	configure(exit, "eth0", "198.51.100.1/24", "2001:db8:2::1/64")
	configure(outside, "outside0", "198.51.100.2/24", "2001:db8:2::2/64")
	configure(exit, exitIf, "203.0.113.1/24", "2001:db8:3::1/64")
	configure(tun, "tunnel0", "203.0.113.2/24", "2001:db8:3::2/64")
	// The overlay link is narrower than the tunnel, as with a real WireGuard
	// pair, so tunnel replies can need fragmentation and the exit must send
	// ICMP errors back through the tunnel.
	exit.IP("link", "set", overlayIf, "mtu", "1280")
	client.IP("link", "set", "client0", "mtu", "1280")
	exit.IP("link", "set", exitIf, "mtu", "1420")
	tun.IP("link", "set", "tunnel0", "mtu", "1420")
	tun.IP("link", "set", "tunnel0", "address", "02:00:00:00:03:02")
	exit.Sysctl("net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1", "net.ipv4.icmp_errors_use_inbound_ifaddr=1")
	client.IP("route", "add", "default", "via", "192.0.2.1")
	client.IP("-6", "route", "add", "default", "via", "2001:db8:1::1")
	exit.IP("route", "add", "default", "via", "198.51.100.2")
	exit.IP("-6", "route", "add", "default", "via", "2001:db8:2::2")
	outside.IP("route", "add", "192.0.2.0/24", "via", "198.51.100.1")
	outside.IP("-6", "route", "add", "2001:db8:1::/64", "via", "2001:db8:2::1")
	tun.IP("route", "add", "192.0.2.0/24", "via", "203.0.113.1")
	tun.IP("-6", "route", "add", "2001:db8:1::/64", "via", "2001:db8:3::1")
	// Real WireGuard has no neighbor discovery; these veth stand-ins do, and
	// the local-delivery guard keeps ARP and ND for the exit's own addresses
	// away from the overlay, so fixed entries stand in.
	for _, a := range []string{"192.0.2.1", "2001:db8:1::1"} {
		client.IP("neigh", "replace", a, "lladdr", "02:00:00:00:01:01", "nud", "permanent", "dev", "client0")
	}
	for _, a := range []string{"192.0.2.2", "2001:db8:1::2"} {
		exit.IP("neigh", "replace", a, "lladdr", "02:00:00:00:01:02", "nud", "permanent", "dev", overlayIf)
	}
	// The same fictitious destination on both paths: a leak would turn an
	// expected failure into a success.
	outside.IP("addr", "add", target4+"/32", "dev", "outside0")
	outside.IP("-6", "addr", "add", target6+"/128", "dev", "outside0", "nodad")
	tun.IP("addr", "add", target4+"/32", "dev", "tunnel0")
	tun.IP("-6", "addr", "add", target6+"/128", "dev", "tunnel0", "nodad")
	pinNeighbors(exit)
	// Counters of what reaches each far side from the overlay.
	for _, ns := range []*nstest.NS{outside, tun} {
		script := `table inet mb {
  counter client {}
  chain pre {
    type filter hook prerouting priority raw; policy accept;
    ip saddr 192.0.2.0/24 counter name client
    ip6 saddr 2001:db8:1::/64 counter name client
  }
}
`
		if out, err := ns.ExecInput(script, "nft", "-f", "-"); err != nil {
			t.Fatalf("nft: %v\n%s", err, out)
		}
	}
	return
}

// pinNeighbors models a point-to-point tunnel without off-subnet ARP/NDP.
func pinNeighbors(exit *nstest.NS) {
	exit.TryIP("-4", "neigh", "replace", target4, "lladdr", "02:00:00:00:03:02", "nud", "permanent", "dev", exitIf)
	exit.TryIP("-6", "neigh", "replace", target6, "lladdr", "02:00:00:00:03:02", "nud", "permanent", "dev", exitIf)
}

type rigOptions struct {
	spec     func(contract.Spec) contract.Spec
	interval time.Duration
	buffer   int
	// source wraps the event source (to stall the watcher).
	source func(watch.Source) watch.Source
	guard  *bool
}

func newRig(t *testing.T, mod ...func(*rigOptions)) *rig {
	t.Helper()
	o := rigOptions{interval: 30 * time.Second}
	for _, m := range mod {
		m(&o)
	}
	r := &rig{t: t, logs: &logs{}}
	r.client, r.exit, r.outside, r.tun = topology(t)
	cfg, err := contract.ConfigFromEnv(func(k string) string {
		return map[string]string{"OVERLAY_CIDR": "192.0.2.0/24", "OVERLAY6_CIDR": "2001:db8:1::/64", "OVERLAY_IF": overlayIf,
			"EXIT_IF": exitIf, "EXIT_TABLE": fmt.Sprint(table)}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	r.spec = contract.Spec{Config: cfg, ReturnPath: map[rtnl.Family][]netip.Addr{rtnl.V4: {tunnel4}, rtnl.V6: {tunnel6}}}
	if o.spec != nil {
		r.spec = o.spec(r.spec)
	}
	// The order the worker uses: subscribe before the first look at the
	// kernel, so no change between the dump and the watch is missed.
	r.sub, err = rtnl.Subscribe(rtnl.Options{NetNS: r.exit.Fd(), ReadBuffer: o.buffer})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := rtnl.Dial(rtnl.Options{NetNS: r.exit.Fd()})
	if err != nil {
		t.Fatal(err)
	}
	r.obs, err = rtnl.Dial(rtnl.Options{NetNS: r.exit.Fd()})
	if err != nil {
		t.Fatal(err)
	}
	guard := !r.spec.Config.IsGluetun()
	if o.guard != nil {
		guard = *o.guard
	}
	r.mut = mutator.New(mutator.Options{Kernel: conn, Spec: r.spec, GuardRepairs: guard, Logf: r.logs.logf})
	r.mut.Start()
	if err := r.mut.Install(context.Background()); err != nil {
		t.Fatalf("install: %v\n%s", err, r.logs.text())
	}
	var src watch.Source = r.sub
	if o.source != nil {
		src = o.source(src)
	}
	r.watcher = watch.New(watch.Config{Source: src, Mutator: r.mut, Interval: o.interval, IdleStep: 100 * time.Millisecond,
		Clock: bootclock.System(), Tables: r.spec.Interest().Tables,
		Links: []string{r.spec.Config.ExitIf, r.spec.Config.OverlayIf}, Logf: r.logs.logf})
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		_ = r.watcher.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		r.wg.Wait()
		r.mut.Close()
		_ = conn.Close()
		_ = r.obs.Close()
		if t.Failed() {
			t.Logf("repair log:\n%s", r.logs.text())
			for _, f := range []string{"-4", "-6"} {
				out, _ := r.exit.TryIP(f, "rule", "show")
				t.Logf("%s rules:\n%s", f, out)
			}
		}
	})
	// The tunnel's default route comes from the first pass that sees the
	// interface up; wait for it so the rig starts connected.
	r.waitHealthy(2 * time.Second)
	return r
}

// healthy: both families hold the whole contract and no guard is left, judged
// from an independent socket.
func (r *rig) healthy() bool {
	snap, err := r.obs.Take(r.spec.Interest())
	if err != nil {
		return false
	}
	for _, f := range []rtnl.Family{rtnl.V4, rtnl.V6} {
		p := r.spec.PlanFamily(snap, f, contract.PlanInput{})
		if !p.Healthy() {
			return false
		}
		for _, rule := range snap.Rules[f] {
			if rule.Priority == contract.PrioTempGuard {
				return false
			}
		}
	}
	return true
}

// waitHealthy polls until the contract holds again and returns how long that
// took from now.
func (r *rig) waitHealthy(within time.Duration) time.Duration {
	r.t.Helper()
	start := time.Now()
	for {
		if r.healthy() {
			return time.Since(start)
		}
		if time.Since(start) > within {
			r.t.Fatalf("the contract did not hold again within %v\nrepair log:\n%s", within, r.logs.text())
		}
		time.Sleep(time.Millisecond)
	}
}

// ping reports whether the client reaches the shared destination.
func (r *rig) ping(f string) bool {
	dst := target4
	if f == "-6" {
		dst = target6
	}
	_, err := r.client.Exec("ping", f, "-c", "1", "-W", "1", dst)
	return err == nil
}

// counter reads the packets from the overlay that reached a far side.
func counter(t *testing.T, ns *nstest.NS) int {
	t.Helper()
	out, err := ns.Exec("nft", "list", "counter", "inet", "mb", "client")
	if err != nil {
		t.Fatalf("nft: %v\n%s", err, out)
	}
	fields := strings.Fields(out)
	for i, f := range fields {
		if f == "packets" && i+1 < len(fields) {
			var n int
			fmt.Sscan(fields[i+1], &n)
			return n
		}
	}
	t.Fatalf("no counter in %q", out)
	return 0
}

func resetCounter(t *testing.T, ns *nstest.NS) {
	t.Helper()
	if out, err := ns.Exec("nft", "reset", "counter", "inet", "mb", "client"); err != nil {
		t.Fatalf("nft: %v\n%s", err, out)
	}
}

// flood sends a steady stream of pings from the client in both families until
// the test ends, so that a moment of leakage anywhere in a repair reaches the
// outside counter.
func (r *rig) flood() {
	r.t.Helper()
	for _, args := range [][]string{
		{"ping", "-4", "-i", "0.003", "-W", "1", "-q", target4},
		{"ping", "-6", "-i", "0.003", "-W", "1", "-q", target6},
	} {
		r.client.Start(args[0], args[1:]...)
	}
	time.Sleep(60 * time.Millisecond)
}

// held asserts nothing from the overlay reached the host path.
func (r *rig) held(what string) {
	r.t.Helper()
	if n := counter(r.t, r.outside); n != 0 {
		r.t.Errorf("%s: %d packets from the overlay left through the host interface", what, n)
	}
}

// pause stops the mutation owner from running anything: a held operation.
func (r *rig) pause() (resume func()) {
	r.t.Helper()
	gate := make(chan struct{})
	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = r.mut.Do(context.Background(), "pause", func(tx *mutator.Tx) error { close(started); <-gate; return nil })
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		r.t.Fatal("the owner did not start the held operation")
	}
	var once sync.Once
	return func() { once.Do(func() { close(gate); <-done }) }
}

// connected reports whether the client reaches the destination in both
// families, trying again for a few seconds: the veth stand-in for the tunnel
// resolves neighbors, and an entry that failed while a fault stood needs one
// more packet to resolve again. Real WireGuard has no such state.
func (r *rig) connected() (ok bool, which string) {
	deadline := time.Now().Add(4 * time.Second)
	for _, f := range []string{"-4", "-6"} {
		for !r.ping(f) {
			if time.Now().After(deadline) {
				return false, f
			}
		}
	}
	return true, ""
}
