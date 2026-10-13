//go:build drill && linux

package drill

// The gluetun backend's namespaces (tools/check-routing.sh, gluetun_drills):
// separate namespaces stand in for gluetun's, with its rules 98 (local
// subnet), 100 (inbound) and 101 (`not fwmark 51820 lookup 51820`) and table
// 51820 through the tunnel interface, and NetBird's 105 and 110. Forwarded
// packets carry marks set in the exit's prerouting; locally generated ones come
// from a socket with SO_MARK, like NetBird's dialers. Counters on the far side
// of the host link and of the tunnel show where each packet went.

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/irashack/molebridge/internal/bootclock"
	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/mutator"
	"github.com/irashack/molebridge/internal/nstest"
	"github.com/irashack/molebridge/internal/rtnl"
	"github.com/irashack/molebridge/internal/watch"
)

const (
	glExitIf  = "wg0"
	glTarget4 = "198.51.100.100"
	glTarget6 = "2001:db8:4::100"
)

type glRig struct {
	*rig
}

func glTunnelUp(r *rig, address string) {
	t := r.t
	r.exit.Veth(glExitIf, r.tun, "tunnel0")
	r.tun.IP("link", "set", "tunnel0", "address", "02:00:00:00:13:02")
	r.exit.IP("addr", "add", address+"/28", "dev", glExitIf)
	r.exit.IP("-6", "addr", "add", "2001:db8:3::1/64", "dev", glExitIf, "nodad")
	r.tun.IP("addr", "add", "203.0.113.2/28", "dev", "tunnel0")
	r.tun.IP("-6", "addr", "add", "2001:db8:3::2/64", "dev", "tunnel0", "nodad")
	r.tun.IP("addr", "add", glTarget4+"/32", "dev", "tunnel0")
	r.tun.IP("-6", "addr", "add", glTarget6+"/128", "dev", "tunnel0", "nodad")
	r.exit.IP("link", "set", glExitIf, "up")
	r.tun.IP("link", "set", "tunnel0", "up")
	r.tun.IP("route", "replace", "192.0.2.0/24", "via", address)
	r.tun.IP("-6", "route", "replace", "2001:db8:1::/64", "via", "2001:db8:3::1")
	// gluetun's own table: the tunnel default.
	for _, f := range []string{"-4", "-6"} {
		r.exit.IP(f, "route", "replace", "default", "dev", glExitIf, "table", "51820")
	}
	r.exit.IP("-4", "neigh", "replace", glTarget4, "lladdr", "02:00:00:00:13:02", "nud", "permanent", "dev", glExitIf)
	r.exit.IP("-6", "neigh", "replace", glTarget6, "lladdr", "02:00:00:00:13:02", "nud", "permanent", "dev", glExitIf)
	// Real WireGuard sends whatever its route gives it; this veth stand-in
	// would first ask for the next hop. The client's overlay addresses are
	// reachable on wg0 only when something sends overlay traffic into the
	// tunnel by mistake, which the rule 91/92 drill must be able to see.
	r.exit.IP("-4", "neigh", "replace", "192.0.2.2", "lladdr", "02:00:00:00:13:02", "nud", "permanent", "dev", glExitIf)
	r.exit.IP("-6", "neigh", "replace", "2001:db8:1::2", "lladdr", "02:00:00:00:13:02", "nud", "permanent", "dev", glExitIf)
	_ = t
}

func newGluetunRig(t *testing.T) *glRig { return newGluetunRigWith(t, nil) }

// newGluetunRigWith is newGluetunRig with a decorator between the owner and
// the kernel connection.
func newGluetunRigWith(t *testing.T, wrap func(*rtnl.Conn) mutator.Kernel) *glRig {
	t.Helper()
	r := &rig{t: t, logs: &logs{}, wrap: wrap}
	r.client = nstest.New(t, "gclient")
	r.exit = nstest.New(t, "gexit")
	r.outside = nstest.New(t, "goutside")
	r.tun = nstest.New(t, "gtunnel")
	for _, ns := range []*nstest.NS{r.client, r.exit, r.outside, r.tun} {
		ns.Sysctl("net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0", "net.ipv6.conf.default.accept_dad=0")
	}
	// The provider's side ends traffic, it doesn't route it on.
	r.tun.Sysctl("net.ipv4.ip_forward=0", "net.ipv6.conf.all.forwarding=0")
	r.exit.Veth(overlayIf, r.client, "client0")
	r.exit.Veth("eth0", r.outside, "outside0")
	r.exit.IP("link", "set", overlayIf, "address", "02:00:00:00:11:01")
	r.client.IP("link", "set", "client0", "address", "02:00:00:00:11:02")
	configure(r.exit, overlayIf, "192.0.2.1/24", "2001:db8:1::1/64")
	configure(r.client, "client0", "192.0.2.2/24", "2001:db8:1::2/64")
	configure(r.exit, "eth0", "198.51.100.1/28", "2001:db8:2::1/64")
	configure(r.outside, "outside0", "198.51.100.2/28", "2001:db8:2::2/64")
	r.outside.IP("addr", "add", glTarget4+"/32", "dev", "outside0")
	r.outside.IP("-6", "addr", "add", glTarget6+"/128", "dev", "outside0", "nodad")
	r.exit.Sysctl("net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1", "net.ipv4.icmp_errors_use_inbound_ifaddr=1")
	r.client.IP("route", "add", "default", "via", "192.0.2.1")
	r.client.IP("-6", "route", "add", "default", "via", "2001:db8:1::1")
	r.exit.IP("route", "add", "default", "via", "198.51.100.2")
	r.exit.IP("-6", "route", "add", "default", "via", "2001:db8:2::2")
	for _, a := range []string{"192.0.2.1", "2001:db8:1::1"} {
		r.client.IP("neigh", "replace", a, "lladdr", "02:00:00:00:11:01", "nud", "permanent", "dev", "client0")
	}
	for _, a := range []string{"192.0.2.2", "2001:db8:1::2"} {
		r.exit.IP("neigh", "replace", a, "lladdr", "02:00:00:00:11:02", "nud", "permanent", "dev", overlayIf)
	}
	glTunnelUp(r, "203.0.113.1")
	// gluetun's rules and NetBird's, as they stand when the guard starts.
	r.exit.IP("-4", "rule", "add", "to", "198.51.100.0/28", "lookup", "main", "priority", "98")
	r.exit.IP("-6", "rule", "add", "to", "2001:db8:2::/64", "lookup", "main", "priority", "98")
	r.exit.IP("-4", "rule", "add", "from", "198.51.100.1", "lookup", "200", "priority", "100")
	r.exit.IP("-6", "rule", "add", "from", "2001:db8:2::1", "lookup", "200", "priority", "100")
	r.exit.IP("-4", "route", "add", "default", "via", "198.51.100.2", "dev", "eth0", "table", "200")
	r.exit.IP("-6", "route", "add", "default", "via", "2001:db8:2::2", "dev", "eth0", "table", "200")
	for _, f := range []string{"-4", "-6"} {
		r.exit.IP(f, "rule", "add", "not", "fwmark", "51820", "lookup", "51820", "priority", "101")
		r.exit.IP(f, "rule", "add", "lookup", "main", "suppress_prefixlength", "0", "priority", "105")
		r.exit.IP(f, "rule", "add", "not", "fwmark", "0x1bd00", "lookup", "7120", "priority", "110")
	}
	// Counters: "client" counts overlay-sourced packets, "local" anything
	// else sent to the shared destination.
	for _, ns := range []*nstest.NS{r.outside, r.tun} {
		script := fmt.Sprintf(`table inet gl {
  counter client {}
  counter local {}
  chain pre {
    type filter hook prerouting priority raw; policy accept;
    ip saddr 192.0.2.0/24 counter name client
    ip6 saddr 2001:db8:1::/64 counter name client
    ip daddr %s ip saddr != 192.0.2.0/24 counter name local
    ip6 daddr %s ip6 saddr != 2001:db8:1::/64 counter name local
  }
}
`, glTarget4, glTarget6)
		if out, err := ns.ExecInput(script, "nft", "-f", "-"); err != nil {
			t.Fatalf("nft: %v\n%s", err, out)
		}
	}
	return &glRig{startStack(t, r, func(s contract.Spec) contract.Spec { return s })}
}

// startStack subscribes, installs and starts the watcher: the same order as
// the native rig.
func startStack(t *testing.T, r *rig, _ func(contract.Spec) contract.Spec) *rig {
	cfg, err := contract.ConfigFromEnv(func(k string) string {
		return map[string]string{"TUNNEL_BACKEND": "gluetun", "OVERLAY_CIDR": "192.0.2.0/24", "OVERLAY6_CIDR": "2001:db8:1::/64",
			"OVERLAY_IF": overlayIf, "EXIT_IF": glExitIf, "EXIT_TABLE": fmt.Sprint(table), "HOST_IF": "eth0", "HOST_TABLE": "51822",
			"CONTROL_MARK": "0x1bd00"}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	r.spec = contract.Spec{Config: cfg}
	r.sub, err = rtnl.Subscribe(rtnl.Options{NetNS: r.exit.Fd()})
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
	r.mut = mutator.New(mutator.Options{Kernel: r.kernel(conn), Spec: r.spec, GuardRepairs: false, Logf: r.logs.logf})
	r.mut.Start()
	if err := r.mut.Install(context.Background()); err != nil {
		t.Fatalf("install: %v\n%s", err, r.logs.text())
	}
	r.watcher = watch.New(watch.Config{Source: r.sub, Mutator: r.mut, Interval: 30 * time.Second, IdleStep: 100 * time.Millisecond,
		Clock: bootclock.System(), Tables: r.spec.Interest().Tables,
		Links: []string{glExitIf, overlayIf, "eth0"}, Logf: r.logs.logf})
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.wg.Add(1)
	go func() { defer r.wg.Done(); _ = r.watcher.Run(ctx) }()
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
				out, _ = r.exit.TryIP(f, "route", "show", "table", "all")
				t.Logf("%s routes:\n%s", f, out)
			}
		}
	})
	return r
}

// healthyGluetun: the plan is healthy for both families and the strict
// judgments agree.
func (g *glRig) strict() (ok bool, why string) {
	snap, err := g.obs.Take(g.spec.Interest())
	if err != nil {
		return false, err.Error()
	}
	link, _ := snap.Link(glExitIf)
	host, _ := snap.Link("eth0")
	for _, f := range []rtnl.Family{rtnl.V4, rtnl.V6} {
		addr, _ := snap.GlobalAddr(glExitIf, f)
		ready, fallback := contract.FamilyStatus(g.spec, f, snap.Rules[f], snap.RoutesInTable(f, table), contract.StatusOptions{
			TunnelAddress: addr, ExitIfIndex: link.Index})
		if !ready || !fallback {
			return false, fmt.Sprintf("%s rules/exit: ready=%v fallback=%v", f, ready, fallback)
		}
		if !contract.HostTableStatus(snap.RoutesInTable(f, 51822), host.Index, f, snap.RoutesInTable(f, rtnl.TableMain), true) {
			return false, fmt.Sprintf("%s host table", f)
		}
	}
	return true, ""
}

func (g *glRig) waitStrict(within time.Duration) time.Duration {
	g.t.Helper()
	start := time.Now()
	for {
		ok, why := g.strict()
		if ok {
			return time.Since(start)
		}
		if time.Since(start) > within {
			g.t.Fatalf("the gluetun contract did not hold again within %v: %s\n%s", within, why, g.logs.text())
		}
		time.Sleep(time.Millisecond)
	}
}

func glCount(t *testing.T, ns *nstest.NS, name string) int {
	t.Helper()
	out, err := ns.Exec("nft", "list", "counter", "inet", "gl", name)
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
	return 0
}

func (g *glRig) resetCounters() {
	for _, ns := range []*nstest.NS{g.outside, g.tun} {
		for _, name := range []string{"client", "local"} {
			if out, err := ns.Exec("nft", "reset", "counter", "inet", "gl", name); err != nil {
				g.t.Fatalf("nft: %v\n%s", err, out)
			}
		}
	}
}

// markForwarded sets the mark on packets arriving on the overlay (0 removes it).
func (g *glRig) markForwarded(mark string) {
	g.t.Helper()
	g.exit.Exec("nft", "delete", "table", "inet", "glmark")
	if mark == "0" {
		return
	}
	script := fmt.Sprintf(`table inet glmark {
  chain pre {
    type filter hook prerouting priority mangle; policy accept;
    iifname "wt0" meta mark set %s
  }
}
`, mark)
	if out, err := g.exit.ExecInput(script, "nft", "-f", "-"); err != nil {
		g.t.Fatalf("nft: %v\n%s", err, out)
	}
}

// forward reports whether a client packet gets an answer.
func (g *glRig) forward(family string) bool {
	dst := glTarget4
	if family == "-6" {
		dst = glTarget6
	}
	_, err := g.client.Exec("ping", family, "-c", "1", "-W", "1", dst)
	return err == nil
}

// forwarding asserts where forwarded packets with each mark go: "tunnel" (into
// the tunnel, never the host side) or "blocked" (nowhere).
func (g *glRig) forwarding(want, what string) {
	g.t.Helper()
	for _, mark := range []string{"0", "0x1bd00", "0x1bd21", "51820"} {
		g.markForwarded(mark)
		for _, family := range []string{"-4", "-6"} {
			g.resetCounters()
			got := "blocked"
			if g.forward(family) {
				got = "tunnel"
			}
			if n := glCount(g.t, g.outside, "client"); n != 0 {
				g.t.Errorf("%s: a forwarded packet with mark %s left through the host interface (%s)", what, mark, family)
			}
			if got != want {
				g.t.Errorf("%s: forwarded packet with mark %s: want %s, got %s (%s)", what, mark, want, got, family)
			}
			if want == "tunnel" && glCount(g.t, g.tun, "client") == 0 {
				g.t.Errorf("%s: mark %s was answered without crossing the tunnel (%s)", what, mark, family)
			}
		}
	}
	g.markForwarded("0")
}

// send writes three UDP datagrams from a socket in the exit namespace with the
// given mark, and says whether routing refused them.
func (g *glRig) send(family, mark string, dst string) (refused bool) {
	g.t.Helper()
	var m int
	fmt.Sscan(mark, &m)
	if strings.HasPrefix(mark, "0x") {
		fmt.Sscanf(mark, "0x%x", &m)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	_ = g.exit.Do(func() error {
		defer wg.Done()
		network := "udp4"
		if family == "-6" {
			network = "udp6"
		}
		d := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			if m != 0 {
				if err := c.Control(func(fd uintptr) { serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, m) }); err != nil {
					return err
				}
			}
			return serr
		}}
		host := dst
		if strings.Contains(dst, ":") {
			host = "[" + dst + "]"
		}
		conn, err := d.Dial(network, host+":9")
		if err != nil {
			refused = true
			return nil
		}
		defer conn.Close()
		for i := 0; i < 3; i++ {
			if _, err := conn.Write([]byte("x")); err != nil {
				refused = true
			}
		}
		return nil
	})
	wg.Wait()
	return refused
}

// localPath says where a datagram the exit itself sends with this mark goes:
// host, tunnel or none.
func (g *glRig) localPath(family, mark string) string {
	g.t.Helper()
	g.resetCounters()
	dst := glTarget4
	if family == "-6" {
		dst = glTarget6
	}
	refused := g.send(family, mark, dst)
	time.Sleep(150 * time.Millisecond)
	host, tun := glCount(g.t, g.outside, "local"), glCount(g.t, g.tun, "local")
	switch {
	case host != 0 && tun == 0:
		return "host"
	case tun != 0 && host == 0:
		return "tunnel"
	case host == 0 && tun == 0 && refused:
		return "none"
	}
	return fmt.Sprintf("mixed:%v:%d:%d", refused, host, tun)
}

var _ = netip.Addr{}

// pause is the native rig's, reachable from the gluetun rig.
func (g *glRig) pause() func() { return g.rig.pause() }

func (g *glRig) flood() {
	g.t.Helper()
	for _, args := range [][]string{
		{"ping", "-4", "-i", "0.003", "-W", "1", "-q", glTarget4},
		{"ping", "-6", "-i", "0.003", "-W", "1", "-q", glTarget6},
	} {
		g.client.Start(args[0], args[1:]...)
	}
	time.Sleep(60 * time.Millisecond)
}
