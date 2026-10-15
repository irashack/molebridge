//go:build drill && linux

package drill

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/mutator"
	"github.com/irashack/molebridge/internal/nstest"
	"github.com/irashack/molebridge/internal/rtnl"
	"github.com/irashack/molebridge/internal/watch"
	"golang.org/x/sys/unix"
)

const (
	sidecarLAN4 = "192.0.2.100"
	sidecarLAN6 = "2001:db8:4::100"
)

// newNativeSidecarRig starts without a tunnel or an overlay. The host's
// ordinary main table can reach both documentation destinations; only one
// belongs to SIDECAR_LAN_CIDRS. A tunnel veth is added after installation,
// matching the worker's order without requiring a VPN provider.
func newNativeSidecarRig(t *testing.T, restart bool) *rig {
	t.Helper()
	r := &rig{t: t, logs: &logs{}}
	r.exit = nstest.New(t, "sidecar")
	r.outside = nstest.New(t, "sidecar-host")
	r.tun = nstest.New(t, "sidecar-tunnel")
	for _, ns := range []*nstest.NS{r.exit, r.outside, r.tun} {
		ns.Sysctl("net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0", "net.ipv6.conf.default.accept_dad=0")
	}
	// A sidecar needs neither forwarding nor the unsafe forwarding ICMP sysctl.
	r.exit.Sysctl("net.ipv4.icmp_errors_use_inbound_ifaddr=0")
	r.exit.Veth("eth0", r.outside, "outside0")
	r.outside.IP("link", "set", "outside0", "address", "02:00:00:00:21:02")
	configure(r.exit, "eth0", "198.51.100.1/24", "2001:db8:2::1/64")
	configure(r.outside, "outside0", "198.51.100.2/24", "2001:db8:2::2/64")
	r.exit.IP("route", "add", "default", "via", "198.51.100.2")
	r.exit.IP("-6", "route", "add", "default", "via", "2001:db8:2::2")
	r.outside.IP("addr", "add", target4+"/32", "dev", "outside0")
	r.outside.IP("-6", "addr", "add", target6+"/128", "dev", "outside0", "nodad")
	r.outside.IP("addr", "add", sidecarLAN4+"/32", "dev", "outside0")
	r.outside.IP("-6", "addr", "add", sidecarLAN6+"/128", "dev", "outside0", "nodad")
	r.exit.IP("route", "add", "192.0.2.0/24", "via", "198.51.100.2")
	r.exit.IP("-6", "route", "add", "2001:db8:4::/64", "via", "2001:db8:2::2")
	// Routing is what these drills isolate; avoid neighbor discovery adding
	// its own interface-bound traffic to the host-path packet assertions.
	for _, addr := range []string{"198.51.100.2", "2001:db8:2::2", target4, target6} {
		r.exit.IP("neigh", "replace", addr, "lladdr", "02:00:00:00:21:02", "nud", "permanent", "dev", "eth0")
	}
	c, err := contract.ConfigFromEnv(func(k string) string {
		return map[string]string{"EXIT_KIND": "sidecar", "TUNNEL_BACKEND": "native", "EXIT_IF": exitIf,
			"SIDECAR_LAN_CIDRS": "192.0.2.0/24,2001:db8:4::/64"}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	r.spec = contract.Spec{Config: c, ReturnPath: map[rtnl.Family][]netip.Addr{rtnl.V4: {tunnel4}, rtnl.V6: {tunnel6}}}
	r.obs, err = rtnl.Dial(rtnl.Options{NetNS: r.exit.Fd()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.obs.Close() })
	stop := startNativeSidecarOwner(t, r)
	r.waitHealthy(2 * time.Second) // exact even before the tunnel exists
	r.exit.Veth(exitIf, r.tun, "tunnel0")
	configure(r.exit, exitIf, "203.0.113.1/24", "2001:db8:3::1/64")
	configure(r.tun, "tunnel0", "203.0.113.2/24", "2001:db8:3::2/64")
	r.waitHealthy(2 * time.Second)
	if restart {
		// Stop the worker, retaining the pod's namespace, rules and routes.
		// The replacement owner must install against that previous run.
		stop()
		startNativeSidecarOwner(t, r)
		r.waitHealthy(2 * time.Second)
	}
	return r
}

func startNativeSidecarOwner(t *testing.T, r *rig) func() {
	t.Helper()
	// Subscribe before installation so changes during the first look are seen.
	sub, err := rtnl.Subscribe(rtnl.Options{NetNS: r.exit.Fd()})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := rtnl.Dial(rtnl.Options{NetNS: r.exit.Fd()})
	if err != nil {
		_ = sub.Close()
		t.Fatal(err)
	}
	m := mutator.New(mutator.Options{Kernel: conn, Spec: r.spec, GuardRepairs: false, Logf: r.logs.logf})
	m.Start()
	ctx, cancel := context.WithCancel(context.Background())
	w := watch.New(watch.Config{Source: sub, Mutator: m, Interval: 30 * time.Second, IdleStep: 100 * time.Millisecond,
		Tables: r.spec.Interest().Tables, Links: []string{r.spec.Config.ExitIf, r.spec.Config.HostIf}, Logf: r.logs.logf})
	var wg sync.WaitGroup
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			wg.Wait()
			m.Close()
			_ = sub.Close()
			_ = conn.Close()
		})
	}
	t.Cleanup(stop)
	if err := m.Install(context.Background()); err != nil {
		t.Fatalf("sidecar install: %v\n%s", err, r.logs.text())
	}
	r.mut, r.watcher = m, w
	wg.Add(1)
	go func() { defer wg.Done(); _ = w.Run(ctx) }()
	return stop
}

// sidecarSend creates an unbound UDP socket inside the shared namespace. A
// bound-interface socket belongs to the firewall drills, not this contract.
func sidecarSend(ns *nstest.NS, f rtnl.Family, mark uint32, dst string, port int) error {
	return ns.Do(func() error {
		network := "udp4"
		if f == rtnl.V6 {
			network = "udp6"
		}
		d := net.Dialer{Timeout: time.Second, Control: func(_, _ string, raw syscall.RawConn) error {
			var err error
			if mark != 0 {
				if e := raw.Control(func(fd uintptr) { err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark)) }); e != nil {
					return e
				}
			}
			return err
		}}
		c, err := d.Dial(network, net.JoinHostPort(dst, fmt.Sprint(port)))
		if err != nil {
			return err
		}
		defer c.Close()
		if err := c.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			return err
		}
		_, err = c.Write([]byte("sidecar routing drill"))
		return err
	})
}

// sidecarReceiver receives only on the far end of eth0. Arrival proves the
// packet crossed the host path rather than the stand-in tunnel's namespace.
func sidecarReceiver(t *testing.T, ns *nstest.NS, f rtnl.Family, dst string) *net.UDPConn {
	t.Helper()
	var c *net.UDPConn
	if err := ns.Do(func() error {
		network := "udp4"
		if f == rtnl.V6 {
			network = "udp6"
		}
		var err error
		c, err = net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(dst)})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}
