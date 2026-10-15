//go:build drill && linux

package nft_test

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/irashack/molebridge/internal/nft"
	"github.com/irashack/molebridge/internal/nstest"
)

func sidecarDrillFirewall() nft.SidecarFirewall {
	return nft.SidecarFirewall{ExitIf: "tun0", TunnelMark: 51821, ControlMark: 0x1bd00,
		LAN4: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		LAN6: []netip.Prefix{netip.MustParsePrefix("2001:db8:1::/64")}}
}

func installSidecarDrill(t *testing.T, ns *nstest.NS, f nft.SidecarFirewall) {
	t.Helper()
	if err := nft.InstallSidecar(t.Context(), ns.Fd(), f); err != nil {
		t.Fatal(err)
	}
	verifySidecarDrill(t, ns, f, true, "")
}

func verifySidecarDrill(t *testing.T, ns *nstest.NS, f nft.SidecarFirewall, want bool, contains string) {
	t.Helper()
	ok, reason, err := nft.VerifySidecar(t.Context(), ns.Fd(), f)
	if err != nil || ok != want || !strings.Contains(reason, contains) || !want && reason == "" {
		t.Fatalf("verify: %t %q %v; want %t containing %q", ok, reason, err, want, contains)
	}
}

func TestSidecarFirewallInstallReplaceAndDrift(t *testing.T) {
	ns := nstest.New(t, "sidecar")
	f := sidecarDrillFirewall()
	f.ForwardedPort = 41234
	installSidecarDrill(t, ns, f)
	f.ForwardedPort = 42345
	installSidecarDrill(t, ns, f)
	live := list(t, ns, "-a", "list", "table", "inet", nft.SidecarTable)
	if strings.Contains(live, "41234") || strings.Count(live, "dport 42345") != 2 {
		t.Fatalf("port replacement did not replace both rules:\n%s", live)
	}
	// Disturb each table independently through nft in another process.
	for _, table := range []string{nft.SidecarTable, nft.SidecarBackstopTable} {
		output := list(t, ns, "-a", "list", "chain", "inet", table, "output")
		match := regexp.MustCompile(`(?m)oifname "lo" accept # handle ([0-9]+)`).FindStringSubmatch(output)
		if len(match) != 2 {
			t.Fatalf("no loopback rule handle:\n%s", output)
		}
		list(t, ns, "delete", "rule", "inet", table, "output", "handle", match[1])
		verifySidecarDrill(t, ns, f, false, table+": chain output:")
		installSidecarDrill(t, ns, f)
		list(t, ns, "add", "chain", "inet", table, "output", "{ policy accept; }")
		verifySidecarDrill(t, ns, f, false, table+": chain output: policy accept")
		installSidecarDrill(t, ns, f)
	}
	f.ForwardedPort = 0
	installSidecarDrill(t, ns, f)
	if live := list(t, ns, "list", "table", "inet", nft.SidecarTable); strings.Contains(live, "dport") {
		t.Fatalf("withdrawing the port left an input exception:\n%s", live)
	}
}

// sidecarSend creates the socket in the namespace and binds its device before
// sending, exercising the SO_BINDTODEVICE path that bypasses policy routing's
// unreachable backstop. The socket has no mark unless the test requests one.
func sidecarSend(ns *nstest.NS, device string, mark uint32, addr [4]byte, port int, payload string) error {
	return ns.Do(func() error {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, device); err != nil {
			return fmt.Errorf("bind device: %w", err)
		}
		if mark != 0 {
			if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(mark)); err != nil {
				return fmt.Errorf("set mark: %w", err)
			}
		}
		return unix.Sendto(fd, []byte(payload), 0, &unix.SockaddrInet4{Addr: addr, Port: port})
	})
}

func sidecarListen(t *testing.T, ns *nstest.NS, address string) *net.UDPConn {
	t.Helper()
	var conn *net.UDPConn
	network := "udp4"
	if strings.HasPrefix(address, "[") {
		network = "udp6"
	}
	if err := ns.Do(func() error {
		addr, err := net.ResolveUDPAddr(network, address)
		if err != nil {
			return err
		}
		conn, err = net.ListenUDP(network, addr)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func sidecarReceive(t *testing.T, conn *net.UDPConn, payload string, want bool) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var data [128]byte
	n, _, err := conn.ReadFromUDP(data[:])
	if !want {
		var timeout net.Error
		if err == nil || !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatalf("expected no input, got %q: %v", data[:n], err)
		}
		return
	}
	if err != nil || string(data[:n]) != payload {
		t.Fatalf("receive: %q %v, want %q", data[:n], err, payload)
	}
}

func TestSidecarFirewallPackets(t *testing.T) {
	ns, peer := nstest.New(t, "sc-app"), nstest.New(t, "sc-peer")
	ns.Veth("host0", peer, "host1")
	for _, endpoint := range []struct {
		ns        *nstest.NS
		dev, addr string
	}{{ns, "host0", "198.51.100.2/24"}, {peer, "host1", "198.51.100.1/24"}} {
		endpoint.ns.IP("addr", "add", endpoint.addr, "dev", endpoint.dev)
		endpoint.ns.IP("link", "set", endpoint.dev, "up")
		endpoint.ns.Sysctl("net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf."+endpoint.dev+".rp_filter=0")
	}
	peer.IP("addr", "add", "192.0.2.1/32", "dev", "lo")
	ns.IP("link", "add", "tun0", "type", "dummy")
	ns.IP("addr", "add", "203.0.113.2/24", "dev", "tun0")
	ns.IP("link", "set", "tun0", "up")
	f := sidecarDrillFirewall()
	f.ForwardedPort = 41234
	installSidecarDrill(t, ns, f)
	receiver := sidecarListen(t, peer, "0.0.0.0:42345")
	// No route to 192.0.2.1: a device-bound send still reaches LOCAL_OUT.
	if err := sidecarSend(ns, "host0", 0, [4]byte{192, 0, 2, 1}, 42345, "escape"); !errors.Is(err, unix.EPERM) {
		t.Fatalf("unmarked bound host send: %v, want EPERM from the output hook", err)
	}
	sidecarReceive(t, receiver, "", false)
	if err := sidecarSend(ns, "host0", 0, [4]byte{198, 51, 100, 1}, 42345, "LAN"); err != nil {
		t.Fatal(err)
	}
	sidecarReceive(t, receiver, "LAN", true)
	for _, mark := range []uint32{f.ControlMark, f.TunnelMark} {
		payload := fmt.Sprintf("mark-%x", mark)
		if err := sidecarSend(ns, "host0", mark, [4]byte{192, 0, 2, 1}, 42345, payload); err != nil {
			t.Fatalf("marked host send: %v", err)
		}
		sidecarReceive(t, receiver, payload, true)
	}
	if err := sidecarSend(ns, "host0", f.ControlMark|1, [4]byte{192, 0, 2, 1}, 42345, "wrong-mark"); !errors.Is(err, unix.EPERM) {
		t.Fatalf("partial control-mark match: %v, want EPERM", err)
	}
	if err := sidecarSend(ns, "tun0", 0, [4]byte{203, 0, 113, 1}, 42345, "tunnel"); err != nil {
		t.Fatalf("unmarked dummy tunnel send: %v", err)
	}

	// A dummy can exercise output but cannot receive from a peer. Replace it
	// with a veth of the same name to exercise real input on the tunnel hook.
	ns.IP("link", "del", "tun0")
	ns.Veth("tun0", peer, "vpn0")
	for _, endpoint := range []struct {
		ns        *nstest.NS
		dev, addr string
	}{{ns, "tun0", "203.0.113.2/24"}, {peer, "vpn0", "203.0.113.1/24"}} {
		endpoint.ns.IP("addr", "add", endpoint.addr, "dev", endpoint.dev)
		endpoint.ns.IP("link", "set", endpoint.dev, "up")
		endpoint.ns.Sysctl("net.ipv4.conf." + endpoint.dev + ".rp_filter=0")
	}
	allowed := sidecarListen(t, ns, "203.0.113.2:41234")
	denied := sidecarListen(t, ns, "203.0.113.2:41235")
	if err := sidecarSend(peer, "vpn0", 0, [4]byte{203, 0, 113, 2}, 41234, "forwarded"); err != nil {
		t.Fatal(err)
	}
	sidecarReceive(t, allowed, "forwarded", true)
	if err := sidecarSend(peer, "vpn0", 0, [4]byte{203, 0, 113, 2}, 41235, "unforwarded"); err != nil {
		t.Fatal(err)
	}
	sidecarReceive(t, denied, "", false)
	// Reply traffic from the tunnel is accepted without opening its port.
	if err := ns.Do(func() error {
		_, err := denied.WriteToUDP([]byte("request"), &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 42345})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	sidecarReceive(t, receiver, "request", true)
	if _, err := receiver.WriteToUDP([]byte("reply"), &net.UDPAddr{IP: net.IPv4(203, 0, 113, 2), Port: 41235}); err != nil {
		t.Fatal(err)
	}
	sidecarReceive(t, denied, "reply", true)
	verifySidecarDrill(t, ns, f, true, "") // counters now differ from their installed zeros
}

// A host link with IPv4, IPv6 and explicit link-local addresses. No static
// neighbour entries: the protected namespace must perform ND itself.
func sidecarHostLink(t *testing.T) (*nstest.NS, *nstest.NS) {
	t.Helper()
	ns, peer := nstest.New(t, "sc-app"), nstest.New(t, "sc-out")
	ns.Veth("host0", peer, "host1")
	for _, endpoint := range []struct {
		ns                 *nstest.NS
		dev, v4, v6, local string
	}{
		{ns, "host0", "198.51.100.2/24", "2001:db8:1::2/64", "fe80::2/64"},
		{peer, "host1", "198.51.100.1/24", "2001:db8:1::1/64", "fe80::1/64"},
	} {
		endpoint.ns.Sysctl("net.ipv6.conf.all.disable_ipv6=0", "net.ipv6.conf."+endpoint.dev+".disable_ipv6=0")
		endpoint.ns.IP("addr", "add", endpoint.v4, "dev", endpoint.dev)
		endpoint.ns.IP("-6", "addr", "add", endpoint.v6, "dev", endpoint.dev, "nodad")
		endpoint.ns.IP("-6", "addr", "add", endpoint.local, "dev", endpoint.dev, "nodad")
		endpoint.ns.IP("link", "set", endpoint.dev, "up")
	}
	return ns, peer
}

func sidecarLeakCounter(t *testing.T, peer *nstest.NS) {
	t.Helper()
	if out, err := peer.ExecInput(`table inet leak {
  counter seen {}
  chain pre {
    type filter hook prerouting priority raw; policy accept;
    udp dport 42345 counter name seen
  }
}
`, "nft", "-f", "-"); err != nil {
		t.Fatalf("leak counter: %v\n%s", err, out)
	}
}

func sidecarLeaked(t *testing.T, peer *nstest.NS) int {
	t.Helper()
	out := list(t, peer, "list", "counter", "inet", "leak", "seen")
	match := regexp.MustCompile(`packets ([0-9]+)`).FindStringSubmatch(out)
	if len(match) != 2 {
		t.Fatalf("no packet count: %s", out)
	}
	n, err := strconv.Atoi(match[1])
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSidecarFirewallCapabilityFreeIPv6(t *testing.T) {
	for _, dest := range []string{"ff02::1", "fe80::1"} {
		t.Run(dest, func(t *testing.T) {
			ns, peer := sidecarHostLink(t)
			sidecarListen(t, peer, "[::]:42345")
			sidecarLeakCounter(t, peer)
			f := sidecarDrillFirewall()
			installSidecarDrill(t, ns, f)
			t.Run("protected", func(t *testing.T) {
				sender := startSidecarSender(t, ns, "host0", dest)
				sender.wait(t, 100, true)
				if n := sidecarLeaked(t, peer); n != 0 {
					t.Fatalf("%s: %d packets escaped", dest, n)
				}
			})
			// Positive control: the same sender and destination reach outside
			// when explicitly LAN-listed. Run this after the zero-count phase
			// so queued control packets cannot contaminate that assertion.
			f.LAN6 = append(f.LAN6, netip.PrefixFrom(netip.MustParseAddr(dest), 128))
			installSidecarDrill(t, ns, f)
			t.Run("explicit LAN", func(t *testing.T) {
				sender := startSidecarSender(t, ns, "host0", dest)
				sender.wait(t, 50, false)
				if sidecarLeaked(t, peer) == 0 {
					t.Fatal("LAN-listed sender did not reach the outside counter")
				}
			})
		})
	}
}

func TestSidecarFirewallIPv6NeighbourDiscovery(t *testing.T) {
	ns, peer := sidecarHostLink(t)
	installSidecarDrill(t, ns, sidecarDrillFirewall())
	for _, endpoint := range []struct {
		ns  *nstest.NS
		dev string
	}{{ns, "host0"}, {peer, "host1"}} {
		endpoint.ns.IP("-6", "neigh", "flush", "dev", endpoint.dev)
		if out := endpoint.ns.IP("-6", "neigh", "show", "dev", endpoint.dev); strings.TrimSpace(out) != "" {
			t.Fatalf("neighbour cache was not empty: %s", out)
		}
	}
	if out, err := ns.Exec("ping", "-6", "-c", "1", "-W", "3", "2001:db8:1::1"); err != nil {
		t.Fatalf("LAN IPv6 neighbour discovery/ping: %v\n%s", err, out)
	}
	if out := ns.IP("-6", "neigh", "show", "to", "2001:db8:1::1", "dev", "host0"); !strings.Contains(out, "lladdr") || strings.Contains(out, "PERMANENT") {
		t.Fatalf("no dynamically discovered neighbour: %s", out)
	}
}

func TestSidecarFirewallSingleTableDeletion(t *testing.T) {
	for _, table := range []string{nft.SidecarTable, nft.SidecarBackstopTable} {
		t.Run(table, func(t *testing.T) {
			ns, peer := sidecarHostLink(t)
			// This neighbour is outside the LAN allowlist and has no route in
			// the application namespace. SO_BINDTODEVICE's on-link fallback
			// can nevertheless reach it when neither output chain is present.
			peer.IP("addr", "add", "192.0.2.1/32", "dev", "host1")
			sidecarListen(t, peer, "0.0.0.0:42345")
			sidecarLeakCounter(t, peer)
			f := sidecarDrillFirewall()
			installSidecarDrill(t, ns, f)
			t.Run("continuous sender", func(t *testing.T) {
				sender := startSidecarSender(t, ns, "host0", "192.0.2.1")
				sent := sender.wait(t, 100, true)
				list(t, ns, "delete", "table", "inet", table)
				verifySidecarDrill(t, ns, f, false, "no table inet "+table)
				sent = sender.wait(t, sent+100, true)
				if n := sidecarLeaked(t, peer); n != 0 {
					t.Fatalf("after deleting %s: %d packets escaped", table, n)
				}
				// Repair with one table missing also stays closed while the
				// same socket keeps sending across the atomic replacement.
				installSidecarDrill(t, ns, f)
				sender.wait(t, sent+100, true)
				if n := sidecarLeaked(t, peer); n != 0 {
					t.Fatalf("after reinstalling: %d packets escaped", n)
				}
			})
			// Positive control after the protected phase: deleting both tables
			// is outside the single-fault guarantee and must expose this path.
			for _, name := range []string{nft.SidecarTable, nft.SidecarBackstopTable} {
				list(t, ns, "delete", "table", "inet", name)
			}
			t.Run("unfiltered control", func(t *testing.T) {
				sender := startSidecarSender(t, ns, "host0", "192.0.2.1")
				sender.wait(t, 50, false)
				if sidecarLeaked(t, peer) == 0 {
					t.Fatal("unfiltered bound sender did not reach the outside counter")
				}
			})
		})
	}
}
