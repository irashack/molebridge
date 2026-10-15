//go:build drill && linux

package nft_test

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
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
	// The edit is made by nft in another process, not through the installer.
	output := list(t, ns, "-a", "list", "chain", "inet", nft.SidecarTable, "output")
	match := regexp.MustCompile(`(?m)oifname "lo" accept # handle ([0-9]+)`).FindStringSubmatch(output)
	if len(match) != 2 {
		t.Fatalf("no loopback rule handle:\n%s", output)
	}
	list(t, ns, "delete", "rule", "inet", nft.SidecarTable, "output", "handle", match[1])
	verifySidecarDrill(t, ns, f, false, "chain output:")
	installSidecarDrill(t, ns, f)
	list(t, ns, "add", "chain", "inet", nft.SidecarTable, "output", "{ policy accept; }")
	verifySidecarDrill(t, ns, f, false, "chain output: policy accept")
	installSidecarDrill(t, ns, f)
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
	if err := ns.Do(func() error {
		addr, err := net.ResolveUDPAddr("udp4", address)
		if err != nil {
			return err
		}
		conn, err = net.ListenUDP("udp4", addr)
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
