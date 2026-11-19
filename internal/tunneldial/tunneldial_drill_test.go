//go:build drill && linux

package tunneldial

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/nstest"
)

// The tunnel dialer against a real kernel: a client namespace with two links
// to a server namespace, "tun0" (the tunnel, 192.0.2.0/24) and "alt0" (any
// other path, 198.51.100.0/24, which also holds the default route). Bound to
// tun0, a connection reaches the server over tun0, never over alt0; with the
// interface absent or renamed, the dial fails.
type dialRig struct {
	client, server *nstest.NS
}

func newDialRig(t *testing.T) *dialRig {
	client := nstest.New(t, "tdc")
	server := nstest.New(t, "tds")
	client.Veth("tun0", server, "tun0")
	client.Veth("alt0", server, "alt0")
	for _, s := range []struct {
		ns       *nstest.NS
		tun, alt string
	}{{client, "192.0.2.1/24", "198.51.100.1/24"}, {server, "192.0.2.2/24", "198.51.100.2/24"}} {
		s.ns.IP("addr", "add", s.tun, "dev", "tun0")
		s.ns.IP("addr", "add", s.alt, "dev", "alt0")
		s.ns.IP("link", "set", "tun0", "up")
		s.ns.IP("link", "set", "alt0", "up")
	}
	client.IP("route", "add", "default", "via", "198.51.100.2", "dev", "alt0")
	// With no route through the bound device, the kernel takes the
	// destination as on link there; the server answers ARP only for tun0's
	// own address on tun0, so such a dial fails instead of reaching alt0's
	// address by tun0.
	server.Sysctl("net.ipv4.conf.all.arp_ignore=1")
	return &dialRig{client: client, server: server}
}

// listen runs a TCP echo of the peer's address on addr in the server
// namespace, and a DNS server on UDP that answers every A query with
// 192.0.2.53.
func (r *dialRig) listen(t *testing.T, addr string) {
	t.Helper()
	var ln net.Listener
	var pc net.PacketConn
	if err := r.server.Do(func() error {
		var err error
		if ln, err = net.Listen("tcp", addr); err != nil {
			return err
		}
		pc, err = net.ListenPacket("udp", addr)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close(); _ = pc.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = io.WriteString(c, c.RemoteAddr().String()+"\n")
			_ = c.Close()
		}
	}()
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(reply(buf[:n], 0, aRecord("192.0.2.53")), from)
		}
	}()
}

func (r *dialRig) dial(d *Dialer, address string) (string, error) {
	var conn net.Conn
	err := r.client.Do(func() error {
		var err error
		conn, err = d.DialContext(context.Background(), "tcp", address)
		return err
	})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	b, err := io.ReadAll(conn)
	return string(b), err
}

func TestDialerBindsToTheTunnelInterface(t *testing.T) {
	r := newDialRig(t)
	r.listen(t, "0.0.0.0:7000")
	d := &Dialer{Interface: "tun0", Timeout: 2 * time.Second}

	// Present: the connection leaves by tun0, from tun0's address.
	got, err := r.dial(d, "192.0.2.2:7000")
	if err != nil || !strings.HasPrefix(got, "192.0.2.1:") {
		t.Fatalf("over tun0: %q %v", got, err)
	}
	// An address only alt0 routes to is not reached when bound to tun0: the
	// bind narrows the route lookup to tun0, with no fallback to alt0.
	if got, err := r.dial(d, "198.51.100.2:7000"); err == nil {
		t.Fatalf("reached alt0's address bound to tun0: %q", got)
	}
	// The server namespace's DNS answers through tun0.
	res := &Resolver{Dialer: d, Server: "192.0.2.2:7000", Timeout: 2 * time.Second}
	var addrs []netip.Addr
	if err := r.client.Do(func() error {
		var err error
		addrs, err = res.LookupNetIP(context.Background(), "ip4", "relay.example.test")
		return err
	}); err != nil || len(addrs) != 1 || addrs[0] != netip.MustParseAddr("192.0.2.53") {
		t.Fatalf("resolver over tun0: %v %v", addrs, err)
	}

	// Absent: an interface of another name fails the dial.
	if _, err := r.dial(&Dialer{Interface: "wg9", Timeout: 2 * time.Second}, "192.0.2.2:7000"); !errors.Is(err, ErrBind) {
		t.Fatalf("absent interface: %v", err)
	}

	// Renamed mid-run: the next dial fails, though the address is still routed
	// by the renamed link.
	r.client.IP("link", "set", "tun0", "down")
	r.client.IP("link", "set", "tun0", "name", "tun1")
	r.client.IP("link", "set", "tun1", "up")
	r.client.IP("route", "replace", "192.0.2.0/24", "dev", "tun1")
	if _, err := r.dial(d, "192.0.2.2:7000"); !errors.Is(err, ErrBind) {
		t.Fatalf("renamed interface: %v", err)
	}
	if err := r.client.Do(func() error {
		_, err := res.LookupNetIP(context.Background(), "ip4", "relay.example.test")
		return err
	}); !errors.Is(err, ErrBind) {
		t.Fatalf("resolver after the rename: %v", err)
	}
	// The new name works, so the failure was the bind.
	if _, err := r.dial(&Dialer{Interface: "tun1", Timeout: 2 * time.Second}, "192.0.2.2:7000"); err != nil {
		t.Fatalf("over tun1: %v", err)
	}
}
