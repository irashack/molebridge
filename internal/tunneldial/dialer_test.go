package tunneldial

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestValidInterfaceName(t *testing.T) {
	for _, name := range []string{"wg0", "tun0", "mullvad", "eth0.100", "a-b_c", "123456789012345"} {
		if !ValidInterfaceName(name) {
			t.Errorf("%q refused", name)
		}
	}
	for _, name := range []string{"", ".", "..", "1234567890123456", "wg/0", "wg 0", "wg:0", "wg\t0", "wg\x00", "wgé"} {
		if ValidInterfaceName(name) {
			t.Errorf("%q accepted", name)
		}
	}
}

func TestDialRefusesBeforeAnySocket(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		d       Dialer
		network string
		address string
		want    error
	}{
		{Dialer{}, "tcp", "192.0.2.1:80", ErrInterface},
		{Dialer{Interface: "wg 0"}, "tcp", "192.0.2.1:80", ErrInterface},
		{Dialer{Interface: "wg0"}, "unix", "192.0.2.1:80", ErrNetwork},
		{Dialer{Interface: "wg0"}, "ip4:icmp", "192.0.2.1", ErrNetwork},
		{Dialer{Interface: "wg0"}, "tcp", "relay.example.test:80", ErrAddress},
		{Dialer{Interface: "wg0"}, "tcp", "192.0.2.1", ErrAddress},
		{Dialer{Interface: "wg0"}, "tcp", "192.0.2.1:0", ErrAddress},
		{Dialer{Interface: "wg0"}, "tcp", "192.0.2.1:65536", ErrAddress},
		{Dialer{Interface: "wg0"}, "tcp", "192.0.2.1:http", ErrAddress},
		{Dialer{Interface: "wg0"}, "tcp", "192.0.2.1:+80", ErrAddress},
		{Dialer{Interface: "wg0"}, "tcp", "[fe80::1%eth0]:80", ErrAddress},
		{Dialer{Interface: "wg0"}, "tcp", ":80", ErrAddress},
	}
	for _, c := range cases {
		conn, err := c.d.DialContext(ctx, c.network, c.address)
		if !errors.Is(err, c.want) || conn != nil {
			t.Errorf("%+v %s %s: %v", c.d, c.network, c.address, err)
		}
	}
}

// A bind that fails (here to an interface that does not exist) fails the
// dial, even to a listener that is reachable without the bind.
func TestDialFailsWhenTheBindFails(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	d := Dialer{Interface: "mbnotthere0"}
	conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err == nil {
		conn.Close()
		t.Fatal("dialled without the bind")
	}
	if !errors.Is(err, ErrBind) {
		t.Fatal(err)
	}
}
