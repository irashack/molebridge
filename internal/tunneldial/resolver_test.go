package tunneldial

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"
)

// fakeDNS serves each dialled connection with answer, which gets the network
// and the query and returns the messages to send back.
type fakeDNS struct {
	mu     sync.Mutex
	dialed []string
	answer func(network string, q []byte) [][]byte
}

func (f *fakeDNS) dial(_ context.Context, network, address string) (net.Conn, error) {
	f.mu.Lock()
	f.dialed = append(f.dialed, network+" "+address)
	f.mu.Unlock()
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		var q []byte
		if network == "tcp" {
			var size [2]byte
			if _, err := io.ReadFull(server, size[:]); err != nil {
				return
			}
			q = make([]byte, binary.BigEndian.Uint16(size[:]))
			if _, err := io.ReadFull(server, q); err != nil {
				return
			}
		} else {
			buf := make([]byte, 512)
			n, err := server.Read(buf)
			if err != nil {
				return
			}
			q = buf[:n]
		}
		for _, msg := range f.answer(network, q) {
			if network == "tcp" {
				msg = append(binary.BigEndian.AppendUint16(nil, uint16(len(msg))), msg...)
			}
			if _, err := server.Write(msg); err != nil {
				return
			}
		}
		// Hold the connection open, as a server that sends nothing more.
		_, _ = io.Copy(io.Discard, server)
	}()
	return client, nil
}

func newTestResolver(f *fakeDNS) *Resolver {
	return &Resolver{Server: "10.64.0.1:53", Timeout: time.Second, dial: f.dial}
}

func TestResolverUDP(t *testing.T) {
	f := &fakeDNS{answer: func(_ string, q []byte) [][]byte { return [][]byte{reply(q, 0, aRecord("192.0.2.1"))} }}
	got, err := newTestResolver(f).LookupNetIP(context.Background(), "ip4", "Relay.Example.Test")
	if err != nil || !reflect.DeepEqual(got, []netip.Addr{netip.MustParseAddr("192.0.2.1")}) {
		t.Fatalf("%v %v", got, err)
	}
	if !reflect.DeepEqual(f.dialed, []string{"udp 10.64.0.1:53"}) {
		t.Fatal(f.dialed)
	}
}

func TestResolverSkipsStrayDatagrams(t *testing.T) {
	f := &fakeDNS{answer: func(_ string, q []byte) [][]byte {
		wrongID := reply(q, 0, aRecord("198.51.100.1"))
		wrongID[0] ^= 0xFF
		wrongName := reply(buildQuery(binary.BigEndian.Uint16(q), "other.example.test", TypeA), 0, aRecord("198.51.100.2"))
		return [][]byte{wrongID, {1, 2, 3}, wrongName, reply(q, 0, aRecord("192.0.2.1"))}
	}}
	got, err := newTestResolver(f).LookupNetIP(context.Background(), "ip4", testName)
	if err != nil || len(got) != 1 || got[0] != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("%v %v", got, err)
	}
}

func TestResolverTruncatedAsksOverTCP(t *testing.T) {
	f := &fakeDNS{answer: func(network string, q []byte) [][]byte {
		if network == "udp" {
			m := reply(q, 0)
			binary.BigEndian.PutUint16(m[2:], 0x8380)
			return [][]byte{m}
		}
		return [][]byte{reply(q, 0, aRecord("192.0.2.4"))}
	}}
	got, err := newTestResolver(f).LookupNetIP(context.Background(), "ip4", testName)
	if err != nil || len(got) != 1 || got[0] != netip.MustParseAddr("192.0.2.4") {
		t.Fatalf("%v %v", got, err)
	}
	if !reflect.DeepEqual(f.dialed, []string{"udp 10.64.0.1:53", "tcp 10.64.0.1:53"}) {
		t.Fatal(f.dialed)
	}
}

func TestResolverTCPLengthBound(t *testing.T) {
	f := &fakeDNS{answer: func(network string, q []byte) [][]byte {
		if network == "udp" {
			m := reply(q, 0)
			binary.BigEndian.PutUint16(m[2:], 0x8380)
			return [][]byte{m}
		}
		return [][]byte{make([]byte, MaxMessage+1)}
	}}
	if _, err := newTestResolver(f).LookupNetIP(context.Background(), "ip4", testName); !errors.Is(err, ErrMalformed) {
		t.Fatal(err)
	}
}

func TestResolverBothFamilies(t *testing.T) {
	ip6 := netip.MustParseAddr("2001:db8::5").As16()
	f := &fakeDNS{answer: func(_ string, q []byte) [][]byte {
		if binary.BigEndian.Uint16(q[len(q)-4:]) == TypeAAAA {
			return [][]byte{reply(q, 0, testRR{rtype: TypeAAAA, data: ip6[:]})}
		}
		return [][]byte{reply(q, 0)} // no A records
	}}
	got, err := newTestResolver(f).LookupNetIP(context.Background(), "ip", testName)
	if err != nil || len(got) != 1 || got[0] != netip.MustParseAddr("2001:db8::5") {
		t.Fatalf("%v %v", got, err)
	}
	f.answer = func(_ string, q []byte) [][]byte { return [][]byte{reply(q, 3)} }
	if _, err := newTestResolver(f).LookupNetIP(context.Background(), "ip", testName); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestResolverTimesOut(t *testing.T) {
	f := &fakeDNS{answer: func(string, []byte) [][]byte { return nil }}
	r := newTestResolver(f)
	r.Timeout = 50 * time.Millisecond
	start := time.Now()
	if _, err := r.LookupNetIP(context.Background(), "ip4", testName); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("the timeout did not end the wait")
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.Timeout = time.Minute
	time.AfterFunc(20*time.Millisecond, cancel)
	if _, err := r.LookupNetIP(ctx, "ip4", testName); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestResolverRefusals(t *testing.T) {
	f := &fakeDNS{answer: func(_ string, q []byte) [][]byte { return [][]byte{reply(q, 0, aRecord("192.0.2.1"))} }}
	r := newTestResolver(f)
	for _, host := range []string{"192.0.2.1", "", "bad name.test"} {
		if _, err := r.LookupNetIP(context.Background(), "ip4", host); !errors.Is(err, ErrName) {
			t.Errorf("%q: %v", host, err)
		}
	}
	if _, err := r.LookupNetIP(context.Background(), "tcp", testName); !errors.Is(err, ErrNetwork) {
		t.Error(err)
	}
	for _, server := range []string{"", "dns.example.test:53", "10.64.0.1", "10.64.0.1:0"} {
		r.Server = server
		if _, err := r.LookupNetIP(context.Background(), "ip4", testName); !errors.Is(err, ErrServer) {
			t.Errorf("%q: %v", server, err)
		}
	}
	if len(f.dialed) != 0 {
		t.Fatal("a refused lookup dialled", f.dialed)
	}
	// Without a Dialer there is nothing to send through.
	none := &Resolver{Server: "10.64.0.1:53"}
	if _, err := none.LookupNetIP(context.Background(), "ip4", testName); !errors.Is(err, ErrInterface) {
		t.Fatal(err)
	}
}
