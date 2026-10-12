//go:build drill && linux

package drill

// The local-delivery drills of tools/check-routing.sh: with rule 1, nothing
// that arrives on the overlay reaches a local socket in the exit, even after
// a DNAT to a local port; the host interface and loopback keep local
// delivery; and the drill is sensitive: with the kernel's rule 0 back, the
// same packets arrive.

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/nstest"
)

type listeners struct {
	mu        sync.Mutex
	delivered []string
}

func (l *listeners) record(peer string, port int) {
	l.mu.Lock()
	l.delivered = append(l.delivered, peer+" "+itoa(port))
	l.mu.Unlock()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func (l *listeners) reset() { l.mu.Lock(); l.delivered = nil; l.mu.Unlock() }
func (l *listeners) any() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.delivered) > 0
}
func (l *listeners) saw(suffix string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, d := range l.delivered {
		if strings.HasSuffix(d, suffix) {
			return true
		}
	}
	return false
}

// listen opens TCP and UDP listeners on ports 53 and 5053 on every address of
// both families, inside the namespace.
func listen(t *testing.T, ns *nstest.NS) *listeners {
	t.Helper()
	l := &listeners{}
	err := ns.Do(func() error {
		for _, port := range []string{"53", "5053"} {
			for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
				addr := "0.0.0.0:" + port
				if strings.HasSuffix(network, "6") {
					addr = "[::]:" + port
				}
				p := 53
				if port == "5053" {
					p = 5053
				}
				if strings.HasPrefix(network, "tcp") {
					ln, err := net.Listen(network, addr)
					if err != nil {
						return err
					}
					t.Cleanup(func() { ln.Close() })
					go func() {
						for {
							c, err := ln.Accept()
							if err != nil {
								return
							}
							host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
							l.record(host, p)
							c.Close()
						}
					}()
				} else {
					pc, err := net.ListenPacket(network, addr)
					if err != nil {
						return err
					}
					t.Cleanup(func() { pc.Close() })
					go func() {
						buf := make([]byte, 512)
						for {
							_, peer, err := pc.ReadFrom(buf)
							if err != nil {
								return
							}
							host, _, _ := net.SplitHostPort(peer.String())
							l.record(host, p)
						}
					}()
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// deliveredFrom sends three UDP datagrams and a TCP connection attempt to
// address:53 from inside ns and says whether the listeners saw any.
func deliveredFrom(t *testing.T, from *nstest.NS, l *listeners, address string) bool {
	t.Helper()
	l.reset()
	host := address
	if strings.Contains(address, ":") {
		host = "[" + address + "]"
	}
	_ = from.Do(func() error {
		if u, err := net.Dial("udp", host+":53"); err == nil {
			for i := 0; i < 3; i++ {
				_, _ = u.Write(make([]byte, 12))
			}
			u.Close()
		}
		if c, err := net.DialTimeout("tcp", host+":53", time.Second); err == nil {
			c.Close()
		}
		return nil
	})
	time.Sleep(150 * time.Millisecond)
	return l.any()
}

var exitAddresses = []string{"192.0.2.1", "198.51.100.1", "2001:db8:1::1", "2001:db8:2::1"}

func TestOverlayTrafficNeverReachesALocalSocket(t *testing.T) {
	r := newRig(t)
	l := listen(t, r.exit)
	for _, a := range exitAddresses {
		if deliveredFrom(t, r.client, l, a) {
			t.Errorf("overlay traffic to %s port 53 reached a local socket", a)
		}
	}
	for _, a := range []string{"198.51.100.1", "2001:db8:2::1"} {
		if !deliveredFrom(t, r.outside, l, a) {
			t.Errorf("the host interface lost local delivery (%s)", a)
		}
	}
	for _, a := range []string{"127.0.0.1", "::1"} {
		if !deliveredFrom(t, r.exit, l, a) {
			t.Errorf("loopback lost local delivery (%s)", a)
		}
	}
}

func TestADroppedGuardIsSeenAndRepairedAndTheDrillIsSensitive(t *testing.T) {
	r := newRig(t)
	l := listen(t, r.exit)
	resume := r.pause()
	defer resume()
	// With the kernel's rule 0 back the validator objects and the same probes
	// arrive: the drill can see local delivery.
	for _, f := range []string{"-4", "-6"} {
		r.exit.IP(f, "rule", "add", "lookup", "local", "priority", "0")
	}
	if r.healthy() {
		t.Error("the plan accepts the kernel's rule 0")
	}
	for _, a := range exitAddresses {
		if !deliveredFrom(t, r.client, l, a) {
			t.Errorf("the drill cannot see local delivery (%s)", a)
		}
	}
	resume()
	r.waitHealthy(time.Second)
	for _, a := range exitAddresses {
		if deliveredFrom(t, r.client, l, a) {
			t.Errorf("overlay traffic to %s reached a local socket after the repair", a)
		}
	}
}

func TestOverlayTrafficDNATedToALocalPortNeverReachesALocalSocket(t *testing.T) {
	r := newRig(t)
	l := listen(t, r.exit)
	// A prerouting DNAT that keeps the local address and changes the port.
	// DNAT happens before the routing decision, so rule 1 still applies.
	script := `table inet mb_local_dnat {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    iifname "wt0" ip daddr 192.0.2.1 udp dport 53 counter dnat ip to 192.0.2.1:5053
    iifname "wt0" ip daddr 192.0.2.1 tcp dport 53 counter dnat ip to 192.0.2.1:5053
    iifname "wt0" ip daddr 198.51.100.1 udp dport 53 counter dnat ip to 198.51.100.1:5053
    iifname "wt0" ip daddr 198.51.100.1 tcp dport 53 counter dnat ip to 198.51.100.1:5053
    iifname "wt0" ip6 daddr 2001:db8:1::1 udp dport 53 counter dnat ip6 to [2001:db8:1::1]:5053
    iifname "wt0" ip6 daddr 2001:db8:1::1 tcp dport 53 counter dnat ip6 to [2001:db8:1::1]:5053
    iifname "wt0" ip6 daddr 2001:db8:2::1 udp dport 53 counter dnat ip6 to [2001:db8:2::1]:5053
    iifname "wt0" ip6 daddr 2001:db8:2::1 tcp dport 53 counter dnat ip6 to [2001:db8:2::1]:5053
  }
}
`
	if out, err := r.exit.ExecInput(script, "nft", "-f", "-"); err != nil {
		t.Skipf("nft cannot do NAT here: %v\n%s", err, out)
	}
	for _, a := range exitAddresses {
		if deliveredFrom(t, r.client, l, a) {
			t.Errorf("overlay traffic to %s port 53 reached a local socket after DNAT", a)
		}
	}
	out, _ := r.exit.Exec("nft", "list", "table", "inet", "mb_local_dnat")
	if n := strings.Count(out, "packets 0 "); n > 0 {
		// The 8 rules each saw traffic: none may have a zero counter.
		t.Errorf("%d of 8 DNAT rules saw no traffic:\n%s", n, out)
	}
	// Drill sensitivity: with rule 0 back (the repairer held), the DNATed
	// traffic is delivered to the local port.
	resume := r.pause()
	defer resume()
	for _, f := range []string{"-4", "-6"} {
		r.exit.IP(f, "rule", "add", "lookup", "local", "priority", "0")
	}
	for _, a := range exitAddresses {
		if !deliveredFrom(t, r.client, l, a) || !l.saw("5053") {
			t.Errorf("the drill cannot see local delivery after DNAT (%s)", a)
		}
	}
}
