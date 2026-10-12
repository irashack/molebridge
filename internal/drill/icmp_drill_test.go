//go:build drill && linux

package drill

// The ICMP return path (rules 94 and 98): the exit's own ICMP errors for
// tunnel traffic carry the tunnel address and go back through the tunnel; if
// rule 94 is missing, or the exit table is empty, rule 98 keeps them off the
// host's route.

import (
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/nstest"
)

// tooBigReported sends an oversized, don't-fragment packet from the tunnel's
// far side, sourced from the off-subnet address the main table would route
// out eth0 (as a real Internet origin is), and says whether the exit's ICMP
// error came back over the tunnel. 1300 bytes of payload fits the 1420 tunnel
// link but not the 1280 overlay link.
func (r *rig) tooBigReported(family string) bool {
	r.t.Helper()
	address, source, pattern := "192.0.2.2", target4, "Frag needed"
	if family == "-6" {
		address, source, pattern = "2001:db8:1::2", target6, "Packet too big"
	}
	// The sender caches the path MTU from a previous answer; a probe served
	// from that cache says nothing about the exit's return path.
	r.tun.TryIP(family, "route", "flush", "cache")
	out, _ := r.tun.Exec("ping", family, "-I", source, "-c", "1", "-W", "1", "-M", "do", "-s", "1300", address)
	if strings.Contains(out, "local error") {
		r.t.Fatalf("the probe was answered from the sender's own path MTU cache (%s)", family)
	}
	return strings.Contains(out, pattern)
}

// hostICMP counts the ICMP errors that reach the host side.
func hostICMP(t *testing.T, ns *nstest.NS) int {
	t.Helper()
	out, err := ns.Exec("nft", "list", "table", "inet", "mbicmp")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	total := 0
	fields := strings.Fields(out)
	for i, f := range fields {
		if f == "packets" && i+1 < len(fields) {
			n := 0
			for _, c := range fields[i+1] {
				n = n*10 + int(c-'0')
			}
			total += n
		}
	}
	return total
}

func icmpRig(t *testing.T) *rig {
	r := newRig(t)
	script := `table inet mbicmp {
  chain input {
    type filter hook input priority 0; policy accept;
    icmp type destination-unreachable counter
    icmpv6 type packet-too-big counter
  }
}
`
	if out, err := r.outside.ExecInput(script, "nft", "-f", "-"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return r
}

func TestOversizedTunnelRepliesGetICMPErrorsBackThroughTheTunnel(t *testing.T) {
	r := icmpRig(t)
	for _, f := range []string{"-4", "-6"} {
		if !r.tooBigReported(f) {
			t.Errorf("%s: an oversized tunnel reply produced no ICMP error over the tunnel", f)
		}
	}
}

func TestMissingReturnPathRuleIsContainedByTheBackstopAndRepaired(t *testing.T) {
	for _, f := range []string{"-4", "-6"} {
		f := f
		t.Run(f, func(t *testing.T) {
			r := icmpRig(t)
			resume := r.pause()
			defer resume()
			before := hostICMP(t, r.outside)
			r.exit.IP(f, "rule", "del", "priority", "94")
			if r.tooBigReported(f) {
				t.Errorf("the ICMP error reached the tunnel without the return-path rule")
			}
			if got := hostICMP(t, r.outside); got != before {
				t.Errorf("tunnel-sourced ICMP reached the host route with rule 94 deleted (%d -> %d)", before, got)
			}
			resume()
			r.waitHealthy(time.Second)
			if !r.tooBigReported(f) {
				t.Error("rule 94 was not repaired")
			}
		})
	}
}

func TestEmptyExitTableIsContainedByTheBackstop(t *testing.T) {
	r := icmpRig(t)
	resume := r.pause()
	defer resume()
	before := hostICMP(t, r.outside)
	for _, f := range []string{"-4", "-6"} {
		r.exit.IP(f, "route", "flush", "table", "51821")
	}
	for _, f := range []string{"-4", "-6"} {
		if r.tooBigReported(f) {
			t.Errorf("%s: an ICMP error reached the tunnel with its table empty", f)
		}
	}
	if got := hostICMP(t, r.outside); got != before {
		t.Errorf("tunnel-sourced ICMP reached the host route with the exit table empty (%d -> %d)", before, got)
	}
	resume()
	r.waitHealthy(time.Second)
	for _, f := range []string{"-4", "-6"} {
		if !r.tooBigReported(f) {
			t.Errorf("%s: not repaired", f)
		}
	}
}

// With both rules gone (two faults, outside the guarantee) the ICMP error takes
// the host route: the drill can see a leak.
func TestTheICMPDrillIsSensitive(t *testing.T) {
	r := icmpRig(t)
	resume := r.pause()
	defer resume()
	before := hostICMP(t, r.outside)
	for _, f := range []string{"-4", "-6"} {
		r.exit.IP(f, "rule", "del", "priority", "94")
		r.exit.IP(f, "rule", "del", "priority", "98")
		r.tooBigReported(f)
	}
	if hostICMP(t, r.outside) == before {
		t.Fatal("the host-side ICMP counter saw nothing with rules 94 and 98 both gone; the drill is not sensitive")
	}
}
