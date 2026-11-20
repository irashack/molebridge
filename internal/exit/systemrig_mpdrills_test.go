//go:build drill && systemrig && linux

package exit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// More multi-provider drills (docs/design/multi-provider.md, "System rig
// drills"): tunnel loss right after a provider change, a replacement
// interrupted by a worker restart, and PIA with port forwarding left for
// Mullvad. Each has a rig of its own with the fake NordVPN and PIA networks
// of systemrig_multiprovider_test.go and systemrig_pia_test.go.

// newMultiRig is a rig with the fake networks of providers, its exit on
// PROVIDERS=providers, started, keyed and verified on Mullvad relay A. It
// returns the fake PIA server when providers has PIA.
func newMultiRig(t *testing.T, providers string, extra ...string) (*systemRig, *exitProc, *rigPIA) {
	r := newSystemRig(t)
	if strings.Contains(providers, "nordvpn") {
		r.addNord()
	}
	var pia *rigPIA
	if strings.Contains(providers, "pia") {
		pia = r.addPIA()
	}
	r.multiProvider(providers)
	r.exitExtra = append(r.exitExtra, extra...)
	p := r.start()
	r.waitReady(p)
	r.connectOverlay()
	A := mullvadExit(r.relays[0])
	r.waitOn(p, A, "", 120*time.Second)
	r.clientOn(A, 30*time.Second)
	r.leakFree("on " + A.String())
	return r, p, pia
}

// endpointWatch records, until stop closes, every peer endpoint the exit's
// tunnel shows.
func (r *systemRig) endpointWatch(stop <-chan struct{}) <-chan map[string]bool {
	out := make(chan map[string]bool, 1)
	go func() {
		seen := map[string]bool{}
		for {
			for _, l := range strings.Split(r.endpoints(), "\n") {
				if f := strings.Fields(l); len(f) == 2 && f[1] != "(none)" {
					seen[f[1]] = true
				}
			}
			select {
			case <-stop:
				out <- seen
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}()
	return out
}

// TestSystemRigMultiProviderTunnelLoss: right after each provider change
// (Mullvad -> PIA -> NordVPN -> Mullvad), the tunnel link is deleted. The
// exit's recovery must bring it back as the new provider's tunnel, never
// the previous provider's, verified again with the new provider's check,
// with nothing from the client leaving outside WireGuard meanwhile.
func TestSystemRigMultiProviderTunnelLoss(t *testing.T) {
	t.Parallel()
	r, p, pia := newMultiRig(t, "mullvad,nordvpn,pia")
	A, B, N, P := mullvadExit(r.relays[0]), mullvadExit(r.relays[1]), nordExit(), piaExit()
	from := A
	for _, to := range []rigExit{P, N, B} {
		r.switchTo(p, from, to)
		stop := make(chan struct{})
		watch := r.endpointWatch(stop)
		lost := time.Now()
		r.exit.IP("link", "del", "vpn")
		// Back: the link again, on the new provider's server, and a record
		// verified on it that was written after the link came back.
		var back time.Time
		r.waitFor(150*time.Second, "the tunnel back on "+to.String(), func() bool {
			if !p.running() {
				t.Fatalf("the exit stopped (%d):\n%s", p.code, p.out.String())
			}
			if back.IsZero() {
				if strings.Contains(r.endpoints(), to.endpoint+":") {
					back = time.Now()
				}
				return false
			}
			checked, err := time.Parse(time.RFC3339, fmt.Sprint(r.result()["checked_at"]))
			return err == nil && !checked.Before(back.Truncate(time.Second)) && r.verifiedOn(to, "")
		})
		close(stop)
		for ep := range <-watch {
			if !strings.HasPrefix(ep, to.endpoint+":") {
				t.Errorf("after the loss on %s, the tunnel came back on %s", to, ep)
			}
		}
		r.clientOn(to, 30*time.Second)
		r.onTunnel(to)
		r.leakFree("the tunnel lost on " + to.String())
		t.Logf("tunnel lost on %s: the link back on its server %v after, verified again %v after",
			to, back.Sub(lost).Round(time.Millisecond), time.Since(lost).Round(time.Millisecond))
		from = to
	}
	if _, adds, _, _ := pia.counts(); adds < 2 {
		t.Errorf("PIA registered %d times; the tunnel lost on PIA must register again", adds)
	}
}

// restartCrashed starts the exit again after it stopped on a crashed
// worker, as a container's restart policy would: the fake NetBird reset,
// the overlay keyed again.
func (r *systemRig) restartCrashed() *exitProc {
	r.t.Helper()
	_, _ = r.exit.Exec("nft", "delete", "table", "ip", "netbird")
	for _, f := range []string{"live", "trace"} {
		_ = os.Remove(filepath.Join(r.fakeDir, f))
	}
	p := r.start()
	r.waitReady(p)
	r.keyOverlay()
	return p
}

// rulesFrom are the exit's rules, both families, naming address as their
// source.
func (r *systemRig) rulesFrom(address string) []string {
	var found []string
	for _, family := range []string{"-4", "-6"} {
		out, _ := r.exit.Exec("ip", family, "rule", "show")
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, "from "+address+" ") {
				found = append(found, strings.TrimSpace(l))
			}
		}
	}
	return found
}

const holdLine = "drill hook: holding the tunnel replacement between its links"

// TestSystemRigMultiProviderInterruptedReplace: a provider change's Replace
// is held between its links (the old link deleted, the new one not yet
// created: the drill build's hold-replace hook) and the worker is killed
// there. The exit stops; started again, as Compose would, it must come back
// on the new provider, finish the interrupted request and verify it, with
// no return-path rule of the old tunnel left and nothing from the client
// leaving outside WireGuard. Twice: Mullvad -> PIA and PIA -> NordVPN.
func TestSystemRigMultiProviderInterruptedReplace(t *testing.T) {
	t.Parallel()
	r, p, _ := newMultiRig(t, "mullvad,nordvpn,pia")
	A, N, P := mullvadExit(r.relays[0]), nordExit(), piaExit()
	hold := filepath.Join(r.runDir, "hold-replace")
	for _, step := range []struct {
		from, to rigExit
		old      []string // the old tunnel's addresses
	}{
		{A, P, []string{rigTunnel4, rigTunnel6}},
		{P, N, []string{rigPIAPeer}},
	} {
		if err := os.WriteFile(hold, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		id := r.request(step.to.provider, step.to.server)
		r.waitFor(60*time.Second, "the replacement held between its links", func() bool {
			if !p.running() {
				t.Fatalf("the exit stopped (%d):\n%s", p.code, p.out.String())
			}
			return strings.Contains(p.out.String(), holdLine)
		})
		if r.linkExists(r.exit, "vpn") {
			t.Errorf("%s -> %s held: a tunnel link exists between the links", step.from, step.to)
		}
		pid := r.workerPid()
		if pid == 0 {
			t.Fatal("no worker process")
		}
		if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
			t.Fatal(err)
		}
		killed := time.Now()
		if code := p.wait(30 * time.Second); code == 0 {
			t.Error("a crashed worker must not exit 0")
		}
		r.leakFree("after the worker was killed in " + step.from.String() + " -> " + step.to.String())
		if got := r.tunnelProvider(); got != step.to.provider {
			t.Errorf("tunnel-provider.json names %q after the crash, want %s", got, step.to.provider)
		}
		if err := os.Remove(hold); err != nil {
			t.Fatal(err)
		}
		p = r.restartCrashed()
		r.waitOn(p, step.to, id, 150*time.Second)
		took := time.Since(killed)
		r.clientOn(step.to, 30*time.Second)
		r.onTunnel(step.to)
		for _, a := range step.old {
			if rules := r.rulesFrom(a); len(rules) > 0 {
				t.Errorf("on %s after the interrupted change, the old tunnel's rules are left: %q", step.to, rules)
			}
		}
		r.leakFree(step.from.String() + " -> " + step.to.String() + " after the restart")
		t.Logf("%s -> %s interrupted between the links: request %s verified on %s %v after the worker was killed; selection %s",
			step.from, step.to, id, step.to, took.Round(time.Millisecond), jsonText(r.result()["selection"]))
	}
}

// fwdSample is one look at the exit: whether its tunnel was on the Mullvad
// relay, and then whether the forwarding table was there.
type fwdSample struct {
	at             time.Time
	mullvad, table bool
}

// TestSystemRigMultiProviderPIAForwardLeft: PIA with port forwarding on
// forwards its port to the client, then the exit changes to Mullvad. The
// forwarding table must be gone before Mullvad's tunnel is up: an exit
// sampled throughout never shows Mullvad's peer while the table is there.
// The record then carries no forwarded port and PIA's registration is
// forgotten; changed back to PIA, the port is forwarded again.
func TestSystemRigMultiProviderPIAForwardLeft(t *testing.T) {
	t.Parallel()
	r, p, pia := newMultiRig(t, "mullvad,pia", "PIA_PORT_FORWARD=on", "PIA_PORT_FORWARD_TARGET="+rigClient4)
	A, B, P := mullvadExit(r.relays[0]), mullvadExit(r.relays[1]), piaExit()
	forwarded := func(what string) {
		t.Helper()
		// Port forwarding starts on a pass after the verdict is ok, and the
		// record that shows it comes with the next full check, a minute on.
		r.waitFor(240*time.Second, what, func() bool {
			if !p.running() {
				t.Fatalf("the exit stopped (%d):\n%s", p.code, p.out.String())
			}
			res := r.result()
			table := r.forwardTable()
			return res["forwarded_port"] == float64(rigPIAForward) &&
				strings.Contains(table, fmt.Sprint(rigPIAForward)) && strings.Contains(table, rigClient4)
		})
	}
	r.switchTo(p, A, P)
	at := time.Now()
	forwarded("PIA's port forwarded to the client")
	t.Logf("PIA forwarding port %d to %s %v after the change", rigPIAForward, rigClient4, time.Since(at).Round(time.Millisecond))

	// Sample the exit through the change: the tunnel's peer first, then the
	// table, so a sample showing both means both held at once.
	stop := make(chan struct{})
	var mu sync.Mutex
	var samples []fwdSample
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			s := fwdSample{at: time.Now(), mullvad: strings.Contains(r.endpoints(), B.endpoint+":")}
			_, err := r.exit.Exec("nft", "list", "table", "ip", "molebridge_forward")
			s.table = err == nil
			mu.Lock()
			samples = append(samples, s)
			mu.Unlock()
		}
	}()
	r.switchTo(p, P, B)
	close(stop)
	<-done
	firstMullvad, lastTable := -1, -1
	for i, s := range samples {
		if s.mullvad && firstMullvad < 0 {
			firstMullvad = i
		}
		if s.table {
			lastTable = i
		}
		if s.mullvad && s.table {
			t.Errorf("at %s the forwarding table was there with Mullvad's tunnel up", s.at.Format(time.RFC3339Nano))
		}
	}
	switch {
	case firstMullvad < 0 || lastTable < 0:
		t.Errorf("the samples missed the change: Mullvad's tunnel first at %d, the table last at %d of %d", firstMullvad, lastTable, len(samples))
	case lastTable >= firstMullvad:
		t.Errorf("the forwarding table was last seen at sample %d, Mullvad's tunnel first at %d", lastTable, firstMullvad)
	default:
		t.Logf("%d samples: the forwarding table last seen %v before Mullvad's tunnel was first seen",
			len(samples), samples[firstMullvad].at.Sub(samples[lastTable].at).Round(time.Millisecond))
	}
	if table := r.forwardTable(); table != "" {
		t.Errorf("the forwarding table outlived PIA:\n%s", table)
	}

	// Back to PIA: registered again, the port forwarded again.
	r.switchTo(p, B, P)
	forwarded("PIA's port forwarded again after coming back")
	logins, adds, sigs, binds := pia.counts()
	t.Logf("fake PIA served %d logins, %d registrations, %d signatures, %d binds", logins, adds, sigs, binds)
	if adds < 2 || sigs < 2 || binds < 2 {
		t.Errorf("PIA should have registered and forwarded twice: %d registrations, %d signatures, %d binds", adds, sigs, binds)
	}
}
