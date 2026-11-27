package applier

import (
	"os"
	"testing"
)

// Leaving a provider (docs/design/multi-provider.md, step 4).

func forwarding(c *PIAConfig) { c.PortForward, c.ForwardTarget = true, "192.0.2.10" }

// onPIAForwarding is a multi-provider exit on PIA with its port forwarded.
func onPIAForwarding(t *testing.T) *multiExit {
	t.Helper()
	m := newMultiPIA(t, "", "pia", allThree, forwarding, nil)
	desire(t, m.a, targetOf("pia"))
	mustTick(t, m.a)
	mustTick(t, m.a)
	if f := piaOf(m.a).forward; f == nil || !f.bound || m.k.lastNFT() != "forward 43210 192.0.2.10" {
		t.Fatalf("not forwarding: %+v %v", f, m.k.nftOps)
	}
	return m
}

func TestLeavingPIARemovesTheForwardBeforeTheTunnelChanges(t *testing.T) {
	m := onPIAForwarding(t)
	pia := piaOf(m.a)
	if _, err := os.Stat(tunnelPath(m.a)); err != nil {
		t.Fatal(err)
	}
	m.tunnels.before = func() {
		if m.k.lastNFT() != "remove-forward" {
			t.Errorf("the tunnel changed with the port forwarded: %v", m.k.nftOps)
		}
		if _, err := os.Stat(tunnelPath(m.a)); !os.IsNotExist(err) {
			t.Errorf("PIA's registration outlived it: %v", err)
		}
	}
	desire(t, m.a, targetOf("nordvpn"))
	r := mustTick(t, m.a)
	if status(r) != "ok" || m.a.Providers().Active() != "nordvpn" {
		t.Fatalf("%s: %s", status(r), message(r))
	}
	d := r.Decoded()
	if _, present := d["forwarded_port"]; present {
		t.Fatalf("forwarded_port after leaving PIA: %v", d["forwarded_port"])
	}
	if _, present := d["port_forward_error"]; present {
		t.Fatalf("port_forward_error after leaving PIA: %v", d["port_forward_error"])
	}
	if pia.forward != nil || pia.forwardError != "" || pia.nftPort != 0 {
		t.Fatalf("forwarding state kept: %+v %q %d", pia.forward, pia.forwardError, pia.nftPort)
	}
	// Nothing binds while another provider is active.
	ops := len(m.k.tableOps())
	for range 5 {
		m.k.now += 600
		mustTick(t, m.a)
	}
	if len(m.k.tableOps()) != ops {
		t.Fatalf("forwarding went on: %v", m.k.tableOps()[ops:])
	}

	// Back to PIA: a new registration, and the port forwarded again.
	m.tunnels.before = nil
	desire(t, m.a, targetOf("pia"))
	mustTick(t, m.a)
	mustTick(t, m.a)
	if m.a.Providers().Active() != "pia" || pia.forward == nil || !pia.forward.bound ||
		m.k.lastNFT() != "forward 43210 192.0.2.10" {
		t.Fatalf("active %s, forward %+v, %v", m.a.Providers().Active(), pia.forward, m.k.nftOps)
	}
	if r := m.a.inspect(t); r.Decoded()["forwarded_port"] != int64(43210) {
		t.Fatalf("forwarded_port %v", r.Decoded()["forwarded_port"])
	}
}

func TestAForwardThatCannotBeRemovedRefusesTheChange(t *testing.T) {
	m := onPIAForwarding(t)
	// Only the removal fails: with the guard failing too, the gate would
	// hold the change before it reached the removal.
	m.k.nftAlwaysFail, m.k.nftFailOnly = true, "remove-forward"
	desire(t, m.a, targetOf("mullvad"))
	r := mustTick(t, m.a)
	if status(r) == "ok" || len(m.tunnels.replaced) != 0 || m.a.Providers().Active() != "pia" {
		t.Fatalf("%s %v %s", status(r), m.tunnels.replaced, m.a.Providers().Active())
	}
	if at := m.attemptFile(t); at["mutation_certainty"] != "definite" || at["provider"] != "mullvad" ||
		at["state"] != "failed" {
		t.Fatalf("attempt %v", at)
	}
	// PIA's tunnel and registration are as they were.
	if _, err := os.Stat(tunnelPath(m.a)); err != nil {
		t.Fatal(err)
	}
	if len(m.k.keys) != 1 || m.k.keys[0] != piaServerKey {
		t.Fatalf("PIA's peer changed: %v", m.k.keys)
	}
	if !m.k.logged("removing the forwarded port before leaving PIA failed") {
		t.Fatalf("%v", m.k.logs)
	}
	// Retried on the backoff once the firewall answers.
	m.k.nftAlwaysFail = false
	for range 20 {
		m.k.now += 60
		if r = mustTick(t, m.a); m.a.Providers().Active() == "mullvad" {
			break
		}
	}
	if m.a.Providers().Active() != "mullvad" || m.k.lastNFT() != "remove-forward" || status(r) != "ok" {
		t.Fatalf("active %s, %s: %s, %v", m.a.Providers().Active(), status(r), message(r), m.k.nftOps)
	}
}
