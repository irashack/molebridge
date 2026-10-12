//go:build drill && linux

package tunnel_test

import (
	"context"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/nstest"
	"github.com/irashack/molebridge/internal/tunnel"
	"github.com/irashack/molebridge/internal/tunnelconf"
)

const zeroKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func conf(t *testing.T, provider tunnelconf.Provider, addresses string) *tunnelconf.Conf {
	t.Helper()
	post := "ip route replace default dev %i table 51821"
	pre := "ip route del default dev %i table 51821"
	allowed := "0.0.0.0/0"
	if strings.Contains(addresses, ":") {
		post += "; ip -6 route replace default dev %i table 51821"
		pre += "; ip -6 route del default dev %i table 51821"
		allowed += ", ::/0"
	}
	lines := []string{"[Interface]", "PrivateKey = " + zeroKey}
	if addresses != "" {
		lines = append(lines, "Address = "+addresses)
	}
	lines = append(lines, "MTU = 1380", "Table = off", "PostUp = "+post, "PreDown = "+pre)
	if provider == tunnelconf.Mullvad {
		lines = append(lines, "", "[Peer]", "PublicKey = "+zeroKey, "Endpoint = 198.51.100.10:51820", "AllowedIPs = "+allowed, "PersistentKeepalive = 25")
	}
	c, err := tunnelconf.Parse(strings.Join(lines, "\n")+"\n", provider, 51821)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func open(t *testing.T, ns *nstest.NS) *tunnel.Manager {
	t.Helper()
	m, err := tunnel.Open(tunnel.Options{NetNS: ns.Fd()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func TestUpBringsUpTheMullvadTunnelAsWgQuickDid(t *testing.T) {
	ns := nstest.New(t, "up")
	m := open(t, ns)
	c := conf(t, tunnelconf.Mullvad, "203.0.113.2/32, 2001:db8:3::2/128")
	if err := m.Up(tunnel.Params{ExitIf: "mullvad", Conf: c}); err != nil {
		t.Fatal(err)
	}
	out := ns.IP("-d", "link", "show", "dev", "mullvad")
	for _, want := range []string{"mtu 1380", "wireguard", "UP"} {
		if !strings.Contains(out, want) {
			t.Errorf("link: %q lacks %q", out, want)
		}
	}
	if a := ns.IP("-4", "addr", "show", "dev", "mullvad"); !strings.Contains(a, "203.0.113.2/32") {
		t.Errorf("IPv4 address: %s", a)
	}
	if a := ns.IP("-6", "addr", "show", "dev", "mullvad"); !strings.Contains(a, "2001:db8:3::2/128") {
		t.Errorf("IPv6 address: %s", a)
	}
	for _, f := range []string{"-4", "-6"} {
		if r := ns.IP(f, "route", "show", "table", "51821"); !strings.Contains(r, "default dev mullvad") {
			t.Errorf("%s exit table: %q", f, r)
		}
	}
	dev, err := m.Device(context.Background(), "mullvad")
	if err != nil {
		t.Fatal(err)
	}
	if dev.PrivateKey != (wgtypes.Key{}) || len(dev.Peers) != 1 {
		t.Fatalf("device: %d peers", len(dev.Peers))
	}
	p := dev.Peers[0]
	if p.Endpoint.String() != "198.51.100.10:51820" || p.PersistentKeepaliveInterval.Seconds() != 25 || len(p.AllowedIPs) != 2 {
		t.Errorf("peer: %v %v %v", p.Endpoint, p.PersistentKeepaliveInterval, p.AllowedIPs)
	}
	if dev.FirewallMark != 0 {
		t.Errorf("Table = off leaves the fwmark alone, got %d", dev.FirewallMark)
	}
	// A second attempt replaces the first cleanly.
	if err := m.Up(tunnel.Params{ExitIf: "mullvad", Conf: c}); err != nil {
		t.Fatalf("second Up: %v", err)
	}
	if r := ns.IP("-4", "route", "show", "table", "51821"); strings.Count(r, "default dev mullvad") != 1 {
		t.Errorf("exit table after the second Up: %q", r)
	}
}

func TestUpForPIAHasNoAddressNoPeerAndIPv4Only(t *testing.T) {
	ns := nstest.New(t, "pia")
	m := open(t, ns)
	c := conf(t, tunnelconf.PIA, "")
	if err := m.Up(tunnel.Params{ExitIf: "pia", Conf: c}); err != nil {
		t.Fatal(err)
	}
	if a := ns.IP("addr", "show", "dev", "pia"); strings.Contains(a, "inet ") || strings.Contains(a, "inet6 2") {
		t.Errorf("addresses on an addressless config: %s", a)
	}
	if r := ns.IP("-4", "route", "show", "table", "51821"); !strings.Contains(r, "default dev pia") {
		t.Errorf("IPv4 exit table: %q", r)
	}
	// The IPv6 table was never touched, so it does not exist.
	if r, err := ns.TryIP("-6", "route", "show", "table", "51821"); err == nil && strings.Contains(r, "default") {
		t.Errorf("IPv6 exit table: %q", r)
	}
	dev, _ := m.Device(context.Background(), "pia")
	if len(dev.Peers) != 0 {
		t.Errorf("peers: %d", len(dev.Peers))
	}
}

func TestDownRemovesTheLinkAndLeavesTheFallback(t *testing.T) {
	ns := nstest.New(t, "down")
	m := open(t, ns)
	c := conf(t, tunnelconf.Mullvad, "203.0.113.2/32")
	for _, f := range []string{"-4", "-6"} {
		ns.IP(f, "route", "replace", "unreachable", "default", "metric", "4096", "table", "51821")
	}
	ns.IP("rule", "add", "iif", "lo", "unreachable", "priority", "97")
	p := tunnel.Params{ExitIf: "mullvad", Conf: c}
	if err := m.Up(p); err != nil {
		t.Fatal(err)
	}
	if err := m.Down(p); err != nil {
		t.Fatal(err)
	}
	if _, err := ns.TryIP("link", "show", "dev", "mullvad"); err == nil {
		t.Error("the link survived Down")
	}
	if r := ns.IP("-4", "route", "show", "table", "51821"); !strings.Contains(r, "unreachable default metric 4096") {
		t.Errorf("the fallback must stay: %q", r)
	}
	if !strings.Contains(ns.IP("rule", "show", "priority", "97"), "unreachable") {
		t.Error("a rule went with the tunnel")
	}
	// Down of a tunnel that is not there is fine.
	if err := m.Down(p); err != nil {
		t.Fatal(err)
	}
}

func TestAFailedAttemptLeavesNoLinkBehind(t *testing.T) {
	ns := nstest.New(t, "fail")
	// New interfaces get IPv6 disabled, so the IPv6 address fails after the
	// link, the key and the IPv4 address are in.
	ns.Sysctl("net.ipv6.conf.default.disable_ipv6=1")
	m := open(t, ns)
	c := conf(t, tunnelconf.Mullvad, "203.0.113.2/32, 2001:db8:3::2/128")
	err := m.Up(tunnel.Params{ExitIf: "mullvad", Conf: c})
	if err == nil {
		t.Skip("this kernel accepted an IPv6 address on an interface with IPv6 disabled")
	}
	if strings.Contains(err.Error(), zeroKey) {
		t.Error("the key in an error")
	}
	if _, lerr := ns.TryIP("link", "show", "dev", "mullvad"); lerr == nil {
		t.Error("a half-built link survived a failed attempt")
	}
	// The next attempt, with the fault gone, succeeds.
	ns.Sysctl("net.ipv6.conf.default.disable_ipv6=0")
	if err := m.Up(tunnel.Params{ExitIf: "mullvad", Conf: c}); err != nil {
		t.Fatal(err)
	}
}

func TestUpReplacesAnyLeftoverLinkOfTheName(t *testing.T) {
	ns := nstest.New(t, "leftover")
	ns.IP("link", "add", "mullvad", "type", "dummy")
	m := open(t, ns)
	if err := m.Up(tunnel.Params{ExitIf: "mullvad", Conf: conf(t, tunnelconf.NordVPN, "10.5.0.2/32")}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ns.IP("-d", "link", "show", "dev", "mullvad"), "wireguard") {
		t.Error("not a wireguard link")
	}
}

func TestCleanup(t *testing.T) {
	setup := func(t *testing.T) (*nstest.NS, *tunnel.Manager) {
		ns := nstest.New(t, "cleanup")
		m := open(t, ns)
		ns.IP("link", "add", "wt0", "type", "wireguard")
		ns.IP("link", "add", "wg0", "type", "wireguard")
		ns.IP("rule", "add", "not", "iif", "wt0", "lookup", "local", "priority", "1")
		ns.IP("rule", "add", "iif", "wt0", "unreachable", "priority", "97")
		ns.IP("-6", "route", "replace", "unreachable", "default", "metric", "4096", "table", "51821")
		return ns, m
	}
	// Native: both the tunnel and the overlay.
	ns, m := setup(t)
	if err := m.Cleanup(contract.Native, "wg0", "wt0"); err != nil {
		t.Fatal(err)
	}
	for _, l := range []string{"wt0", "wg0"} {
		if _, err := ns.TryIP("link", "show", "dev", l); err == nil {
			t.Errorf("native: %s survived", l)
		}
	}
	for _, p := range []string{"1", "97"} {
		if ns.IP("rule", "show", "priority", p) == "" {
			t.Errorf("a rule (%s) went with the links", p)
		}
	}
	if !strings.Contains(ns.IP("-6", "route", "show", "table", "51821"), "unreachable") {
		t.Error("the fallback went")
	}
	if err := m.Cleanup(contract.Native, "wg0", "wt0"); err != nil {
		t.Fatalf("a second cleanup: %v", err)
	}
	// gluetun: only the overlay; gluetun's own tunnel is not ours.
	ns, m = setup(t)
	if err := m.Cleanup(contract.Gluetun, "wg0", "wt0"); err != nil {
		t.Fatal(err)
	}
	if _, err := ns.TryIP("link", "show", "dev", "wt0"); err == nil {
		t.Error("gluetun: the overlay survived")
	}
	if _, err := ns.TryIP("link", "show", "dev", "wg0"); err != nil {
		t.Error("gluetun: the tunnel is not ours to delete")
	}
}

func TestFwmark(t *testing.T) {
	ns := nstest.New(t, "fwmark")
	m := open(t, ns)
	if _, err := m.Fwmark("wt0"); err != tunnel.ErrNoDevice {
		t.Fatalf("missing device: %v", err)
	}
	ns.IP("link", "add", "wt0", "type", "wireguard")
	if v, err := m.Fwmark("wt0"); err != nil || v != 0 {
		t.Fatalf("%d %v", v, err)
	}
	mark := 0x1bd00
	if err := m.Configure(context.Background(), "wt0", wgtypes.Config{FirewallMark: &mark}); err != nil {
		t.Fatal(err)
	}
	if v, err := m.Fwmark("wt0"); err != nil || v != 0x1bd00 {
		t.Fatalf("%#x %v", v, err)
	}
}
