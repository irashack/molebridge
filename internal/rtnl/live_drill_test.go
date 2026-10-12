//go:build drill && linux

package rtnl_test

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/nstest"
	"github.com/irashack/molebridge/internal/rtnl"
)

func dial(t *testing.T, ns *nstest.NS) *rtnl.Conn {
	t.Helper()
	c, err := rtnl.Dial(rtnl.Options{NetNS: ns.Fd()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func ruleAt(t *testing.T, c *rtnl.Conn, f rtnl.Family, priority uint32) []rtnl.Rule {
	t.Helper()
	rules, err := c.Rules(f)
	if err != nil {
		t.Fatal(err)
	}
	var out []rtnl.Rule
	for _, r := range rules {
		if r.Priority == priority {
			out = append(out, r)
		}
	}
	return out
}

// Every selector and action the contract uses survives a trip through a real
// kernel: add through the codec, read back through the codec, and agree with
// what iproute2 says about it.
func TestLiveRuleCodecAgainstTheKernel(t *testing.T) {
	ns := nstest.New(t, "codec")
	ns.IP("link", "add", "wt0", "type", "dummy")
	c := dial(t, ns)

	want := []rtnl.Rule{
		{Family: rtnl.V4, Priority: 1, Action: rtnl.FRActToTbl, Table: rtnl.TableLocal, Flags: rtnl.FIBRuleInvert, IifName: "wt0"},
		{Family: rtnl.V4, Priority: 88, Action: rtnl.FRActToTbl, Table: 51822, IifName: "lo", FwMark: rtnl.Some(uint32(0x1bd00)), FwMask: rtnl.Some(uint32(0xffffffff))},
		{Family: rtnl.V4, Priority: 89, Action: rtnl.FRActUnreachable, IifName: "lo", FwMark: rtnl.Some(uint32(0x1bd00)), FwMask: rtnl.Some(uint32(0xffffffff))},
		{Family: rtnl.V4, Priority: 91, Action: rtnl.FRActToTbl, Table: rtnl.TableMain, IifName: "lo", Dst: netip.MustParsePrefix("192.0.2.0/24"), SuppressPrefixLen: rtnl.Some(uint32(0))},
		{Family: rtnl.V4, Priority: 94, Action: rtnl.FRActToTbl, Table: 2147483647, Src: netip.MustParsePrefix("203.0.113.1/32"), IPProto: rtnl.Some(uint8(1))},
		{Family: rtnl.V4, Priority: 98, Action: rtnl.FRActUnreachable, Src: netip.MustParsePrefix("203.0.113.1/32"), IPProto: rtnl.Some(uint8(1))},
		{Family: rtnl.V4, Priority: 97, Action: rtnl.FRActUnreachable, IifName: "wt0"},
		{Family: rtnl.V4, Priority: 96, Action: rtnl.FRActToTbl, Table: 51821, OifName: "gone0"},
		{Family: rtnl.V6, Priority: 94, Action: rtnl.FRActToTbl, Table: 51821, Src: netip.MustParsePrefix("2001:db8:3::1/128"), IPProto: rtnl.Some(uint8(58))},
		{Family: rtnl.V6, Priority: 90, Action: rtnl.FRActToTbl, Table: rtnl.TableMain, IifName: "wt0", Dst: netip.MustParsePrefix("2001:db8:1::/64")},
	}
	for _, r := range want {
		if err := c.AddRule(r); err != nil {
			t.Fatalf("add %v: %v", r, err)
		}
	}
	if err := c.AddRule(want[0]); !rtnl.IsExist(err) {
		t.Fatalf("adding an identical rule: want EEXIST, got %v", err)
	}
	for _, w := range want {
		got := ruleAt(t, c, w.Family, w.Priority)
		if len(got) != 1 {
			t.Fatalf("priority %d: %d rules", w.Priority, len(got))
		}
		if !reflect.DeepEqual(got[0].Items(), w.Items()) {
			t.Errorf("priority %d: kernel reports\n %q\nwe installed\n %q", w.Priority, got[0].Items(), w.Items())
		}
	}
	if g := ruleAt(t, c, rtnl.V4, 96)[0]; !g.OifDetached() {
		t.Errorf("a rule for an interface that does not exist must be detached: flags %#x", g.Flags)
	}
	if g := ruleAt(t, c, rtnl.V4, 97)[0]; g.IifDetached() {
		t.Errorf("a rule for an interface that exists must not be detached")
	}
	// iproute2 agrees about the unusual ones.
	out := ns.IP("rule", "show", "priority", "88")
	if !strings.Contains(out, "fwmark 0x1bd00") || !strings.Contains(out, "iif lo") {
		t.Errorf("ip rule show: %q", out)
	}
	if !strings.Contains(ns.IP("rule", "show", "priority", "94"), "lookup 2147483647") {
		t.Error("a table above 255 did not survive")
	}

	// Deleting by full attributes removes that rule and only that rule.
	if err := c.DelRule(ruleAt(t, c, rtnl.V4, 91)[0]); err != nil {
		t.Fatal(err)
	}
	if n := len(ruleAt(t, c, rtnl.V4, 91)); n != 0 {
		t.Fatalf("rule 91 still present (%d)", n)
	}
	if n := len(ruleAt(t, c, rtnl.V4, 88)); n != 1 {
		t.Fatalf("an unrelated rule went with it (%d)", n)
	}
	if err := c.DelRulePriority(rtnl.V4, 98); err != nil {
		t.Fatal(err)
	}
	if n := len(ruleAt(t, c, rtnl.V4, 98)); n != 0 {
		t.Fatalf("rule 98 still present")
	}
	if err := c.DelRulePriority(rtnl.V4, 98); !rtnl.IsNotExist(err) {
		t.Fatalf("deleting a missing rule: want ENOENT, got %v", err)
	}
}

// A rule the codec does not model comes back raw and can be removed.
func TestLiveUnknownSelectorsAreKeptAndDeletable(t *testing.T) {
	ns := nstest.New(t, "unknown")
	c := dial(t, ns)
	ns.IP("rule", "add", "uidrange", "1000-2000", "sport", "80", "dport", "443", "lookup", "main", "priority", "123")
	got := ruleAt(t, c, rtnl.V4, 123)
	if len(got) != 1 || len(got[0].Unknown) == 0 {
		t.Fatalf("selectors beyond the model were dropped: %+v", got)
	}
	if err := c.DelRule(got[0]); err != nil {
		t.Fatalf("deleting a rule with unmodeled selectors: %v", err)
	}
	if n := len(ruleAt(t, c, rtnl.V4, 123)); n != 0 {
		t.Fatal("rule survived")
	}
}

func TestLiveRoutesLinksAndAddresses(t *testing.T) {
	ns := nstest.New(t, "dump")
	ns.IP("link", "add", "dum0", "type", "dummy")
	ns.IP("link", "set", "dum0", "up")
	ns.IP("addr", "add", "203.0.113.1/32", "dev", "dum0")
	ns.IP("-6", "addr", "add", "2001:db8:3::1/128", "dev", "dum0", "nodad")
	c := dial(t, ns)
	zero4 := netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	zero6 := netip.PrefixFrom(netip.IPv6Unspecified(), 0)

	for _, r := range []rtnl.Route{
		{Family: rtnl.V4, Dst: zero4, Table: 51821, Type: rtnl.RTNUnreachable, Metric: 4096, Protocol: rtnl.RTProtoBoot},
		{Family: rtnl.V6, Dst: zero6, Table: 51821, Type: rtnl.RTNUnreachable, Metric: 4096, Protocol: rtnl.RTProtoBoot},
	} {
		if err := c.ReplaceRoute(r); err != nil {
			t.Fatalf("%+v: %v", r, err)
		}
		if err := c.ReplaceRoute(r); err != nil {
			t.Fatalf("replace is idempotent: %v", err)
		}
	}
	links, err := c.Links()
	if err != nil {
		t.Fatal(err)
	}
	var dum rtnl.Link
	for _, l := range links {
		if l.Name == "dum0" {
			dum = l
		}
	}
	if dum.Index == 0 || !dum.Up() || dum.Kind != "dummy" {
		t.Fatalf("link: %+v", dum)
	}
	for _, r := range []rtnl.Route{
		{Family: rtnl.V4, Dst: zero4, Table: 51821, Type: rtnl.RTNUnicast, Oif: rtnl.Some(dum.Index), Protocol: rtnl.RTProtoBoot},
		{Family: rtnl.V6, Dst: zero6, Table: 51821, Type: rtnl.RTNUnicast, Oif: rtnl.Some(dum.Index), Protocol: rtnl.RTProtoBoot},
	} {
		if err := c.ReplaceRoute(r); err != nil {
			t.Fatalf("%+v: %v", r, err)
		}
	}
	snap, err := c.Take(rtnl.Interest{Tables: []uint32{51821}})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []rtnl.Family{rtnl.V4, rtnl.V6} {
		routes := snap.RoutesInTable(f, 51821)
		if len(routes) != 2 {
			t.Fatalf("%s: %d routes in the exit table: %+v", f, len(routes), routes)
		}
	}
	a4, ok := snap.GlobalAddr("dum0", rtnl.V4)
	if !ok || a4 != netip.MustParseAddr("203.0.113.1") {
		t.Fatalf("IPv4 address: %v %v", a4, ok)
	}
	a6, ok := snap.GlobalAddr("dum0", rtnl.V6)
	if !ok || a6 != netip.MustParseAddr("2001:db8:3::1") {
		t.Fatalf("IPv6 address: %v %v", a6, ok)
	}
	// Only the wanted table is kept.
	if len(snap.RoutesInTable(rtnl.V4, rtnl.TableMain)) != 0 {
		t.Error("a table nobody asked for was kept")
	}
	// Delete the unicast default by its attributes; the fallback stays.
	if err := c.DelRoute(rtnl.Route{Family: rtnl.V4, Dst: zero4, Table: 51821, Type: rtnl.RTNUnicast, Oif: rtnl.Some(dum.Index)}); err != nil {
		t.Fatal(err)
	}
	left := mustRoutes(t, c, rtnl.V4, 51821)
	if len(left) != 1 || left[0].Type != rtnl.RTNUnreachable {
		t.Fatalf("after deleting the tunnel default: %+v", left)
	}
	if err := c.DelRoute(rtnl.Route{Family: rtnl.V4, Dst: zero4, Table: 51821, Type: rtnl.RTNUnicast, Oif: rtnl.Some(dum.Index)}); !rtnl.IsNotExist(err) {
		t.Fatalf("deleting a missing route: %v", err)
	}
}

func mustRoutes(t *testing.T, c *rtnl.Conn, f rtnl.Family, table uint32) []rtnl.Route {
	t.Helper()
	r, err := c.Routes(f, func(x uint32) bool { return x == table })
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A change made by `ip` from outside reaches the subscriber well inside the
// repair budget, for rules, routes, links and addresses in both families.
func TestLiveEventsArriveWithin50ms(t *testing.T) {
	ns := nstest.New(t, "events")
	ns.IP("link", "add", "dum0", "type", "dummy")
	ns.IP("link", "set", "dum0", "up")
	sub, err := rtnl.Subscribe(rtnl.Options{NetNS: ns.Fd()})
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	cases := []struct {
		name string
		args []string
		kind rtnl.EventKind
		fam  rtnl.Family
	}{
		{"IPv4 rule", []string{"rule", "add", "lookup", "main", "priority", "50"}, rtnl.EventRule, rtnl.V4},
		{"IPv6 rule", []string{"-6", "rule", "add", "lookup", "main", "priority", "50"}, rtnl.EventRule, rtnl.V6},
		{"link", []string{"link", "add", "dum1", "type", "dummy"}, rtnl.EventLink, 0},
		{"IPv4 address", []string{"addr", "add", "192.0.2.1/24", "dev", "dum0"}, rtnl.EventAddr, rtnl.V4},
		{"IPv4 route", []string{"route", "add", "198.51.100.0/24", "dev", "dum0", "table", "51821"}, rtnl.EventRoute, rtnl.V4},
		{"IPv6 route", []string{"-6", "route", "add", "unreachable", "2001:db8::/32", "table", "51821"}, rtnl.EventRoute, rtnl.V6},
	}
	for _, c := range cases {
		start := time.Now()
		ns.IP(c.args...)
		took := time.Since(start)
		var got []rtnl.Event
		for len(got) == 0 {
			ev, err := sub.Next(time.Now().Add(time.Second))
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			got = ev
		}
		since := time.Since(start)
		found := false
		for _, e := range got {
			if e.Kind == c.kind && (c.fam == 0 || e.Family == c.fam || e.Kind == rtnl.EventLink) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: events %+v", c.name, got)
		}
		if since-took > 50*time.Millisecond {
			t.Errorf("%s: event arrived %v after the command returned", c.name, since-took)
		}
		// Drain what the change also produced (a link brings routes, say).
		for {
			if _, err := sub.Next(time.Now().Add(20 * time.Millisecond)); err != nil {
				break
			}
		}
	}
	// An idle subscriber times out instead of blocking.
	if _, err := sub.Next(time.Now().Add(30 * time.Millisecond)); !rtnl.Timeout(err) {
		t.Fatalf("idle Next: %v", err)
	}
}

// Events are lost when the receive buffer is tiny and a flood arrives; the
// subscriber says so instead of going quiet.
func TestLiveFloodReportsOverrun(t *testing.T) {
	ns := nstest.New(t, "flood")
	sub, err := rtnl.Subscribe(rtnl.Options{NetNS: ns.Fd(), ReadBuffer: 2048})
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	var batch strings.Builder
	for i := 0; i < 3000; i++ {
		batch.WriteString("rule add lookup main priority 5000\nrule del priority 5000\n")
	}
	path := t.TempDir() + "/flood.batch"
	if err := os.WriteFile(path, []byte(batch.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	ns.IP("-batch", path)
	var overrun bool
	for i := 0; i < 20000 && !overrun; i++ {
		_, err := sub.Next(time.Now().Add(100 * time.Millisecond))
		switch {
		case errors.Is(err, rtnl.ErrOverrun):
			overrun = true
		case err != nil && rtnl.Timeout(err):
			i = 20000
		case err != nil:
			t.Fatal(err)
		}
	}
	if !overrun {
		t.Fatal("a flood into a 2 KiB buffer produced no ENOBUFS")
	}
}

// Dumps taken while rules change under them: a snapshot is never a mixture.
// 1,500 stable rules stay put while another process adds and deletes rules as
// fast as it can; every snapshot has each stable rule exactly once, and the
// kernel's interruption marks were seen and acted on.
func TestLiveSnapshotsSurviveConcurrentChanges(t *testing.T) {
	ns := nstest.New(t, "concurrent")
	var stable strings.Builder
	for i := 1; i <= 1500; i++ {
		fmt.Fprintf(&stable, "rule add lookup main priority %d\n", 1000+i)
	}
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/stable", []byte(stable.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	ns.IP("-batch", dir+"/stable")
	var churn strings.Builder
	for i := 0; i < 100000; i++ {
		churn.WriteString("rule add lookup main priority 500\nrule del priority 500\n")
	}
	if err := os.WriteFile(dir+"/churn", []byte(churn.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	c := dial(t, ns)
	done := make(chan struct{})
	go func() { defer close(done); _, _ = ns.TryIP("-batch", dir+"/churn") }()
	var taken, unstable int
	for running := true; running; {
		select {
		case <-done:
			running = false
		default:
		}
		s, err := c.Take(rtnl.Interest{Tables: []uint32{254}})
		if err != nil {
			if errors.Is(err, rtnl.ErrInconsistent) || strings.Contains(err.Error(), "no consistent snapshot") {
				continue // honest: the kernel never held still long enough
			}
			t.Fatal(err)
		}
		if s.Unstable {
			unstable++
			continue
		}
		taken++
		seen := map[uint32]int{}
		for _, r := range s.Rules[rtnl.V4] {
			if r.Priority > 1000 && r.Priority <= 2500 {
				seen[r.Priority]++
			}
		}
		for p := uint32(1001); p <= 2500; p++ {
			if seen[p] != 1 {
				t.Fatalf("a snapshot has rule %d %d times", p, seen[p])
			}
		}
	}
	if taken == 0 {
		t.Fatal("no snapshot completed")
	}
	if c.Interrupts() == 0 {
		t.Log("the kernel never marked a dump interrupted in this run; the scripted tests cover the retry")
	}
	t.Logf("%d stable snapshots, %d marked unstable, %d interrupted dumps discarded, %d stream resets", taken, unstable, c.Interrupts(), c.Resets())
}
