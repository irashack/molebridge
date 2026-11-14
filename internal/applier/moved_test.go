package applier

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/verdict"
)

// A selected server the provider retires: the exit moves to another server in
// the same city, only for a server it verified, and returns when it is listed
// again (moved.go). Against the fake kernel.

const elsewhereHost = "de-fra-wg-001"

// retire removes a server from the catalogue, as a refresh without it would.
func retire(a *Applier, host string) {
	catalog := snapshot(a)
	catalog.Relays = catalog.Relays.Filter(func(name string, _ *providers.Relay) bool { return name != host })
}

func elsewhere(a *Applier) {
	relay := mullvadEntry(elsewhereHost, thirdKey)
	relay["city"], relay["country"], relay["location_code"] = "Other City", "Elsewhere", "de-fra"
	snapshot(a).Relays.Set(elsewhereHost, providers.ValidateMullvadEntry(relay))
}

func movedOf(r *Record) (from, to any) {
	moved, _ := r.Decoded()["moved"].(map[string]any)
	return moved["from"], moved["to"]
}

// verifiedOn is an applier whose panel request for testHost is verified.
func verifiedOn(t *testing.T) (*Applier, *kernel, string) {
	t.Helper()
	a, k, dir := pipelineSetup(t)
	desire(t, a, requestAt(testHost, nil))
	if r := mustTick(t, a); status(r) != "ok" || r.Get("server") != testHost {
		t.Fatalf("%s %v %s", status(r), r.Get("server"), message(r))
	}
	return a, k, dir
}

func TestARetiredServerMovesToAnotherInTheSameCity(t *testing.T) {
	a, k, _ := verifiedOn(t)
	elsewhere(a)
	retire(a, testHost)
	k.now += 600
	r := mustTick(t, a)
	from, to := movedOf(r)
	if status(r) != "ok" || r.Get("server") != otherHost || r.Get("requested_server") != testHost ||
		from != testHost || to != otherHost {
		t.Fatalf("%s server %v requested %v moved %v -> %v: %s", status(r), r.Get("server"), r.Get("requested_server"), from, to, message(r))
	}
	if len(k.keys) != 1 || k.keys[0] != otherKey {
		t.Fatalf("live peer %v", k.keys)
	}
	if !k.logged("moving to another server in the same city") {
		t.Fatalf("logs %v", k.logs)
	}
	// Readers judge the record connected for the request it stands in for.
	v := a.assess(a.judged(r).Decoded())
	if v.State != "ok" || len(v.Reasons) != 1 || v.Reasons[0] != "server-moved" {
		t.Fatalf("verdict %s %v", v.State, v.Reasons)
	}
	target := verdict.Target{Server: testHost, Source: "panel", Request: a.request}
	if v := verdict.Assess(a.exitConfig(), a.judged(r).Decoded(), target, a.wall()); v.State != "ok" {
		t.Fatalf("the panel's verdict %s %v", v.State, v.Reasons)
	}
	// The choice holds: later passes change nothing.
	mutations := len(k.adds())
	k.now += 600
	if r := mustTick(t, a); r == nil || status(r) != "ok" || r.Get("server") != otherHost || len(k.adds()) != mutations {
		t.Fatalf("a later pass: %v, %d mutations", r, len(k.adds())-mutations)
	}
}

func TestAMovedExitReturnsWhenItsServerIsListedAgain(t *testing.T) {
	a, k, _ := verifiedOn(t)
	retire(a, testHost)
	k.now += 600
	if r := mustTick(t, a); r.Get("server") != otherHost {
		t.Fatalf("not moved: %v %s", r.Get("server"), message(r))
	}
	addRelay(a, testHost, testKey)
	k.now += 600
	r := mustTick(t, a)
	if status(r) != "ok" || r.Get("server") != testHost || r.Decoded()["moved"] != nil {
		t.Fatalf("%s %v moved %v", status(r), r.Get("server"), r.Decoded()["moved"])
	}
	if a.location.Replacement != "" || a.location.Server != testHost {
		t.Fatalf("location %+v", a.location)
	}
}

func TestAMoveSurvivesARestart(t *testing.T) {
	a, k, dir := verifiedOn(t)
	retire(a, testHost)
	k.now += 600
	mustTick(t, a)
	// The snapshot on disk still lists the server; the restarted exit's
	// catalogue is made to miss it again.
	b := newApplier(t, k, dir, NewMullvad(), "")
	retire(b, testHost)
	if b.location.Server != testHost || b.location.Replacement != otherHost {
		t.Fatalf("loaded %+v", b.location)
	}
	k.now += 600
	r := mustTick(t, b)
	from, to := movedOf(r)
	if status(r) != "ok" || r.Get("server") != otherHost || from != testHost || to != otherHost {
		t.Fatalf("%s %v %v -> %v: %s", status(r), r.Get("server"), from, to, message(r))
	}
}

func TestAServerNeverVerifiedHereIsStillRefused(t *testing.T) {
	a, k, _ := verifiedOn(t)
	k.now += 600
	desire(t, a, requestAt("se-sto-wg-009", map[string]any{"request_id": "11111111111111111111111111111111"}))
	r := mustTick(t, a)
	if message(r) != Unlisted || r.Decoded()["moved"] != nil || r.Get("server") != testHost {
		t.Fatalf("%s %q server %v moved %v", status(r), message(r), r.Get("server"), r.Decoded()["moved"])
	}
}

func TestARetiredServerWithNoOtherInItsCityIsRefused(t *testing.T) {
	a, k, _ := verifiedOn(t)
	elsewhere(a)
	retire(a, testHost)
	retire(a, otherHost)
	k.now += 600
	desire(t, a, requestAt(testHost, map[string]any{"request_id": "22222222222222222222222222222222"}))
	r := mustTick(t, a)
	if message(r) != Unlisted || r.Decoded()["moved"] != nil {
		t.Fatalf("%s %q moved %v", status(r), message(r), r.Decoded()["moved"])
	}
	for _, key := range k.keys {
		if key == thirdKey {
			t.Fatal("moved to another city")
		}
	}
}

func TestARetiredConfiguredServerMoves(t *testing.T) {
	dir := t.TempDir()
	k := newKernel(t)
	a := buildApplier(t, k, dir, NewMullvad(), testHost)
	if r := mustTick(t, a); status(r) != "ok" || r.Get("server") != testHost {
		t.Fatalf("%s %v %s", status(r), r.Get("server"), message(r))
	}
	retire(a, testHost)
	k.now += 600
	r := mustTick(t, a)
	from, to := movedOf(r)
	if status(r) != "ok" || r.Get("server") != otherHost || from != testHost || to != otherHost {
		t.Fatalf("%s %v %v -> %v: %s", status(r), r.Get("server"), from, to, message(r))
	}
	if v := a.assess(a.judged(r).Decoded()); v.State != "ok" {
		t.Fatalf("verdict %s %v", v.State, v.Reasons)
	}
}

func TestNextAfterIsTheNeighbourAndWraps(t *testing.T) {
	names := func() []string { return []string{"c", "a", "e"} }
	for from, want := range map[string]string{"b": "c", "c": "e", "e": "a", "z": "a", "": "a"} {
		if got := nextAfter(names(), from); got != want {
			t.Errorf("after %q: %q, want %q", from, got, want)
		}
	}
	if nextAfter(nil, "a") != "" {
		t.Error("no candidates")
	}
}

func TestAMalformedLocationIsNoMemory(t *testing.T) {
	a, _, dir := verifiedOn(t)
	for _, content := range []string{`{"server":"se-sto-wg-001","city":"","country":"Example"}`, `[]`, `{"server":7}`,
		`{"server":"not a host","city":"Example City","country":"Example"}`} {
		writeFile(t, dir+"/applier/location.json", content, 0o600)
		if l := a.loadLocation(); l != (location{}) {
			t.Errorf("%s: %+v", content, l)
		}
	}
}

func TestPickingTheReplacementMakesItTheRememberedServer(t *testing.T) {
	a, k, _ := verifiedOn(t)
	retire(a, testHost)
	k.now += 600
	mustTick(t, a)
	if a.location.Server != testHost || a.location.Replacement != otherHost {
		t.Fatalf("location %+v", a.location)
	}
	k.now += 600
	desire(t, a, requestAt(otherHost, map[string]any{"request_id": "33333333333333333333333333333333"}))
	r := mustTick(t, a)
	if status(r) != "ok" || r.Get("server") != otherHost || r.Decoded()["moved"] != nil {
		t.Fatalf("%s %v moved %v: %s", status(r), r.Get("server"), r.Decoded()["moved"], message(r))
	}
	if a.location.Server != otherHost || a.location.Replacement != "" {
		t.Fatalf("location %+v", a.location)
	}
}

// glSettle runs passes until the exit is verified on server.
func glSettle(t *testing.T, f *glFixture, server string) *Record {
	t.Helper()
	var r *Record
	for i := 0; i < 40 && (r == nil || r.Get("status") != "ok" || r.Get("server") != server); i++ {
		f.k.now += 30
		if next := mustTick(t, f.a); next != nil && next.Get("status") != nil {
			r = next
		}
	}
	if r == nil || r.Get("status") != "ok" || r.Get("server") != server {
		t.Fatalf("not verified on %s: %v; logs %v", server, r, f.k.logs)
	}
	return r
}

// glServers rewrites gluetun's servers.json, as its updater does. hostA and
// hostB share a city; hostC is in another.
func glServers(t *testing.T, f *glFixture, modified int64, hosts ...string) {
	t.Helper()
	content := strings.ReplaceAll(serversJSON("ivpn", 0, hostA, hostB, hostC), "City 1", "City 0")
	if len(hosts) == 2 {
		content = serversJSON("ivpn", 0, hosts...)
	}
	writeFile(t, f.servers, content, 0o644)
	if err := os.Chtimes(f.servers, time.Unix(modified, 0), time.Unix(modified, 0)); err != nil {
		t.Fatal(err)
	}
}

// The gluetun backend: the same move, through gluetun's control server.
func TestARetiredGluetunServerMovesToAnotherInTheSameCity(t *testing.T) {
	f := newGluetunFixture(t, glOptions{})
	glServers(t, f, 1)
	desire(t, f.a, glRequest(hostA))
	glSettle(t, f, hostA)
	if f.a.location.Server != hostA || f.a.location.City != "City 0" {
		t.Fatalf("location %+v", f.a.location)
	}
	// gluetun's updater drops hostA; hostB is in its city, hostC is not.
	glServers(t, f, 2, hostB, hostC)
	r := glSettle(t, f, hostB)
	from, to := movedOf(r)
	if r.Get("requested_server") != hostA || from != hostA || to != hostB {
		t.Fatalf("requested %v moved %v -> %v: %s", r.Get("requested_server"), from, to, message(r))
	}
	if last := f.control.puts[len(f.control.puts)-1]; last != hostB {
		t.Fatalf("puts %v", f.control.puts)
	}
	if v := f.a.assess(f.a.judged(r).Decoded()); v.State != "ok" {
		t.Fatalf("verdict %s %v", v.State, v.Reasons)
	}
}

// With no request and no SERVER, gluetun's exit restores its last good
// server; a retired one is restored as its neighbour.
func TestARetiredServerToRestoreIsItsNeighbour(t *testing.T) {
	f := newGluetunFixture(t, glOptions{})
	glServers(t, f, 1)
	if r := f.a.switchTo(t, glRequest(hostA)); status(r) != "ok" || r.Get("server") != hostA {
		t.Fatalf("%s %v %s", status(r), r.Get("server"), message(r))
	}
	glServers(t, f, 2, hostB, hostC)
	r := glSettle(t, f, hostB)
	if r.Decoded()["moved"] != nil || f.a.location.Server != hostB || f.a.location.Replacement != "" {
		t.Fatalf("moved %v location %+v", r.Decoded()["moved"], f.a.location)
	}
	if v := f.a.assess(f.a.judged(r).Decoded()); v.State != "ok" {
		t.Fatalf("verdict %s %v", v.State, v.Reasons)
	}
}

// A region that forwards ports is replaced only by one that does too.
func TestAPortForwardingServerMovesOnlyToOneThatForwards(t *testing.T) {
	a, k, _ := pipelineSetup(t)
	forwarding, _ := snapshot(a).Relays.Get(testHost)
	forwarding.PortForward = true
	desire(t, a, requestAt(testHost, nil))
	if r := mustTick(t, a); status(r) != "ok" || !a.location.PortForward {
		t.Fatalf("%s %+v", status(r), a.location)
	}
	retire(a, testHost)
	k.now += 600
	if r := mustTick(t, a); status(r) != "failed" || r.Decoded()["moved"] != nil || len(k.keys) != 1 || k.keys[0] != testKey {
		t.Fatalf("%s %q moved %v peers %v", status(r), message(r), r.Decoded()["moved"], k.keys)
	}
	neighbour, _ := snapshot(a).Relays.Get(otherHost)
	neighbour.PortForward = true
	if got := a.replacementFor(testHost); got != otherHost {
		t.Fatalf("replacement %q", got)
	}
}
