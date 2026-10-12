// Tests ported from tools/test_gluetun_applier.py: the gluetun backend's
// applier against a fake kernel (gluetun_fake_test.go), a fake gluetun control
// server and a gluetun server list in a temporary directory. Nothing here
// contacts gluetun, a provider or a tunnel; the marked echo is exercised
// against TLS servers on loopback.
//
// Not ported, because the code they test is not the applier's, or is gone:
// test_doctor_checks_gluetuns_control_server_and_data_age (the doctor is
// dropped, decision D22; its two questions are asked directly in
// TestControlAnswersAndDataAge), test_auth_file_takes_only_url_safe_keys
// (internal/gluetunauth), test_panel_shows_the_backend_and_the_datas_date and
// test_panel_shows_a_server_list_update (internal/panel), and the Python
// socket-level echo tests (SlowSocket, _DeadlineReader, _DeadlineResponse and
// the getaddrinfo thread: net/http and internal/netx replace them; their
// questions are asked of a real TLS exchange in the MarkedEcho tests).
package applier

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/egress"
	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/rtnl"
	"github.com/irashack/molebridge/internal/state"
	"github.com/irashack/molebridge/internal/validate"
)

func relayNames(r *providers.Entries) map[string]bool {
	names := map[string]bool{}
	for _, n := range r.Names() {
		names[n] = true
	}
	return names
}

func sameNames(t testing.TB, got *providers.Entries, want ...string) {
	t.Helper()
	g := relayNames(got)
	if len(g) != len(want) {
		t.Errorf("relays %v, want %v", got.Names(), want)
		return
	}
	for _, n := range want {
		if !g[n] {
			t.Errorf("relays %v, want %v", got.Names(), want)
		}
	}
}

func readState(t testing.TB, path string) map[string]any {
	t.Helper()
	m, ok := state.ReadObject(path, 1<<20)
	if !ok {
		t.Fatalf("cannot read %s", path)
	}
	return m
}

func selectionOf(r *Record) map[string]any { return r.Decoded()["selection"].(map[string]any) }

// -- the catalogue -------------------------------------------------------------------------------------------

func TestCatalogueComesFromGluetunsFileWithTheDatasOwnDate(t *testing.T) {
	f := newGluetunFixture(t, glOptions{})
	snapshot := readState(t, f.dir+"/applier/relays.json")
	if snapshot["provider"] != "gluetun-ivpn" || snapshot["source"] != "gluetun" {
		t.Fatalf("snapshot %v", snapshot)
	}
	var stamp int64
	raw, _ := os.ReadFile(f.servers)
	decoded, _ := validate.DecodeJSON(raw)
	stamp, _ = validate.IsInt(decoded.(map[string]any)["ivpn"].(map[string]any)["timestamp"])
	if snapshot["data_timestamp"] != validate.FormatTime(time.Unix(stamp, 0)) {
		t.Errorf("data_timestamp %v", snapshot["data_timestamp"])
	}
	sameNames(t, f.a.catalog.Relays(), hostA, hostB, hostC)
	// The panel reads the same snapshot through the registry.
	sameNames(t, providers.SnapshotRelays(snapshot, "gluetun-ivpn"), hostA, hostB, hostC)
	if !f.a.catalog.Usable() {
		t.Error("catalogue not usable")
	}
	if _, err := f.provider.FetchCatalog(context.Background(), f.a); err == nil ||
		err.Error() != "with gluetun the server list is read from gluetun, not downloaded" {
		t.Errorf("fetch: %v", err)
	}
	if len(f.k.reqs) != 0 {
		t.Errorf("requests %v", f.k.reqs)
	}
	// The snapshot's member order is the Python one.
	text, _ := os.ReadFile(f.dir + "/applier/relays.json")
	if !strings.HasPrefix(string(text), `{"fetched_at": "`) || !strings.Contains(string(text), `"provider": "gluetun-ivpn", "source": "gluetun", "data_timestamp": "`) {
		t.Errorf("snapshot text %.200s", text)
	}
}

func TestABrokenFileKeepsTheLastGoodCatalogue(t *testing.T) {
	f := newGluetunFixture(t, glOptions{})
	path := f.dir + "/applier/relays.json"
	before, _ := os.ReadFile(path)
	// gluetun truncates the file in place while it writes.
	writeFile(t, f.servers, serversJSON("ivpn", 0)[:100], 0o644)
	ok, err := f.a.catalog.Refresh(context.Background(), nil)
	if err != nil || ok {
		t.Fatalf("refresh %v %v", ok, err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Error("the snapshot changed")
	}
	sameNames(t, f.a.catalog.Relays(), hostA, hostB, hostC)
	if m := readState(t, f.dir+"/applier/relay-error.json"); m["message"] !=
		"gluetun's server list is missing or invalid; retaining the last good catalogue." || m["checked_at"] == nil {
		t.Errorf("error record %v", m)
	}
	os.Remove(f.servers)
	elsewhere := f.dir + "/elsewhere.json"
	writeFile(t, elsewhere, serversJSON("ivpn", 0), 0o644)
	if err := symlink(elsewhere, f.servers); err != nil {
		t.Fatal(err)
	}
	if ok, _ := f.a.catalog.Refresh(context.Background(), nil); ok {
		t.Error("a symlink was read")
	}
}

func TestAnotherProvidersBlockIsNotThisCatalogue(t *testing.T) {
	f := newGluetunFixture(t, glOptions{noWrite: true})
	writeFile(t, f.servers, serversJSON("nordvpn", 0), 0o644)
	ok, _ := f.a.catalog.Refresh(context.Background(), nil)
	if ok || f.a.catalog.Relays().Len() != 0 {
		t.Errorf("read another provider's block: %v %v", ok, f.a.catalog.Relays().Names())
	}
}

func TestTheFileIsReadAgainOnlyWhenItChangesOrAges(t *testing.T) {
	f := newGluetunFixture(t, glOptions{})
	c := f.gluetunCatalog()
	reads := c.reads
	if ok, _ := c.Refresh(context.Background(), nil); !ok || c.reads != reads {
		t.Fatalf("unchanged file: %v, %d reads more", ok, c.reads-reads)
	}
	writeFile(t, f.servers, serversJSON("ivpn", 0, hostA, hostB), 0o644)
	if err := os.Chtimes(f.servers, time.Unix(1, 0), time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if ok, _ := c.Refresh(context.Background(), nil); !ok || c.reads != reads+1 {
		t.Fatalf("changed file: %v, %d reads more", ok, c.reads-reads)
	}
	sameNames(t, c.Relays(), hostA, hostB)
	c.readAt -= CatalogRereadSec
	if ok, _ := c.Refresh(context.Background(), nil); !ok || c.reads != reads+2 {
		t.Fatalf("aged read: %v, %d reads more", ok, c.reads-reads)
	}
}

func TestADedicatedIPServerNeverReachesTheSnapshot(t *testing.T) {
	f := newGluetunFixture(t, glOptions{provider: "nordvpn"})
	snapshot := readState(t, f.dir+"/applier/relays.json")
	relays := snapshot["relays"].(map[string]any)
	if _, ok := relays["dedicated.example.test"]; ok || len(relays) != 3 {
		t.Errorf("relays %v", relays)
	}
	r := f.a.switchTo(t, glRequest("dedicated.example.test"))
	if status(r) != "failed" || len(f.control.puts) != 0 {
		t.Errorf("%s %v", status(r), f.control.puts)
	}
}

func TestCatalogueClassIsTheGluetunOne(t *testing.T) {
	f := newGluetunFixture(t, glOptions{})
	c, ok := f.a.catalog.(*GluetunCatalog)
	if !ok || c.gluetunProvider != "ivpn" {
		t.Errorf("%T", f.a.catalog)
	}
}

// -- switching -----------------------------------------------------------------------------------------------

func TestSwitchPutsTheServerAndWaitsOutGluetunsRestart(t *testing.T) {
	f := newGluetunFixture(t, glOptions{})
	statuses := withPublished(f.a, f.dir)
	f.control.restartTicks = 12
	r := f.a.switchTo(t, glRequest(hostB))
	if len(f.control.puts) != 1 || f.control.puts[0] != hostB {
		t.Fatalf("puts %v", f.control.puts)
	}
	if status(r) != "ok" || r.Get("server") != hostB {
		t.Fatalf("%s %s", status(r), message(r))
	}
	// The interface going away during the switch was not a failure.
	applying := 0
	for _, s := range *statuses {
		if s == "failed" {
			t.Errorf("a failed record during the switch: %v", *statuses)
		}
		if s == "applying" {
			applying++
		}
	}
	if applying < 2 {
		t.Errorf("%d applying records: %v", applying, *statuses)
	}
	if tierOf(r) != "tunnel" {
		t.Errorf("tier %v", tierOf(r))
	}
	want := selection{Desired: hostB, LastPut: hostB, LastApplied: hostB, LastSuccessful: hostB}
	if f.provider.selection != want {
		t.Errorf("selection %+v", f.provider.selection)
	}
	file := readState(t, f.dir+"/applier/gluetun-selection.json")
	if file["desired"] != hostB || file["last_put"] != hostB || file["last_applied"] != hostB || file["last_successful"] != hostB || len(file) != 4 {
		t.Errorf("selection file %v", file)
	}
	// The host's own address was measured off the tunnel, with NetBird's control mark.
	if len(f.k.marked) == 0 {
		t.Error("no marked echo")
	}
	for _, m := range f.k.marked {
		if m.SocketMark != 0x1bd00 {
			t.Errorf("mark %#x", m.SocketMark)
		}
	}
	v := f.a.assess(r.Decoded())
	if v.State != "ok" || v.Label != "connected" {
		t.Errorf("verdict %s %s", v.State, v.Label)
	}
}

func TestAnAcceptedSelectionIsRecordedBeforeItsResultIsKnown(t *testing.T) {
	// put(): "Records it before the result is known: gluetun may apply a
	// selection whose answer is lost."
	f := newGluetunFixture(t, glOptions{})
	f.control.fail = true
	f.a.switchTo(t, glRequest(hostB))
	if f.provider.selection.LastPut != hostB || f.provider.selection.LastApplied != "" || f.provider.selection.Desired != hostB {
		t.Errorf("selection %+v", f.provider.selection)
	}
	file := readState(t, f.dir+"/applier/gluetun-selection.json")
	if file["last_put"] != hostB || file["last_applied"] != nil || file["last_successful"] != nil {
		t.Errorf("file %v", file)
	}
}

func TestARefusedSelectionFailsWithoutWaiting(t *testing.T) {
	f := newGluetunFixture(t, glOptions{})
	f.control.fail = true
	r := f.a.switchTo(t, glRequest(hostB))
	if status(r) != "failed" || message(r) != "gluetun did not accept the server selection; retrying automatically." {
		t.Errorf("%s %q", status(r), message(r))
	}
	if f.k.now != 0 {
		t.Errorf("waited %v", f.k.now)
	}
}

func TestASwitchThatLandsElsewhereTimesOut(t *testing.T) {
	f := newGluetunFixture(t, glOptions{})
	f.control.connectTo = hostC
	r := f.a.switchTo(t, glRequest(hostB))
	if status(r) != "failed" || message(r) != "Switch verification timed out; retrying automatically." {
		t.Errorf("%s %q", status(r), message(r))
	}
	if selectionOf(r)["next_action"] != "reapply" {
		t.Errorf("selection %v", selectionOf(r))
	}
	if f.k.now < GluetunSwitchTimeoutSec {
		t.Errorf("gave up after %v", f.k.now)
	}
	if f.provider.selection.LastSuccessful != "" {
		t.Errorf("selection %+v", f.provider.selection)
	}
}

func TestUnlistedAndInvalidRequestsChangeNothing(t *testing.T) {
	f := newGluetunFixture(t, glOptions{})
	if r := f.a.switchTo(t, glRequest("four.example.test")); status(r) != "failed" {
		t.Error("an unlisted server")
	}
	if r := f.a.switchTo(t, requestAt("../x", map[string]any{"request_id": nil})); status(r) != "failed" {
		t.Error("an invalid server")
	}
	if len(f.control.puts) != 0 {
		t.Errorf("puts %v", f.control.puts)
	}
}

// -- egress ---------------------------------------------------------------------------------------------------

func TestTunnelChecksFailWhenTheEchoIsTheHostsOwnAddress(t *testing.T) {
	f := newGluetunFixture(t, glOptions{})
	f.k.egress = glHost4
	r := f.a.inspect(t)
	if status(r) != "failed" || tierOf(r) != nil || message(r) != "Tunnel egress did not pass the tunnel checks." {
		t.Errorf("%s %v %q", status(r), tierOf(r), message(r))
	}
}

func TestMullvadThroughGluetunUsesMullvadsOwnCheck(t *testing.T) {
	f := newGluetunFixture(t, glOptions{provider: "mullvad"})
	r := f.a.inspect(t)
	if status(r) != "ok" || tierOf(r) != "provider" {
		t.Fatalf("%s %v %q", status(r), tierOf(r), message(r))
	}
	if len(f.k.requestsTo("am.i.mullvad.net")) == 0 {
		t.Error("no Mullvad request")
	}
	f.k.mullvadExit = false
	r = f.a.inspect(t)
	if status(r) != "failed" || message(r) != "Tunnel egress is not confirmed as Mullvad." {
		t.Errorf("%s %q", status(r), message(r))
	}
}

func TestNordVPNThroughGluetunUsesNordVPNsOwnCheck(t *testing.T) {
	f := newGluetunFixture(t, glOptions{provider: "nordvpn"})
	r := f.a.inspect(t)
	if status(r) != "ok" || tierOf(r) != "provider" {
		t.Fatalf("%s %v %q", status(r), tierOf(r), message(r))
	}
	if len(f.k.requestsTo("/ips/insights")) == 0 {
		t.Error("no insights request")
	}
	if r.Get("mullvad_exit_ip") != nil {
		t.Error("a Mullvad member in a NordVPN record")
	}
}

// -- routing --------------------------------------------------------------------------------------------------

func TestAMissingGuardRuleHoldsTheRequest(t *testing.T) {
	for _, priority := range []uint32{88, 89, 91, 92, 95, 97, 102, 103, 104} {
		f := newGluetunFixture(t, glOptions{})
		f.k.dropRule(6, priority)
		if protected, _ := f.a.routingStatus(context.Background(), true); protected {
			t.Errorf("%d: protected", priority)
		}
		r := f.a.switchTo(t, glRequest(hostB))
		if len(f.control.puts) != 0 || status(r) != "failed" || f.a.attempt.State != "pending" ||
			!strings.HasPrefix(f.a.attempt.Message, "Waiting for tunnel and overlay routing") {
			t.Errorf("%d: puts %v, %s, %q %q", priority, f.control.puts, status(r), f.a.attempt.State, f.a.attempt.Message)
		}
	}
}

func TestTheHostTableIsPartOfTheGuard(t *testing.T) {
	f := newGluetunFixture(t, glOptions{})
	if p, fb := f.a.routingStatus(context.Background(), true); !p || !fb {
		t.Fatal("not protected to begin with")
	}
	hostRoutes := f.k.hostRoutes[4]
	f.k.hostRoutes[4] = hostRoutes[:1]
	if p, _ := f.a.routingStatus(context.Background(), true); p {
		t.Error("a host table without its default")
	}
	f.k.hostRoutes[4] = append(append([]rtnl.Route(nil), hostRoutes...), rtnl.Route{Family: rtnl.V4,
		Dst: netip.MustParsePrefix("0.0.0.0/0"), Table: f.k.c.HostTable, Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(glTunnelIfIndex)), Metric: 10})
	if p, _ := f.a.routingStatus(context.Background(), true); p {
		t.Error("a host table with a route through the tunnel")
	}
}

func TestNoTunnelInterfaceIsNotARoutingFailure(t *testing.T) {
	f := newGluetunFixture(t, glOptions{})
	f.k.tunnel = ""
	if p, fb := f.a.routingStatus(context.Background(), true); !p || !fb {
		t.Errorf("(%v, %v)", p, fb)
	}
	r := f.a.inspect(t)
	if checkState(r, "routing") != "pass" || status(r) != "failed" {
		t.Errorf("%s %s", checkState(r, "routing"), status(r))
	}
}

func TestATunnelWithoutItsRouteIsNotProtected(t *testing.T) {
	f := newGluetunFixture(t, glOptions{})
	f.k.tunnelRoutePresent = false
	if p, _ := f.a.routingStatus(context.Background(), true); p {
		t.Error("protected without the tunnel route")
	}
}

func TestATunnelThatIsDownKeepsTheGuardReady(t *testing.T) {
	f := newGluetunFixture(t, glOptions{})
	f.k.tunnelUp, f.k.tunnelRoutePresent = false, false
	if p, fb := f.a.routingStatus(context.Background(), true); !p || !fb {
		t.Errorf("(%v, %v)", p, fb)
	}
}

func TestARoutingReadThatFailsIsNotProtection(t *testing.T) {
	// Every read of the namespace that fails or makes no sense is "not
	// protected", never an error out of the check.
	for name, change := range map[string]func(*glKernel){
		"overlay missing": func(k *glKernel) { k.overlayPresent = false },
		"sysctl":          func(k *glKernel) { k.returnPath = "0\n" },
		"unreadable":      func(k *glKernel) { k.addrErr = errors.New("x") },
	} {
		f := newGluetunFixture(t, glOptions{})
		change(f.k)
		if p, fb := f.a.routingStatus(context.Background(), true); p || (name == "overlay missing" && fb) {
			t.Errorf("%s: (%v, %v)", name, p, fb)
		}
	}
	// Only the tunnel's absence is tolerated: several addresses of a family
	// make no sense.
	f := newGluetunFixture(t, glOptions{})
	f.k.twoAddresses = true
	if p, _ := f.a.routingStatus(context.Background(), true); p {
		t.Error("two tunnel addresses were accepted")
	}
}

// -- restoring after gluetun restarts --------------------------------------------------------------------------

// settled is the Python helper of that name.
func settled(t testing.TB, f *glFixture, lastPut, lastSuccessful, live string) {
	t.Helper()
	if err := f.provider.saveSelection(func(s *selection) { s.Desired, s.LastPut, s.LastSuccessful = lastPut, lastPut, lastSuccessful }); err != nil {
		t.Fatal(err)
	}
	f.k.tunnel = live
	f.a.nextHealth = infinity
}

func TestGluetunOnItsStartUpServerGetsTheLastVerifiedOneBack(t *testing.T) {
	f := newGluetunFixture(t, glOptions{})
	settled(t, f, hostB, hostB, hostA)
	r := mustTick(t, f.a)
	if len(f.control.puts) != 1 || f.control.puts[0] != hostB || status(r) != "ok" {
		t.Fatalf("puts %v, %s %q", f.control.puts, status(r), message(r))
	}
	if selectionOf(r)["source"] != "restore" {
		t.Errorf("selection %v", selectionOf(r))
	}
	// Not again within the 90 s guard, even if the peer has not changed yet.
	f.k.hasPending = false
	f.k.tunnel = hostA
	mustTick(t, f.a)
	if len(f.control.puts) != 1 {
		t.Errorf("puts %v", f.control.puts)
	}
	f.k.now += GluetunSwitchTimeoutSec
	r = mustTick(t, f.a)
	if len(f.control.puts) != 2 || selectionOf(r)["source"] != "reconverge" {
		t.Errorf("puts %v, selection %v", f.control.puts, selectionOf(r))
	}
}

func TestNoRestoreWhileThePanelsRequestIsLive(t *testing.T) {
	f := newGluetunFixture(t, glOptions{})
	settled(t, f, hostC, hostB, hostC)
	f.a.attempt.TargetKey = glRequest(hostC)["request_id"].(string)
	f.a.attempt.Target, f.a.attempt.Source = hostC, "panel"
	desire(t, f.a, glRequest(hostC))
	mustTick(t, f.a)
	if len(f.control.puts) != 0 {
		t.Errorf("puts %v", f.control.puts)
	}
}

func TestNoRestoreWhenTheLiveServerIsUnknown(t *testing.T) {
	f := newGluetunFixture(t, glOptions{})
	settled(t, f, hostB, hostB, hostA)
	f.k.tunnel = ""
	mustTick(t, f.a)
	if len(f.control.puts) != 0 || f.a.attempt.State != "pending" {
		t.Errorf("puts %v, state %s", f.control.puts, f.a.attempt.State)
	}
}

func TestThePanelsRequestTakesPrecedence(t *testing.T) {
	f := newGluetunFixture(t, glOptions{})
	settled(t, f, hostB, hostB, hostA)
	desire(t, f.a, glRequest(hostC))
	mustTick(t, f.a)
	if len(f.control.puts) != 1 || f.control.puts[0] != hostC || f.provider.selection.LastSuccessful != hostC {
		t.Fatalf("puts %v, selection %+v", f.control.puts, f.provider.selection)
	}
	// Verified, then gluetun restarts: the pipeline puts it again.
	f.k.tunnel = hostA
	f.k.now += GluetunSwitchTimeoutSec
	mustTick(t, f.a)
	if len(f.control.puts) != 2 || f.control.puts[1] != hostC {
		t.Errorf("puts %v", f.control.puts)
	}
}

func TestARefusedRequestFallsBackToTheLastVerifiedServerAfterARestart(t *testing.T) {
	// D12: a rejected panel request never becomes the target; the last
	// verified server is still restored, and the rejection stays shown.
	f := newGluetunFixture(t, glOptions{})
	settled(t, f, hostB, hostB, hostB)
	desire(t, f.a, glRequest("four.example.test"))
	mustTick(t, f.a)
	if !f.a.requestRejected() || len(f.control.puts) != 0 {
		t.Fatalf("rejected %v, puts %v", f.a.requestRejected(), f.control.puts)
	}
	f.k.tunnel = hostA
	r := mustTick(t, f.a)
	if len(f.control.puts) != 1 || f.control.puts[0] != hostB {
		t.Errorf("puts %v", f.control.puts)
	}
	if status(r) != "failed" || selectionOf(r)["outcome"] != "rejected" || !strings.HasPrefix(message(r), "Requested server is not in a fresh") {
		t.Errorf("%s %v %q", status(r), selectionOf(r), message(r))
	}
}

func TestTheSelectionFileIsReadWithTheRegistrysNameRules(t *testing.T) {
	// load_selection: a member that is not a valid server name for the
	// provider is dropped; the file is bounded.
	dir := t.TempDir()
	writeFile(t, dir+"/applier/gluetun-selection.json",
		`{"desired": "one.example.test", "last_put": "../x", "last_applied": 3, "last_successful": "two.example.test", "extra": 1}`, 0o600)
	k := newGlKernel(t, glRouting(t))
	provider, err := newGluetun("gluetun-ivpn", GluetunSettings{Routing: glRouting(t), ServersFile: dir + "/none", UpdaterPeriodSec: 86400},
		newFakeGluetun(k))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{StateDir: dir, Exit: k.exit, Provider: provider, System: k, BootID: testBoot,
		Monotonic: k.clock, Sleep: k.sleep}); err != nil {
		t.Fatal(err)
	}
	want := selection{Desired: hostA, LastSuccessful: hostB}
	if provider.selection != want {
		t.Errorf("selection %+v", provider.selection)
	}
}

// -- control, settings and setup ------------------------------------------------------------------------------------

func TestControlAnswersAndDataAge(t *testing.T) {
	// The doctor's two gluetun questions (D22 dropped the doctor): the control
	// server answers with the key, and its data is less than 30 days old.
	f := newGluetunFixture(t, glOptions{})
	if !f.provider.ControlAnswers(context.Background(), f.a) {
		t.Error("the control server does not answer")
	}
	f.control.statusErr = ErrGluetunRequest
	if f.provider.ControlAnswers(context.Background(), f.a) {
		t.Error("an unanswered control server answers")
	}
	f.control.statusErr, f.control.status = nil, "bogus"
	if f.provider.ControlAnswers(context.Background(), f.a) {
		t.Error("an unknown status answers")
	}
	now := float64(time.Now().Unix())
	if age, ok := dataAge(f.a.catalog.Snapshot()["data_timestamp"], now); !ok || age > GluetunDataStaleSec {
		t.Errorf("fresh data: %v %v", age, ok)
	}
	writeFile(t, f.servers, serversJSON("ivpn", 1000), 0o644)
	if err := os.Chtimes(f.servers, time.Unix(2, 0), time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	if ok, _ := f.a.catalog.Refresh(context.Background(), nil); !ok {
		t.Fatal("refresh")
	}
	if age, ok := dataAge(f.a.catalog.Snapshot()["data_timestamp"], now); !ok || age <= GluetunDataStaleSec {
		t.Errorf("old data: %v %v", age, ok)
	}
}

func TestDataAge(t *testing.T) {
	for _, c := range []struct {
		value any
		now   float64
		age   float64
		ok    bool
	}{{"1970-01-01T00:00:10Z", 100, 90, true}, {"1970-01-01T00:01:40Z", 100, 0, true}, {"1970-01-01T00:01:41Z", 100, 0, false},
		{"yesterday", 100, 0, false}, {nil, 100, 0, false}, {5, 100, 0, false}} {
		if age, ok := dataAge(c.value, c.now); ok != c.ok || age != c.age {
			t.Errorf("%v: %v %v", c.value, age, ok)
		}
	}
}

func gluetunEnv(t testing.TB, extra map[string]string) (func(string) string, string) {
	t.Helper()
	dir := t.TempDir()
	key := dir + "/api_key"
	writeFile(t, key, strings.Repeat("k", 43)+"\n", 0o600)
	env := map[string]string{"GLUETUN_API_KEY_FILE": key, "GLUETUN_SERVERS_FILE": dir + "/servers.json",
		"TUNNEL_BACKEND": "gluetun", "OVERLAY_CIDR": "192.0.2.0/24", "EXIT_IF": "wg0"}
	for k, v := range extra {
		if v == "" {
			delete(env, k)
		} else {
			env[k] = v
		}
	}
	return func(k string) string { return env[k] }, dir
}

func TestFromEnvReadsTheKeyFileAndNeedsTheGluetunBackend(t *testing.T) {
	getenv, dir := gluetunEnv(t, nil)
	p, err := ProviderFor("gluetun-ivpn", Exit{Kind: "overlay"}, getenv)
	if err != nil {
		t.Fatal(err)
	}
	g := p.(*gluetunProvider)
	if g.client.(*GluetunClient).BaseURL() != "http://127.0.0.1:8000" || g.settings.ServersFile != dir+"/servers.json" ||
		g.settings.UpdaterPeriodSec != 86400 || g.routing.Backend != contract.Gluetun || g.routing.ControlMark != 0x1bd00 {
		t.Errorf("provider %+v", g.settings)
	}
	getenv, _ = gluetunEnv(t, map[string]string{"TUNNEL_BACKEND": "wireguard"})
	if _, err := ProviderFor("gluetun-ivpn", Exit{Kind: "overlay"}, getenv); err == nil ||
		!strings.Contains(err.Error(), "TUNNEL_BACKEND=gluetun") {
		t.Errorf("a native backend: %v", err)
	}
	getenv, _ = gluetunEnv(t, nil)
	if err := os.Chmod(getenv("GLUETUN_API_KEY_FILE"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ProviderFor("gluetun-ivpn", Exit{Kind: "overlay"}, getenv); err == nil {
		t.Error("an exposed key file was accepted")
	}
	// The settings it reads.
	getenv, _ = gluetunEnv(t, map[string]string{"GLUETUN_CONTROL_URL": "http://[::1]:9", "GLUETUN_UPDATER_PERIOD": "1h30m"})
	p, err = ProviderFor("gluetun-ivpn", Exit{Kind: "overlay"}, getenv)
	if err != nil {
		t.Fatal(err)
	}
	if g := p.(*gluetunProvider); g.client.(*GluetunClient).BaseURL() != "http://[::1]:9" || g.settings.UpdaterPeriodSec != 5400 {
		t.Errorf("provider %+v", g.settings)
	}
	for _, bad := range []map[string]string{{"GLUETUN_CONTROL_URL": "http://localhost:8000"}, {"GLUETUN_UPDATER_PERIOD": "1d"}} {
		getenv, _ = gluetunEnv(t, bad)
		if _, err := ProviderFor("gluetun-ivpn", Exit{Kind: "overlay"}, getenv); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestFromEnvForASidecarNeedsNoRoutingSettings(t *testing.T) {
	getenv, _ := gluetunEnv(t, map[string]string{"OVERLAY_CIDR": "", "EXIT_KIND": "sidecar"})
	p, err := ProviderFor("gluetun-nordvpn", Exit{Kind: "sidecar", ExitIf: "wg0"}, getenv)
	if err != nil {
		t.Fatal(err)
	}
	if g := p.(*gluetunProvider); g.routing.Kind != contract.Sidecar || g.routing.ExitIf != "wg0" {
		t.Errorf("routing %+v", g.routing)
	}
}

func TestEveryGluetunEntryHasItsOwnProvider(t *testing.T) {
	n := 0
	for _, id := range providers.IDs() {
		spec, _ := providers.Get(id)
		if spec.Backend != providers.BackendGluetun {
			continue
		}
		n++
		getenv, _ := gluetunEnv(t, nil)
		p, err := ProviderFor(id, Exit{Kind: "overlay"}, getenv)
		if err != nil {
			t.Errorf("%s: %v", id, err)
			continue
		}
		if g, ok := p.(*gluetunProvider); !ok || g.ID() != id {
			t.Errorf("%s: %T %s", id, p, p.ID())
		}
		known := false
		for _, name := range providers.GluetunSupportedProviders {
			known = known || name == spec.GluetunProvider
		}
		if !known {
			t.Errorf("%s: gluetun provider %q is not supported", id, spec.GluetunProvider)
		}
		wantTier := providers.TierTunnel
		if spec.EgressCheck != "" {
			wantTier = providers.TierProvider
		}
		if spec.EgressTier != wantTier {
			t.Errorf("%s: tier %s", id, spec.EgressTier)
		}
	}
	if n < 5 {
		t.Errorf("%d gluetun entries", n)
	}
	// A native entry is never a gluetun provider.
	if p, err := ProviderFor("mullvad", Exit{}, func(string) string { return "" }); err != nil || p.ID() != "mullvad" {
		t.Errorf("mullvad: %v", err)
	}
}

func TestNewRefusesAProviderItsSystemCannotServe(t *testing.T) {
	// The overlay kind reads the namespace through GluetunKernel: the plain
	// native fake offers none.
	k := newKernel(t)
	provider, err := newGluetun("gluetun-ivpn", GluetunSettings{Routing: glRouting(t), ServersFile: "/none"}, newFakeGluetun(newGlKernel(t, glRouting(t))))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{StateDir: t.TempDir(), Exit: k.exit, Provider: provider, System: k}); err == nil {
		t.Error("a system without GluetunKernel was accepted")
	}
	// The exit kind is the settings' kind.
	g := newGlKernel(t, glRouting(t))
	exit := g.exit
	exit.Kind = "sidecar"
	if _, err := New(Config{StateDir: t.TempDir(), Exit: exit, Provider: provider, System: g}); err == nil {
		t.Error("a sidecar on overlay settings was accepted")
	}
	// And the gluetun backend is required.
	if _, err := newGluetun("gluetun-ivpn", GluetunSettings{Routing: contract.Config{Kind: contract.Overlay, Backend: contract.Native}},
		newFakeGluetun(g)); err == nil || !strings.Contains(err.Error(), "TUNNEL_BACKEND=gluetun") {
		t.Errorf("native settings: %v", err)
	}
	if _, err := newGluetun("mullvad", GluetunSettings{Routing: glRouting(t)}, newFakeGluetun(g)); err == nil {
		t.Error("a native entry was accepted as a gluetun provider")
	}
}

// -- the marked echo ------------------------------------------------------------------------------------------------------

func TestMarkedEchoTakesOnlyPlainHTTPSURLs(t *testing.T) {
	calls := 0
	fetch := func(context.Context, netx.Request) (netx.Response, error) {
		calls++
		return netx.Response{Status: 200, Body: []byte("203.0.113.9\n")}, nil
	}
	for _, url := range []string{"http://api.ipify.org", "https://api.ipify.org:8443", "https://user@x.test/", "https://x.test/?q=1",
		"file:///etc/passwd", "", "https://", "%zz"} {
		if _, err := MarkedEcho(context.Background(), fetch, url, 4, 0x1bd00, time.Second); err != ErrEchoURL {
			t.Errorf("%q: %v", url, err)
		}
	}
	if calls != 0 {
		t.Errorf("%d requests", calls)
	}
	var got netx.Request
	record := func(_ context.Context, r netx.Request) (netx.Response, error) {
		got = r
		return netx.Response{Status: 200, Body: []byte("203.0.113.9\n")}, nil
	}
	for url, want := range map[string]string{"https://echo.test": "https://echo.test/", "https://echo.test/ip": "https://echo.test/ip",
		"https://echo.test/ip#frag": "https://echo.test/ip", "https://[2001:db8::1]/": "https://[2001:db8::1]/"} {
		body, err := MarkedEcho(context.Background(), record, url, 6, 0x1bd00, 7*time.Second)
		if err != nil || body != "203.0.113.9\n" || got.URL != want {
			t.Errorf("%s: %q %v, requested %s", url, body, err, got.URL)
		}
	}
	// The socket carries the mark and one family; the request is bounded.
	if got.SocketMark != 0x1bd00 || got.Family != 6 || got.BindInterface != "" || got.Timeout != 7*time.Second ||
		got.MaxBytes != egress.EchoMaxBytes || got.UserAgent != "molebridge-applier" || got.Header["Accept"] != "text/plain" ||
		got.RootCAs != nil || got.AllowHTTP {
		t.Errorf("request %+v", got)
	}
}

func TestMarkedEchoFailuresCarryNoDetail(t *testing.T) {
	for name, c := range map[string]struct {
		response netx.Response
		err      error
	}{
		"transport": {err: errors.New("dial tcp 198.51.100.1:443: refused")},
		"timeout":   {err: netx.ErrTimeout},
		"not 200":   {response: netx.Response{Status: 404, Body: []byte("203.0.113.9")}},
		"redirect":  {response: netx.Response{Status: 302}},
		"too large": {response: netx.Response{Status: 200, Body: []byte(strings.Repeat("1", egress.EchoMaxBytes+1))}},
		"not ASCII": {response: netx.Response{Status: 200, Body: []byte("203.0.113.9\xc3\xa9")}},
		"not UTF-8": {response: netx.Response{Status: 200, Body: []byte("\xff")}},
	} {
		fetch := func(context.Context, netx.Request) (netx.Response, error) { return c.response, c.err }
		_, err := MarkedEcho(context.Background(), fetch, "https://echo.test/", 4, 1, time.Second)
		if err != ErrEchoFailed {
			t.Errorf("%s: %v", name, err)
		}
	}
	fetch := func(context.Context, netx.Request) (netx.Response, error) { return netx.Response{}, netx.ErrCanceled }
	if _, err := MarkedEcho(context.Background(), fetch, "https://echo.test/", 4, 1, time.Second); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled: %v", err)
	}
}

// echoServer is a TLS server on loopback and a FetchFunc that reaches it
// through the real netx client in place of any host name: the request keeps
// its URL, family and deadline, and records the mark it would have carried
// (an unprivileged test cannot set SO_MARK).
type echoServer struct {
	server *httptest.Server
	mu     sync.Mutex
	seen   []netx.Request
}

func newEchoServer(t *testing.T, handler http.HandlerFunc) *echoServer {
	t.Helper()
	e := &echoServer{server: httptest.NewTLSServer(handler)}
	t.Cleanup(e.server.Close)
	return e
}

func (e *echoServer) fetch(ctx context.Context, req netx.Request) (netx.Response, error) {
	e.mu.Lock()
	e.seen = append(e.seen, req)
	e.mu.Unlock()
	pool := x509.NewCertPool()
	pool.AddCert(e.server.Certificate())
	req.SocketMark, req.RootCAs, req.ServerName, req.ConnectAddr = 0, pool, "example.com", e.server.Listener.Addr().String()
	return netx.Client{}.Fetch(ctx, req)
}

func TestMarkedEchoReadsAnAnswerOverRealTLS(t *testing.T) {
	var gotPath, gotAccept, gotAgent string
	s := newEchoServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAccept, gotAgent = r.URL.Path, r.Header.Get("Accept"), r.Header.Get("User-Agent")
		w.Write([]byte("203.0.113.9\n"))
	})
	body, err := MarkedEcho(context.Background(), s.fetch, "https://echo.test/where", 4, 0x1bd00, 5*time.Second)
	if err != nil || body != "203.0.113.9\n" {
		t.Fatalf("%q %v", body, err)
	}
	if gotPath != "/where" || gotAccept != "text/plain" || gotAgent != "molebridge-applier" {
		t.Errorf("%q %q %q", gotPath, gotAccept, gotAgent)
	}
	if len(s.seen) != 1 || s.seen[0].SocketMark != 0x1bd00 || s.seen[0].Family != 4 {
		t.Errorf("request %+v", s.seen)
	}
}

func TestMarkedEchoEndsWithinItsTimeoutWhateverTheServerDoes(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)
	for name, handler := range map[string]http.HandlerFunc{
		"never answers": func(w http.ResponseWriter, r *http.Request) { <-stop },
		"dribbles": func(w http.ResponseWriter, r *http.Request) {
			w.(http.Flusher).Flush()
			for i := 0; i < 100; i++ {
				select {
				case <-stop:
					return
				case <-time.After(50 * time.Millisecond):
				}
				w.Write([]byte("1"))
				w.(http.Flusher).Flush()
			}
		},
	} {
		s := newEchoServer(t, handler)
		started := time.Now()
		_, err := MarkedEcho(context.Background(), s.fetch, "https://echo.test/", 4, 0x1bd00, 300*time.Millisecond)
		if err != ErrEchoFailed || time.Since(started) > 1500*time.Millisecond {
			t.Errorf("%s: %v after %v", name, err, time.Since(started))
		}
	}
}

func TestMarkedEchoReadsABodySentAfterTheHeaders(t *testing.T) {
	for name, c := range map[string]struct{ head, body string }{
		"content-length and close": {"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 12\r\n\r\n", "203.0.113.9\n"},
		"http/1.0":                 {"HTTP/1.0 200 OK\r\n\r\n", "203.0.113.9\n"},
		"content-length":           {"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n", "203.0.113.9\n"},
		"chunked":                  {"HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n", "c\r\n203.0.113.9\n\r\n0\r\n\r\n"},
	} {
		s := newEchoServer(t, func(w http.ResponseWriter, r *http.Request) {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			conn.Write([]byte(c.head))
			time.Sleep(200 * time.Millisecond)
			conn.Write([]byte(c.body))
		})
		body, err := MarkedEcho(context.Background(), s.fetch, "https://echo.test/", 4, 0x1bd00, 5*time.Second)
		if err != nil || body != "203.0.113.9\n" {
			t.Errorf("%s: %q %v", name, body, err)
		}
	}
}

func TestMarkedEchoAnUnreachableHostFailsAtOnce(t *testing.T) {
	// A closed port on loopback: refused, not waited out.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	fetch := func(ctx context.Context, req netx.Request) (netx.Response, error) {
		req.SocketMark, req.ConnectAddr = 0, addr
		req.RootCAs = x509.NewCertPool()
		return netx.Client{}.Fetch(ctx, req)
	}
	started := time.Now()
	if _, err := MarkedEcho(context.Background(), fetch, "https://echo.test/", 4, 1, 5*time.Second); err != ErrEchoFailed ||
		time.Since(started) > 2*time.Second {
		t.Errorf("%v after %v", err, time.Since(started))
	}
}

// -- refreshing gluetun's server list ---------------------------------------------------------------------------------------

// stale is the Python helper: a fixture whose data is 400 days old.
func staleFixture(t testing.TB, o glOptions) *glFixture {
	t.Helper()
	o.noWrite = true
	if o.provider == "" {
		o.provider = "ivpn"
	}
	f := newGluetunFixture(t, o)
	writeFile(t, f.servers, serversJSON(o.provider, time.Now().Unix()-400*86400), 0o644)
	if ok, _ := f.a.catalog.Refresh(context.Background(), nil); !ok {
		t.Fatal("refresh")
	}
	f.a.nextCatalog = infinity
	return f
}

func (f *glFixture) update() { f.provider.updateServers(context.Background(), f.a) }

func TestOldDataStartsOneUpdateAndFollowsIt(t *testing.T) {
	f := staleFixture(t, glOptions{})
	f.update()
	if f.control.updates != 1 || f.provider.updateState != "updating" {
		t.Fatalf("%d updates, state %q", f.control.updates, f.provider.updateState)
	}
	if r := f.a.inspect(t); r.Get("server_list_update") != "updating" {
		t.Errorf("server_list_update %v", r.Get("server_list_update"))
	}
	f.update()
	if f.control.updates != 1 {
		t.Errorf("%d updates", f.control.updates)
	}
	// gluetun finished and wrote newer data; the catalogue re-reads it at once.
	f.control.updater = "completed"
	writeFile(t, f.servers, serversJSON("ivpn", 0), 0o644)
	if err := os.Chtimes(f.servers, time.Unix(5, 0), time.Unix(5, 0)); err != nil {
		t.Fatal(err)
	}
	mustTick(t, f.a)
	if f.provider.updateState != "done" || f.control.updates != 1 {
		t.Errorf("state %q, %d updates", f.provider.updateState, f.control.updates)
	}
	// The next look at the file is a minute away, not six hours.
	if f.a.nextCatalog != f.k.now+CatalogPollSec {
		t.Errorf("next catalogue %v", f.a.nextCatalog)
	}
	if age, ok := dataAge(f.a.catalog.Snapshot()["data_timestamp"], float64(time.Now().Unix())); !ok || age >= 2*3600 {
		t.Errorf("data age %v %v", age, ok)
	}
	if r := f.a.inspect(t); r.Get("server_list_update") != nil {
		t.Errorf("server_list_update %v", r.Get("server_list_update"))
	}
	if !f.k.logged("gluetun's server list update finished") || !f.k.logged("asked gluetun to update its server list") {
		t.Errorf("logs %v", f.k.logs)
	}
}

func TestFreshDataStartsNoUpdate(t *testing.T) {
	f := newGluetunFixture(t, glOptions{})
	f.update()
	if f.control.updates != 0 || f.provider.updateState != "done" {
		t.Errorf("%d updates, state %q", f.control.updates, f.provider.updateState)
	}
}

func TestNoUpdateBeforeTheTunnelRunsOrWithTheUpdaterOff(t *testing.T) {
	f := staleFixture(t, glOptions{})
	f.control.status = "starting"
	f.update()
	if f.control.updates != 0 || f.provider.updateState != "" {
		t.Errorf("%d updates, state %q", f.control.updates, f.provider.updateState)
	}
	off := staleFixture(t, glOptions{period: -1})
	off.update()
	if off.control.updates != 0 {
		t.Errorf("%d updates with the updater off", off.control.updates)
	}
}

func TestAShortUpdaterPeriodLowersTheThreshold(t *testing.T) {
	f := newGluetunFixture(t, glOptions{noWrite: true, period: 3600})
	writeFile(t, f.servers, serversJSON("ivpn", time.Now().Unix()-2*3600), 0o644)
	if ok, _ := f.a.catalog.Refresh(context.Background(), nil); !ok {
		t.Fatal("refresh")
	}
	f.update()
	if f.control.updates != 1 {
		t.Errorf("%d updates", f.control.updates)
	}
}

func TestFailedUpdatesAreRetriedABoundedNumberOfTimes(t *testing.T) {
	f := staleFixture(t, glOptions{})
	for attempt := 1; attempt <= UpdateAttempts; attempt++ {
		f.update()
		if f.control.updates != attempt || f.provider.updateState != "updating" {
			t.Fatalf("attempt %d: %d updates, state %q", attempt, f.control.updates, f.provider.updateState)
		}
		f.control.updater = "crashed"
		f.update()
		want := ""
		if attempt == UpdateAttempts {
			want = "failed"
		}
		if f.provider.updateState != want {
			t.Fatalf("attempt %d: state %q", attempt, f.provider.updateState)
		}
		f.update()
		if f.control.updates != attempt { // waits before the next try
			t.Fatalf("attempt %d: %d updates", attempt, f.control.updates)
		}
		f.k.now += UpdateRetrySec
	}
	f.update()
	if f.control.updates != UpdateAttempts {
		t.Errorf("%d updates", f.control.updates)
	}
	if r := f.a.inspect(t); r.Get("server_list_update") != "failed" {
		t.Errorf("server_list_update %v", r.Get("server_list_update"))
	}
}

func TestAnUpdateThatNeverFinishesTimesOut(t *testing.T) {
	f := staleFixture(t, glOptions{})
	f.update()
	f.k.now += UpdateTimeoutSec
	f.update()
	if f.provider.updateState != "" || f.provider.updateAttempts != 1 {
		t.Fatalf("state %q, %d attempts", f.provider.updateState, f.provider.updateAttempts)
	}
	f.control.updateFails = true
	f.k.now += UpdateRetrySec
	f.update()
	if f.provider.updateAttempts != 2 || f.provider.updateState != "" {
		t.Errorf("state %q, %d attempts", f.provider.updateState, f.provider.updateAttempts)
	}
}

func TestUpdaterPeriod(t *testing.T) {
	for value, seconds := range map[string]int{"24h": 86400, "1h30m": 5400, "90s": 90, "0": 0, "0s": 0, "5m": 300, "1h1s": 3601} {
		if got, err := UpdaterPeriod(value); err != nil || got != seconds {
			t.Errorf("%q: %d %v", value, got, err)
		}
	}
	for _, value := range []string{"", "1d", "24", "h", "-1h", "1.5h", "1h\n", "99999h", "1s1h"} {
		if _, err := UpdaterPeriod(value); err == nil || err.Error() != "invalid GLUETUN_UPDATER_PERIOD" {
			t.Errorf("%q: %v", value, err)
		}
	}
}

func TestNoUpdateUntilTheTunnelAnswers(t *testing.T) {
	// gluetun reports running while it still tries stale servers that don't answer.
	for _, broken := range []string{"no interface", "old handshake"} {
		f := staleFixture(t, glOptions{})
		if broken == "no interface" {
			f.k.tunnel = ""
		} else {
			f.k.age = UpdateHandshakeSec + 10
		}
		f.update()
		if f.control.updates != 0 || f.provider.updateAttempts != 0 || f.provider.updateState != "" {
			t.Errorf("%s: %d updates, %d attempts, state %q", broken, f.control.updates, f.provider.updateAttempts, f.provider.updateState)
		}
		f.k.tunnel, f.k.age = hostA, 1
		f.update()
		if f.control.updates != 1 {
			t.Errorf("%s: %d updates once the tunnel answers", broken, f.control.updates)
		}
	}
}

func TestTheLiveServerIsFoundByAnyOfItsAddresses(t *testing.T) {
	// gluetun picks any address of the selected server, IPv6 included.
	for _, endpoint := range []string{"198.51.100.122:51820", "[2001:db8:5::22]:51820"} {
		f := newGluetunFixture(t, glOptions{noWrite: true})
		raw := strings.Replace(serversJSON("ivpn", 0), `"ips":["198.51.100.22"]`, `"ips":["198.51.100.22","198.51.100.122","2001:db8:5::22"]`, 1)
		if raw == serversJSON("ivpn", 0) {
			t.Fatal("fixture not edited")
		}
		writeFile(t, f.servers, raw, 0o644)
		if ok, _ := f.a.catalog.Refresh(context.Background(), nil); !ok {
			t.Fatal("refresh")
		}
		f.k.tunnel, f.k.endpointOverride = hostB, endpoint
		keys, err := f.a.peers(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if server, err := f.provider.ServerFor(context.Background(), f.a, keys); err != nil || server != hostB {
			t.Errorf("%s: %q %v", endpoint, server, err)
		}
		r := f.a.inspect(t)
		if status(r) != "ok" || r.Get("server") != hostB {
			t.Errorf("%s: %s %q", endpoint, status(r), message(r))
		}
	}
}

// -- the egress check, asked once more --------------------------------------------------------------------------------------------

func TestEveryCheckThroughGluetunIsAskedOnceMoreWhenUnanswered(t *testing.T) {
	for _, c := range []struct {
		provider string
		match    func(netx.Request) bool
		calls    int
	}{
		{"mullvad", func(r netx.Request) bool { return strings.Contains(r.URL, "am.i.mullvad.net") }, 2},
		{"nordvpn", func(r netx.Request) bool { return strings.HasSuffix(r.URL, "/ips/insights") }, 2},
		{"ivpn", func(r netx.Request) bool {
			// The off-tunnel echo shares the services' URLs; it carries a mark.
			return r.SocketMark == 0 && (r.URL == egress.EchoURLs[4][0] || r.URL == egress.EchoURLs[4][1])
		}, 3},
	} {
		f := newGluetunFixture(t, glOptions{provider: c.provider})
		calls := f.k.unanswered(c.match, 1, 10)
		start := f.k.now
		r := f.a.inspect(t)
		if status(r) != "ok" || (tierOf(r) != "provider" && tierOf(r) != "tunnel") {
			t.Errorf("%s: %s %q %v", c.provider, status(r), message(r), tierOf(r))
		}
		if f.k.now-start != 10+EgressRetrySec {
			t.Errorf("%s: took %v", c.provider, f.k.now-start)
		}
		// The tunnel tier stops at the first unanswered echo, then asks both services.
		if len(*calls) != c.calls {
			t.Errorf("%s: %d requests", c.provider, len(*calls))
		}
	}
}

func TestATunnelTierAnswerThatFailsIsNeverAskedAgainThroughGluetun(t *testing.T) {
	f := newGluetunFixture(t, glOptions{})
	f.k.egress = glHost4
	start := f.k.now
	r := f.a.inspect(t)
	if message(r) != "Tunnel egress did not pass the tunnel checks." || f.k.now != start {
		t.Errorf("%q, took %v", message(r), f.k.now-start)
	}
}
