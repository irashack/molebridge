// Tests ported from tools/test_nordvpn_applier.py: the NordVPN applier against
// a fake kernel and fake NordVPN answers. Nothing here contacts NordVPN or
// touches a tunnel.
//
// Not ported: the catalogue entry validation tests (internal/providers'), the
// routing-initialization and doctor tests (shell and host tools), and the
// malformed endpoint listing cases beyond one error (System.Endpoints owns the
// parse of `wg show endpoints`; the fake returns the error).
package applier

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/validate"
)

const (
	nordUS     = "us9001.nordvpn.com"
	nordDE     = "de9002.nordvpn.com"
	nordUS2    = "us9004.nordvpn.com"
	nordUSKey  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	nordDEKey  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE="
	nordTunnel = "10.5.0.2"
)

var nordStation = map[string]string{nordUS: "198.51.100.11", nordDE: "198.51.100.22", nordUS2: "198.51.100.14"}

func fixturePath(parts ...string) string {
	return strings.Join(append([]string{"..", "..", "tools", "fixtures"}, parts...), "/")
}

func nordFixture(t testing.TB, name string) string {
	t.Helper()
	raw, err := readTestFile(fixturePath("nordvpn", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func decodeText(t testing.TB, text string) any {
	t.Helper()
	v, err := validate.DecodeJSONString(text)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// nordCatalogue is the fixture plus a second Dallas server sharing the
// location's key.
func nordCatalogue(t testing.TB) *providers.Entries {
	t.Helper()
	data := decodeText(t, nordFixture(t, "nordvpn-servers.json")).(map[string]any)
	servers := data["servers"].([]any)
	raw, err := validate.MarshalJSON(servers[0])
	if err != nil {
		t.Fatal(err)
	}
	clone := decodeText(t, string(raw)).(map[string]any)
	clone["hostname"], clone["station"], clone["id"] = nordUS2, nordStation[nordUS2], int64(990004)
	clone["ips"].([]any)[0].(map[string]any)["ip"].(map[string]any)["ip"] = nordStation[nordUS2]
	data["servers"] = append(servers, clone)
	entries, err := providers.ParseNordCatalog(data)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func nordSetup(t testing.TB) (*Applier, *kernel, string) {
	t.Helper()
	dir := t.TempDir()
	writeSnapshot(t, dir, "nordvpn", nordCatalogue(t))
	k := newNordKernel(t)
	return newApplier(t, k, dir, NewNordVPN(), ""), k, dir
}

// newNordKernel is the Python NordKernel: IPv4 only, no peer, the exit
// interface named nordvpn.
func newNordKernel(t testing.TB) *kernel {
	k := newKernel(t)
	k.exit.ExitIf = "nordvpn"
	k.addrs = []netip.Addr{mustAddr(nordTunnel)}
	k.rules = map[int][]Rule{4: {
		{Priority: 94, Src: nordTunnel, SrcLen: -1, IPProto: 1, Table: 51821},
		{Priority: 98, Src: nordTunnel, SrcLen: -1, IPProto: 1, Action: "unreachable"}}}
	k.keys = nil
	k.insights = []any{map[string]any{"ip": "198.51.100.11", "country": "United States", "city": "Dallas",
		"country_code": "US", "protected": true}}
	return k
}

func connect(k *kernel, host string) {
	key := nordUSKey
	if host == nordDE {
		key = nordDEKey
	}
	k.keys = []string{key}
	k.endpoints = map[string]string{key: nordStation[host] + ":51820"}
}

func nordRequest(server string, changes map[string]any) map[string]any {
	r := requestAt(server, map[string]any{"request_id": strings.Repeat("a", 32)})
	for k, v := range changes {
		r[k] = v
	}
	return r
}

func unprotected(ip string) map[string]any {
	return map[string]any{"ip": ip, "country": "Unknown", "city": "Unknown", "country_code": "Unknown", "protected": false}
}

func TestNordSnapshotRoundTripKeepsEveryRelay(t *testing.T) {
	a, _, _ := nordSetup(t)
	names := a.catalog.Relays().Names()
	if !a.catalog.Usable() || len(names) != 3 {
		t.Fatalf("%v", names)
	}
	us, _ := a.catalog.Relays().Get(nordUS)
	us2, _ := a.catalog.Relays().Get(nordUS2)
	if us.PublicKey != nordUSKey || us2.PublicKey != us.PublicKey {
		t.Errorf("keys %s %s", us.PublicKey, us2.PublicKey)
	}
	snap := providers.ReadSnapshot(a.directory+"/relays.json", "nordvpn")
	if providers.SnapshotRelays(snap, "nordvpn").Len() != 3 || providers.SnapshotRelays(snap, "mullvad").Len() != 0 {
		t.Error("snapshot of another provider has authority")
	}
}

func TestNordRefreshParsesWithTheNordParserAndKeepsTheLastGoodCatalogue(t *testing.T) {
	a, _, _ := nordSetup(t)
	raw := []byte(nordFixture(t, "nordvpn-servers.json"))
	ok, err := a.catalog.Refresh(context.Background(), func() ([]byte, error) { return raw, nil })
	if err != nil || !ok || a.catalog.Relays().Len() != 2 || !a.catalog.Relays().Has(nordUS) || !a.catalog.Relays().Has(nordDE) {
		t.Fatalf("%v %v %v", ok, err, a.catalog.Relays().Names())
	}
	ok, err = a.catalog.Refresh(context.Background(), func() ([]byte, error) { return []byte(`{"servers": []}`), nil })
	if err != nil || ok || a.catalog.Relays().Len() != 2 {
		t.Fatalf("%v %v %v", ok, err, a.catalog.Relays().Names())
	}
	record, _ := jsonfile.ReadObject(snapshot(a).ErrorPath, 4096)
	if record["message"] != "Relay refresh failed; retaining the last good catalogue." {
		t.Errorf("%v", record)
	}
}

// -- switching ---------------------------------------------------------------------------------

func TestNordSwitchSetsKeyEndpointIPv4OnlyAndKeepalive(t *testing.T) {
	a, k, _ := nordSetup(t)
	r := a.switchTo(t, nordRequest(nordUS, nil))
	if status(r) != "ok" || r.Get("server") != nordUS {
		t.Fatalf("%s %s", status(r), message(r))
	}
	want := "set " + nordUSKey + " endpoint 198.51.100.11:51820 allowed-ips 0.0.0.0/0 keepalive 25"
	if len(k.mutations) != 1 || k.mutations[0] != want {
		t.Fatalf("%v", k.mutations)
	}
	// The address is the config's; a switch never changes it.
	for _, c := range k.calls {
		if strings.HasPrefix(c, "ChangePIAAddress") || strings.HasPrefix(c, "rule ") || strings.HasPrefix(c, "address ") {
			t.Errorf("changed addresses or rules: %s", c)
		}
	}
}

func TestNordSwitchReplacesEveryPeerFirstEvenWithTheSameKey(t *testing.T) {
	a, k, _ := nordSetup(t)
	connect(k, nordUS)
	r := a.switchTo(t, nordRequest(nordUS2, nil))
	if status(r) != "ok" || r.Get("server") != nordUS2 {
		t.Fatalf("%s %s", status(r), message(r))
	}
	want := []string{"remove " + nordUSKey,
		"set " + nordUSKey + " endpoint 198.51.100.14:51820 allowed-ips 0.0.0.0/0 keepalive 25"}
	if strings.Join(k.mutations, "\n") != strings.Join(want, "\n") {
		t.Fatalf("%v", k.mutations)
	}
}

func TestNordSwitchToAnotherLocationRemovesTheOldPeer(t *testing.T) {
	a, k, _ := nordSetup(t)
	connect(k, nordDE)
	if r := a.switchTo(t, nordRequest(nordUS, nil)); status(r) != "ok" {
		t.Fatalf("%s %s", status(r), message(r))
	}
	if k.mutations[0] != "remove "+nordDEKey || len(k.endpoints) != 1 || k.endpoints[nordUSKey] != "198.51.100.11:51820" {
		t.Fatalf("%v %v", k.mutations, k.endpoints)
	}
}

func TestNordFailedRemovalAddsNoPeer(t *testing.T) {
	a, k, _ := nordSetup(t)
	connect(k, nordDE)
	k.failSet = true
	r := a.switchTo(t, nordRequest(nordUS, nil))
	if status(r) != "failed" || message(r) != "Peer update failed; retrying automatically." {
		t.Fatalf("%s %s", status(r), message(r))
	}
	if len(k.endpoints) != 1 || k.endpoints[nordDEKey] != "198.51.100.22:51820" {
		t.Errorf("%v", k.endpoints)
	}
	for _, m := range k.mutations {
		if !strings.HasPrefix(m, "remove ") {
			t.Errorf("added a peer: %s", m)
		}
	}
}

func TestNordUnlistedServerChangesNothing(t *testing.T) {
	a, k, _ := nordSetup(t)
	connect(k, nordUS)
	r := a.switchTo(t, nordRequest("uk9003.nordvpn.com", nil))
	if status(r) != "failed" || len(k.mutations) != 0 || message(r) != "Requested server is not in a fresh trusted relay catalogue; no change applied." {
		t.Fatalf("%s %s %v", status(r), message(r), k.mutations)
	}
}

// -- which server is live ------------------------------------------------------------------------

func TestNordServerIsIdentifiedByLiveEndpointAndKey(t *testing.T) {
	for name, c := range map[string]struct {
		peers    map[string]string
		expected string
	}{
		"US":                     {map[string]string{nordUSKey: "198.51.100.11:51820"}, nordUS},
		"US2 shares the key":     {map[string]string{nordUSKey: "198.51.100.14:51820"}, nordUS2},
		"DE":                     {map[string]string{nordDEKey: "198.51.100.22:51820"}, nordDE},
		"location key elsewhere": {map[string]string{nordUSKey: "198.51.100.22:51820"}, ""},
		"other key here":         {map[string]string{nordDEKey: "198.51.100.11:51820"}, ""},
		"wrong port":             {map[string]string{nordUSKey: "198.51.100.11:51821"}, ""},
		"unknown address":        {map[string]string{nordUSKey: "203.0.113.99:51820"}, ""},
		"no endpoint":            {map[string]string{nordUSKey: "(none)"}, ""},
		"IPv6 endpoint":          {map[string]string{nordUSKey: "[2001:db8::1]:51820"}, ""},
		"two peers":              {map[string]string{nordUSKey: "198.51.100.11:51820", nordDEKey: "198.51.100.22:51820"}, ""},
		"none":                   {map[string]string{}, ""},
	} {
		a, k, _ := nordSetup(t)
		k.keys, k.endpoints = nil, c.peers
		for key := range c.peers {
			k.keys = append(k.keys, key)
		}
		keys, err := a.peers(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		got, err := a.hooks.ServerFor(context.Background(), a, keys)
		if err != nil || got != c.expected {
			t.Errorf("%s: %q %v", name, got, err)
		}
	}
}

func TestNordMalformedEndpointListingIsRefused(t *testing.T) {
	a, k, _ := nordSetup(t)
	connect(k, nordUS)
	k.endpointsErr = errors.New("invalid peer endpoint listing")
	if _, err := a.hooks.ServerFor(context.Background(), a, []string{nordUSKey}); err == nil {
		t.Fatal("accepted")
	}
	r := a.inspect(t)
	if status(r) != "failed" || r.Get("server") != nil {
		t.Fatalf("%s %v", status(r), r.Get("server"))
	}
}

func TestNordRecreatedTunnelGetsTheSelectionBack(t *testing.T) {
	a, k, _ := nordSetup(t)
	desire(t, a, nordRequest(nordUS2, nil))
	if r := mustTick(t, a); status(r) != "ok" || k.endpoints[nordUSKey] != "198.51.100.14:51820" {
		t.Fatalf("%s %s %v", status(r), message(r), k.endpoints)
	}
	k.keys, k.endpoints = nil, map[string]string{} // the container came back from its config, which has no peer
	k.calls = nil
	// Without a new owner generation, a missing peer is waited out like any drift.
	mustTick(t, a)
	k.now += 90
	if r := mustTick(t, a); status(r) != "ok" || k.endpoints[nordUSKey] != "198.51.100.14:51820" {
		t.Fatalf("%s %s %v", status(r), message(r), k.endpoints)
	}
	// Same key, other server in the location: still not the selection, so it
	// is applied again after the 90 s guard.
	k.keys, k.endpoints = []string{nordUSKey}, map[string]string{nordUSKey: "198.51.100.11:51820"}
	k.now += 90
	if r := mustTick(t, a); r.Get("server") != nordUS2 {
		t.Fatalf("%v", r.Get("server"))
	}
}

// -- egress ---------------------------------------------------------------------------------------

func TestNordProtectedEgressIsTheProviderTier(t *testing.T) {
	a, k, dir := nordSetup(t)
	withPublished(a, dir)
	connect(k, nordUS)
	r := a.inspect(t)
	if status(r) != "ok" || tierOf(r) != "provider" {
		t.Fatalf("%s %s", status(r), message(r))
	}
	if r.Get("egress_ip") != "198.51.100.11" || r.Get("egress_city") != "Dallas" || r.Get("egress_country") != "United States" {
		t.Errorf("%v %v %v", r.Get("egress_ip"), r.Get("egress_city"), r.Get("egress_country"))
	}
	ips := r.Decoded()["egress_ips"].(map[string]any)
	if len(ips) != 1 || ips["4"] != "198.51.100.11" || r.Get("provider") != "nordvpn" || r.Decoded()["mullvad_exit_ip"] != nil {
		t.Errorf("%v", r.Decoded())
	}
	if state, label := statusViewOf(t, a, "nordvpn"); state != "ok" || label != "connected" {
		t.Errorf("%s %s", state, label)
	}
	if n := len(k.requestsTo(providers.NordInsightsURL)); n != 1 {
		t.Errorf("%d insights calls", n)
	}
}

func TestNordUnprotectedEgressElsewhereFailsAtOnce(t *testing.T) {
	a, k, _ := nordSetup(t)
	connect(k, nordUS)
	k.insights = []any{decodeText(t, nordFixture(t, "nordvpn-insights-unprotected.json"))}
	r := a.inspect(t)
	if status(r) != "failed" || tierOf(r) != nil || message(r) != "Tunnel egress is not confirmed as NordVPN." ||
		len(k.requestsTo(providers.NordInsightsURL)) != 1 || k.now != 0 {
		t.Fatalf("%s %s now %v", status(r), message(r), k.now)
	}
}

func TestNordCachedAnswerForTheServersOwnAddressIsAskedAgain(t *testing.T) {
	a, k, _ := nordSetup(t)
	connect(k, nordUS)
	stale := unprotected("198.51.100.11")
	protected := unprotected("198.51.100.11")
	protected["protected"], protected["city"] = true, "Dallas"
	k.insights = []any{stale, stale, protected}
	r := a.inspect(t)
	if status(r) != "ok" || tierOf(r) != "provider" || len(k.requestsTo(providers.NordInsightsURL)) != 3 || k.now != 2*InsightsRetrySec {
		t.Fatalf("%s %s calls %d now %v", status(r), message(r), len(k.requestsTo(providers.NordInsightsURL)), k.now)
	}
}

func TestNordCachedAnswerThatNeverChangesFailsWithinTheSwitchTimeout(t *testing.T) {
	a, k, _ := nordSetup(t)
	connect(k, nordUS)
	k.insights = []any{unprotected("198.51.100.11")}
	r := a.inspect(t)
	if status(r) != "failed" || message(r) != "Tunnel egress is not confirmed as NordVPN." || k.now > SwitchTimeoutSec ||
		len(k.requestsTo(providers.NordInsightsURL)) != int(SwitchTimeoutSec)/InsightsRetrySec+1 {
		t.Fatalf("%s %s now %v calls %d", status(r), message(r), k.now, len(k.requestsTo(providers.NordInsightsURL)))
	}
}

func TestNordASwitchWaitsOutACachedAnswerWithinItsOwnTimeout(t *testing.T) {
	a, k, _ := nordSetup(t)
	connect(k, nordDE)
	stale := unprotected("198.51.100.11")
	protected := unprotected("198.51.100.11")
	protected["protected"] = true
	k.insights = []any{stale, stale, stale, protected}
	r := a.switchTo(t, nordRequest(nordUS, nil))
	if status(r) != "ok" || r.Get("server") != nordUS || k.now >= SwitchTimeoutSec {
		t.Fatalf("%s %s now %v", status(r), message(r), k.now)
	}
	k.insights = []any{stale}
	connect(k, nordDE)
	k.now = 0
	r = a.switchTo(t, nordRequest(nordUS, map[string]any{"request_id": strings.Repeat("b", 32)}))
	if status(r) != "failed" || k.now > SwitchTimeoutSec+3 {
		t.Fatalf("%s now %v", status(r), k.now)
	}
	// The server is the one requested: applied, not yet verified, re-checked.
	if message(r) != "Tunnel egress is not confirmed as NordVPN." || a.attempt.State != "unverified" || a.switchDeadline != nil {
		t.Fatalf("%s %s %v", message(r), a.attempt.State, a.switchDeadline)
	}
}

func TestNordUnusableInsightsAnswersFailClosed(t *testing.T) {
	for name, answer := range map[string]string{
		"unknown":            nordFixture(t, "nordvpn-insights-unknown.json"),
		"protected a string": `{"ip": "198.51.100.11", "protected": "true"}`,
		"IPv6 address":       `{"ip": "2001:db8::1", "protected": true}`,
		"not json":           `not json`,
		"a list":             `[]`,
		"duplicate member":   `{"ip": "198.51.100.11", "protected": true, "protected": false}`,
	} {
		a, k, _ := nordSetup(t)
		connect(k, nordUS)
		k.insights = []any{answer}
		r := a.inspect(t)
		if status(r) != "failed" || tierOf(r) != nil {
			t.Errorf("%s: %s", name, status(r))
		}
		if !strings.Contains(answer, "Unknown") && message(r) != EgressFailedMessage {
			t.Errorf("%s: %s", name, message(r))
		}
	}
}

func TestNordIPv6IsNeverTunnelledOrProbed(t *testing.T) {
	a, k, _ := nordSetup(t)
	connect(k, nordUS)
	if p, f := a.routingStatus(context.Background(), true); !p || !f {
		t.Fatalf("routing %v %v", p, f)
	}
	addrs, err := a.tunnelAddresses(context.Background(), true)
	if err != nil || len(addrs) != 1 || addrs[4] != nordTunnel {
		t.Fatalf("%v %v", addrs, err)
	}
	if status(a.inspect(t)) != "ok" {
		t.Fatal("not ok")
	}
	for _, req := range k.reqs {
		if req.Family == 6 {
			t.Errorf("IPv6 request %s", req.URL)
		}
	}
	for _, m := range k.mutations {
		if strings.Contains(m, "::/0") {
			t.Errorf("IPv6 in %s", m)
		}
	}
	// An IPv6 return-path rule would mean the config carries IPv6, which
	// NordLynx does not.
	k.rules[6] = []Rule{{Priority: 94, Src: "2001:db8:3::1", SrcLen: -1, IPProto: 58, Table: 51821}}
	if p, _ := a.routingStatus(context.Background(), true); p {
		t.Error("protected with an IPv6 return-path rule")
	}
}

func TestNordMissingTunnelAddressBlocksASwitch(t *testing.T) {
	a, k, _ := nordSetup(t)
	k.addrs = nil
	r := a.switchTo(t, nordRequest(nordUS, nil))
	if status(r) != "failed" || len(k.mutations) != 0 || a.attempt.State != "pending" ||
		!strings.HasPrefix(a.attempt.Message, "Waiting for tunnel and overlay routing") {
		t.Fatalf("%s %v %s %q", status(r), k.mutations, a.attempt.State, a.attempt.Message)
	}
}

func TestNordFreshExitAsksForAServer(t *testing.T) {
	a, k, _ := nordSetup(t)
	r := a.inspect(t)
	if status(r) != "failed" || message(r) != "No NordVPN server is selected yet; choose one in the panel." ||
		checkState(r, "routing") != "pass" || checkState(r, "netbird") != "pass" || len(k.requestsTo(providers.NordInsightsURL)) != 0 {
		t.Fatalf("%s %s", status(r), message(r))
	}
}

func TestNordProviderIsBuiltFromTheRegistry(t *testing.T) {
	a, _, _ := nordSetup(t)
	if a.hooks.ID() != "nordvpn" || !a.spec.AddressBeforeSwitch || a.spec.IPv6 {
		t.Errorf("%s %v %v", a.hooks.ID(), a.spec.AddressBeforeSwitch, a.spec.IPv6)
	}
}

// -- egress check retry -----------------------------------------------------------------------------

func insightsCall(r netx.Request) bool { return r.URL == providers.NordInsightsURL }

func TestAnUnansweredInsightsCheckIsAskedOnceMore(t *testing.T) {
	a, k, _ := nordSetup(t)
	if status(a.switchTo(t, nordRequest(nordUS, nil))) != "ok" {
		t.Fatal("switch")
	}
	calls := k.unanswered(insightsCall, 1, 10)
	start := k.now
	r := a.inspect(t)
	if status(r) != "ok" || tierOf(r) != "provider" || len(*calls) != 2 || k.now-start != 10+EgressRetrySec {
		t.Fatalf("%s calls %d elapsed %v", status(r), len(*calls), k.now-start)
	}
}

func TestAnInsightsCheckUnansweredTwiceFails(t *testing.T) {
	a, k, _ := nordSetup(t)
	a.switchTo(t, nordRequest(nordUS, nil))
	calls := k.unanswered(insightsCall, 2, 10)
	r := a.inspect(t)
	if status(r) != "failed" || message(r) != EgressFailedMessage || len(*calls) != 2 {
		t.Fatalf("%s %s %d", status(r), message(r), len(*calls))
	}
}

func TestUnprotectedFromAnotherAddressIsNeverAskedAgain(t *testing.T) {
	a, k, _ := nordSetup(t)
	a.switchTo(t, nordRequest(nordUS, nil))
	k.insights = []any{map[string]any{"ip": "203.0.113.99", "country": "United States", "city": "Dallas",
		"country_code": "US", "protected": false}}
	calls := k.delayed(insightsCall)
	start := k.now
	if r := a.inspect(t); message(r) != "Tunnel egress is not confirmed as NordVPN." || len(*calls) != 1 || k.now != start {
		t.Fatalf("%s %d %v", message(r), len(*calls), k.now-start)
	}
}

func TestASecondAttemptWaitsForTheCacheOnlyWithinItsBudget(t *testing.T) {
	a, k, _ := nordSetup(t)
	a.switchTo(t, nordRequest(nordUS, nil))
	// The server's own address, unprotected: the cache answer NordVPN can serve.
	k.insights = []any{map[string]any{"ip": "198.51.100.11", "country": "United States", "city": "Dallas",
		"country_code": "US", "protected": false}}
	k.unanswered(insightsCall, 1, 10)
	start := k.now
	r := a.inspect(t)
	if message(r) != "Tunnel egress is not confirmed as NordVPN." || k.now-start != 10+EgressRetrySec+EgressRetryBudgetSec {
		t.Fatalf("%s elapsed %v", message(r), k.now-start)
	}
}

func TestACacheWaitThenNoAnswerIsNotAskedAgain(t *testing.T) {
	a, k, _ := nordSetup(t)
	a.switchTo(t, nordRequest(nordUS, nil))
	k.insights = []any{map[string]any{"ip": "198.51.100.11", "country": "United States", "city": "Dallas",
		"country_code": "US", "protected": false}}
	// One cached answer, the 10-second wait, then no answer: over the limit for
	// a second attempt.
	calls := k.delayed(insightsCall, step{0, true}, step{10, false})
	start := k.now
	r := a.inspect(t)
	if message(r) != EgressFailedMessage || k.now-start != InsightsRetrySec+10 || k.now-start <= EgressRetryWithinSec || len(*calls) != 2 {
		t.Fatalf("%s elapsed %v calls %d", message(r), k.now-start, len(*calls))
	}
}
