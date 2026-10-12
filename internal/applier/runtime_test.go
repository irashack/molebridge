// Tests ported from tools/test_runtime.py: the applier's behavior against the
// fake kernel (support_test.go, fake_test.go). Nothing touches a live tunnel.
//
// Not ported, because the code they test is not the applier's: the routing
// rule and route judgments (family_status, local_rule_admits_overlay,
// overlay_is_kernel_wireguard, netbird_firewall_present: the exit worker's
// routing package; here the fake's RoutingStatus answers), the relay parsers
// and snapshot (internal/providers), status_view (internal/verdict),
// read_json and write_json_atomic (internal/jsonfile), RoutingConfig
// (the exit worker), command (internal/netx), and the owner record tests
// (test_container_health_needs_a_live_owner_record,
// test_owner_record_six_seconds_old_still_counts,
// test_owner_record_may_not_go_backwards_within_a_generation,
// test_native_aborts_when_the_owner_record_is_lost_during_a_switch: the
// supervisor's lease replaces the owner record, decision D7).
package applier

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/validate"
)

func TestSwitchAndObservedInitialPeer(t *testing.T) {
	a, k, _ := mullvadSetup(t)
	if r := a.inspect(t); r.Get("server") != testHost {
		t.Fatalf("server %v", r.Get("server"))
	}
	r := a.switchTo(t, requestAt(testHost, nil))
	if status(r) != "ok" || checkState(r, "routing") != "pass" || r.Get("request_id") != strings.Repeat("0", 32) {
		t.Fatalf("%s %s", status(r), message(r))
	}
	if len(k.mutations) != 1 {
		t.Fatalf("mutations %v", k.mutations)
	}
	for _, c := range k.calls {
		if strings.Contains(c, "dump") || strings.Contains(c, "private-key") || strings.Contains(c, "showconf") {
			t.Errorf("secret-reading call %s", c)
		}
	}
}

func TestUntrustedRequestCannotMutate(t *testing.T) {
	for name, change := range map[string]map[string]any{
		"flag": {"server": "--flag"}, "newline": {"server": testHost + "\n"}, "list": {"server": []any{}},
		"request id": {"request_id": 2}, "bad time": {"requested_at": "bad"}, "extra member": {"endpoint": "198.51.100.1"}} {
		a, k, _ := mullvadSetup(t)
		if r := a.switchTo(t, requestAt(testHost, change)); status(r) != "failed" {
			t.Errorf("%s: %s", name, status(r))
		}
		if len(k.mutations) != 0 {
			t.Errorf("%s: mutated", name)
		}
	}
}

func TestPanelOwnedCatalogueCannotAuthorizeEndpoint(t *testing.T) {
	dir := t.TempDir()
	// A snapshot in the panel's directory is not the applier's.
	writeFile(t, dir+"/panel/relays.json", `{"fetched_at": "`+validate.FormatTime(time.Now())+`", "relays": {}}`, 0o644)
	k := newKernel(t)
	a := newApplier(t, k, dir, NewMullvad(), "")
	if r := a.switchTo(t, requestAt(testHost, nil)); status(r) != "failed" || len(k.mutations) != 0 {
		t.Fatalf("%s %v", status(r), k.mutations)
	}
}

func TestStaleCatalogueRefusesSwitch(t *testing.T) {
	a, k, _ := mullvadSetup(t)
	staleCatalogue(a)
	if r := a.switchTo(t, requestAt(testHost, nil)); status(r) != "failed" || len(k.mutations) != 0 {
		t.Fatalf("%s %v", status(r), k.mutations)
	}
}

func TestSavedSelectionRetriesAfterCatalogueRecovers(t *testing.T) {
	dir := t.TempDir()
	writeSnapshot(t, dir, "", map[string]any{testHost: mullvadEntry(testHost, testKey)})
	k := newKernel(t)
	o := &overridden{Provider: NewMullvad()}
	a := newApplier(t, k, dir, o, "")
	staleCatalogue(a)
	a.nextCatalog = 0
	answers := [][]byte{nil, mullvadPayload(nil)}
	o.fetch = func(context.Context) ([]byte, error) {
		next := answers[0]
		answers = answers[1:]
		if next == nil {
			return nil, errors.New("unavailable")
		}
		return next, nil
	}
	desire(t, a, requestAt(testHost, nil))
	if r := mustTick(t, a); status(r) != "failed" {
		t.Fatalf("first tick: %s", status(r))
	}
	if a.attempt.State != "pending" || len(k.mutations) != 0 {
		t.Fatalf("%s %v", a.attempt.State, k.mutations)
	}
	// While the catalogue stays stale nothing is probed or pushed again.
	probes := len(k.reqs)
	if r := mustTick(t, a); r != nil || len(k.reqs) != probes {
		t.Fatalf("second tick published %v, requests %d -> %d", r, probes, len(k.reqs))
	}
	k.now = 60
	r := mustTick(t, a)
	if status(r) != "ok" || r.Get("request_id") != strings.Repeat("0", 32) || len(k.mutations) != 1 {
		t.Fatalf("%s %s %v", status(r), message(r), k.mutations)
	}
	if a.attempt.State == "pending" {
		t.Error("still pending")
	}
}

func TestSavedSelectionRetriesAfterRoutingRecovers(t *testing.T) {
	for _, prerequisite := range []string{"overlay", "tunnel", "route"} {
		a, k, _ := mullvadSetup(t)
		k.overlayPresent = prerequisite != "overlay"
		k.tunnelPresent = prerequisite != "tunnel"
		if prerequisite == "route" {
			k.routeMissing[6] = true
		}
		desire(t, a, requestAt(testHost, nil))
		if r := mustTick(t, a); status(r) != "failed" {
			t.Fatalf("%s: %s", prerequisite, status(r))
		}
		if a.attempt.State != "pending" || len(k.mutations) != 0 {
			t.Fatalf("%s: %s %v", prerequisite, a.attempt.State, k.mutations)
		}
		k.overlayPresent, k.tunnelPresent = true, true
		k.routeMissing[6] = false
		if r := mustTick(t, a); status(r) != "ok" || len(k.mutations) != 1 {
			t.Fatalf("%s: %s %s %v", prerequisite, status(r), message(r), k.mutations)
		}
	}
}

func TestUnlistedRequestIsTriedAgainOnceTheCatalogueChanges(t *testing.T) {
	a, k, _ := mullvadSetup(t)
	const unlisted = "xx-xxx-wg-999"
	desire(t, a, requestAt(unlisted, nil))
	if r := mustTick(t, a); status(r) != "failed" {
		t.Fatalf("%s", status(r))
	}
	if !a.requestRejected() {
		t.Fatal("not rejected")
	}
	// Listed now, under another key than the live peer's.
	ok, err := a.catalog.Refresh(context.Background(), func() ([]byte, error) {
		return mullvadPayload(map[string]any{"hostname": unlisted, "public_key": otherKey}), nil
	})
	if err != nil || !ok {
		t.Fatalf("refresh %v %v", ok, err)
	}
	// The catalogue changed, so the request is admitted again.
	if r := mustTick(t, a); status(r) != "ok" || len(k.mutations) != 2 {
		t.Fatalf("%s %s %v", status(r), message(r), k.mutations)
	}
}

func TestRemovingPendingRequestCancelsRetry(t *testing.T) {
	a, k, _ := mullvadSetup(t)
	k.overlayPresent = false
	desire(t, a, requestAt(testHost, nil))
	mustTick(t, a)
	if err := removeFile(a.desiredPath); err != nil {
		t.Fatal(err)
	}
	k.overlayPresent = true
	mustTick(t, a)
	if a.attempt.State == "pending" || len(k.mutations) != 0 {
		t.Fatalf("%s %v", a.attempt.State, k.mutations)
	}
}

func TestTunnelDisappearingBeforePeerUpdateLeavesRequestPending(t *testing.T) {
	dir := t.TempDir()
	writeSnapshot(t, dir, "", map[string]any{testHost: mullvadEntry(testHost, testKey)})
	k := newKernel(t)
	o := &overridden{Provider: NewMullvad()}
	a := newApplier(t, k, dir, o, "")
	k.peersErr = errors.New("interface disappeared")
	desire(t, a, requestAt(testHost, nil))
	if r := mustTick(t, a); status(r) != "failed" {
		t.Fatalf("%s", status(r))
	}
	if a.attempt.State != "pending" || len(k.mutations) != 0 {
		t.Fatalf("%s %v", a.attempt.State, k.mutations)
	}
	k.peersErr = nil
	if r := mustTick(t, a); status(r) != "ok" {
		t.Fatalf("%s %s", status(r), message(r))
	}
}

func TestMissingRulePreventsSuccessAndSwitch(t *testing.T) {
	// The fake's RoutingStatus stands for the rule judgment (the exit worker's):
	// a family whose contract is broken, whichever rule is missing.
	for _, family := range []int{4, 6} {
		a, k, _ := mullvadSetup(t)
		k.routeFault[family] = true
		if r := a.switchTo(t, requestAt(testHost, nil)); status(r) != "failed" || len(k.mutations) != 0 {
			t.Errorf("family %d: %s %v", family, status(r), k.mutations)
		}
	}
}

func TestMissingFallbackPreventsSwitchSuccess(t *testing.T) {
	a, k, _ := mullvadSetup(t)
	k.fallbackMissing[6] = true
	r := a.switchTo(t, requestAt(testHost, nil))
	if status(r) != "failed" || checkField(r, "routing", "fallback") != false || len(k.mutations) != 0 {
		t.Fatalf("%s %v %v", status(r), checkField(r, "routing", "fallback"), k.mutations)
	}
}

func TestSingleFamilyRouteLossIsUnhealthyAndRefusesSwitch(t *testing.T) {
	for _, family := range []int{4, 6} {
		a, k, _ := mullvadSetup(t)
		k.routeMissing[family] = true
		r := a.inspect(t)
		if status(r) != "failed" || checkState(r, "routing") == "pass" || checkField(r, "routing", "fallback") != true {
			t.Fatalf("family %d: %s", family, status(r))
		}
		if r := a.switchTo(t, requestAt(testHost, nil)); status(r) != "failed" || len(k.mutations) != 0 {
			t.Fatalf("family %d: switch %s %v", family, status(r), k.mutations)
		}
	}
}

func TestEachEgressFamilyMustPass(t *testing.T) {
	for _, family := range []int{4, 6} {
		for _, failure := range []string{"unreachable", "not-mullvad", "wrong-address-family"} {
			a, k, _ := mullvadSetup(t)
			probe := k.probes[family]
			switch failure {
			case "unreachable":
				k.failedEgress[family] = true
			case "not-mullvad":
				probe["mullvad_exit_ip"] = false
			default:
				if family == 4 {
					probe["ip"] = "2001:db8::1"
				} else {
					probe["ip"] = "203.0.113.1"
				}
			}
			if r := a.inspect(t); status(r) != "failed" {
				t.Errorf("family %d %s: %s", family, failure, status(r))
			}
		}
	}
}

func TestIPv4OnlyTunnelKeepsIPv6GuardWithoutRequiringIPv6Egress(t *testing.T) {
	a, k, _ := mullvadSetup(t)
	k.addrs = k.addrs[:1]
	k.failedEgress[6] = true
	// A return-path rule for an address the tunnel does not have is unexpected.
	if r := a.inspect(t); status(r) != "failed" {
		t.Fatalf("%s", status(r))
	}
	k.rules[6] = nil
	r := a.switchTo(t, requestAt(testHost, nil))
	if status(r) != "ok" {
		t.Fatalf("%s %s", status(r), message(r))
	}
	ips := r.Decoded()["egress_ips"].(map[string]any)
	if len(ips) != 1 || ips["4"] != exitIP4 {
		t.Errorf("egress_ips %v", ips)
	}
	for _, req := range k.reqs {
		if req.Family == 6 {
			t.Errorf("IPv6 request %s", req.URL)
		}
	}
	k.routeFault[6] = true // rule 97 gone
	if r := a.inspect(t); status(r) != "failed" {
		t.Fatalf("%s", status(r))
	}
}

func TestHealthyDualStackResultRecordsBothProbes(t *testing.T) {
	a, _, _ := mullvadSetup(t)
	r := a.inspect(t)
	ips := r.Decoded()["egress_ips"].(map[string]any)
	if status(r) != "ok" || ips["4"] != exitIP4 || ips["6"] != exitIP6 || len(ips) != 2 {
		t.Fatalf("%s %v", status(r), ips)
	}
}

func TestHealthyResultRecordsNetbirdKernelMode(t *testing.T) {
	a, k, _ := mullvadSetup(t)
	r := a.inspect(t)
	if status(r) != "ok" || checkState(r, "netbird") != "pass" || k.countCalls("NetbirdFirewallPresent") == 0 {
		t.Fatalf("%s", status(r))
	}
}

func TestNetbirdOutsideKernelModeIsNeverConnected(t *testing.T) {
	for _, fault := range []string{"tun", "no-linkinfo", "no-netbird-chains", "nft-fails"} {
		a, k, _ := mullvadSetup(t)
		switch fault {
		case "tun", "no-linkinfo":
			k.overlayWG = false
		case "no-netbird-chains":
			k.netbirdChains = false
		default:
			k.netbirdErr = true
		}
		r := a.inspect(t)
		if status(r) != "failed" || message(r) != NetbirdModeFailed || checkState(r, "routing") != "pass" ||
			checkState(r, "netbird") != "fail" {
			t.Fatalf("%s: %s %s", fault, status(r), message(r))
		}
		// A switch waits instead of changing the tunnel, and retries later.
		r = a.switchTo(t, requestAt(testHost, nil))
		if status(r) != "failed" || !strings.Contains(message(r), "kernel firewall") || a.attempt.State != "pending" ||
			len(k.mutations) != 0 {
			t.Fatalf("%s: switch %s %s %s %v", fault, status(r), message(r), a.attempt.State, k.mutations)
		}
	}
}

func TestReturnPathSysctlIsRequiredForHealthAndSwitching(t *testing.T) {
	for _, value := range []string{"0\n", "", "x"} {
		a, k, _ := mullvadSetup(t)
		k.returnPath = value
		r := a.inspect(t)
		if status(r) != "failed" || checkState(r, "routing") == "pass" {
			t.Fatalf("%q: %s", value, status(r))
		}
		if r := a.switchTo(t, requestAt(testHost, nil)); status(r) != "failed" || len(k.mutations) != 0 {
			t.Fatalf("%q: switch %s", value, status(r))
		}
	}
}

func TestUnsupportedTunnelAddressesAreUnhealthy(t *testing.T) {
	two4 := []string{"203.0.113.1", "203.0.113.2"}
	for name, addresses := range map[string][]string{"none": nil, "two IPv4": two4, "only IPv6": {tunnel6}} {
		a, k, _ := mullvadSetup(t)
		k.addrs = nil
		for _, s := range addresses {
			k.addrs = append(k.addrs, mustAddr(s))
		}
		if r := a.inspect(t); status(r) != "failed" {
			t.Errorf("%s: %s", name, status(r))
		}
		if r := a.switchTo(t, requestAt(testHost, nil)); status(r) != "failed" || len(k.mutations) != 0 {
			t.Errorf("%s: switch %s %v", name, status(r), k.mutations)
		}
	}
	// An address the system cannot report (Python's "bad" local address).
	a, k, _ := mullvadSetup(t)
	k.addrErr = errors.New("invalid tunnel address")
	if r := a.inspect(t); status(r) != "failed" {
		t.Errorf("unreadable: %s", status(r))
	}
	if r := a.switchTo(t, requestAt(testHost, nil)); status(r) != "failed" || len(k.mutations) != 0 {
		t.Errorf("unreadable: switch %s", status(r))
	}
}

func isMullvadProbe(family int) func(netx.Request) bool {
	return func(r netx.Request) bool {
		return strings.Contains(r.URL, "am.i.mullvad.net") && (family == 0 || r.Family == family)
	}
}

func TestAnUnansweredEgressCheckIsAskedOnceMore(t *testing.T) {
	a, k, dir := mullvadSetup(t)
	probes := k.unanswered(isMullvadProbe(6), 1, 10)
	statuses := withPublished(a, dir)
	r := a.inspect(t)
	if status(r) != "ok" || checkState(r, "egress") != "pass" || checkField(r, "egress", "tier") != "provider" {
		t.Fatalf("%s %s", status(r), message(r))
	}
	if len(*probes) != 2 || len(*statuses) != 1 || (*statuses)[0] != "ok" || k.now != 10+EgressRetrySec {
		t.Fatalf("probes %d statuses %v now %v", len(*probes), *statuses, k.now)
	}
	if !k.logged("asking once more") {
		t.Error("no log line")
	}
}

func TestAnEgressCheckUnansweredTwiceFailsAfterOnePause(t *testing.T) {
	a, k, dir := mullvadSetup(t)
	probes := k.unanswered(isMullvadProbe(6), 2, 10)
	statuses := withPublished(a, dir)
	r := a.inspect(t)
	if status(r) != "failed" || message(r) != EgressFailedMessage {
		t.Fatalf("%s %s", status(r), message(r))
	}
	if checkState(r, "egress") != "fail" || checkField(r, "egress", "reason") != "unanswered" || checkField(r, "egress", "tier") != nil {
		t.Errorf("egress check %v", r.Decoded()["checks"])
	}
	if len(*probes) != 2 || len(*statuses) != 1 || (*statuses)[0] != "failed" || k.now != 10+EgressRetrySec+10 {
		t.Fatalf("probes %d statuses %v now %v", len(*probes), *statuses, k.now)
	}
	if !k.logged("no answer twice") {
		t.Error("no log line")
	}
}

func TestAnAnswerThatIsNotMullvadIsNeverAskedAgain(t *testing.T) {
	a, k, _ := mullvadSetup(t)
	k.probes[6]["mullvad_exit_ip"] = false
	probes := k.delayed(isMullvadProbe(0))
	r := a.inspect(t)
	if status(r) != "failed" || message(r) != "Tunnel egress is not confirmed as Mullvad." {
		t.Fatalf("%s %s", status(r), message(r))
	}
	if len(*probes) != 2 || k.now != 0 { // one per family, no pause
		t.Fatalf("probes %d now %v", len(*probes), k.now)
	}
}

func TestRoutingNetbirdAndPeerFaultsFailBeforeAnyEgressCheck(t *testing.T) {
	for name, change := range map[string]func(*kernel){
		"return path": func(k *kernel) { k.returnPath = "0\n" },
		"rule 97":     func(k *kernel) { k.routeFault[4] = true },
		"no linkinfo": func(k *kernel) { k.overlayWG = false },
		"no peer":     func(k *kernel) { k.keys = nil },
		"second peer": func(k *kernel) { k.keys = []string{testKey, otherKey} },
	} {
		a, k, _ := mullvadSetup(t)
		change(k)
		probes := k.delayed(isMullvadProbe(0))
		if r := a.inspect(t); status(r) != "failed" {
			t.Errorf("%s: %s", name, status(r))
		}
		if len(*probes) != 0 || k.now != 0 {
			t.Errorf("%s: probes %d now %v", name, len(*probes), k.now)
		}
	}
}

func TestAStaleOrMissingHandshakeIsNotAskedAgain(t *testing.T) {
	for _, name := range []string{"stale", "missing"} {
		a, k, _ := mullvadSetup(t)
		if name == "stale" {
			k.age = 500
		} else {
			k.noHandshake = true
		}
		probes := k.unanswered(isMullvadProbe(6), 1, 10)
		if r := a.inspect(t); status(r) != "failed" || len(*probes) != 1 || k.now != 10 {
			t.Errorf("%s: %s probes %d now %v", name, status(r), len(*probes), k.now)
		}
	}
}

func TestACheckThatFailsAnywayIsNotAskedAgain(t *testing.T) {
	for name, change := range map[string]func(*Applier){
		"invalid desired": func(a *Applier) { a.invalidDesired = true },
		"pending":         func(a *Applier) { a.attempt.State = "pending" },
		"empty catalogue": func(a *Applier) { snapshot(a).Relays = providers.NewEntries() },
	} {
		a, k, _ := mullvadSetup(t)
		change(a)
		probes := k.unanswered(isMullvadProbe(6), 1, 10)
		if r := a.inspect(t); status(r) != "failed" || len(*probes) != 1 || k.now != 10 {
			t.Errorf("%s: %s probes %d now %v", name, status(r), len(*probes), k.now)
		}
	}
}

func TestANegativeAnswerIsKeptWhenALaterRequestWouldGoUnanswered(t *testing.T) {
	for _, negative := range []int{4, 6} {
		a, k, _ := mullvadSetup(t)
		k.probes[negative]["mullvad_exit_ip"] = false
		// IPv6 would time out: after an IPv4 "no" it is never asked.
		other := 4
		if negative == 4 {
			other = 6
		}
		probes := k.delayed(isMullvadProbe(other))
		if negative == 4 {
			k.unanswered(isMullvadProbe(6), 1, 10)
		}
		r := a.inspect(t)
		if status(r) != "failed" || message(r) != "Tunnel egress is not confirmed as Mullvad." {
			t.Fatalf("%d: %s %s", negative, status(r), message(r))
		}
		if checkState(r, "egress") != "fail" || checkField(r, "egress", "reason") != "not-confirmed" || checkField(r, "egress", "tier") != nil ||
			checkField(r, "egress", "families").(map[string]any)[itoaF(negative)] != "fail" {
			t.Errorf("%d: egress %v", negative, r.Decoded()["checks"])
		}
		wantProbes := 0
		if negative == 6 {
			wantProbes = 1
		}
		if k.now != 0 || len(*probes) != wantProbes {
			t.Errorf("%d: now %v probes %d", negative, k.now, len(*probes))
		}
	}
}

func TestTheSecondAttemptStartsNoRequestAfterItsBudget(t *testing.T) {
	a, k, _ := mullvadSetup(t)
	// First attempt: IPv6 unanswered. Second: IPv4 answers only after the whole
	// budget, so IPv6 is not asked again and the check fails.
	k.unanswered(isMullvadProbe(6), 1, 10)
	k.delayed(isMullvadProbe(4), step{0, true}, step{EgressRetryBudgetSec + 1, true})
	r := a.inspect(t)
	if status(r) != "failed" || message(r) != EgressFailedMessage {
		t.Fatalf("%s %s", status(r), message(r))
	}
	if k.now != 10+EgressRetrySec+EgressRetryBudgetSec+1 || a.retryDeadline != nil {
		t.Fatalf("now %v deadline %v", k.now, a.retryDeadline)
	}
}

func TestASlowFirstAttemptIsNotAskedAgain(t *testing.T) {
	a, k, _ := mullvadSetup(t)
	probes := k.unanswered(isMullvadProbe(6), 1, EgressRetryWithinSec+1)
	if r := a.inspect(t); status(r) != "failed" || len(*probes) != 1 || k.now != EgressRetryWithinSec+1 {
		t.Fatalf("%s probes %d now %v", status(r), len(*probes), k.now)
	}
}

func TestASwitchVerifiesThroughItsOwnLoopNotTheRetry(t *testing.T) {
	a, k, dir := mullvadSetup(t)
	probes := k.unanswered(isMullvadProbe(6), 1, 10)
	statuses := withPublished(a, dir)
	r := a.switchTo(t, requestAt(testHost, nil))
	if status(r) != "ok" || len(k.mutations) != 1 {
		t.Fatalf("%s %s %v", status(r), message(r), k.mutations)
	}
	// Never ok before a check that passed: applying, the failed check shown as
	// applying, then the next pass of the switch's own loop.
	if strings.Join(*statuses, ",") != "applying,applying,ok" || len(*probes) != 2 || k.now != 10+3 {
		t.Fatalf("statuses %v probes %d now %v", *statuses, len(*probes), k.now)
	}
	if k.logged("asking once more") {
		t.Error("asked once more during a switch")
	}
}

func TestAHealthTickPublishesAndPushesOnceAfterARetry(t *testing.T) {
	a, k, dir := mullvadSetup(t)
	a.gatus = Gatus{URL: "https://gatus.example.test", Token: "token"}
	k.unanswered(isMullvadProbe(4), 1, 10)
	statuses := withPublished(a, dir)
	if r := mustTick(t, a); status(r) != "ok" {
		t.Fatalf("%s %s", status(r), message(r))
	}
	if strings.Join(*statuses, ",") != "ok" || len(k.pushed) != 1 || k.pushed[0] != "success=true&error=" {
		t.Fatalf("statuses %v pushed %v", *statuses, k.pushed)
	}
}

const peerUpdateFailed = "Peer update failed; retrying automatically."

func TestASwitchThatNeverVerifiesIsRecheckedNotReapplied(t *testing.T) {
	// D7: applied but unverified is re-checked; the tunnel isn't touched again
	// while the live server is the target.
	a, k, _ := mullvadSetup(t)
	k.egressOK = false
	desire(t, a, requestAt(testHost, nil))
	r := mustTick(t, a)
	if status(r) != "failed" || message(r) != EgressFailedMessage || r.Get("server") != testHost || len(k.mutations) != 1 {
		t.Fatalf("%s %s %v", status(r), message(r), k.mutations)
	}
	sel := r.Decoded()["selection"].(map[string]any)
	if a.attempt.State != "unverified" || sel["outcome"] != "applied-unverified" || sel["next_action"] != "recheck" {
		t.Fatalf("%s %v", a.attempt.State, sel)
	}
	for i := 0; i < 20; i++ {
		k.now += 60
		mustTick(t, a)
	}
	if len(k.mutations) != 1 {
		t.Fatalf("reapplied: %v", k.mutations)
	}
	k.egressOK = true // the tunnel comes good on the requested server
	k.now += 60
	r = mustTick(t, a)
	sel = r.Decoded()["selection"].(map[string]any)
	if status(r) != "ok" || r.Get("server") != testHost || a.attempt.State != "idle" || sel["outcome"] != "verified" ||
		len(k.mutations) != 1 {
		t.Fatalf("%s %s %v", status(r), a.attempt.State, k.mutations)
	}
}

func TestAFailedMutationIsReportedUntilACheckFindsTheTarget(t *testing.T) {
	a, k, _ := mullvadSetup(t)
	addRelay(a, otherHost, otherKey)
	k.keys = []string{otherKey}
	k.failSet = true
	desire(t, a, requestAt(testHost, nil))
	r := mustTick(t, a)
	sel := r.Decoded()["selection"].(map[string]any)
	if status(r) != "failed" || message(r) != peerUpdateFailed || sel["outcome"] != "mutation-failed" || sel["next_action"] != "reapply" ||
		a.attempt.State != "failed" || a.attempt.MutationCertainty != "uncertain" {
		t.Fatalf("%s %s %v %s", status(r), message(r), sel, a.attempt.State)
	}
	// The live peer is the target after all (a lost response): the next check
	// finds it met, and nothing is applied again.
	k.failSet = false
	k.keys = []string{testKey}
	k.now += 60
	r = mustTick(t, a)
	if status(r) != "ok" || a.attempt.State != "idle" || len(k.adds()) != 0 {
		t.Fatalf("%s %s %v", status(r), a.attempt.State, k.adds())
	}
}

func TestAFailedMutationStandsWhileAnotherServerIsLive(t *testing.T) {
	a, k, _ := mullvadSetup(t)
	addRelay(a, otherHost, otherKey)
	k.keys = []string{otherKey}
	k.failSet = true
	desire(t, a, requestAt(testHost, nil))
	for i := 0; i < 3; i++ {
		r := mustTick(t, a)
		if r == nil {
			r = a.inspect(t)
		}
		if status(r) != "failed" || message(r) != peerUpdateFailed || r.Get("server") != otherHost {
			t.Fatalf("%d: %s %s %v", i, status(r), message(r), r.Get("server"))
		}
	}
}

func TestAFailedMutationIsRetriedOnTheBackoffAfterInspecting(t *testing.T) {
	a, k, _ := mullvadSetup(t)
	addRelay(a, otherHost, otherKey)
	k.keys = []string{otherKey}
	k.failSet = true
	desire(t, a, requestAt(testHost, nil))
	mustTick(t, a)
	for _, wait := range []float64{59, 1} {
		k.now += wait
		mustTick(t, a)
	}
	// Re-applied after one minute, not before.
	if a.attempt.Attempts != 2 || a.attempt.BackoffStep != 2 {
		t.Fatalf("attempts %d step %d", a.attempt.Attempts, a.attempt.BackoffStep)
	}
	k.failSet = false
	for _, wait := range []float64{119, 1} {
		k.now += wait
		mustTick(t, a)
	}
	if a.attempt.State != "idle" || a.attempt.Attempts != 3 || len(k.keys) != 1 || k.keys[0] != testKey {
		t.Fatalf("%s %d %v", a.attempt.State, a.attempt.Attempts, k.keys)
	}
}

func TestASwitchTimeoutNeverFailsOverAndANewRequestRetriesNow(t *testing.T) {
	a, k, _ := mullvadSetup(t)
	k.egressOK = false
	desire(t, a, requestAt(testHost, nil))
	if r := mustTick(t, a); status(r) != "failed" {
		t.Fatalf("%s", status(r))
	}
	if k.now < 60 || len(k.mutations) != 1 {
		t.Fatalf("now %v mutations %v", k.now, k.mutations)
	}
	mustTick(t, a)
	if len(k.mutations) != 1 {
		t.Fatalf("%v", k.mutations)
	}
	k.egressOK = true
	desire(t, a, requestAt(testHost, map[string]any{"request_id": strings.Repeat("1", 32)}))
	if r := mustTick(t, a); status(r) != "ok" || len(k.mutations) != 2 {
		t.Fatalf("%s %v", status(r), k.mutations)
	}
}

func TestPeerUpdateFailureNotHidden(t *testing.T) {
	a, k, _ := mullvadSetup(t)
	addRelay(a, otherHost, otherKey)
	k.keys = []string{otherKey}
	k.failSet = true
	r := a.switchTo(t, requestAt(testHost, nil))
	if status(r) != "failed" || !strings.Contains(message(r), "update failed") {
		t.Fatalf("%s %s", status(r), message(r))
	}
}

func TestRoutingLostDuringASwitchAbortsIt(t *testing.T) {
	a, k, _ := mullvadSetup(t)
	k.afterReplacePeer = func() { k.routeMissing[6] = true }
	desire(t, a, requestAt(testHost, nil))
	r := mustTick(t, a)
	if status(r) != "failed" || message(r) != "Routing changed during the switch; retrying after recovery." ||
		a.attempt.State != "failed" || a.attempt.NextAction != "reapply" {
		t.Fatalf("%s %s %s", status(r), message(r), a.attempt.State)
	}
	k.afterReplacePeer = nil
	k.routeMissing[6] = false
	k.now += 60
	// The peer it set is the requested one: once routing is back the next check
	// finds the target met, and nothing is applied again.
	r = mustTick(t, a)
	if len(k.mutations) != 1 || status(r) != "ok" || r.Get("server") != testHost || a.attempt.State != "idle" {
		t.Fatalf("%v %s %s", k.mutations, status(r), a.attempt.State)
	}
}

func TestEgressBooleanMustBeBoolean(t *testing.T) {
	for name, value := range map[string]any{"string": "true", "int": 1, "null": nil, "object": map[string]any{}} {
		a, k, _ := mullvadSetup(t)
		k.probes[4]["mullvad_exit_ip"] = value
		if r := a.inspect(t); status(r) != "failed" {
			t.Errorf("%s: %s", name, status(r))
		}
	}
}

func TestClockInFutureIsNotFreshHandshake(t *testing.T) {
	a, k, _ := mullvadSetup(t)
	k.age = -60
	if r := a.inspect(t); status(r) != "failed" {
		t.Fatalf("%s", status(r))
	}
}

func TestContainerHealthWaitsForACompletedCheck(t *testing.T) {
	for st, want := range map[string]bool{"unknown": false, "applying": false, "ok": true, "failed": true} {
		a, _, dir := mullvadSetup(t)
		withPublished(a, dir)
		if _, err := a.publishRecord(st, "Example status.", "", nil, nil); err != nil {
			t.Fatal(err)
		}
		if got := a.Healthy(context.Background()); got != want {
			t.Errorf("%s: healthy %v", st, got)
		}
	}
}

func TestContainerHealthRejectsAnOrphanedNamespace(t *testing.T) {
	for _, broken := range []string{"missing-tunnel", "not-wireguard", "missing-overlay"} {
		a, k, dir := mullvadSetup(t)
		withPublished(a, dir)
		if _, err := a.publishRecord("failed", "Tunnel inspection failed.", "", nil, nil); err != nil {
			t.Fatal(err)
		}
		switch broken {
		case "missing-tunnel":
			k.tunnelPresent = false
		case "not-wireguard":
			k.peersErr = errors.New("not a WireGuard interface")
		default:
			k.overlayPresent = false
		}
		if a.Healthy(context.Background()) {
			t.Errorf("%s: healthy", broken)
		}
	}
}

func TestContainerHealthWithoutAResultOrWithAStaleOne(t *testing.T) {
	a, _, dir := mullvadSetup(t)
	if a.Healthy(context.Background()) {
		t.Error("healthy without a result")
	}
	withPublished(a, dir)
	if _, err := a.publishRecord("ok", "Example status.", "", nil, nil); err != nil {
		t.Fatal(err)
	}
	if !a.Healthy(context.Background()) {
		t.Fatal("not healthy")
	}
	a.wallNow = func() time.Time { return time.Now().Add(151 * time.Second) }
	if a.Healthy(context.Background()) {
		t.Error("healthy with a result older than 150 s")
	}
}

func TestCatalogueFetchIsBoundedAndDoesNotFollowRedirect(t *testing.T) {
	a, k, _ := mullvadSetup(t)
	var seen netx.Request
	k.handler = func(r netx.Request) (netx.Response, error) {
		seen = r
		return netx.Response{Status: 200, Body: mullvadPayload(nil)}, nil
	}
	raw, err := a.hooks.FetchCatalog(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := providers.ParseMullvadCatalog(raw, false)
	relay, _ := entries.Get(testHost)
	if err != nil || relay == nil || relay.PublicKey != testKey {
		t.Fatalf("catalogue %v %v", entries, err)
	}
	if seen.URL != providers.MullvadRelaysURL || seen.Timeout != 20*time.Second || seen.MaxBytes != 10*1024*1024 ||
		seen.AllowHTTP || seen.AnyStatus || seen.ConnectTimeout != 10*time.Second || seen.UserAgent != "molebridge-applier/0.2" {
		t.Errorf("request %+v", seen)
	}
	k.handler = func(netx.Request) (netx.Response, error) { return netx.Response{Status: 302, Body: []byte("{}")}, nil }
	if _, err := a.hooks.FetchCatalog(context.Background(), a); err == nil || !strings.Contains(err.Error(), "redirects refused") {
		t.Fatalf("redirect: %v", err)
	}
}

func TestTruncatedOrMalformedDesiredJSONIsReportedWithoutMutation(t *testing.T) {
	a, k, _ := mullvadSetup(t)
	writeFile(t, a.desiredPath, `{"server":`, 0o644)
	r := mustTick(t, a)
	if status(r) != "failed" || !strings.Contains(message(r), "Invalid desired-state") || len(k.mutations) != 0 {
		t.Fatalf("%s %s %v", status(r), message(r), k.mutations)
	}
}

func TestFailureRemovingOldPeerAbortsBeforeAddition(t *testing.T) {
	a, k, _ := mullvadSetup(t)
	k.keys = []string{otherKey}
	k.failSet = true
	r := a.switchTo(t, requestAt(testHost, nil))
	if status(r) != "failed" || len(k.mutations) != 1 || !strings.HasPrefix(k.mutations[0], "remove ") {
		t.Fatalf("%s %v", status(r), k.mutations)
	}
}
