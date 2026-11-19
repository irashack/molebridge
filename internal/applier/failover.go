package applier

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/irashack/molebridge/internal/failover"
	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/validate"
)

// Automatic failover (docs/design/failover.md): when the selected server
// (the primary) keeps failing for reasons that belong to the server, the exit
// moves to a backup in the same city or country, or from FAILOVER_SERVERS,
// and tries the primary again on a schedule. The rules are internal/failover;
// this file feeds them the pipeline's outcomes, persists their state in
// failover.json and turns their decisions into targets. A backup is a target
// like any other: the same gates, the same mutation owner, the same
// verification. The operator's choice is never rewritten: desired.json,
// requested_server and configured_server keep naming the primary, and a new
// request ends any failover at once.

// failoverMaxBytes bounds failover.json: a handful of names and numbers.
const failoverMaxBytes = 4096

// UplinkTimeout is the uplink probe's limit.
const UplinkTimeout = 5 * time.Second

// FailoverOf is what a failover target stands in for: the primary and its
// own source.
type FailoverOf struct {
	Primary, Source string
}

func (a *Applier) failoverPath() string { return filepath.Join(a.privateDir, "failover.json") }

// failoverSignature is the configuration failover.json was written under:
// a file from another mode or list is no episode.
func failoverSignature(cfg failover.Config) string {
	return string(cfg.Mode) + "|" + strings.Join(cfg.Servers, ",")
}

// loadFailover reads failover.json; anything missing, malformed or written
// under another configuration is no episode.
func (a *Applier) loadFailover() {
	a.fo, a.foKey = failover.State{}, ""
	raw, _ := a.readJSON(a.failoverPath(), failoverMaxBytes).(map[string]any)
	if raw == nil || raw["signature"] != failoverSignature(a.failover) {
		return
	}
	key, _ := raw["key"].(string)
	object, _ := raw["state"].(map[string]any)
	s, ok := a.parseFailoverState(object)
	if !ok || key == "" || validate.RuneCount(key) > 1024 {
		return
	}
	a.fo, a.foKey = s, key
	a.foSaved = a.fo
}

// parseFailoverState is the strict reading of failover.json's state.
func (a *Applier) parseFailoverState(o map[string]any) (failover.State, bool) {
	var s failover.State
	if o == nil {
		return s, false
	}
	name := func(key string, optional bool) (string, bool) {
		value, present := o[key]
		if value == nil && optional {
			return "", true
		}
		text, isString := value.(string)
		return text, present && isString && a.spec.ValidServerName(text)
	}
	number := func(key string) (float64, bool) {
		f, ok := validate.IsNumber(o[key])
		return f, ok && f >= 0 && !math.IsNaN(f) && !math.IsInf(f, 0)
	}
	var ok [12]bool
	s.Primary, ok[0] = name("primary", false)
	s.Backup, ok[1] = name("backup", true)
	s.LastVerified, ok[2] = name("last_verified", true)
	s.FailingSince, ok[3] = number("failing_since")
	s.NextReturn, ok[4] = number("next_return")
	s.HoldUntil, ok[5] = number("hold_until")
	failures, isInt := validate.IsInt(o["failures"])
	ok[6] = isInt && failures >= 0 && failures < 1<<20
	s.Failures = int(failures)
	step, isInt := validate.IsInt(o["return_step"])
	ok[7] = isInt && step >= 0 && step < 1<<20
	s.ReturnStep = int(step)
	s.Reason, _ = o["reason"].(string)
	ok[8] = s.Reason == "" || failover.ValidReason(s.Reason)
	s.Phase, _ = o["phase"].(string)
	ok[9] = failover.ValidPhase(s.Phase)
	s.Since, _ = o["since"].(string)
	_, timeOK := validate.ParseTime(s.Since)
	ok[10] = s.Since == "" || timeOK
	s.BootID, _ = o["boot_id"].(string)
	tried, isList := o["tried"].([]any)
	ok[11] = isList && len(tried) <= failover.MaxTries && validate.RuneCount(s.BootID) <= 64
	for _, value := range tried {
		text, isString := value.(string)
		if !isString || !a.spec.ValidServerName(text) {
			return failover.State{}, false
		}
		s.Tried = append(s.Tried, text)
	}
	for _, good := range ok {
		if !good {
			return failover.State{}, false
		}
	}
	if (s.Phase == failover.PhaseTrying || s.Phase == failover.PhaseOnBackup || s.Phase == failover.PhaseReturning) && s.Backup == "" {
		return failover.State{}, false
	}
	return s, true
}

func (a *Applier) failoverObject() validate.Obj {
	s := a.fo
	tried := make([]any, len(s.Tried))
	for i, name := range s.Tried {
		tried[i] = name
	}
	state := validate.Members("primary", s.Primary, "failing_since", s.FailingSince, "failures", s.Failures,
		"reason", s.Reason, "backup", orNull(s.Backup), "last_verified", orNull(s.LastVerified), "since", s.Since,
		"tried", tried, "phase", s.Phase, "next_return", s.NextReturn, "return_step", s.ReturnStep,
		"hold_until", s.HoldUntil, "boot_id", s.BootID)
	return validate.Members("signature", failoverSignature(a.failover), "key", a.foKey, "state", state)
}

// keepFailover saves the state when it changed. A failed write is logged and
// the decision still used, as keepLocation does: the next pass decides the
// same from the same evidence.
func (a *Applier) keepFailover() {
	if a.foKey == a.foSavedKey && reflect.DeepEqual(a.fo, a.foSaved) {
		return
	}
	if a.fo.Primary == "" {
		// No primary yet: nothing worth keeping.
		a.foSaved, a.foSavedKey = a.fo, a.foKey
		return
	}
	err := jsonfile.Write(a.failoverPath(), a.failoverObject(), jsonfile.Options{MaxBytes: failoverMaxBytes})
	if err != nil {
		a.log("applier: the failover state could not be saved: " + truncateChars(err.Error(), IOFailureReportChars))
		return
	}
	a.foSaved, a.foSavedKey = a.fo, a.foKey
	a.foSaved.Tried = append([]string(nil), a.fo.Tried...)
}

// dropFailover removes a failover.json left by an earlier configuration
// with failover on.
func (a *Applier) dropFailover() {
	if err := os.Remove(a.failoverPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		a.log("applier: the failover state could not be removed: " + truncateChars(err.Error(), IOFailureReportChars))
	}
}

// withFailover is the target for a resolved primary: the backup standing in
// while the policy has one in place for that primary, the primary with
// source failover while returning to it, else the primary itself.
func (a *Applier) withFailover(primary *Selection) *Selection {
	if !a.failover.On() || primary == nil || a.fo.Primary != primary.Server || a.foKey != primary.Key() {
		return primary
	}
	server, standingIn := a.fo.Target()
	if !standingIn {
		return primary
	}
	return &Selection{Server: server, Source: "failover", Request: primary.Request, Replaces: primary.Replaces,
		Failover: &FailoverOf{Primary: primary.Server, Source: primary.Source}}
}

// notePrimary records the primary this pass resolved: a new one (a new panel
// request, Retry, a changed SERVER, the retired server's move) ends any
// episode.
func (a *Applier) notePrimary(primary *Selection) {
	a.primary = primary
	if !a.failover.On() || primary == nil {
		return
	}
	if key := primary.Key(); key != a.foKey {
		if a.fo.Phase != "" {
			a.log("applier: a new selection ends the failover")
		}
		a.fo.Reset()
		a.foKey = key
		a.keepFailover()
	}
}

// failoverWaits holds a failover switch until the reapply guard has passed
// since the last change, as for drift: moving to a backup, between backups,
// returning, and back to the primary after an exhausted episode. The one
// exception is the immediate return to a verified backup after a failed
// return.
func (a *Applier) failoverWaits(target *Selection) bool {
	if target == nil || a.foRestore {
		return false
	}
	at := a.attempt
	switching := target.Failover != nil ||
		(strings.HasPrefix(at.TargetKey, target.Key()+"|failover:") && at.Target != target.Server)
	return switching && !at.GuardPassed(a.clock())
}

// classify is a pass's outcome for the policy (docs/design/failover.md, "When
// it keeps failing"), from the attempt's state and target and the inspection
// the pass ended on. mutated is whether the pass changed the tunnel, repaired whether that
// change was a lapse repair.
func classify(state, target string, f *Finding, mutated, repaired bool) (failover.Outcome, string) {
	switch {
	case state == "pending" || state == "rejected":
		return failover.Ineligible, ""
	case f == nil:
		return failover.None, ""
	case !f.Safe:
		// A protective guard was lost: the host's, not the server's.
		return failover.Ineligible, ""
	case f.Status == "ok" && f.Server != "" && f.Server == target:
		return failover.Verified, ""
	case repaired:
		return failover.Eligible, failover.ReasonRepairFailed
	case mutated && state == "failed":
		return failover.Eligible, failover.ReasonSwitchFailed
	case f.Server == "" || f.Server != target:
		// Not an inspection of the target: drift and an unidentified peer
		// are the pipeline's to repair, and its change is what counts.
		return failover.None, ""
	}
	if checkStateOf(f.Checks, "handshake") == "fail" {
		return failover.Eligible, failover.ReasonHandshakeFailed
	}
	if checkStateOf(f.Checks, "egress") == "fail" {
		switch reason := checkMember(f.Checks, "egress", "reason"); {
		case reason == "tunnel-silent" || f.Silent:
			return failover.Eligible, failover.ReasonTunnelSilent
		case reason == "unanswered" && f.Quiet:
			return failover.Eligible, failover.ReasonTunnelSilent
		}
		// An answer that doesn't confirm the egress, or no answer while
		// the tunnel received: never the server's to blame.
		return failover.Ineligible, ""
	}
	if f.Status == "" {
		// The inspection itself failed (the interface couldn't be read).
		return failover.None, ""
	}
	return failover.Ineligible, ""
}

func checkStateOf(checks validate.Obj, name string) string {
	text, _ := checkMember(checks, name, "state").(string)
	return text
}

func checkMember(checks validate.Obj, name, member string) any {
	for _, pair := range checks {
		if pair.Key != name {
			continue
		}
		if check, ok := pair.Value.(validate.Obj); ok {
			for _, field := range check {
				if field.Key == member {
					return field.Value
				}
			}
		}
	}
	return nil
}

// primaryLocation is the primary's location for choosing backups: the one
// location.json remembers, for the server itself or the replacement standing
// in for it; with FAILOVER=servers, the catalogue's entry is enough.
func (a *Applier) primaryLocation(primary string) failover.Location {
	l := a.location
	switch {
	case l.Server == primary:
		return failover.Location{Server: primary, City: l.City, Country: l.Country, PortForward: l.PortForward}
	case l.Replacement == primary:
		return failover.Location{Server: primary, City: l.City, Country: l.Country, PortForward: l.PortForward}
	}
	location := failover.Location{Server: primary}
	if a.failover.Mode == failover.ModeServers {
		if relay, ok := a.catalog.Relays().Get(primary); ok {
			location.PortForward = relay.PortForward
		}
	}
	return location
}

// failoverCandidates are the backups from a fresh catalogue, none without
// one.
func (a *Applier) failoverCandidates(primary string) []failover.Candidate {
	if !a.catalog.Usable() {
		return nil
	}
	relays := a.catalog.Relays()
	entries := make([]failover.Entry, 0, relays.Len())
	for _, name := range relays.Names() {
		relay, _ := relays.Get(name)
		entries = append(entries, failover.Entry{Server: name, City: relay.City, Country: relay.Country, PortForward: relay.PortForward})
	}
	return failover.Candidates(a.failover, a.primaryLocation(primary), entries, a.fo.Tried)
}

// observeFailover feeds this pass's outcome to the policy and acts on its
// decision; the next pass resolves the new target.
func (a *Applier) observeFailover(ctx context.Context, published bool) {
	if !a.failover.On() || a.primary == nil {
		return
	}
	primary := a.primary.Server
	outcome, reason := failover.None, ""
	if published {
		at := a.attempt
		outcome, reason = classify(at.State, at.Target, a.measurement, a.passMutated, a.passRepaired)
	}
	live := ""
	if a.measurement != nil {
		live = a.measurement.Server
	}
	before := a.fo
	before.Tried = append([]string(nil), a.fo.Tried...)
	o := failover.Observation{Now: a.clock(), BootID: a.bootID, Wall: a.wall(), Primary: primary, Live: live,
		Outcome: outcome, Reason: reason, Fresh: a.askedNow(a.primary),
		Uplink: func() bool { return a.hooks.UplinkAnswers(ctx, a) },
		ReturnReady: func() bool {
			return a.catalog.Usable() && a.catalog.Relays().Has(primary) && a.hooks.ServerAnswers(ctx, a, primary)
		}}
	if a.foTrace != nil {
		a.foTrace(a.attempt.State, o)
	}
	d := a.fo.Observe(a.failover, o, func() []failover.Candidate { return a.failoverCandidates(primary) })
	a.foRestore = d.Action == failover.Restore
	switch d.Action {
	case failover.FailOver:
		if before.Phase == "" || before.Phase == failover.PhaseExhausted {
			a.log(fmt.Sprintf("applier: the selected server has kept failing for %d s (%s); moving to backup %s",
				int(o.Now-before.FailingSince), d.Reason, d.Server))
		} else {
			a.log("applier: backup " + before.Backup + " did not verify; trying the next")
		}
	case failover.Exhausted:
		a.log("applier: no backup verified; staying on the selected server")
	case failover.Return:
		a.log("applier: trying the selected server again")
	case failover.Restore:
		a.log("applier: the selected server still fails; back to backup " + d.Server)
	}
	if before.Phase == failover.PhaseReturning && a.fo.Phase == "" {
		a.log("applier: the selected server verified again; failover ended")
	}
	uplinkDown := d.Reason == failover.ReasonUplink
	if uplinkDown && !a.foUplinkDown {
		a.log("applier: the host's network does not answer; not failing over")
	}
	if uplinkDown || d.Action != failover.Stay {
		a.foUplinkDown = uplinkDown
	}
	a.keepFailover()
}

// settleEpisode publishes the pass's record again when this pass verified
// the backup being tried: the record was built before the policy saw the
// pass, so it says "trying", with no return time, and readers would see
// that until the next check.
func (a *Applier) settleEpisode(record *Record) (*Record, error) {
	was, _ := record.Get("failover").(validate.Obj)
	if a.fo.Phase != failover.PhaseOnBackup || len(was) == 0 {
		return record, nil
	}
	if phase, _ := memberOf(was, "phase").(string); phase != failover.PhaseTrying {
		return record, nil
	}
	episode := a.failoverRecord()
	if episode == nil {
		return record, nil
	}
	settled := &Record{members: append(validate.Obj(nil), record.members...).Set("failover", episode)}
	if a.publish != nil {
		if err := a.publish(settled); err != nil {
			return settled, wrapIO(err)
		}
	}
	a.hooks.Published(a.judged(settled))
	return settled, nil
}

func memberOf(o validate.Obj, key string) any {
	for _, pair := range o {
		if pair.Key == key {
			return pair.Value
		}
	}
	return nil
}

// failoverRecord is the record's "failover" member, nil without an episode
// for the current primary.
func (a *Applier) failoverRecord() any {
	s := a.fo
	if !a.failover.On() || s.Phase == "" || a.primary == nil || s.Primary != a.primary.Server || a.foKey != a.primary.Key() {
		return nil
	}
	tried := make([]any, len(s.Tried))
	for i, name := range s.Tried {
		tried[i] = name
	}
	var nextReturn any
	if s.Phase == failover.PhaseOnBackup && s.NextReturn > 0 {
		at := s.NextReturn
		nextReturn = a.wallOf(&at)
	}
	return validate.Members("from", s.Primary, "to", orNull(s.Backup), "phase", s.Phase, "reason", orNull(s.Reason),
		"since", orNull(s.Since), "next_return_at", nextReturn, "tried", tried)
}

// UplinkAnswers implements Provider: an HTTPS request over the host's own
// route to the provider's catalogue host, with a 5-second limit. Any HTTP
// answer counts; redirects are not followed and no more than 1 KiB of the
// body is read.
func (BaseProvider) UplinkAnswers(ctx context.Context, a *Applier) bool {
	return catalogHostAnswers(ctx, a)
}

func catalogHostAnswers(ctx context.Context, a *Applier) bool {
	if a.spec.CatalogURL == "" {
		return false
	}
	_, err := a.sys.Fetch(ctx, netx.Request{URL: a.spec.CatalogURL, Method: "HEAD", Timeout: UplinkTimeout,
		MaxBytes: 1024, AnyStatus: true})
	return err == nil || errors.Is(err, netx.ErrTooLarge)
}

// ServerAnswers implements Provider: Mullvad and NordVPN have no way to test
// a WireGuard server without switching to it.
func (BaseProvider) ServerAnswers(context.Context, *Applier, string) bool { return true }
