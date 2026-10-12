// Package attempt is the per-exit attempt record (state/applier/attempt.json),
// ported from applier/attempt.py.
//
// Every change to the live selection goes through one admission pipeline. Its
// state lives here, so a restart resumes it: written atomically before every
// mutation's I/O, because a lost response can hide success, and after every
// outcome.
//
// Deadlines and the time of the last mutation are kept on the boot clock
// (CLOCK_MONOTONIC on Linux, passed in as seconds) together with the boot's id:
// a value from another boot means nothing on this one (Load).
//
// It offers Attempt (New, Load, Save, GuardPassed, Schedule, Settle), Backoff,
// ReadBootID and the pipeline's constants.
package attempt

import (
	"crypto/rand"
	"encoding/hex"
	"math"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/validate"
)

// States an attempt can be in.
var States = []string{"idle", "pending", "rejected", "attempting", "unverified", "failed"}

// BackoffSec: automatic retries wait 1, 2, 4 and 8 minutes, then every 15.
var BackoffSec = [5]int{60, 120, 240, 480, 900}

const (
	// ReapplyGuardSec: no automatic re-apply within this long of the last mutation.
	ReapplyGuardSec = 90
	// UnidentifiedSec: a live peer the catalogue can't name is waited out this
	// long before it counts as drift.
	UnidentifiedSec = 90
	// BootIDFile is where the kernel keeps the boot's id.
	BootIDFile = "/proc/sys/kernel/random/boot_id"
	// MaxBytes bounds the file when read back.
	MaxBytes = 16384
)

// Backoff is the wait, in seconds, of a retry step.
func Backoff(step int) int {
	if step < 0 {
		step = 0
	}
	if step >= len(BackoffSec) {
		step = len(BackoffSec) - 1
	}
	return BackoffSec[step]
}

// ReadBootID reads the boot id from path (BootIDFile in production; tests pass
// their own). A missing or odd file is "unknown": the id must be at most 64
// ASCII letters, digits and dashes.
func ReadBootID(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "unknown"
	}
	defer f.Close()
	buf := make([]byte, 1025)
	n, _ := f.Read(buf)
	if n > 1024 {
		return "unknown"
	}
	value := strings.TrimFunc(string(buf[:n]), validate.IsSpace)
	for _, r := range value {
		if r >= unicode.MaxASCII {
			return "unknown"
		}
	}
	if value == "" || len(value) > 64 {
		return "unknown"
	}
	alnum := strings.ReplaceAll(value, "-", "")
	if alnum == "" {
		return "unknown"
	}
	for _, r := range alnum {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return "unknown"
		}
	}
	return value
}

// Rejected is the last rejected panel request, kept apart from the target so
// its acknowledgement survives a restart without blocking restore. Release is
// what lifts it (the catalogue's or the credentials' signature at the time).
type Rejected struct {
	Key     string
	Reason  string
	Why     string
	Release string
}

// JSONObject implements validate.ObjectMarshaler.
func (r Rejected) JSONObject() validate.Obj {
	o := validate.Members("key", r.Key, "reason", r.Reason)
	if r.Why != "" {
		o = append(o, validate.Pair{Key: "why", Value: r.Why})
	}
	if r.Release != "" {
		o = append(o, validate.Pair{Key: "release", Value: r.Release})
	}
	return o
}

// Extra holds why a rejection or failure stands and what lifts it; empty
// outside those states.
type Extra struct {
	Why     string
	Release string
}

// JSONObject implements validate.ObjectMarshaler.
func (e Extra) JSONObject() validate.Obj {
	o := validate.Obj{}
	if e.Why != "" {
		o = append(o, validate.Pair{Key: "why", Value: e.Why})
	}
	if e.Release != "" {
		o = append(o, validate.Pair{Key: "release", Value: e.Release})
	}
	return o
}

// Attempt is one exit's admission state for its current effective target.
// Optional strings are empty for None, and optional times are nil.
type Attempt struct {
	AttemptID string
	// Source says why the target is what it is (verdict.Sources), Target is
	// its server and TargetKey its identity: a panel request's token,
	// "configured:<server>" or "restore:<server>". A new identity is a new
	// target.
	Source    string
	Target    string
	TargetKey string
	State     string
	// Outcome is the last outcome published for this target (verdict.Outcomes).
	Outcome   string
	Message   string
	BootID    string
	StartedAt string
	// Attempts counts the mutations made for this target, and BackoffStep is the
	// step the next retry uses.
	Attempts    int
	BackoffStep int
	NextAction  string
	// NextActionAt and LastMutationAt are on the boot clock, in seconds.
	NextActionAt   *float64
	LastMutationAt *float64
	// MutationCertainty is "definite" when the change was refused before
	// taking effect, "uncertain" when its outcome is unknown.
	MutationCertainty string
	// Generation is the native exit's owner generation already given its one
	// re-apply.
	Generation string
	Rejected   *Rejected
	Extra      Extra
}

func orNull(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func orNullTime(t *float64) any {
	if t == nil {
		return nil
	}
	return *t
}

// JSONObject implements validate.ObjectMarshaler: the members in the order of
// Python's dataclass, which asdict() wrote.
func (a *Attempt) JSONObject() validate.Obj {
	var rejected any
	if a.Rejected != nil {
		rejected = *a.Rejected
	}
	return validate.Members("attempt_id", a.AttemptID, "source", orNull(a.Source), "target", orNull(a.Target),
		"target_key", orNull(a.TargetKey), "state", a.State, "outcome", orNull(a.Outcome), "message", orNull(a.Message),
		"boot_id", a.BootID, "started_at", orNull(a.StartedAt), "attempts", a.Attempts, "backoff_step", a.BackoffStep,
		"next_action", orNull(a.NextAction), "next_action_at", orNullTime(a.NextActionAt),
		"last_mutation_at", orNullTime(a.LastMutationAt), "mutation_certainty", orNull(a.MutationCertainty),
		"generation", orNull(a.Generation), "rejected", rejected, "extra", a.Extra)
}

// NewParams are the arguments of New.
type NewParams struct {
	Source, Target, TargetKey, BootID string
	Rejected                          *Rejected
	Generation                        string
}

// New starts an attempt for a new target at now (the wall clock, for the
// started_at member), with a random id.
func New(now time.Time, p NewParams) *Attempt {
	id := make([]byte, 8)
	rand.Read(id)
	return &Attempt{AttemptID: hex.EncodeToString(id), Source: p.Source, Target: p.Target, TargetKey: p.TargetKey,
		State: "idle", BootID: p.BootID, StartedAt: validate.FormatTime(now), Rejected: p.Rejected, Generation: p.Generation}
}

func idle(bootID string) *Attempt { return &Attempt{State: "idle", BootID: bootID} }

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// text reads an optional string member: absent or null is empty, anything but
// a string is not ok.
func text(m map[string]any, key string) (string, bool) {
	v, present := m[key]
	if !present || v == nil {
		return "", true
	}
	s, ok := v.(string)
	return s, ok
}

func clockValue(m map[string]any, key string) *float64 {
	f, ok := validate.IsNumber(m[key])
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
		return nil
	}
	return &f
}

func stringMember(object map[string]any, key string) string {
	s, _ := object[key].(string)
	return s
}

// Load is the persisted attempt, adjusted for this boot (now is the boot
// clock, in seconds). Anything unreadable starts idle: a missing, unsafe or
// oversized file, one that is not a JSON object, an unknown state, a negative
// or mistyped backoff step or attempt count, or a member of the wrong type.
func Load(path, bootID string, now float64) *Attempt {
	raw, ok := jsonfile.ReadObject(path, MaxBytes)
	if !ok {
		return idle(bootID)
	}
	a := &Attempt{State: "idle"}
	for _, field := range []struct {
		key  string
		into *string
	}{{"attempt_id", &a.AttemptID}, {"source", &a.Source}, {"target", &a.Target}, {"target_key", &a.TargetKey},
		{"outcome", &a.Outcome}, {"message", &a.Message}, {"boot_id", &a.BootID}, {"started_at", &a.StartedAt},
		{"next_action", &a.NextAction}, {"mutation_certainty", &a.MutationCertainty}, {"generation", &a.Generation}} {
		value, ok := text(raw, field.key)
		if !ok {
			return idle(bootID)
		}
		*field.into = value
	}
	if value, present := raw["state"]; present {
		state, ok := value.(string)
		if !ok {
			return idle(bootID)
		}
		a.State = state
	}
	if !contains(States, a.State) {
		return idle(bootID)
	}
	for _, field := range []struct {
		key  string
		into *int
	}{{"attempts", &a.Attempts}, {"backoff_step", &a.BackoffStep}} {
		if value, present := raw[field.key]; present {
			n, ok := validate.IsInt(value)
			if !ok || n < 0 || n > math.MaxInt32 {
				return idle(bootID)
			}
			*field.into = int(n)
		}
	}
	a.NextActionAt, a.LastMutationAt = clockValue(raw, "next_action_at"), clockValue(raw, "last_mutation_at")
	if a.NextAction != "" && a.NextAction != "recheck" && a.NextAction != "reapply" {
		a.NextAction = ""
	}
	if rejected, ok := raw["rejected"].(map[string]any); ok {
		a.Rejected = &Rejected{Key: stringMember(rejected, "key"), Reason: stringMember(rejected, "reason"),
			Why: stringMember(rejected, "why"), Release: stringMember(rejected, "release")}
	}
	if extra, ok := raw["extra"].(map[string]any); ok {
		a.Extra = Extra{Why: stringMember(extra, "why"), Release: stringMember(extra, "release")}
	}
	if a.BootID != bootID {
		// Clock values from another boot: a recheck is due now, a reapply
		// waits the current step, and the last mutation is long past.
		a.LastMutationAt = nil
		switch a.NextAction {
		case "recheck":
			due := now
			a.NextActionAt = &due
		case "reapply":
			due := now + float64(Backoff(a.BackoffStep))
			a.NextActionAt = &due
		}
		a.BootID = bootID
	}
	return a
}

// Save writes the attempt atomically, private (0600).
func (a *Attempt) Save(path string) error {
	return jsonfile.Write(path, a, jsonfile.Options{})
}

// GuardPassed is true when no mutation happened within ReapplyGuardSec.
func (a *Attempt) GuardPassed(now float64) bool {
	return a.LastMutationAt == nil || now-*a.LastMutationAt >= ReapplyGuardSec
}

// Schedule sets the next automatic action on the backoff, and advances it.
func (a *Attempt) Schedule(action string, now float64) {
	a.NextAction = action
	due := now + float64(Backoff(a.BackoffStep))
	a.NextActionAt = &due
	a.BackoffStep++
}

// Settle records a verified selection: no further action, the backoff starts
// over.
func (a *Attempt) Settle() {
	a.State, a.Outcome = "idle", "verified"
	a.Message = ""
	a.NextAction, a.NextActionAt = "", nil
	a.BackoffStep = 0
	a.MutationCertainty = ""
}
