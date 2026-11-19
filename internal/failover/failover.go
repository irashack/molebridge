// Package failover is the automatic failover policy: when the operator's
// server (the primary) keeps failing, which backup to move to, when to give
// up, and when to try the primary again (docs/design/failover.md).
//
// It is pure: no I/O and no clock of its own. The applier classifies each
// pass of its pipeline into an Observation, feeds it to State.Observe and
// acts on the Decision; it persists the State in failover.json. Everything
// about counts, windows, candidates, limits and the return schedule lives
// here, so it is tested without an applier.
package failover

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// Mode is the FAILOVER setting.
type Mode string

const (
	ModeOff         Mode = "off"
	ModeSameCity    Mode = "same-city"
	ModeSameCountry Mode = "same-country"
	ModeServers     Mode = "servers"
	// ModeOn is FAILOVER=on: failover with the default backups,
	// DefaultOnMode.
	ModeOn Mode = "on"
)

const (
	ReturnAuto   = "auto"
	ReturnManual = "manual"
)

// The owner's decisions (docs/design/failover.md, "Decisions for the
// owner"), each in one place so that an answer is a one-line change.
const (
	// DefaultMode is FAILOVER's default: failover is opt-in.
	DefaultMode = ModeOff
	// DefaultOnMode is the backups FAILOVER=on means.
	DefaultOnMode = ModeSameCity
	// DefaultReturn is FAILOVER_RETURN's default.
	DefaultReturn = ReturnAuto
	// DefaultAfter is FAILOVER_AFTER's default: how long the primary must
	// keep failing.
	DefaultAfter = 300 * time.Second
	// MinFailures is how many eligible failures that window must hold.
	MinFailures = 3
)

// ReturnSchedule is when the primary is tried again with ReturnAuto: the
// first entry after a backup verified, each next one after a return that
// failed or couldn't start, and the last one from then on (owner).
var ReturnSchedule = []time.Duration{15 * time.Minute, 30 * time.Minute, 60 * time.Minute, 120 * time.Minute}

const (
	// MinAfter and MaxAfter bound FAILOVER_AFTER.
	MinAfter = 120 * time.Second
	MaxAfter = 3600 * time.Second
	// MaxServers bounds FAILOVER_SERVERS.
	MaxServers = 8
	// MaxTries is how many backups one episode tries.
	MaxTries = 3
	// HoldDown is how long no new episode starts after one is exhausted.
	HoldDown = 30 * time.Minute
)

// Eligible reasons: the failures that belong to the server.
const (
	ReasonSwitchFailed    = "switch-failed"
	ReasonHandshakeFailed = "handshake-failed"
	ReasonTunnelSilent    = "tunnel-silent"
	ReasonRepairFailed    = "repair-failed"
)

// ValidReason is whether reason is one of the eligible reasons.
func ValidReason(reason string) bool {
	switch reason {
	case ReasonSwitchFailed, ReasonHandshakeFailed, ReasonTunnelSilent, ReasonRepairFailed:
		return true
	}
	return false
}

// Phases of an episode; "" is no episode.
const (
	PhaseTrying    = "trying"
	PhaseOnBackup  = "on-backup"
	PhaseReturning = "returning"
	PhaseExhausted = "exhausted"
)

// ValidPhase is whether phase is a phase State can hold.
func ValidPhase(phase string) bool {
	switch phase {
	case "", PhaseTrying, PhaseOnBackup, PhaseReturning, PhaseExhausted:
		return true
	}
	return false
}

// Config is the exit's failover settings.
type Config struct {
	Mode    Mode
	Servers []string      // with ModeServers, in order of preference
	After   time.Duration // FAILOVER_AFTER
	Return  string        // ReturnAuto or ReturnManual
}

// On is whether failover is on at all.
func (c Config) On() bool { return c.Mode != "" && c.Mode != ModeOff }

// ParseMode reads FAILOVER: "" is DefaultMode and "on" is DefaultOnMode.
func ParseMode(value string) (Mode, error) {
	switch Mode(value) {
	case "":
		return DefaultMode, nil
	case ModeOn:
		return DefaultOnMode, nil
	case ModeOff, ModeSameCity, ModeSameCountry, ModeServers:
		return Mode(value), nil
	}
	return "", fmt.Errorf("FAILOVER must be off, on, same-city, same-country or servers")
}

// Validate checks a parsed Config's own consistency; validName says whether
// a name is a server name for the provider, and server is SERVER ("" for
// none).
func (c Config) Validate(validName func(string) bool, server string) error {
	switch c.Mode {
	case ModeOff, ModeSameCity, ModeSameCountry, ModeServers:
	default:
		return errors.New("FAILOVER must be off, on, same-city, same-country or servers")
	}
	if c.Mode == ModeServers {
		if len(c.Servers) == 0 {
			return errors.New("FAILOVER=servers needs FAILOVER_SERVERS")
		}
		if len(c.Servers) > MaxServers {
			return fmt.Errorf("FAILOVER_SERVERS lists more than %d servers", MaxServers)
		}
		seen := map[string]bool{}
		for _, name := range c.Servers {
			if !validName(name) {
				return errors.New("FAILOVER_SERVERS has a name that isn't a server name for the provider")
			}
			if name == server {
				return errors.New("FAILOVER_SERVERS must not list SERVER")
			}
			if seen[name] {
				return errors.New("FAILOVER_SERVERS lists a server twice")
			}
			seen[name] = true
		}
	} else if len(c.Servers) > 0 {
		return errors.New("FAILOVER_SERVERS is only for FAILOVER=servers")
	}
	if c.After < MinAfter || c.After > MaxAfter {
		return fmt.Errorf("FAILOVER_AFTER must be %d to %d seconds", int(MinAfter.Seconds()), int(MaxAfter.Seconds()))
	}
	if c.Return != ReturnAuto && c.Return != ReturnManual {
		return errors.New("FAILOVER_RETURN must be auto or manual")
	}
	return nil
}

// Outcome is one inspection's or attempt's result for the current target,
// classified by the applier from the pipeline's own state.
type Outcome int

const (
	None       Outcome = iota // nothing new this pass
	Verified                  // idle and verified
	Eligible                  // an eligible failure; Observation.Reason says which
	Ineligible                // pending, rejected, a non-confirming egress, a guard failure
)

// Observation is what the applier saw on one pass.
type Observation struct {
	Now     float64   // boot clock, seconds
	BootID  string    // the boot's id: a new one is a reboot
	Wall    time.Time // the wall clock, for State.Since
	Primary string    // the effective primary: the target, or the retired server's replacement
	Live    string    // the server the inspection found live, "" for none
	Outcome Outcome
	Reason  string      // with Eligible: ReasonSwitchFailed, ...
	Fresh   bool        // the target is a panel request younger than FreshRequestSec
	Uplink  func() bool // asked only when a backup is about to be chosen; nil answers
	// ReturnReady is asked only when a return is due: the primary is in
	// a fresh catalog and the provider's cheap checks outside the tunnel
	// pass. nil answers.
	ReturnReady func() bool
}

// Candidate is a backup the applier may move to.
type Candidate struct {
	Server      string
	PortForward bool
}

// Action is what the applier should do.
type Action int

const (
	Stay      Action = iota
	FailOver         // switch to Decision.Server
	Return           // switch to the primary
	Restore          // a return failed: back to Decision.Server, the last verified backup
	Exhausted        // no backup verified: the primary is the target again
)

func (a Action) String() string {
	switch a {
	case Stay:
		return "stay"
	case FailOver:
		return "fail-over"
	case Return:
		return "return"
	case Restore:
		return "restore"
	case Exhausted:
		return "exhausted"
	}
	return fmt.Sprintf("action(%d)", int(a))
}

// Decision is Observe's answer. Reason says why: an eligible reason with
// FailOver, Exhausted and Restore; "uplink" when the host's network didn't
// answer and nothing was done.
type Decision struct {
	Action Action
	Server string
	Reason string
}

// ReasonUplink is a Stay's Reason when the uplink probe declined.
const ReasonUplink = "uplink"

// State is the episode and the count, persisted by the applier in
// failover.json. The zero State is "no episode".
type State struct {
	Primary      string
	FailingSince float64 // boot clock; 0 for none
	Failures     int
	// Reason is the latest eligible reason before an episode, and the
	// reason that started it during one.
	Reason       string
	Backup       string // the server standing in, "" for none
	LastVerified string // the backup that last verified
	Since        string // wall-clock RFC 3339 of the first failover, for the record
	Tried        []string
	Phase        string  // "", "trying", "on-backup", "returning", "exhausted"
	NextReturn   float64 // boot clock; 0 for none
	ReturnStep   int
	HoldUntil    float64 // no new episode before this (boot clock)
	BootID       string
}

// Target is the server the pipeline should apply for this State, and
// whether it is a failover target (source "failover"): the backup while
// trying one or on one, the primary with source failover while returning to
// it, and the primary itself otherwise.
func (s *State) Target() (server string, failover bool) {
	switch s.Phase {
	case PhaseTrying, PhaseOnBackup:
		if s.Backup != "" {
			return s.Backup, true
		}
	case PhaseReturning:
		return s.Primary, true
	}
	return s.Primary, false
}

// Reset ends the episode: a new target, a changed configuration. The boot's
// id is kept.
func (s *State) Reset() {
	boot := s.BootID
	*s = State{BootID: boot}
}

func (s *State) clearCount() {
	s.FailingSince, s.Failures = 0, 0
	if s.Phase == "" {
		s.Reason = ""
	}
}

// count adds an eligible failure and says whether the rule's window and
// count now hold.
func (s *State) count(cfg Config, o Observation) bool {
	if s.Failures == 0 {
		s.FailingSince = o.Now
	}
	s.Failures++
	if s.Phase == "" {
		s.Reason = o.Reason
	}
	after := cfg.After
	if after <= 0 {
		after = DefaultAfter
	}
	return !o.Fresh && s.Failures >= MinFailures && o.Now-s.FailingSince >= after.Seconds()
}

func returnAfter(step int) float64 {
	if step < 0 {
		step = 0
	}
	if step >= len(ReturnSchedule) {
		step = len(ReturnSchedule) - 1
	}
	return ReturnSchedule[step].Seconds()
}

func (s *State) tried(server string) bool {
	for _, name := range s.Tried {
		if name == server {
			return true
		}
	}
	return false
}

// next is the first candidate that is not the primary and not yet tried,
// "" for none or when the episode has tried MaxTries backups.
func (s *State) next(candidates func() []Candidate) string {
	if len(s.Tried) >= MaxTries || candidates == nil {
		return ""
	}
	for _, c := range candidates() {
		if c.Server != "" && c.Server != s.Primary && !s.tried(c.Server) {
			return c.Server
		}
	}
	return ""
}

// rebooted carries the State across a reboot: the boot clock started over,
// so a running window starts over (its evidence is from before), the
// hold-down has passed, and a due return runs at once.
func (s *State) rebooted(o Observation) {
	s.BootID = o.BootID
	s.FailingSince, s.Failures = 0, 0
	s.HoldUntil = 0
	switch s.Phase {
	case PhaseExhausted:
		s.endEpisode()
	case PhaseOnBackup:
		if s.NextReturn != 0 {
			s.NextReturn = o.Now
		}
	}
}

// endEpisode clears the episode, keeping the primary, the boot and the
// hold-down.
func (s *State) endEpisode() {
	*s = State{Primary: s.Primary, BootID: s.BootID, HoldUntil: s.HoldUntil}
}

// failOver starts trying server.
func (s *State) failOver(o Observation, server string) Decision {
	if s.Phase == "" || s.Phase == PhaseExhausted {
		reason := s.Reason
		*s = State{Primary: s.Primary, BootID: s.BootID, Reason: reason, Since: formatWall(o.Wall)}
	}
	s.Phase, s.Backup = PhaseTrying, server
	s.Tried = append(s.Tried, server)
	s.FailingSince, s.Failures, s.NextReturn = 0, 0, 0
	return Decision{Action: FailOver, Server: server, Reason: s.Reason}
}

// exhaust gives the episode up: the primary is the target again.
func (s *State) exhaust(o Observation) Decision {
	s.Phase, s.Backup = PhaseExhausted, ""
	s.FailingSince, s.Failures, s.NextReturn, s.ReturnStep = 0, 0, 0, 0
	s.HoldUntil = o.Now + HoldDown.Seconds()
	return Decision{Action: Exhausted, Reason: s.Reason}
}

func formatWall(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// Observe applies one observation and returns what to do. candidates is
// called only when a backup is to be chosen.
func (s *State) Observe(cfg Config, o Observation, candidates func() []Candidate) Decision {
	if !cfg.On() || o.Primary == "" {
		s.Reset()
		s.BootID = o.BootID
		return Decision{Action: Stay}
	}
	if s.BootID != o.BootID {
		if s.BootID != "" {
			s.rebooted(o)
		}
		s.BootID = o.BootID
	}
	if s.Primary != o.Primary {
		// A new effective primary is a new target: no episode carries over.
		s.Reset()
		s.Primary = o.Primary
	}
	if s.Phase == PhaseExhausted && o.Now >= s.HoldUntil {
		// The hold-down is over: the exhausted episode ends, and a new
		// one needs a full window of its own.
		s.endEpisode()
	}
	switch s.Phase {
	case "", PhaseExhausted:
		return s.onPrimary(cfg, o, candidates)
	case PhaseTrying:
		return s.onTrying(cfg, o, candidates)
	case PhaseOnBackup:
		return s.onBackup(cfg, o, candidates)
	case PhaseReturning:
		return s.onReturning(cfg, o)
	}
	// An unknown phase (a State not built by this package) is no episode.
	s.Reset()
	s.Primary = o.Primary
	return Decision{Action: Stay}
}

func (s *State) onPrimary(cfg Config, o Observation, candidates func() []Candidate) Decision {
	switch o.Outcome {
	case Verified:
		s.clearCount()
		if s.Phase == PhaseExhausted {
			// The primary verified: the exhausted episode is over, the
			// hold-down still stands.
			s.endEpisode()
		}
	case Ineligible:
		s.clearCount()
	case Eligible:
		if !s.count(cfg, o) || s.Phase == PhaseExhausted || o.Now < s.HoldUntil {
			return Decision{Action: Stay}
		}
		backup := s.next(candidates)
		if backup == "" {
			return Decision{Action: Stay}
		}
		if o.Uplink != nil && !o.Uplink() {
			return Decision{Action: Stay, Reason: ReasonUplink}
		}
		return s.failOver(o, backup)
	}
	return Decision{Action: Stay}
}

func (s *State) onTrying(cfg Config, o Observation, candidates func() []Candidate) Decision {
	switch o.Outcome {
	case Verified:
		if o.Live != "" && o.Live != s.Backup {
			return Decision{Action: Stay}
		}
		s.Phase, s.LastVerified = PhaseOnBackup, s.Backup
		s.FailingSince, s.Failures = 0, 0
		s.ReturnStep, s.NextReturn = 0, 0
		if cfg.Return == ReturnAuto {
			s.NextReturn = o.Now + returnAfter(0)
		}
	case Eligible:
		// A backup that doesn't verify: the next one at once, the primary
		// already being known to fail.
		if backup := s.next(candidates); backup != "" {
			return s.failOver(o, backup)
		}
		return s.exhaust(o)
	case Ineligible:
		s.FailingSince, s.Failures = 0, 0
	}
	return Decision{Action: Stay}
}

func (s *State) onBackup(cfg Config, o Observation, candidates func() []Candidate) Decision {
	switch o.Outcome {
	case Eligible:
		if !s.count(cfg, o) {
			return Decision{Action: Stay}
		}
		if o.Uplink != nil && !o.Uplink() {
			return Decision{Action: Stay, Reason: ReasonUplink}
		}
		if backup := s.next(candidates); backup != "" {
			return s.failOver(o, backup)
		}
		return s.exhaust(o)
	case Verified:
		s.FailingSince, s.Failures = 0, 0
	case Ineligible:
		s.FailingSince, s.Failures = 0, 0
	}
	if cfg.Return != ReturnAuto {
		s.NextReturn, s.ReturnStep = 0, 0
		return Decision{Action: Stay}
	}
	if s.NextReturn == 0 {
		// Return turned on since the backup verified.
		s.NextReturn = o.Now + returnAfter(s.ReturnStep)
	}
	if o.Now < s.NextReturn {
		return Decision{Action: Stay}
	}
	if o.ReturnReady != nil && !o.ReturnReady() {
		s.ReturnStep++
		s.NextReturn = o.Now + returnAfter(s.ReturnStep)
		return Decision{Action: Stay}
	}
	s.Phase = PhaseReturning
	s.FailingSince, s.Failures = 0, 0
	return Decision{Action: Return, Server: s.Primary}
}

func (s *State) onReturning(cfg Config, o Observation) Decision {
	switch o.Outcome {
	case Verified:
		if o.Live != "" && o.Live != s.Primary {
			return Decision{Action: Stay}
		}
		// Back on the primary: the episode is over.
		s.HoldUntil = 0
		s.endEpisode()
	case Eligible:
		s.Phase, s.Backup = PhaseOnBackup, s.LastVerified
		s.FailingSince, s.Failures = 0, 0
		s.ReturnStep++
		s.NextReturn = 0
		if cfg.Return == ReturnAuto {
			s.NextReturn = o.Now + returnAfter(s.ReturnStep)
		}
		return Decision{Action: Restore, Server: s.LastVerified, Reason: o.Reason}
	}
	return Decision{Action: Stay}
}

// Location is the primary's remembered location (location.json).
type Location struct {
	Server, City, Country string
	PortForward           bool
}

// Entry is one server in a fresh catalog.
type Entry struct {
	Server, City, Country string
	PortForward           bool
}

// Candidates orders the backups for cfg from a fresh catalog's entries,
// given the primary's remembered location: never the primary, never a
// server in tried, and only servers that forward ports when the primary
// does. same-city and same-country need the location; they are sorted by
// name starting after the primary's and wrapping, so the order is the same
// on every pass. servers keeps FAILOVER_SERVERS' order, skipping names the
// catalog doesn't list.
func Candidates(cfg Config, primary Location, entries []Entry, tried []string) []Candidate {
	if primary.Server == "" {
		return nil
	}
	skip := map[string]bool{primary.Server: true}
	for _, name := range tried {
		skip[name] = true
	}
	listed := map[string]Entry{}
	for _, e := range entries {
		if e.Server == "" {
			continue
		}
		if _, dup := listed[e.Server]; !dup {
			listed[e.Server] = e
		}
	}
	usable := func(e Entry) bool { return !skip[e.Server] && (e.PortForward || !primary.PortForward) }
	var out []Candidate
	switch cfg.Mode {
	case ModeServers:
		for _, name := range cfg.Servers {
			if e, ok := listed[name]; ok && usable(e) {
				out = append(out, Candidate{Server: name, PortForward: e.PortForward})
				skip[name] = true
			}
		}
		return out
	case ModeSameCity, ModeSameCountry:
		if primary.Country == "" || (cfg.Mode == ModeSameCity && primary.City == "") {
			return nil
		}
		var names []string
		for name, e := range listed {
			if e.Country == primary.Country && (cfg.Mode == ModeSameCountry || e.City == primary.City) && usable(e) {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		start := sort.SearchStrings(names, primary.Server)
		for start < len(names) && names[start] <= primary.Server {
			start++
		}
		for _, name := range append(append([]string(nil), names[start:]...), names[:start]...) {
			out = append(out, Candidate{Server: name, PortForward: listed[name].PortForward})
		}
		return out
	}
	return nil
}
