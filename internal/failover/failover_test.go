package failover

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"
)

var wall0 = time.Date(2026, 11, 19, 18, 0, 0, 0, time.UTC)

func onConfig() Config {
	return Config{Mode: ModeSameCity, After: DefaultAfter, Return: ReturnAuto}
}

// rig drives a State the way the applier does: one Observe per pass.
type rig struct {
	t       *testing.T
	cfg     Config
	s       State
	now     float64
	boot    string
	cands   []Candidate
	uplink  bool
	ready   bool
	asked   int // candidate calls
	probes  int // uplink calls
	readies int // return-ready calls
}

func newRig(t *testing.T) *rig {
	return &rig{t: t, cfg: onConfig(), now: 1000, boot: "boot-a", uplink: true, ready: true,
		cands: []Candidate{{Server: "b1"}, {Server: "b2"}, {Server: "b3"}, {Server: "b4"}}}
}

func (r *rig) observe(at float64, out Outcome, reason, live string) Decision {
	r.t.Helper()
	r.now = at
	o := Observation{Now: at, BootID: r.boot, Wall: wall0.Add(time.Duration(at) * time.Second),
		Primary: "p", Live: live, Outcome: out, Reason: reason,
		Uplink:      func() bool { r.probes++; return r.uplink },
		ReturnReady: func() bool { r.readies++; return r.ready }}
	return r.s.Observe(r.cfg, o, func() []Candidate { r.asked++; return r.cands })
}

func (r *rig) fail(at float64) Decision {
	r.t.Helper()
	return r.observe(at, Eligible, ReasonHandshakeFailed, "")
}

// failOverAt fails the primary from start every 60 s until a decision other
// than Stay, and returns it with its time.
func (r *rig) failUntil(start float64) (Decision, float64) {
	r.t.Helper()
	for at := start; at < start+3600; at += 60 {
		if d := r.fail(at); d.Action != Stay {
			return d, at
		}
	}
	r.t.Fatalf("no decision in an hour; state %+v", r.s)
	return Decision{}, 0
}

func want(t *testing.T, got Decision, action Action, server string) {
	t.Helper()
	if got.Action != action || got.Server != server {
		t.Fatalf("decision = %v %q, want %v %q", got.Action, got.Server, action, server)
	}
}

func TestThreeFailuresUnderTheWindowStay(t *testing.T) {
	r := newRig(t)
	for _, at := range []float64{1000, 1060, 1120, 1180, 1240} {
		want(t, r.fail(at), Stay, "")
	}
	if r.asked != 0 || r.probes != 0 {
		t.Fatalf("candidates or uplink asked before the window: %d %d", r.asked, r.probes)
	}
	// 300 s after the first, with six failures: fail over.
	d := r.fail(1300)
	want(t, d, FailOver, "b1")
	if d.Reason != ReasonHandshakeFailed || r.s.Phase != PhaseTrying || r.s.Since != "2026-11-19T18:21:40Z" {
		t.Fatalf("decision %+v state %+v", d, r.s)
	}
}

func TestWindowNeedsThreeFailures(t *testing.T) {
	r := newRig(t)
	want(t, r.fail(1000), Stay, "")
	want(t, r.fail(1400), Stay, "") // over the window, two failures
	want(t, r.fail(1401), FailOver, "b1")
}

func TestIneligibleOutcomesReset(t *testing.T) {
	for _, out := range []Outcome{Ineligible, Verified} {
		r := newRig(t)
		r.fail(1000)
		r.fail(1100)
		r.fail(1200)
		r.observe(1250, out, "", "p")
		if r.s.Failures != 0 || r.s.FailingSince != 0 {
			t.Fatalf("outcome %v kept the count: %+v", out, r.s)
		}
		want(t, r.fail(1300), Stay, "")
		want(t, r.fail(1400), Stay, "")
		want(t, r.fail(1500), Stay, "")
		want(t, r.fail(1600), FailOver, "b1")
	}
}

func TestNoneKeepsTheCount(t *testing.T) {
	r := newRig(t)
	r.fail(1000)
	r.observe(1100, None, "", "")
	r.fail(1200)
	r.fail(1250)
	want(t, r.fail(1300), FailOver, "b1")
}

func TestFreshRequestDefersTheDecision(t *testing.T) {
	r := newRig(t)
	for _, at := range []float64{1000, 1100, 1200, 1300, 1400} {
		r.now = at
		d := r.s.Observe(r.cfg, Observation{Now: at, BootID: "boot-a", Primary: "p", Outcome: Eligible,
			Reason: ReasonSwitchFailed, Fresh: true}, func() []Candidate { return r.cands })
		want(t, d, Stay, "")
	}
	// The window ran from the first failure; the request is no longer
	// fresh, so the next failure decides.
	want(t, r.observe(1460, Eligible, ReasonSwitchFailed, ""), FailOver, "b1")
}

func TestUplinkDeclinesAndKeepsTheCount(t *testing.T) {
	r := newRig(t)
	r.uplink = false
	r.fail(1000)
	r.fail(1100)
	r.fail(1200)
	d := r.fail(1300)
	if d.Action != Stay || d.Reason != ReasonUplink || r.probes != 1 {
		t.Fatalf("decision %+v probes %d", d, r.probes)
	}
	if r.s.Failures != 4 || r.s.Phase != "" {
		t.Fatalf("count not kept: %+v", r.s)
	}
	r.uplink = true
	want(t, r.fail(1360), FailOver, "b1")
	if r.probes != 2 {
		t.Fatalf("probes = %d", r.probes)
	}
}

func TestNoCandidatesNoProbe(t *testing.T) {
	r := newRig(t)
	r.cands = nil
	r.failUntilStay(1000, 20)
	if r.probes != 0 || r.s.Phase != "" {
		t.Fatalf("probes %d state %+v", r.probes, r.s)
	}
}

func (r *rig) failUntilStay(start float64, n int) {
	r.t.Helper()
	for i := 0; i < n; i++ {
		want(r.t, r.fail(start+float64(i)*60), Stay, "")
	}
}

func TestBackupFailingTriesTheNextAtOnce(t *testing.T) {
	r := newRig(t)
	_, at := r.failUntil(1000)
	d := r.observe(at+60, Eligible, ReasonSwitchFailed, "")
	want(t, d, FailOver, "b2")
	if !reflect.DeepEqual(r.s.Tried, []string{"b1", "b2"}) || r.s.Reason != ReasonHandshakeFailed {
		t.Fatalf("state %+v", r.s)
	}
	want(t, r.observe(at+120, Verified, "", "b2"), Stay, "")
	if r.s.Phase != PhaseOnBackup || r.s.LastVerified != "b2" || r.s.NextReturn != at+120+900 {
		t.Fatalf("state %+v", r.s)
	}
	if server, fo := r.s.Target(); server != "b2" || !fo {
		t.Fatalf("target %q %v", server, fo)
	}
}

func TestPendingBackupStaysTried(t *testing.T) {
	r := newRig(t)
	_, at := r.failUntil(1000)
	want(t, r.observe(at+10, Ineligible, "", ""), Stay, "")
	if r.s.Phase != PhaseTrying || r.s.Backup != "b1" {
		t.Fatalf("state %+v", r.s)
	}
}

func TestThreeBackupsExhaustAndHoldDown(t *testing.T) {
	r := newRig(t)
	_, at := r.failUntil(1000)
	want(t, r.observe(at+60, Eligible, ReasonSwitchFailed, ""), FailOver, "b2")
	want(t, r.observe(at+120, Eligible, ReasonSwitchFailed, ""), FailOver, "b3")
	d := r.observe(at+180, Eligible, ReasonSwitchFailed, "")
	want(t, d, Exhausted, "")
	if r.s.Phase != PhaseExhausted || r.s.Backup != "" || r.s.HoldUntil != at+180+1800 || len(r.s.Tried) != 3 {
		t.Fatalf("state %+v", r.s)
	}
	if server, fo := r.s.Target(); server != "p" || fo {
		t.Fatalf("target %q %v", server, fo)
	}
	// The primary keeps failing through the hold-down: nothing.
	end := at + 180 + 1800
	for x := at + 240; x < end; x += 60 {
		want(t, r.fail(x), Stay, "")
		if r.s.Phase != PhaseExhausted {
			t.Fatalf("exhausted episode ended early at %v: %+v", x, r.s)
		}
	}
	// After it, a new episode with a full window of its own.
	d, at2 := r.failUntil(end)
	want(t, d, FailOver, "b1")
	if at2 < end+300 || !reflect.DeepEqual(r.s.Tried, []string{"b1"}) {
		t.Fatalf("new episode at %v (hold-down ended %v): %+v", at2, end, r.s)
	}
}

func TestFewerCandidatesExhaustSooner(t *testing.T) {
	r := newRig(t)
	r.cands = []Candidate{{Server: "b1"}}
	_, at := r.failUntil(1000)
	want(t, r.observe(at+60, Eligible, ReasonSwitchFailed, ""), Exhausted, "")
}

func TestPrimaryVerifyingEndsAnExhaustedEpisode(t *testing.T) {
	r := newRig(t)
	r.cands = []Candidate{{Server: "b1"}}
	_, at := r.failUntil(1000)
	r.observe(at+60, Eligible, ReasonSwitchFailed, "")
	r.observe(at+120, Verified, "", "p")
	if r.s.Phase != "" || r.s.HoldUntil == 0 || len(r.s.Tried) != 0 {
		t.Fatalf("state %+v", r.s)
	}
}

func TestReturnSchedule(t *testing.T) {
	r := newRig(t)
	r.cands = []Candidate{{Server: "b1"}}
	_, at := r.failUntil(1000)
	r.observe(at+30, Verified, "", "b1")
	verifiedAt := at + 30
	// Each return fails; the next is due by the schedule.
	next := verifiedAt
	for i, step := range []float64{15, 30, 60, 120, 120, 120} {
		next += step * 60
		want(t, r.observe(next-1, None, "", "b1"), Stay, "")
		want(t, r.observe(next, None, "", "b1"), Return, "p")
		if r.s.Phase != PhaseReturning {
			t.Fatalf("return %d: state %+v", i, r.s)
		}
		if server, fo := r.s.Target(); server != "p" || !fo {
			t.Fatalf("return target %q %v", server, fo)
		}
		want(t, r.observe(next+60, Eligible, ReasonSwitchFailed, ""), Restore, "b1")
		if r.s.Phase != PhaseOnBackup || r.s.Backup != "b1" {
			t.Fatalf("restore %d: state %+v", i, r.s)
		}
		next += 60
	}
}

func TestReturnVerifiedEndsTheEpisode(t *testing.T) {
	r := newRig(t)
	_, at := r.failUntil(1000)
	r.observe(at+30, Verified, "", "b1")
	want(t, r.observe(at+30+900, None, "", "b1"), Return, "p")
	want(t, r.observe(at+30+960, Verified, "", "p"), Stay, "")
	if r.s.Phase != "" || r.s.Backup != "" || len(r.s.Tried) != 0 || r.s.Primary != "p" || r.s.HoldUntil != 0 {
		t.Fatalf("state %+v", r.s)
	}
	if server, fo := r.s.Target(); server != "p" || fo {
		t.Fatalf("target %q %v", server, fo)
	}
}

func TestReturnWaitsWhenNotReady(t *testing.T) {
	r := newRig(t)
	_, at := r.failUntil(1000)
	r.observe(at, Verified, "", "b1")
	r.ready = false
	want(t, r.observe(at+900, None, "", "b1"), Stay, "")
	if r.s.NextReturn != at+900+1800 || r.s.ReturnStep != 1 || r.readies != 1 {
		t.Fatalf("state %+v", r.s)
	}
	r.ready = true
	want(t, r.observe(at+2700, None, "", "b1"), Return, "p")
}

func TestManualNeverReturns(t *testing.T) {
	r := newRig(t)
	r.cfg.Return = ReturnManual
	_, at := r.failUntil(1000)
	r.observe(at, Verified, "", "b1")
	if r.s.NextReturn != 0 {
		t.Fatalf("state %+v", r.s)
	}
	for x := at; x < at+86400; x += 600 {
		want(t, r.observe(x, Verified, "", "b1"), Stay, "")
	}
	// The backup keeps failing: the next one.
	d, _ := r.failUntil(at + 86400)
	want(t, d, FailOver, "b2")
}

func TestBackupKeepsFailingByTheSameRule(t *testing.T) {
	r := newRig(t)
	_, at := r.failUntil(1000)
	r.observe(at, Verified, "", "b1")
	want(t, r.fail(at+60), Stay, "") // one failure on a verified backup isn't enough
	d, at2 := r.failUntil(at + 120)
	want(t, d, FailOver, "b2")
	if at2-(at+60) < 300 {
		t.Fatalf("moved after %v s", at2-(at+60))
	}
	if r.s.Reason != ReasonHandshakeFailed {
		t.Fatalf("episode reason changed: %+v", r.s)
	}
}

func TestBackupKeepsFailingWithNoneLeftExhausts(t *testing.T) {
	r := newRig(t)
	r.cands = []Candidate{{Server: "b1"}}
	_, at := r.failUntil(1000)
	r.observe(at, Verified, "", "b1")
	d, _ := r.failUntil(at + 60)
	want(t, d, Exhausted, "")
}

func TestResetOnANewPrimary(t *testing.T) {
	r := newRig(t)
	_, at := r.failUntil(1000)
	r.observe(at, Verified, "", "b1")
	d := r.s.Observe(r.cfg, Observation{Now: at + 60, BootID: "boot-a", Primary: "q", Outcome: None},
		func() []Candidate { return nil })
	want(t, d, Stay, "")
	if r.s.Phase != "" || r.s.Primary != "q" || r.s.Backup != "" {
		t.Fatalf("state %+v", r.s)
	}
	r.s.Reset()
	if !reflect.DeepEqual(r.s, State{BootID: "boot-a"}) {
		t.Fatalf("Reset left %+v", r.s)
	}
}

func TestOffResets(t *testing.T) {
	r := newRig(t)
	r.failUntil(1000)
	r.cfg.Mode = ModeOff
	want(t, r.fail(5000), Stay, "")
	if r.s.Phase != "" || r.s.Primary != "" {
		t.Fatalf("state %+v", r.s)
	}
}

func TestRebootRestartsTheWindow(t *testing.T) {
	r := newRig(t)
	r.fail(1000)
	r.fail(1100)
	r.fail(1200)
	r.boot = "boot-b"
	want(t, r.fail(30), Stay, "") // the boot clock started over
	if r.s.Failures != 1 || r.s.FailingSince != 30 || r.s.BootID != "boot-b" {
		t.Fatalf("state %+v", r.s)
	}
}

func TestRebootMakesADueReturnRun(t *testing.T) {
	r := newRig(t)
	_, at := r.failUntil(1000)
	r.observe(at, Verified, "", "b1")
	r.boot = "boot-b"
	want(t, r.observe(40, None, "", "b1"), Return, "p")
}

func TestRebootEndsTheHoldDown(t *testing.T) {
	r := newRig(t)
	r.cands = []Candidate{{Server: "b1"}}
	_, at := r.failUntil(1000)
	r.observe(at+60, Eligible, ReasonSwitchFailed, "")
	if r.s.Phase != PhaseExhausted {
		t.Fatalf("state %+v", r.s)
	}
	r.boot = "boot-b"
	r.fail(20)
	if r.s.Phase != "" || r.s.HoldUntil != 0 {
		t.Fatalf("state %+v", r.s)
	}
	d, _ := r.failUntil(80)
	want(t, d, FailOver, "b1")
}

func TestVerifiedOnAnotherServerIsNotTheBackup(t *testing.T) {
	r := newRig(t)
	r.failUntil(1000)
	r.observe(2000, Verified, "", "zz")
	if r.s.Phase != PhaseTrying {
		t.Fatalf("state %+v", r.s)
	}
}

func TestCandidatesSameCity(t *testing.T) {
	entries := []Entry{
		{Server: "se-got-wg-003", City: "Gothenburg", Country: "Sweden"},
		{Server: "se-got-wg-001", City: "Gothenburg", Country: "Sweden"},
		{Server: "se-sto-wg-001", City: "Stockholm", Country: "Sweden"},
		{Server: "se-got-wg-002", City: "Gothenburg", Country: "Sweden"},
		{Server: "se-got-wg-004", City: "Gothenburg", Country: "Sweden"},
		{Server: "se-got-wg-002", City: "Gothenburg", Country: "Sweden"}, // a duplicate
	}
	primary := Location{Server: "se-got-wg-003", City: "Gothenburg", Country: "Sweden"}
	got := names(Candidates(Config{Mode: ModeSameCity}, primary, entries, nil))
	if want := []string{"se-got-wg-004", "se-got-wg-001", "se-got-wg-002"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("same-city = %v, want %v", got, want)
	}
	got = names(Candidates(Config{Mode: ModeSameCity}, primary, entries, []string{"se-got-wg-004"}))
	if want := []string{"se-got-wg-001", "se-got-wg-002"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("with tried = %v, want %v", got, want)
	}
	got = names(Candidates(Config{Mode: ModeSameCountry}, primary, entries, nil))
	if want := []string{"se-got-wg-004", "se-sto-wg-001", "se-got-wg-001", "se-got-wg-002"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("same-country = %v, want %v", got, want)
	}
	// The primary no longer listed (its own name still orders the wrap).
	got = names(Candidates(Config{Mode: ModeSameCity}, Location{Server: "se-got-wg-0025", City: "Gothenburg", Country: "Sweden"}, entries, nil))
	if want := []string{"se-got-wg-003", "se-got-wg-004", "se-got-wg-001", "se-got-wg-002"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("wrap = %v, want %v", got, want)
	}
	// No location, no backups.
	if got := Candidates(Config{Mode: ModeSameCity}, Location{Server: "se-got-wg-003"}, entries, nil); got != nil {
		t.Fatalf("without a location = %v", got)
	}
	if got := Candidates(Config{Mode: ModeOff}, primary, entries, nil); got != nil {
		t.Fatalf("off = %v", got)
	}
}

func TestCandidatesPortForwardFilter(t *testing.T) {
	entries := []Entry{
		{Server: "a", City: "X", Country: "C", PortForward: true},
		{Server: "b", City: "X", Country: "C"},
		{Server: "c", City: "X", Country: "C", PortForward: true},
	}
	got := Candidates(Config{Mode: ModeSameCity}, Location{Server: "a", City: "X", Country: "C", PortForward: true}, entries, nil)
	if want := []Candidate{{Server: "c", PortForward: true}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("forwarding = %v, want %v", got, want)
	}
	got = Candidates(Config{Mode: ModeServers, Servers: []string{"b", "c"}}, Location{Server: "a", PortForward: true}, entries, nil)
	if want := []Candidate{{Server: "c", PortForward: true}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("servers forwarding = %v, want %v", got, want)
	}
	// A primary that doesn't forward takes any.
	got = Candidates(Config{Mode: ModeSameCity}, Location{Server: "b", City: "X", Country: "C"}, entries, nil)
	if len(got) != 2 {
		t.Fatalf("non-forwarding = %v", got)
	}
}

func TestCandidatesServersSkipsUnlisted(t *testing.T) {
	entries := []Entry{{Server: "a"}, {Server: "c"}, {Server: "d"}}
	cfg := Config{Mode: ModeServers, Servers: []string{"d", "gone", "a", "c"}}
	got := names(Candidates(cfg, Location{Server: "c"}, entries, []string{"a"}))
	if want := []string{"d"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("servers = %v, want %v", got, want)
	}
}

func names(cs []Candidate) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Server)
	}
	return out
}

func TestParseModeAndValidate(t *testing.T) {
	for in, want := range map[string]Mode{"": DefaultMode, "on": DefaultOnMode, "off": ModeOff,
		"same-city": ModeSameCity, "same-country": ModeSameCountry, "servers": ModeServers} {
		got, err := ParseMode(in)
		if err != nil || got != want {
			t.Fatalf("ParseMode(%q) = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"On", "yes", "city", " same-city"} {
		if _, err := ParseMode(in); err == nil {
			t.Fatalf("ParseMode(%q) accepted", in)
		}
	}
	valid := func(name string) bool { return name != "" && !strings.ContainsAny(name, " /") }
	good := Config{Mode: ModeServers, Servers: []string{"a", "b"}, After: DefaultAfter, Return: DefaultReturn}
	if err := good.Validate(valid, "p"); err != nil {
		t.Fatal(err)
	}
	bad := map[string]Config{
		"no list":       {Mode: ModeServers, After: DefaultAfter, Return: ReturnAuto},
		"list on city":  {Mode: ModeSameCity, Servers: []string{"a"}, After: DefaultAfter, Return: ReturnAuto},
		"invalid name":  {Mode: ModeServers, Servers: []string{"a b"}, After: DefaultAfter, Return: ReturnAuto},
		"server listed": {Mode: ModeServers, Servers: []string{"p"}, After: DefaultAfter, Return: ReturnAuto},
		"duplicate":     {Mode: ModeServers, Servers: []string{"a", "a"}, After: DefaultAfter, Return: ReturnAuto},
		"nine":          {Mode: ModeServers, Servers: strings.Split("a,b,c,d,e,f,g,h,i", ","), After: DefaultAfter, Return: ReturnAuto},
		"short after":   {Mode: ModeSameCity, After: 119 * time.Second, Return: ReturnAuto},
		"long after":    {Mode: ModeSameCity, After: 3601 * time.Second, Return: ReturnAuto},
		"return":        {Mode: ModeSameCity, After: DefaultAfter, Return: "never"},
		"mode":          {Mode: "on", After: DefaultAfter, Return: ReturnAuto},
	}
	for name, cfg := range bad {
		if err := cfg.Validate(valid, "p"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestPropertyDecisionsStayInsideTheCandidates drives random sequences of
// observations and checks every decision: a backup is never the primary
// and always one of the candidates offered; a restore names the backup that
// last verified; a return names the primary; an episode never tries more
// than MaxTries backups; and the target is always the primary or a
// candidate.
func TestPropertyDecisionsStayInsideTheCandidates(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	pool := []string{"p", "b1", "b2", "b3", "b4", "b5"}
	for seq := 0; seq < 3000; seq++ {
		cfg := onConfig()
		if rng.Intn(2) == 0 {
			cfg.Return = ReturnManual
		}
		cfg.After = time.Duration(120+rng.Intn(400)) * time.Second
		var s State
		now := float64(rng.Intn(5000))
		boot := "a"
		offered := map[string]bool{}
		for step := 0; step < 200; step++ {
			now += float64(rng.Intn(400))
			if rng.Intn(150) == 0 {
				boot += "x"
				now = float64(rng.Intn(100))
			}
			var cands []Candidate
			for _, name := range pool {
				if rng.Intn(3) != 0 {
					cands = append(cands, Candidate{Server: name}) // sometimes the primary, as a hostile input
				}
			}
			out := Outcome(rng.Intn(4))
			live := pool[rng.Intn(len(pool))]
			o := Observation{Now: now, BootID: boot, Primary: "p", Live: live, Outcome: out,
				Reason: ReasonTunnelSilent, Fresh: rng.Intn(10) == 0,
				Uplink: func() bool { return rng.Intn(5) != 0 }, ReturnReady: func() bool { return rng.Intn(4) != 0 }}
			var given []Candidate
			lastVerified := s.LastVerified
			d := s.Observe(cfg, o, func() []Candidate { given = cands; return cands })
			for _, c := range given {
				offered[c.Server] = true
			}
			switch d.Action {
			case FailOver:
				found := false
				for _, c := range given {
					found = found || c.Server == d.Server
				}
				if d.Server == "p" || !found {
					t.Fatalf("seq %d step %d: failover to %q, offered %v", seq, step, d.Server, given)
				}
			case Restore:
				if d.Server != lastVerified || d.Server == "p" || d.Server == "" {
					t.Fatalf("seq %d step %d: restore to %q, last verified %q", seq, step, d.Server, lastVerified)
				}
			case Return:
				if d.Server != "p" {
					t.Fatalf("seq %d step %d: return to %q", seq, step, d.Server)
				}
			case Stay, Exhausted:
				if d.Server != "" {
					t.Fatalf("seq %d step %d: %v names %q", seq, step, d.Action, d.Server)
				}
			}
			if len(s.Tried) > MaxTries {
				t.Fatalf("seq %d step %d: tried %v", seq, step, s.Tried)
			}
			server, fo := s.Target()
			if server != "p" && (!fo || !offered[server]) {
				t.Fatalf("seq %d step %d: target %q (failover %v) not offered", seq, step, server, fo)
			}
			if fo && server == "p" && s.Phase != PhaseReturning {
				t.Fatalf("seq %d step %d: failover target is the primary in phase %q", seq, step, s.Phase)
			}
			if !ValidPhase(s.Phase) || (s.Phase != "" && s.Phase != PhaseExhausted && s.Phase != PhaseReturning && s.Backup == "") {
				t.Fatalf("seq %d step %d: state %+v", seq, step, s)
			}
		}
	}
}
