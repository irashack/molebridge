# Design: automatic failover

Status: **built** (2026-11-20), experimental. Every piece is built, with
unit and fake-kernel tests and the [system rig drills](#system-rig-drills)
1 to 6 in CI. The live drill has not run. The user documentation is
[automatic failover](../failover.md); where this record and the code
disagree, the code wins and that page follows the code. This file stays as
the working contract for the roadmap's [automatic
failover](../../ROADMAP.md#automatic-failover). The choices marked
**(owner)** are product decisions, gathered in [decisions for the
owner](#decisions-for-the-owner): the owner took every recommended default
(2026-11-19, issue #90), and the code keeps each one a named constant.

As built, three points differ from the text below:

- PIA's port-forwarding filter on backups applies whenever the selected
  region offers port forwarding, not only when `PIA_PORT_FORWARD=on`.
- `molebridge init` offers no failover extra; failover is turned on in a
  `compose.override.yaml` ([automatic failover](../failover.md)).
- A multi-provider exit refuses `FAILOVER`; backups don't stay within one
  provider, because there are none.

## What it is

Today Molebridge never picks another server by itself, except for [a server
the provider retires](../architecture.md#a-server-the-provider-retires). It
retries the one the operator chose, on a backoff, and says that it is failing.
Failover moves an exit to a **backup** server when the operator's server
(the **primary**) keeps failing, and back to the primary when it works again.

Four rules, which every piece below keeps:

1. **The guarantee doesn't change.** A backup is a target like any other: the
   same gates, the same mutation owner, the same verification. Nothing about
   failover routes traffic outside the tunnel or holds the routing contract
   differently; between servers, forwarded traffic meets the exit table's
   fallback, as in any switch.
2. **Never "connected" on a server the operator didn't choose without saying
   so.** Every reader that says connected on a backup says "backup" in the
   same place, and every reader that doesn't know about failover says
   failed, never connected ([old readers](#old-readers)).
3. **The operator's choice is never rewritten.** `desired.json`,
   `requested_server` and `configured_server` keep naming the primary. A new
   panel request ends any failover at once.
4. **Failover only where it can help.** It acts on failures that belong to
   the server, never on the host's own network, a missing prerequisite, a
   refused login, or a provider check service that is down while the tunnel
   carries traffic. When in doubt it does nothing, and the exit behaves as
   today.

Scope: the native backend, for the overlay exit and the native sidecar (the
applier is the same). The gluetun backend is out of scope **(owner)**:
gluetun owns its tunnel and reconnects by itself, and the exit restores the
selection after it; an exit with `TUNNEL_BACKEND=gluetun` (or a gluetun
sidecar) refuses to start with failover on. On a [multi-provider
exit](multi-provider.md), backups are of the primary's provider only
**(owner)**.

## The pieces

| Piece | What it is | Depends on |
|---|---|---|
| [The failover policy](#the-failover-policy) | package `internal/failover`: pure rules, state in, decision out, no I/O | — |
| [Backups](#which-backups) | choosing the candidates from a fresh catalog | the policy (by interface) |
| [The uplink probe](#the-uplink-probe) | a provider hook: does the host's own network answer outside the tunnel | — |
| [The applier's integration](#the-applier) | observations from the pipeline, the failover target, `failover.json` | all three above |
| [The record and the verdict](#the-record-and-the-verdict) | the `failover` member, `selection.source: "failover"`, the label and reason codes | the applier (record shape only) |
| [The panel](#the-panel) | wording, the request while on a backup, the 409 gate | the verdict |
| [Settings](#settings) | `FAILOVER*`, validated at start | — |
| [Testing](#testing) | unit tests, the system rig's drills, the live drill | all |

The policy, the uplink probe, the verdict change and the settings can be built
at once; the applier's integration joins them; the panel needs only the
verdict.

## Settings

Read by the exit at start, validated by the supervisor before the worker
starts, like every other setting: a refusal exits with status 1 and one line.

| Setting | Default | Meaning |
|---|---|---|
| `FAILOVER` | `off` **(owner)** | `off`; `same-city` or `same-country` (backups from the catalog, [which backups](#which-backups)); `servers` (the list in `FAILOVER_SERVERS`); `on`, the default backups (`same-city` **(owner)**). Anything else is refused. |
| `FAILOVER_SERVERS` | empty | With `FAILOVER=servers`, required: 1 to 8 server names valid for the provider, comma-separated, in order of preference, none equal to `SERVER`. Refused with any other mode. Names not in a fresh catalog are skipped when a backup is chosen, never refused at start: catalogs change. |
| `FAILOVER_AFTER` | `300` **(owner)** | Seconds the primary must keep failing ([below](#when-it-keeps-failing)). 120 to 3600. |
| `FAILOVER_RETURN` | `auto` **(owner)** | `auto` (try the primary again on a schedule) or `manual` (stay on the backup until the operator picks a server, or the backup itself keeps failing). |

The panel can't change these **(owner)**: the panel writes only
`desired.json`, and failover is a property of the exit, like `SERVER`. The
settings are also what `molebridge init` asks, as an extra of the exit, and
`docs/configuration.md` gets them when they ship.

## When it keeps failing

The policy counts **eligible failures** of the current target: inspections
and attempts whose outcome says the server is not carrying the tunnel, in the
pipeline's existing terms.

**Eligible** (the server's fault, as far as the exit can tell):

| Pipeline outcome | Reason code |
|---|---|
| An attempt ends `failed`: the change failed (`mutation-failed`), or verification timed out with another server live, or "The last switch was interrupted" is followed by a failed re-apply | `switch-failed` |
| An inspection of the live target finds `handshake` `fail`: none, or 180 seconds old or older (`unverified`) | `handshake-failed` |
| An egress check with `reason` `unanswered` (no usable answer twice) while the peer received nothing during the check but whole handshake initiations (148 bytes each), or `tunnel-silent` (PIA) | `tunnel-silent` |
| A PIA lapse repair (`repair.reason` `tunnel-silent` or `handshake-stale`) that ends without a verified record | `repair-failed` |

**Not eligible**, and each one **resets** the count (the episode, if one has
started, keeps its state; see [the episode](#the-episode)):

- `pending`: a prerequisite is missing (routing protection, NetBird's mode,
  readable peers, a fresh catalog). The exit isn't able to judge any server.
- `rejected`: an invalid request, an unlisted server (that is [the retired
  server's move](#the-retired-server-move), not failover), or a refused login
  (every server of the provider would refuse it).
- An egress answer that doesn't confirm the egress (`mullvad_exit_ip: false`,
  PIA's `connected: false`, NordVPN's `protected: false`). That may be
  traffic leaving the wrong way; moving it to another server would hide it.
  It stays the failure it is today.
- An egress check that got no answer while the tunnel still received
  anything but handshake initiations (the provider's check service is down,
  not the server): it never triggers a repair today, and it never triggers
  failover. A server that hears the exit answers with data, a handshake
  response or a keepalive; one that doesn't hear it keeps sending handshake
  initiations, because the exit's responses never reach it, while the
  exit's last handshake stays fresh for up to three minutes. Data alone
  adds up to whole initiations about once in 148 checks, and failover takes
  at least three eligible checks in a row.
- A routing, NetBird or owner-record failure, a lost lease, a worker restart.
- Any verified record (`idle` verified): the count and the window clear.

**The rule.** Failover starts when all of these hold on one pass:

1. The target is not a panel request made within the last 150 seconds
   (`FreshRequestSec`): an operator asking now gets their full window, which
   starts at the request.
2. Eligible failures have followed each other with no reset for at least
   `FAILOVER_AFTER` seconds on the boot clock, measured from the first one.
3. There were at least **3** eligible failures in that window. With the
   default 300 seconds and the pipeline's own timing that is, for a switch
   that fails, the change at 0 and its re-applies at 1 and 3 minutes; for a
   live server that stopped answering, five periodic checks about a minute
   apart. The policy never makes the pipeline check sooner than it does today.
4. [The uplink probe](#the-uplink-probe) answers now. If it doesn't, the
   host's own network is probably down, every server would fail the same way,
   and nothing happens; the count is kept, so the probe is asked again on the
   next eligible failure.
5. There is a [backup](#which-backups) that hasn't been tried in this
   episode, and the episode's limits allow another ([the episode](#the-episode)).

## Which backups

Candidates are computed from a fresh catalog only. Without one nothing is
decided (the gates hold every change anyway), as in `moved.go`.

- `same-city`: the servers the catalog lists with the primary's city and
  country. `same-country`: with its country. The primary's location is the
  one `location.json` remembers ([a server the provider
  retires](../architecture.md#a-server-the-provider-retires)), so the primary
  must have been verified on this exit once, with 0.11.0 or later; a primary
  never verified here has no location and no backups. The candidates are
  sorted by name, starting after the primary's name and wrapping
  (`nextAfter`), so the choice is the same on every pass and after a restart.
- `servers`: `FAILOVER_SERVERS` in its order, skipping names not in a fresh
  catalog.
- In every mode: never the primary itself; never a server already tried in
  this episode; and if the primary forwards ports (a PIA region with
  `port_forward`, and `PIA_PORT_FORWARD=on`), only servers that forward ports,
  as for the retired server's move.

The default mode when failover is on is `same-city` **(owner)**: an operator
who picked a server picked a location, and a backup in the same city keeps
it. It finds few or no backups with PIA, whose regions are mostly one per
city; `same-country` or a list suits PIA better, and the docs say so.

## The episode

From the first failover until the exit is back on the primary and verified
there (or the operator picks a server) is one **episode**.

- **Trying a backup.** The backup becomes the target, with source `failover`,
  through the whole admission pipeline: the gates (a backup that fails a gate
  stays `pending` like any target), `attempting` before any I/O, the change,
  verification for up to the switch timeout (60 seconds natively). The
  pipeline's 90-second guard applies to the switch after it, as to drift.
- **A backup that doesn't verify** (the attempt ends `failed`, or
  `applied-unverified` with an eligible check failing) is marked tried, and
  the next candidate is tried at once, without waiting `FAILOVER_AFTER`
  again: the primary is already known to be failing. A backup that verifies
  stays the target.
- **Limits.** At most **3** backups are tried in one episode. When none
  verifies (or none is left), the episode is **exhausted**: the primary
  becomes the target again, with the pipeline's backoff, and the record says
  so ([the record](#the-record-and-the-verdict)). No new episode starts for
  **30 minutes** after an exhaustion. These two numbers are constants, not
  settings, until a live pass shows a reason.
- **A backup that later keeps failing** counts eligible failures by the same
  rule, and the next untried candidate is tried. If none is left, the episode
  is exhausted as above.

### Returning to the primary

With `FAILOVER_RETURN=auto`, the exit tries the primary again 15 minutes
after the backup verified, then after 30, 60 and 120 minutes, and every 120
minutes after that **(owner)**. One server can be live at a time, so trying
the primary means switching to it, which interrupts traffic for the switch;
the schedule keeps that rare.

- **Before a return**, cheap checks outside the tunnel must pass, or the
  return waits for the next slot: the primary is in a fresh catalog (Mullvad's
  lists only active relays); for PIA, the primary region's registration API
  answers (the check the silent tunnel already uses). Mullvad and NordVPN have
  no way to test a WireGuard server without switching to it.
- **The return** is a switch to the primary with source `failover` and the
  record's `failover.phase` `returning` ([the record](#the-record-and-the-verdict)).
  If the primary verifies within the switch timeout, the episode ends: the
  target is the primary again with its own source (`panel` or `configured`),
  and the `failover` member goes.
- **A failed return** switches back to the backup that last verified, at
  once, without the 90-second guard and without counting a new
  `FAILOVER_AFTER`: that backup was verified within the last return interval.
  If it then fails to verify, it counts as a backup that keeps failing.
- With `FAILOVER_RETURN=manual`, the exit stays on the backup until the
  operator picks a server (the primary again is a new request, applied at
  once) or the backup keeps failing.

### What ends an episode

- The primary verified after a return.
- A new target: a new panel request (any server, including the primary, or
  Retry), a changed `SERVER`, or failover turned off (the exit restarts with
  the new settings and finds `failover.json` naming another configuration:
  it is dropped and the primary is the target).
- The primary leaving the catalog: [the retired server's
  move](#the-retired-server-move) takes over.

## The uplink probe

A new hook on `applier.Provider`:

```go
// UplinkAnswers is whether the host's own network answers outside the
// tunnel now: an HTTPS request over the host's route, through System.Fetch,
// to the provider's catalog host (the registry entry's CatalogURL), with a
// 5-second limit. Any HTTP answer counts, redirects are not followed and
// the body is not read beyond 1 KiB. PIA asks the recorded server's
// registration API first (RegistrationAnswers) and the catalog host after.
UplinkAnswers(ctx context.Context, a *Applier) bool
```

`BaseProvider` has the default above. The exit already reaches the catalog
host over the host's route for every refresh, so the probe opens no new kind
of connection and tells the provider nothing it doesn't already learn every
hour. It runs only when the policy is about to fail over or return, never
on a schedule of its own.

## The failover policy

Package `internal/failover`, standard library only, no I/O and no clock of
its own: the applier feeds it, it answers. Everything above about counts,
windows, candidates, limits and the return schedule lives here, so it is
tested without an applier.

```go
package failover

type Mode string // "off", "same-city", "same-country", "servers"

type Config struct {
	Mode    Mode
	Servers []string      // with ModeServers
	After   time.Duration // FAILOVER_AFTER
	Return  string        // "auto" or "manual"
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

type Observation struct {
	Now      float64 // boot clock, seconds
	BootID   string  // the boot's id: a new one is a reboot
	Wall     time.Time // the wall clock, for State.Since
	Primary  string  // the effective primary: the target, or the retired server's replacement
	Live     string  // the server the inspection found live, "" for none
	Outcome  Outcome
	Reason   string // "switch-failed", "handshake-failed", "tunnel-silent", "repair-failed"
	Fresh    bool   // the target is a panel request younger than FreshRequestSec
	Uplink   func() bool // asked only when a decision needs it
	ReturnReady func() bool // asked only when a return is due: the checks before a return
}

type Candidate struct {
	Server      string
	PortForward bool
}

type Action int

const (
	Stay      Action = iota
	FailOver         // switch to Decision.Server
	Return           // switch to the primary
	Restore          // a return failed: back to Decision.Server, the last verified backup
	Exhausted        // no backup verified: the primary is the target again
)

type Decision struct {
	Action Action
	Server string
	Reason string
}

// State is the episode and the count, persisted by the applier in
// failover.json. The zero State is "no episode".
type State struct {
	Primary       string
	FailingSince  float64 // boot clock; 0 for none
	Failures      int
	Reason        string  // the latest eligible reason
	Backup        string  // the server standing in, "" for none
	LastVerified  string  // the backup that last verified
	Since         string  // wall-clock RFC 3339 of the first failover, for the record
	Tried         []string
	Phase         string  // "", "trying", "on-backup", "returning", "exhausted"
	NextReturn    float64 // boot clock; 0 for none
	ReturnStep    int
	HoldUntil     float64 // no new episode before this (boot clock)
	BootID        string
}

// Observe applies one observation and returns what to do. candidates is
// called only when a backup is to be chosen.
func (s *State) Observe(cfg Config, o Observation, candidates func() []Candidate) Decision

// Reset ends the episode: a new target, a changed configuration.
func (s *State) Reset()

// Target is the server to apply and whether its source is failover: the
// backup while trying or on it, the primary while returning, else the
// primary with its own source.
func (s *State) Target() (server string, failover bool)

// Candidates orders the backups for cfg from a fresh catalog's entries,
// given the primary's remembered location.
func Candidates(cfg Config, primary Location, entries []Entry, tried []string) []Candidate

type Location struct{ Server, City, Country string; PortForward bool }
type Entry struct{ Server, City, Country string; PortForward bool }
```

As built, three additions to the interface above: `Observation.BootID` and
`Observation.Wall` (the policy has no clock, so the boot's id and the wall
time come in with the observation), `Observation.ReturnReady` (the checks
[before a return](#returning-to-the-primary), which the applier owns), and
`State.Target`. `FAILOVER=on` is accepted as `DefaultOnMode` (`same-city`),
so the owner's second decision is one constant.

The applier's wiring added, as built: `classify(state, target, finding,
mutated, repaired)`, because whether this pass changed the tunnel or ran a
repair decides `switch-failed` and `repair-failed`; `Finding.Quiet`, the
tunnel's receive counter risen by nothing but whole handshake initiations
across a failed egress check (`unheard`), measured only with failover on,
for `tunnel-silent` on Mullvad and NordVPN; and a
second hook, `Provider.ServerAnswers(ctx, a, server)`, the provider tier of
`ReturnReady` (PIA asks the region's registration API; the others answer
true, as the design allows). The port-forwarding filter on candidates is the
retired-server move's (the region's own `port_forward`, remembered in
`location.json`).

Deadlines are on the boot clock with the boot's id, as `attempt.json`'s are:
after a reboot, a due return runs at once, a running `FAILOVER_AFTER` window
starts over (the evidence is from before the reboot), and the hold-down after
an exhaustion has passed.

## The applier

Changes in `internal/applier`, in a new `failover.go` beside `moved.go`.

- **`failover.json`** in `PRIVATE_STATE_DIR` (the exit's own file, like
  `location.json` and `attempt.json`; the panel can't write it), bounded to
  4 KiB, written atomically. It carries the `State` and a signature of the
  configuration (mode, list, the primary). A missing, malformed or
  mismatching file is no episode: the primary is the target. A failed write
  is logged and the decision still used, as `keepLocation` does, because the
  next pass decides the same from the same evidence.
- **The target.** `resolve` builds the target as today (configured, panel,
  retired-server replacement). Then, if the policy has a backup in place
  for that primary, the target becomes
  `Selection{Server: backup, Source: "failover", Request: <the primary's>,
  Failover: &FailoverOf{Primary: primary, Source: <the primary's source>}}`.
  `Selection.Key()` appends `|failover:<backup>`, so moving to a backup,
  between backups and back are new targets for the pipeline, as for
  `moved`. `Selection.target()` still returns the primary: a reader's target
  is what was asked for.
- **Observations.** After each `runPipeline`, `check` and lapse repair, the
  applier classifies the outcome ([eligible](#when-it-keeps-failing)) and
  calls `Observe` once per pass with what changed. The classification is one
  function, `classify(attempt, finding) (Outcome, reason)`, unit-tested
  against every row of the tables above.
- **Remembered location.** `verified()` must not remember a backup as the
  primary's location, exactly as it skips a replacement today: a target with
  `Failover` set is excluded.
- **Logs**, one line each, on change only: `applier: the selected server
  has kept failing for <n> s (<reason>); moving to backup <server>`; `applier:
  backup <server> did not verify; trying the next`; `applier: no backup
  verified; staying on the selected server`; `applier: trying the selected
  server again`; `applier: the selected server verified again; failover
  ended`; `applier: the selected server still fails; back to backup <server>`;
  `applier: the host's network does not answer; not failing over`.

## The record and the verdict

### The record

While a backup is the target (trying it, on it, or returning from it) the
record has:

- `selection.source`: `"failover"` (already in the verdict's vocabulary of
  sources, unused until now), `selection.target` the server being applied
  (the backup, or the primary during a return);
- `requested_server` and `configured_server` unchanged: the primary;
- a new member `failover`:

```json
"failover": {
  "from": "se-got-wg-001", "to": "se-got-wg-002",
  "phase": "on-backup", "reason": "handshake-failed",
  "since": "2026-11-19T18:00:00Z", "next_return_at": "2026-11-19T18:15:00Z",
  "tried": ["se-got-wg-002"]
}
```

`from` is the effective primary, `to` the backup standing in (null while
exhausted), `phase` `trying`, `on-backup`, `returning` or `exhausted`,
`reason` the eligible reason that started the episode, `since` when it
started, `next_return_at` null with `FAILOVER_RETURN=manual` or while not on
a backup, `tried` at most 3 names. Server names are bounded as everywhere in
the record (256 characters), so the member stays well inside the 16 KiB
bound. An exhausted episode keeps the member, with `to` null and `phase`
`exhausted`, until the hold-down ends or the primary verifies. Records
without an episode have no `failover` member. The pass that verifies a
backup publishes its record again once the policy has seen it, so the first
record that readers keep from the backup already says `on-backup`, with its
`next_return_at`, rather than `trying` until the next check.

It is deliberately **not** `moved`. `verdict.Moved` and `movedFrom` ignore
`moved.reason`, so an older reader given `moved` would accept the backup as
agreement and say "connected" with the label of a retired server. A member
of its own keeps old readers failing safe.

### The verdict

In `internal/verdict`:

- `targetDisagreement` accepts a record whose `failover.from` is the
  expected server (or the expected server's `moved.to`, [below](#the-retired-server-move)),
  whose `failover.to` is its own `server`, whose `failover.phase` is
  `on-backup` or `trying`, and whose `selection.source` is `failover`. All
  four, or the record disagrees as today.
- A connected verdict on a backup is state **`ok`** **(owner)**, label
  **"connected to backup"**, reason code **`failover`**, and the verdict
  carries `Failover{From, To, Since, NextReturnAt}` for the panel. The state
  stays `ok` because the traffic is verified in the tunnel: `/readyz`, the
  proxy and PIA's port forwarding (which run only on `ok`) keep working, and
  the label and reason say it isn't the chosen server.
- A failed or unknown verdict on a record with an exhausted episode adds the
  reason code **`failover-exhausted`** after the others.
- `failover.phase` `returning` with `applying` is "switching", as any switch.
- A new accessor `Failover(record) (from, to, phase string, ok bool)`, like
  `Moved`.

The Gatus push follows the verdict: up on a backup, with the label in its
message **(owner)**.

### Old readers

A reader from before this change (an older panel, `molebridge status`,
Switchyard's bridges, a health bridge) given a record on a backup: the
record is schema 2 and valid, `selection.source` `failover` is in its
vocabulary, there is no `moved`, and `server` is not the requested or
configured server, so its verdict is `failed`, "verification failed"
(`not-requested-server` or `not-configured-server`). Never connected. That is
loud but true from what it knows, and it is why no schema change is needed.
A golden test keeps it so ([testing](#testing)). The one reader that says
connected is one with no target of its own, which holds the record to
itself, before failover as now: the proxy, which is newer than failover.

## The panel

- **Wording.** On a connected verdict with reason `failover`, the status line
  says: "Connected to backup se-got-wg-002. se-got-wg-001 has kept failing
  since 18:00; trying it again at 18:15." (with `manual`: "…; pick it again to
  return."). The exit tabs and `/api/exits` show "backup" beside the
  server. `/api/status` passes the record and the verdict through, as it does
  `moved`. During `exhausted`: the usual failed wording, then "No backup
  verified; retrying se-got-wg-001." The page script renders the server's
  view, with no rules of its own.
- **Requests.** The selection list marks the primary as selected and the
  backup as live. Picking any server, the primary included, is a new
  request: it ends the episode and is applied at once, as Retry is.
- **The 409 gate is unchanged.** A failover switch publishes `applying` like
  any other, so a selection during it gets 409 "A switch is in progress; wait
  for it to finish." for at most the switch timeout. While on a backup the
  verdict is `ok` and selection is open.
- **`SERVER` set.** Failover applies to a configured server too (its primary
  is the configured server). The panel still offers no switching controls; it
  shows the backup and the return time.

## Interactions

### The retired-server move

The move comes first: when the primary leaves the catalog, `moved.go`'s
replacement is the effective primary, and the record has `moved` as today.
Failover then works on the replacement: `failover.from` is the replacement,
and the verdict accepts the chain `requested → moved.to → failover.to`. When
the retired server returns to the catalog, the exit returns to it as today,
which is a new target and ends any episode. A backup that leaves the catalog
is simply not a candidate; the backup in place leaving it counts as a
backup that keeps failing.

### PIA's port forwarding

A backup of a forwarding region forwards too ([which backups](#which-backups)).
The forwarded port belongs to a registration, so a failover changes it, as a
switch does: forwarding stops while the verdict isn't `ok`, then binds a new
port on the backup, `forwarded_port` changes and `port-sync` follows it. A
return changes it again. The docs must say so where port forwarding is
described.

### The proxy

Unaffected. It reads the exit's verdict without the panel's request, so its
target is none and the record's own `selection` must agree with itself,
which a record on a backup does (`source` `failover`, `server` equal to
`selection.target`). It refuses new connections while the verdict isn't `ok`
(during a failover switch) and serves on the backup. Mullvad's relay proxies
are reached through whatever server the exit is on. `proxy.json`'s
`tunnel.server` names the backup.

### Drift, retries and repairs

All unchanged and applied to the target in place: a backup drifts, is
re-applied and repaired as any target. The 90-second guard after a change
holds for failover switches too, except the immediate return to a verified
backup after a failed return. A PIA lapse repair of the primary comes before
failover (it is the cheaper fix); only a repair that ends without a verified
record counts as an eligible failure.

## Testing

### Unit tests

- `internal/failover`: table tests of `Observe` over sequences of
  observations: three eligible failures under and over `FAILOVER_AFTER`;
  each ineligible outcome resetting the count; a fresh panel request
  deferring the window; the uplink probe declining (no failover, count kept);
  each backup mode's ordering, wrapping, and the port-forward filter; skipped
  unlisted names in `servers`; a backup failing and the next tried at once;
  three failures exhausting the episode and the 30-minute hold-down; the
  return schedule (15, 30, 60, 120, 120); a failed return restoring the last
  verified backup; `manual`; `Reset` on a new target; a reboot (a new boot
  id) restarting the window and making a due return run; a property test
  that no sequence produces a decision naming the primary as a backup or a
  server outside the candidates.
- `internal/applier`: `classify` against every row of the eligibility
  tables; with the fakes, a primary whose handshake stops for 300 seconds
  moving to a same-city backup with source `failover` and the `failover`
  member, the first record on the backup already `on-backup`; a server
  that stops hearing the exit (it keeps sending handshake initiations, the
  handshake still fresh) counted from the first unanswered check;
  `location.json` unchanged by the backup; `pending`, a refused login and a
  check service that is down or drops requests never failing over; a panel
  request during an episode ending it; `SERVER` with failover; the move and
  failover chained; a malformed `failover.json`; PIA's forwarding filter.
- `internal/verdict`: golden records for each phase; agreement for panel,
  configured and chained targets; each of the four conditions missing
  making it disagree; `failover-exhausted`; and a test that judges every
  failover golden record with the agreement rules as they were before this
  change (kept as a copy in the test) and requires `failed`, never `ok`.
- `internal/panel`: the wording for each phase, `/api/exits`, 409 during a
  failover `applying`, a selection on a backup accepted.
- `internal/exit`: the settings' refusals (unknown mode, list with another
  mode, names invalid for the provider, `SERVER` in the list, gluetun with
  failover on).

### System rig drills

In the system rig (`internal/exit/systemrig_*`), with its fake Mullvad
network and two fake servers in one city, `FAILOVER=same-city`, and the
policy's timings shortened through the rig's test hook (the settings' own
minimum stays 120 seconds):

1. Drop the primary's UDP in the fake network: the exit moves to the backup,
   verifies, and the record and both verdicts (panel's and exit's) say
   "connected to backup". With `FAILOVER_AFTER` at its minimum, 120 seconds,
   the first check after the drop must count (it ends within 170 seconds of
   the drop) and the failover come within `FAILOVER_AFTER` plus a minute of
   it; the drill logs the times. The drill binary also logs each pass the
   policy sees and the bytes the tunnel received during each failed check
   (`MOLEBRIDGE_DRILL_FAILOVER_TRACE`).
2. Restore the primary: the exit returns at the scheduled time and the
   `failover` member goes.
3. Keep the primary dropped during a return: the exit is back on the backup
   within the switch timeout.
4. Drop the fake uplink (the catalog host too): no failover.
5. Drop both servers: two tries, an exhausted episode, the primary retried
   on its backoff.
6. A panel request during an episode: applied at once, episode ended.

Throughout, an nftables counter on the host interface shows no forwarded
packet leaving outside WireGuard, as the switch drills already check.

### Live drill

On a real Mullvad exit with `FAILOVER=same-city`: a drop rule in the exit's
namespace for the primary's endpoint address makes the exit fail over within
`FAILOVER_AFTER` plus a minute and verify the backup at the provider tier;
removing it brings the exit back at the next return slot. On a PIA exit with
port forwarding and `FAILOVER=same-country`: the same, with the forwarded
port changing and the panel showing the backup. The results go in
[testing](../testing.md), with what wasn't run.

## Decisions for the owner

Decided as recommended: the owner accepted every default below (owner,
2026-11-19, issue #90).

| # | Decision | Decided |
|---|---|---|
| 1 | Failover on by default, or opt-in | **Opt-in** (`FAILOVER=off`): today's promise is "it retries the one you chose", and an exit that moves by itself should be asked for |
| 2 | Default backups when it's on | **`same-city`**, with `same-country` and an explicit list as the other modes; the docs point PIA users at `same-country` |
| 3 | Return to the primary by itself | **Yes** (`FAILOVER_RETURN=auto`), at 15, 30, 60, then every 120 minutes, each return a short interruption; `manual` for operators who'd rather stay |
| 4 | How long the primary must keep failing | **300 seconds**, and at least 3 eligible failures |
| 5 | What a backup looks like to readers | State **`ok`**, label "connected to backup", reason `failover`: traffic is verified in the tunnel, and the label says whose choice it isn't. The alternative, `failed` or a new state, would break `/readyz`, the proxy and port forwarding for a working tunnel, and readers outside the repo |
| 6 | Monitoring (Gatus) on a backup | **Up**, with the label in its message |
| 7 | Can the panel turn failover on or edit backups | **No, not now**: exit settings only, like `SERVER` |
| 8 | gluetun exits | **Out of scope**: refused at start with failover on |
| 9 | Failover to another provider on a multi-provider exit | **No**: backups are of the primary's provider |
