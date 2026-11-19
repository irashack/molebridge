# Design: one exit for several providers

Status: **proposed** (2026-11-19); piece 1, [whole-tunnel
replacement](#whole-tunnel-replacement), is built and nothing calls it yet.
This is the working contract for the
roadmap's [one exit for several
providers](../../ROADMAP.md#one-exit-for-several-providers): the target
shape, the pieces, their boundaries and the interfaces between them, the
order they are built in and how each is tested. Nothing else here is built. The
choices marked **(owner)** are product decisions, gathered with a
recommended default in [decisions for the owner](#decisions-for-the-owner).
When the feature ships, its user documentation replaces this file.

## What it is

A **multi-provider exit** is one NetBird peer that can carry Mullvad, PIA
or NordVPN, one at a time. Switchyard picks the provider and the server in
one step. Everyone using the exit shares its current provider; to put
devices on different providers at once, run single-provider exits beside
it, which stay exactly as they are.

Rules every piece keeps:

1. **The guarantee doesn't change.** A provider change is a switch: the
   routing contract holds throughout, and between one provider's tunnel and
   the next, forwarded traffic meets the exit table's unreachable fallback.
   No step ever has two providers' tunnels up, and a failed change never
   falls back to the previous provider: it stays failed, fail-closed, and
   retries.
2. **Opt-in, and nothing else changes.** It is a new configuration of the
   overlay exit with native providers. `PROVIDER` without `PROVIDERS` is a
   single-provider exit with today's behavior, record and files, byte for
   byte; the golden records and every drill must pass unchanged.
3. **No reader is misled.** A reader that doesn't know about multi-provider
   exits sees "provider mismatch" (unknown) or a true record of its own
   provider, never a connected verdict on a server it didn't ask for
   ([old readers](#old-readers)).

Scope: the overlay exit (`EXIT_KIND=overlay`) on the native backend, with any
two or three of `mullvad`, `pia`, `nordvpn`. Out of scope: gluetun (it owns
its tunnel), the native sidecar **(owner)**, and the proxy on a
multi-provider exit **(owner)**, which `molebridge init` refuses and the
proxy refuses at start (its `PROVIDER` would be wrong after a switch).

## The pieces, and the order

| # | Piece | What it is | Depends on |
|---|---|---|---|
| 0 | [Memory first](#the-catalogs-in-one-process) | the roadmap's memory work measured live, NordVPN under target | — |
| 1 | [Whole-tunnel replacement](#whole-tunnel-replacement) | a mutation-owner operation that swaps the tunnel's whole configuration; recovery rebuilds the current one | — |
| 2 | [The provider set](#the-provider-set) | the applier holding several providers' hooks, catalogs and memory, one active | — |
| 3 | [The target](#the-target) | (provider, server) through the admission pipeline; attempt and location records | 2 |
| 4 | [Leaving a provider](#leaving-a-provider) | PIA's port-forward and return-path teardown before another tunnel | 1, 3 |
| 5 | [The status record and the verdict](#the-status-record-and-the-verdict) | the record's new members, readers' configuration, old readers | 3 (shape only) |
| 6 | [Settings, files and credentials](#settings-files-and-credentials) | `PROVIDERS`, per-provider configs, secrets and catalogs | — |
| 7 | [The panel](#the-panel) | the provider and the server in one step | 5 |
| 8 | [`molebridge init`](#molebridge-init) | the multi-provider exit as a menu choice | 6 |
| 9 | [Testing](#testing) | unit tests, rig drills, the live pass | all |

Pieces 1, 2, 5 and 6 can be built at once. Piece 1 is useful on its own and
is merged first, behind no setting: a single-provider exit's recovery goes
through it with no behavior change. 3 and 4 need 1 and 2; the panel needs
only 5's interfaces. Nothing ships to operators until 0 says NordVPN fits
**(owner)**.

## Whole-tunnel replacement

Today a server switch keeps the tunnel and changes its peer (and, for PIA,
its address, through the mutation owner's address transaction). The tunnel
itself is built once, from the config the exit started with
(`worker.tunnelParams`: `Settings.Conf` plus the last peer set), and the
recovery loop rebuilds exactly that.

**The operation.** A new operation of the mutation owner, in
`internal/tunnel`:

```go
// Replace swaps the tunnel's whole configuration: key, addresses, MTU,
// peer and the exit table's default route. It runs as one operation of the
// mutation owner, within its 10-second bound, and never across a provider
// HTTP call (registration happens before it is queued).
func (m *Manager) Replace(ctx context.Context, from, to Params) error
```

Its steps, in order, and why:

1. **Expected state first.** The contract's expected `Spec` takes the new
   `ReturnPath` (the new addresses' rules 94 and 98, or `LeaveReturnPath`
   for a PIA config without an address), keeping the old ones meanwhile, as
   PIA's address transaction does. The repairer then neither removes the new
   rules nor re-adds the old ones.
2. **Delete the old link.** Its addresses and its default route in the exit
   table go with it; forwarded traffic now meets the exit table's
   unreachable fallback. The link goes before its return-path rules, so
   there is no moment with a tunnel address live and no rule 94 for it.
3. **Remove the old return-path rules** (each deletion asked of
   `internal/policy` first, as every deletion is).
4. **Create the new link** with the same name, key, addresses, MTU and peer,
   bring it up, put the default route into the exit table, add the new
   rules 94 and 98 and drop the old pair from the expected state.

A failure at any step leaves no half-built link (as `Up` does today), the
expected state naming only what exists, and the fallback in place: the exit
has no tunnel, fails closed, and the recovery loop brings up **the new**
configuration on its 2-to-60-second backoff.

**Recovery.** `worker.tunnelParams` reads the current configuration from a
`TunnelSource` instead of `Settings.Conf`:

```go
// TunnelSource is the tunnel configuration recovery rebuilds: the current
// provider's config and the last peer set for it. The applier updates it
// before it queues a Replace, so a tunnel lost during or after a provider
// change comes back as the new provider's.
type TunnelSource interface {
	Current() (provider string, conf *tunnelconf.Conf)
}
```

A single-provider exit's source returns its one config, with today's
remembered-peer rule (Mullvad and NordVPN come back on the last peer; PIA
with none, and restores its registration itself). A multi-provider exit's
source returns the config of the provider in `tunnel-provider.json`
(below), so recovery never resurrects the previous provider.

**As built (piece 1).** `Manager.Replace(ctx, owner, from, to)` takes the
mutation owner as well, and hands the steps to its operation
`mutator.ReplaceTunnel`, which runs them in one transaction. Three
departures from the steps above, each to keep the invariant they state:
the new rules 94 and 98 are installed and confirmed in step 1, with the
expected state, rather than in step 4, so a new address is never live
without its pair (the model refuses that state:
`internal/policy/replace_test.go`); the old link's default route is
deleted, as an approved deletion, just before the link; and the old pair
leaves the expected state as soon as its rules are gone, in step 3. Both
`from` and `to` must name the exit interface the contract expects. On a
failure the owner removes whatever link exists, keeps the pairs of every
address still live and of the new config, and withdraws readiness until a
pass verifies; when the kernel can't be read after the failure, it keeps
every pair it expected (extra rules, harmless, until the next replacement
or a restart). If the kernel also refuses to remove the old link, the
error says so and the old tunnel stays up with its pairs; the caller
retries. Recovery's bring-up doesn't confirm the new pairs itself: they
are in the expected state, and the repairer's pass after a failure puts
them back if they went, before the tunnel loop's next attempt. The worker
reads its tunnel from a `TunnelSource`; nothing sets one yet, so every exit
uses the single-provider source, which is today's code moved.

## The provider set

The applier holds one `Provider` (hooks) and one `Catalog` today. A
multi-provider applier holds a set, one of them **active** (the provider of
the tunnel in place):

```go
type ProviderSet interface {
	IDs() []string                  // in PROVIDERS order
	Active() string                 // the tunnel's provider
	Hooks(id string) Provider       // each provider's hooks, as today
	Catalog(id string) Catalog      // each provider's catalog
	SetActive(id string) error      // persists tunnel-provider.json
}
```

`a.hooks` and `a.catalog` become `a.hooks()` and `a.catalog()`, the active
provider's; the gates use the **target's** provider's catalog and hooks.
Each provider keeps its own state: PIA's `tunnel.json` (its registration),
`location.json` (as `location-<id>.json`), its catalog's refresh schedule
and backoff. A single-provider exit is a set of one, with today's file names.

## The target

A target names a provider and a server. `Selection` gains `Provider`;
`Selection.Key()` begins with it, so the same server name on another
provider is another target (names don't collide across the three providers
today, but nothing should depend on it).

- **Requests.** The panel's `desired.json` for a multi-provider exit has a
  fourth member: `{"provider": "pia", "server": "us_chicago",
  "requested_at": "…", "request_id": "…"}`.
  `state.DesiredRequestFor(value, providers []string)` accepts it (the server
  valid for that provider, the provider in the set), and the old three-member
  request too, read as the **active** provider's. `state.DesiredRequest`, as
  every single-provider exit uses it, is unchanged, so a single-provider
  exit given a four-member request refuses it as an invalid desired-state
  file: never a switch to the wrong provider.
- **`SERVER`** on a multi-provider exit is `<provider>/<server>`
  (`pia/us_chicago`), validated against that provider. With it set the exit
  is locked to one provider, which defeats the purpose, but it keeps the
  rule that `SERVER` locks the exit.
- **The pipeline.** The same admission pipeline, with the target's provider
  in every step:
  1. **Gates**: the target provider's catalog is fresh and lists the server;
     its credentials are readable (PIA's two files, the provider's tunnel
     config parsed at start); routing protection and NetBird as today.
  2. **Record, then change**: `attempt.json` `attempting`, with the provider,
     before any I/O.
  3. **Same provider**: today's switch, through that provider's
     `ApplyRelay`. **Another provider**: [leave](#leaving-a-provider) the
     active one; the target provider's preparation outside the mutation
     owner (PIA: a token and a registration with the tunnel's new public
     key, which gives its address and peer; Mullvad and NordVPN: nothing);
     `TunnelSource` updated and `SetActive`; then `Replace`.
  4. **Verify** with the target provider's own egress check, at its tier,
     for up to the switch timeout (60 seconds). Failure is a failed attempt,
     re-applied on the backoff as today, on the target provider: the exit
     never goes back to the previous provider by itself.
- **Attempt records.** `attempt.json` gains `provider` beside `target`, and
  `Rejected` keys and release signatures include it (a refused PIA login
  waits for PIA's files, not Mullvad's catalog). An attempt file without
  `provider` is the active provider's, which is what a single-provider exit
  always wrote. An `attempting` attempt found at start for another provider
  than the tunnel's is inspected as today: the target isn't live, so it is
  "The last switch was interrupted; retrying automatically."
- **Drift.** A live server identified in the active provider's catalog that
  isn't the target is drift as today; a live tunnel of another provider than
  the target's (after an interrupted change) is "no live peer" for the
  target, and the target is applied again.
- **Failover** ([its design](failover.md)) stays within the target's
  provider **(owner)**.

### Key handling

Mullvad and NordVPN tunnels carry the account's own key from their config.
PIA's key is generated for its registration, as today. Each provider's key
stays in its own config or state; `Replace` sets the target's. No key is
ever reused across providers.

## Leaving a provider

Before another provider's tunnel comes up, everything provider-specific of
the active one must be gone. A new hook:

```go
// Leave undoes what the provider holds beyond the tunnel itself, before
// another provider's tunnel replaces it. An error refuses the change
// (it wraps ErrMutationRefused) and nothing else is touched.
Leave(ctx context.Context, a *Applier) error
```

- **PIA**: stop port forwarding (no new bind), remove table
  `ip molebridge_forward` (`removeForwardRules`), clear `forwarded_port`
  and `port_forward_error` from the next record, and forget the registration
  in `tunnel.json` (the server forgets it by itself). Its return-path rules
  go in `Replace`, step 3. If the forward table can't be removed, `Leave`
  fails and the change is refused: a forwarded port must never point into
  another provider's tunnel.
- **PIA's repair of an interrupted switch**, which runs before the gates on
  every pass, runs only while PIA is active.
- **Mullvad, NordVPN**: nothing beyond the tunnel.

The ingress guard (`inet molebridge_guard`) is per interface name, not per
provider, and stays.

## One interface name

Every provider's tunnel is the same interface, `EXIT_IF`, default `vpn` on
a multi-provider exit **(owner)** (the single-provider defaults `mullvad`,
`pia` and `nordvpn` would mislead). This keeps the routing contract, the
ingress guard and NetBird's interface exclusion
(`NB_EXTRA_IFACE_BLACKLIST`, checked against the stored profile at start)
exactly as they are: one name, never changing while the exit runs. The
alternative, one name per provider and an exclusion list naming all of them,
changes the contract's spec at every switch and is not taken.

## Settings, files and credentials

| Setting | Meaning |
|---|---|
| `PROVIDERS` | Two or three of `mullvad`, `pia`, `nordvpn`, comma-separated, no repeats. Set: a multi-provider exit. Refused with `TUNNEL_BACKEND=gluetun`, `EXIT_KIND=sidecar`, or a gluetun provider. |
| `PROVIDER` | Required with `PROVIDERS`, one of them: the provider the tunnel starts on the first time. Later starts use the provider in `tunnel-provider.json` **(owner)**. |
| `EXIT_IF` | The one interface name; default `vpn` with `PROVIDERS`. |
| `PIA_PORT_FORWARD`, `PIA_PORT_FORWARD_TARGET` | As today, applying while PIA is active. |

Files:

- **Tunnel configs**: `tunnel/wg_confs/<provider>.conf` for each provider in
  `PROVIDERS` (not `<EXIT_IF>.conf`), each parsed and validated at start by
  `tunnelconf.Load` for its provider. A missing or invalid one refuses the
  start. The other-configs warning names files that are neither.
- **Secrets**: PIA's `secrets/pia/username` and `password`, as today, when
  `pia` is in the set. Mullvad and NordVPN keep their keys in their configs.
- **State**: `tunnel-provider.json` (the active provider, private, written
  before each `Replace`); per-provider `location-<id>.json`; PIA's
  `tunnel.json` as today.
- **Catalogs**: `state/applier/relays-<provider>.json` for each provider,
  each with its own error file. `relays.json` is **not** written on a
  multi-provider exit, so a reader that expects one provider's catalog there
  (an older panel, the proxy) finds none and offers nothing, rather than
  the wrong provider's servers.

**Credentials in one container** widen what a compromised exit holds: every
provider's key and PIA's password instead of one. The docs say so where the
multi-provider exit is described, beside the advice to run single-provider
exits when that matters **(owner)**.

## The catalogs in one process

This is why piece 0 comes first. A single NordVPN exit used about 190 MB
at 0.8.0, against a target of 70 MB; 0.9.3's parser should have fixed most
of it, but it hasn't been measured live
([the memory work](../../ROADMAP.md#smaller-memory-with-large-server-catalogs)).
A multi-provider exit holds every provider's catalog.

- **Resident**: the active provider's validated `Entries`, as today.
- **On disk only**: the other providers' catalogs are refreshed on their own
  schedules, validated, written to `relays-<id>.json`, and then dropped from
  memory (and the memory returned, as after every parse). A switch to
  another provider loads its snapshot with `providers.ReadSnapshot` (the
  same validation) at the gate, and it becomes resident once that provider
  is active.
- **One refresh at a time**: refreshes are serialized across providers, so
  the peak is one provider's parse, not three.
- **Done** means a multi-provider exit with all three providers idles, and
  peaks during a NordVPN refresh, within the single NordVPN exit's measured
  figures plus a few MB, with the measurement in [testing](../testing.md). If
  NordVPN can't meet the target, the first release offers Mullvad and PIA
  only **(owner)**.

## The status record and the verdict

The record stays **schema 2** **(owner)**. Its `provider` is the provider of
the tunnel in place, `server` that provider's server, and every check is
judged against that provider's registry entry, as now. New members, present
only on a multi-provider exit:

- `providers`: the exit's `PROVIDERS`, in order;
- `requested_provider`: the panel request's provider (null without one),
  beside `requested_server`; `configured_server` carries the
  `<provider>/<server>` form when `SERVER` is set.
- `selection.target_provider`: the target's provider, beside
  `selection.target`.

During a change to another provider the `applying` records name the old
provider until `Replace` has run, then the new one. A record is built only
from one provider's evidence: `peer`, `handshake` and `egress` are always
measured on the tunnel in place.

```json
{
  "schema": 2, "kind": "overlay", "backend": "native", "provider": "pia",
  "providers": ["mullvad", "pia", "nordvpn"],
  "status": "ok", "message": "Healthy.", "checked_at": "2026-11-19T18:00:00Z",
  "server": "us_chicago", "requested_server": "us_chicago", "requested_provider": "pia",
  "configured_server": null, "request_id": "0123456789abcdef0123456789abcdef",
  "selection": {"source": "panel", "outcome": "verified", "attempt": 1,
                "target": "us_chicago", "target_provider": "pia",
                "next_action": null, "next_action_at": null},
  "checks": {"…": "as for a single-provider native overlay"},
  "port_forward": false, "forwarded_port": null, "port_forward_error": null
}
```

**Readers' configuration.** `verdict.ExitConfig` gains `Providers []string`.
A reader configured for a multi-provider exit (`PROVIDERS`, or a panel exit
`id=mullvad+pia+nordvpn`) requires the record's `providers` to equal its own
list and its `provider` to be in it; anything else is "provider mismatch".
`verdict.Target` gains `Provider`; a record whose `provider` isn't the
target's disagrees with the new reason code `not-requested-provider` (or
`not-configured-provider`).

### Old readers

Why schema 2 is safe: a reader that knows one provider (`PROVIDER=pia`)
judging a multi-provider exit's record sees either another provider
(`unknown`, "provider mismatch") or a complete, true PIA record: the tunnel
is PIA's, verified at PIA's tier. A four-member request is invalid to it,
so it judges with no panel target, and the record's own `selection` must
agree with itself, as today. A three-member request it wrote itself is read
by the exit as the active provider's, so it can't make the exit judge a
server against the wrong provider. The members it doesn't know it ignores,
as it ignores `routing_activity`. Schema 3 would make every older reader say "unsupported
status version" even when the record is true; it is kept for the day the
record must change meaning ([the lease](../../ROADMAP.md#publishing-the-lease-apart-from-the-status-record)).

## The panel

- **Configuration.** `PANEL_EXITS` takes `id=mullvad+pia+nordvpn[:label]`
  (no provider id contains `+`), kind overlay only. A single exit's panel
  reads `PROVIDERS` as the exit does.
- **Choosing.** The server list has the provider first: a provider switch
  (tabs or a select) above each provider's server list, read from
  `relays-<provider>.json`. Picking a server writes the four-member request.
  The current provider is marked; picking another provider's server says,
  before the post, that every device on the exit moves to that provider.
- **The 409 gate**, the configured lock and sign-in are unchanged.
- **Status.** The status line names the provider with the server
  ("Connected: PIA, us_chicago"). Provider fields (PIA's forwarded port) show
  only while that provider is active.
- **Switchyard's views** of single-provider exits are unchanged; one panel
  can serve both kinds.

## `molebridge init`

The menu's first question allows several native providers for a NetBird
exit; choosing more than one writes `PROVIDERS`, `PROVIDER` (the first),
`EXIT_IF=vpn` and one tunnel-config mount per provider. It refuses a
multi-provider exit with a sidecar, the proxy or gluetun, and
`tools/check-compose.sh` checks the combinations it can write.

## Testing

### Unit tests

- `internal/tunnel`: `Replace` against the fake kernel: the order of the
  four steps, the expected state at each, a failure at each step leaving no
  link, the fallback in place and the expected state matching the kernel;
  recovery after a failed `Replace` bringing up the new configuration.
- `internal/mutator` and `internal/policy`: the property tests extended
  with `Replace` in their random sequences: no state during it lets a
  protected class escape.
- `internal/applier`: with the fakes, switches between every pair of
  providers in both directions; a failed change staying on the target
  provider; PIA's `Leave` failing refusing the change; port-forward fields
  gone after leaving PIA; `attempt.json` with and without `provider`; an
  interrupted change to another provider resumed; rejected keys per
  provider; a catalog loaded from disk at the gate; a single-provider exit's
  golden records unchanged.
- `internal/state`: `DesiredRequestFor` and `DesiredRequest`, including a
  four-member request refused by the single-provider reader.
- `internal/verdict`: golden multi-provider records; `providers` mismatch;
  `not-requested-provider`; a single-provider reader judging each golden
  multi-provider record gets either "provider mismatch" or the verdict a
  single-provider record with the same evidence gets.
- `internal/exit`: the settings' refusals; per-provider configs loaded.
- `internal/panel`: `PANEL_EXITS` with `+`; the request written; provider
  fields shown only while active.

### System rig drills

The system rig grows fake PIA and NordVPN networks beside its fake Mullvad
one. Drills: a switch between every pair in both directions with the
nftables counter showing no forwarded packet outside WireGuard during the
replacement; tunnel loss right after a provider change, recovered as the
new provider; a `Replace` interrupted by a worker restart; PIA with port
forwarding left for Mullvad, with the forward table gone before the new
tunnel is up; the routing-repair drills on each provider.

### The live pass

On a live host with all three accounts: switches in both directions between
every pair of providers, each verified at the provider tier; the tunnel-loss
and repair drills on each provider; PIA with port forwarding left and
re-entered; the memory measured idle and during each provider's refresh.
The results go in [testing](../testing.md), with what wasn't run.

## Decisions for the owner

| # | Decision | Recommended default |
|---|---|---|
| 1 | Status record schema | **Stay on schema 2** with the new members: old readers see "provider mismatch" or a true record of their provider; schema 3 would blind every older reader for no safety gain |
| 2 | Kinds | **Overlay exit only** for now; the native sidecar later if asked for |
| 3 | Which providers | **Any two or three** of Mullvad, PIA, NordVPN |
| 4 | Ship before NordVPN's memory is measured | **No**: build behind the setting; if NordVPN misses the target, ship Mullvad and PIA first |
| 5 | Every provider's credentials in one container | **Accept**, opt-in, with the wider exposure stated in the docs next to the setting |
| 6 | The proxy on a multi-provider exit | **Refused** for now |
| 7 | Failover to another provider | **No**: failover stays within the target's provider |
| 8 | The provider after a restart | **The last active one** (`tunnel-provider.json`), not `PROVIDER`, so a restart doesn't move everyone |
| 9 | The interface name | **`vpn`** by default with `PROVIDERS` |
| 10 | PIA port forwarding on a multi-provider exit | **Allowed** while PIA is active, torn down before any other provider |
