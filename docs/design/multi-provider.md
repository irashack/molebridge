# Design: one exit for several providers

Status: **built, experimental, and in release builds** (switched on after
the live pass of 2026-11-20 on a drill image, issue #79). Every piece below,
`molebridge init` included, is built. The user documentation is
[one exit for several providers](../multi-provider.md); where this record and
the code disagree, the code wins and that page follows the code. This file
stays as the design: the target shape, the pieces, their boundaries and how
each is tested, for the roadmap's [one exit for several
providers](../../ROADMAP.md#one-exit-for-several-providers). The choices
marked **(owner)** are product decisions; the owner took every recommended
default on 2026-11-19 ([decisions for the owner](#decisions-for-the-owner)).

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
reads its tunnel from a `TunnelSource`; a single-provider exit uses the
single-provider source, which is today's code moved (piece 6 sets the
multi-provider one). On the system rig, a `Replace` killed between its
links and a tunnel lost right after a change both come back as the new
provider's ([System rig drills](#system-rig-drills)).

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

**As built (piece 2).** `applier.Config.Providers` (two or three native
providers, `Provider` among them) makes a multi-provider applier; nothing
sets it before piece 6, so no setting of the release binary reaches it.
`New` refuses more than three, a repeat, a gluetun provider, the sidecar
kind and automatic failover (decision 7: failover is for single-provider
exits for now, so on a set it is refused rather than reworked). The
applier's `hooks`, `catalog` and `spec` fields stay, always the active
provider's: `SetActive` writes `tunnel-provider.json` (private, `{"provider":
id}`) and then re-points them, with the provider's refresh schedule and
location memory, so the code that inspects the tunnel in place is
unchanged. `Healthy`, on another goroutine, reads the active hooks through
an atomic copy. The catalogues are `relays-<id>.json` and
`relay-error-<id>.json`; only the active one's is resident, another's is
read from disk when asked for (`ProviderSet.Catalog`) and dropped at the
end of the pass, and the inactive ones are refreshed on their own
schedules, at most one per pass, then dropped. A start reads
`tunnel-provider.json` (anything but one of the set's ids is ignored) and
falls back to `Provider`. A single-provider exit's files and records are
locked byte for byte by `internal/applier/single_provider_test.go` and the
golden records.

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

**As built (piece 3).** The applier's side only, still behind
`Config.Providers`, which no setting sets. `Selection.Provider` and the
attempt's `provider` are set on a multi-provider exit only, so a
single-provider exit's keys, signatures and files are as before (locked by
`single_provider_test.go`); `provider` follows `target` in `attempt.json`,
and one naming a provider outside the set is read as naming none. A
request without `provider` must be valid for the active provider. A panel
target's key is `<provider>/<request token>`, and a release signature
begins `<provider>:`. A retired server is replaced by its successor only
on the active provider, whose catalogue and location memory are resident;
another provider's retired server is refused until that provider is
active. At the gate the target provider's catalogue is read from disk and
kept while it is the target; its credentials are asked of the provider
when it can tell (`CredentialChecker`: PIA's two files), pending with
"Waiting for PIA's credentials; …" otherwise. The change itself
(`internal/applier/target.go`) records the attempt, calls the active
provider's `Leave`, then the target's new `EnterTunnel` hook, which does
what must happen outside the mutation owner first (PIA: a token and a
registration of the target config's public key) and then calls back for
`SetActive` and the exit's `Replace`, then (PIA) sets the address and peer
as a switch does. The exit's part is an interface, `ProviderTunnels`
(`PublicKey`, `Replace`), required with `Config.Providers`; nothing
implements it outside the tests yet: the per-provider configs, the
`TunnelSource` that reads `tunnel-provider.json` and the call into
`tunnel.Manager.Replace` come with piece 6. A refusal before `SetActive`
(a refused PIA login or registration, a `Leave` that fails) leaves the
previous provider's tunnel as it was; a failure after it leaves the target
provider active, and the retry, once the exit's recovery has brought up
that provider's config, is a switch on it through its `ApplyRelay`. PIA's
`Leave` is piece 4's ([below](#leaving-a-provider)). The status record names the providers since piece 5 ([below](#the-status-record-and-the-verdict)).
Tested with a fake kernel and a fake `ProviderTunnels`: every change
between Mullvad, NordVPN and PIA, failures before and
after `SetActive`, interrupted changes resumed after a restart, rejections
per provider, both gates and `SERVER=<provider>/<server>`
(`internal/applier/target_test.go`); no rig, namespace or live test.

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

**As built (piece 4).** PIA's `Leave` removes the forwarding table (on a
native sidecar, which a multi-provider exit is not, the firewall's
forwarded port) first; a failure is logged and refuses the change
(`ErrMutationRefused`, a definite failure retried on the backoff) with
nothing else touched, PIA's tunnel and registration included. Then it
deletes `tunnel.json` (a failure there refuses the change too), stops
forwarding and clears its error, so no record after it has
`forwarded_port` or `port_forward_error` (the next provider's record has
neither member) and no bind runs while another provider is active; should
PIA come back, its leftover-port cleanup runs again before it forwards.
PIA's return-path rules are left to the exit's `Replace`, which is piece
6's to wire. Tested with the fake kernel
(`internal/applier/leave_test.go`: the table is gone and the registration
forgotten before the tunnel is replaced, a table that can't be removed
refuses the change and is retried, and the port is forwarded again after
coming back to PIA) and a namespace drill that removes a real forwarding
table (`internal/exit/pia_leave_drill_test.go`, in CI), and on the system
rig with a fake PIA server forwarding a port
(`TestSystemRigMultiProviderPIAForwardLeft`: the table is gone before
Mullvad's tunnel is up; see [System rig drills](#system-rig-drills)); not on
a real tunnel.

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

**As built (piece 6).** `exit.LoadSettings` reads `PROVIDERS` (empty is
unset, as Compose passes it) and refuses the combinations above, plus
`FAILOVER` on (decision 7) and `EXCHANGE_URL`, whose exchange carries one
provider's requests and catalogue. With `EXIT_IF` unset it fills `vpn` into
the environment itself, so the contract, NetBird's gate, `fix-blacklist`
(`nbprofile.TunnelFromEnv`) and the cleanup child see the same name. Each
`<provider>.conf` is loaded by `tunnelconf.Load` for its provider into
`Settings.Confs` (`Settings.Conf` is nil on such an exit), and the start
provider is the one `tunnel-provider.json` names (read with
`applier.ReadTunnelProvider`, the applier's own rule), else `PROVIDER`. The
worker's `multiSource` is the `TunnelSource`: it reads the file on every
call and keeps the last provider read when the file can't be read, so a
passing error never brings back another provider's tunnel; the remembered
peer is kept with the provider it was set for (Mullvad and NordVPN come
back on it, PIA restores its own). The contract's expected state at a start
is the start provider's config. `exitTunnels` is the `ProviderTunnels`:
`PublicKey` derives each config's public key, and `Replace` calls
`tunnel.Manager.Replace` with the config last brought up as `from` (the
owner adds every address still live on the link, so PIA's per-registration
rules 94 and 98 are removed too) and the target's config on the target's
peer as `to`. The applier gets every provider's hooks, `PROVIDER`'s the
same instance. The supervisor accepts a record of any of the exit's
providers with `providers` naming them all in order; the starting record
carries the piece 5 members, PIA's only when PIA is active. The proxy
refuses `PROVIDERS`; `molebridge status` judges for the set and
`check-config` prints each config. Not built here: the Compose files and
`tools/check-compose.sh` (with piece 8), the exchange, and a check that no
key is reused across providers (each provider's tunnel uses its own
config's key, but two configs holding the same key aren't refused).
Tested: the refusals, the configs, `EXIT_IF`'s default and the restart
provider (`internal/exit/multi_provider_settings_test.go`), the source,
remembered peers, keys and the pipeline built from settings
(`multi_provider_linux_test.go`), and a single-provider exit's settings,
child environments and starting record byte for byte
(`single_provider_test.go`, generated before this piece); the replacement
on a kernel is the rig drill's.

As built (the switch, now removed): until the live pass, release builds
refused `PROVIDERS` in the exit, the panel and `molebridge init` with "...
not available in this release yet", behind one constant that only the
`drill` build tag turned on (decision 4: no shipping before NordVPN's memory
is measured). The live pass of 2026-11-20 measured it (48 MB idle, 65 MB at
peak, with all three providers), and the release after it removed the
switch: every build accepts `PROVIDERS`, with the refusals below.

As built (the rig drills): the `TestSystemRigMultiProvider*` drills
(`internal/exit/systemrig_multiprovider_test.go`,
`systemrig_mpdrills_test.go`) run the rig's `molebridge-drill` (the release
build's flags plus the `drill` tag, for its hooks: the fake PIA network's
certificate authority and the hold-replace hook) beside a fake NordVPN network and a
fake PIA network (`systemrig_pia_test.go`), by requests written to
`desired.json` (the rig drives the exit without a panel). What they
cover is under [System rig drills](#system-rig-drills).

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

**As built (piece 5).** `verdict.ExitConfig.Providers` (checked by
`verdict.NewMultiExitConfig`: an overlay exit, two or three distinct native
providers, `Provider` among them) and `verdict.Target.Provider`. A
multi-provider reader judges a record as its `provider`'s once its
`providers` equal the reader's; the target's provider is judged before its
server, with `not-configured-provider`, `not-requested-provider` (the
record's `requested_provider` must be the request's too) and, for any other
target, `not-target-server`; with no target of the reader's own, a
`restore`, `reconverge`, `retry`, `operator-retry` or `failover` record's
`selection.target_provider` must be its `provider`. A lock that doesn't
split into one of the exit's providers and a server valid for it is
`not-configured-server`. `verdict.TargetFor(exit, result, desired)` is the
reader's target for any exit: a multi-provider exit's lock split, its
request read by `state.DesiredRequestFor`, a three-member one as the
record's provider's. One departure: a single-provider reader built now
calls any record with a `providers` member "provider mismatch" (it isn't
configured for the exit), rather than judging it as its own provider's;
only readers from before piece 5 do that, as below. The applier writes the
members on a multi-provider exit only (its `exitConfig` and its own target
carry the providers too), so a single-provider record is unchanged. Nothing
reads `PROVIDERS` yet: the doctor and the exit's settings come with piece
6, the panel's `+` exits with piece 7. Tested by golden records
(`internal/verdict/testdata/multiprovider_golden.json`, judged by
`multiprovider_test.go`) for a multi-provider reader, a single-provider
reader built now, and, with a copy of the rules from before piece 5, an old
reader of each provider, which must get either "provider mismatch" or the
verdict a single-provider record with the same evidence gets; and by the
applier's records after every change between the three providers
(`internal/applier/record_multi_test.go`).

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

**As built (piece 7).** `panel.ParseExits` takes `id=mullvad+pia[+nordvpn][:label]`
(two or three, each once, native only; `/overlay` may be written, any other
kind is refused; the default label joins the providers, "Mullvad + PIA").
A single exit's panel reads `PROVIDERS` and `PROVIDER` with the exit's own
refusals and messages. A multi-provider exit is
refused in `PANEL_PROXY_STATUS` (the proxy refuses `PROVIDERS`) and
`PANEL_NETWORK_EXITS` (the exchange carries one provider). The panel judges
with `verdict.TargetFor` for the set, reads each provider's catalogue from
`applier/relays-<provider>.json` and `relay-error-<provider>.json`, and
shows the provider in use: the configured lock's, else the request's while
a switch is applying, else the record's `provider`. The provider switch is
a row of links (`?provider=<id>`, so the page works without JavaScript)
above the server list; the provider in use is marked "in use", and the list
of another provider carries, before any post, "Picking a PIA server moves
every device on this exit from Mullvad to PIA." The script's two-click
confirm adds that sentence to its prompt, and saved and recent servers are
kept per provider. The form posts `provider` with `server`; the panel
checks both against that provider's catalogue (400 "unknown provider",
400 "unknown or unlisted server") and writes the four-member request,
provider first. The 409 gate, the configured lock (`<provider>/<server>`)
and sign-in run before it, unchanged. The status line under the heading
reads "Connected: PIA, us_chicago", the provider named only on evidence (a
record, a lock or a request); PIA's forwarded port shows only while the
record's provider is PIA. Metrics label such an exit's `provider`
`mullvad+pia`. Tested: `internal/panel/multi_provider_test.go` (the
entries, the refusals, the request written, the
gate and the lock, the page per provider, the status line and PIA's fields
only while PIA is active, one panel serving both kinds), the browser's
status line against the server's (`panel/js-tests/provider-line.test.js`),
and every single-provider view byte for byte
(`single_provider_golden_test.go`, generated before this piece).

## `molebridge init`

The menu's first question allows several native providers for a NetBird
exit; choosing more than one writes `PROVIDERS`, `PROVIDER` (the first),
`EXIT_IF=vpn` and one tunnel-config mount per provider. It refuses a
multi-provider exit with a sidecar, the proxy or gluetun, and
`tools/check-compose.sh` checks the combinations it can write.

As built (piece 8): `internal/tools/initmenu` offers several providers in
its prompt and `--help`. Several providers are one answer, comma-separated, in the order given
(`"provider": "mullvad,nordvpn"`), so the answers file keeps schema 1. The
exit is `compose.yaml`'s with `PROVIDERS` added and, in place of the
`tunnel/wg_confs` directory, one read-only bind of each
`<provider>.conf` with `create_host_path: false`; port-sync is refused too
(it needs the sidecar). Each ordering is its own output (the first is
`PROVIDER`), so init accepts 76 combinations, 24 more than the 52 of the
single-provider forms. `TestEveryCombination` counts them, and
`tools/check-compose.sh` checks each: the multi-provider exits resolve as `compose.yaml`'s exit apart from
`PROVIDERS` and the config mounts, which it checks on their own. The panel
receives the same `PROVIDERS` (piece 7).

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

**As built.** All five run in CI's "System rig" job, on fake networks only.
The fake NordVPN network is one server cut from the fixture catalogue,
kernel WireGuard for the exit's `nordvpn.conf` key and `10.5.0.2`, IPv4
only, an SNAT to its egress address, and `ips/insights` protected only from
it. The fake PIA network is a region list with one port-forwarding region,
the login and the status check (connected only from the server's egress
address), and one kernel WireGuard server whose `addKey` answers at its
public address and whose `getSignature` and `bindPort` answer at its tunnel
address, by TLS name; the drill build trusts the rig's certificate authority
for those calls (`MOLEBRIDGE_DRILL_PIA_CA`, `internal/exit/pia_hook_drill.go`),
and every registration hands out the same tunnel address.

- `TestSystemRigMultiProviderSwitch`: Mullvad, NordVPN, PIA, Mullvad, PIA,
  NordVPN, Mullvad, every ordered pair once, each change verified for its
  request with its provider's check, the client's traffic following, the
  tunnel's peer and `tunnel-provider.json` the new provider's, PIA's
  registration and port-forward fields gone after leaving it, and the leak
  counter at zero.
- `TestSystemRigMultiProviderTunnelLoss`: the tunnel link deleted right
  after the changes to PIA, NordVPN and Mullvad; every peer the link shows
  until it is verified again is the new provider's.
- `TestSystemRigMultiProviderInterruptedReplace`: Mullvad to PIA, then PIA
  to NordVPN, each `Replace` held between deleting the old link and
  creating the new one (`tunnel.Options.BetweenLinks`, set only by the drill
  build's worker when `<run dir>/hold-replace` exists) and the worker killed
  there. The exit stops, `tunnel-provider.json` already names the new
  provider; started again, it finishes the same request on the new
  provider, and no rule 94 or 98 of the old tunnel's addresses is left.
- `TestSystemRigMultiProviderPIAForwardLeft`: PIA forwards its port to the
  client (`PIA_PORT_FORWARD_TARGET`), then the exit changes to Mullvad while
  a loop samples the tunnel's peer and then the forwarding table; no sample
  shows Mullvad's peer with the table, and the table is last seen before
  Mullvad's peer first is. Back on PIA, it registers and forwards again.
- The repair drills: the namespace drills' drift table
  (`internal/drill/drift_drill_test.go`) has a rig of its own with no
  providers, so rather than parameterise it, the switch drill applies a
  subset of its faults on each provider's tunnel: each of rules 1, 90, 94,
  95, 96, 97 and 98 deleted, the tunnel's default route deleted and the exit
  table flushed, in each family where the exit has them, each repaired back
  to the routing it had before. The drift table's other faults (foreign
  rules and routes, a replaced rule 97, the interface down) and its
  250-millisecond bound are not checked per provider.

**Recovery times (issue 121).** The first runs had PIA slow: a tunnel lost
right after the change to PIA was back on PIA's server after 90.3 s
(NordVPN 0.4 s, Mullvad 1.3 s), and the interrupted Mullvad to PIA change
was verified 65.4 s after the kill, on its second attempt with source
`retry` (PIA to NordVPN: 5.2 s). PIA's login and registration were not the
cause: the token is kept in memory for 12 hours (the port-forward drill's
fake PIA served one login for two registrations), and a whole change to PIA,
registration included, verifies in about 5 s. Mullvad and NordVPN come back
on the peer the worker remembers; PIA's tunnel comes back with no peer,
since its peer belongs to a registration, and the applier has to register
again. That re-apply ("no live peer", trigger 3 in the
[architecture](../architecture.md)) waited out the 90-second re-apply guard
from the change. After a worker restart, the new generation's re-apply was
held by the same guard, so the interrupted change, failed by `resume` with
no peer live, waited for its one-minute retry. Neither is specific to a
multi-provider exit: a single-provider PIA exit waits the same whenever its
tunnel is lost within 90 s of a change (earlier live drills measured PIA
back in 3 to 6 s, their loss well after the last change; [testing](../testing.md)).

With the native backend, no live peer now waits `attempt.NoPeerGuardSec`
(10 s) from the last change instead. The exit's own changes never leave a
native tunnel at rest with no peer, and a tunnel with no peer passes
nothing, so failing closed is unchanged; the 10 s spaces re-applies (and
PIA's registrations) under an interface that keeps disappearing or a
worker that keeps restarting. Drift, unidentified peers and gluetun keep
the 90 s guard. Nothing about leaving a provider changed: a re-apply on the
same provider runs no `Leave`. In CI (two runs on the PR) PIA's tunnel was
back 10.1 s after the loss and verified at 10.2 s, and the interrupted
Mullvad to PIA change verified 10.25 s after the kill (attempt 2, source
`reconverge`); PIA to NordVPN 5.1 s, NordVPN's tunnel back in 0.6 s and
Mullvad's in 1.5 s. The drills fail a tunnel not back within 30 s
(`tunnelBackWithin`) or an interrupted change not verified within 45 s of
the kill (`replacedWithin`). Mullvad's and NordVPN's tunnels come back by
the worker alone, with no pipeline run, so their next verified record comes
with the periodic check, up to a minute later. Not measured on a real PIA
tunnel.

### The live pass

On a live host with all three accounts: switches in both directions between
every pair of providers, each verified at the provider tier; the tunnel-loss
and repair drills on each provider; PIA with port forwarding left and
re-entered; the memory measured idle and during each provider's refresh.
The results go in [testing](../testing.md), with what wasn't run.

## Decisions for the owner

The owner took every recommended default below on 2026-11-19
([irashack/molebridge#90](https://github.com/irashack/molebridge/issues/90)).
The marks **(owner)** above refer to these decisions.

| # | Decision | Decided (the recommended default) |
|---|---|---|
| 1 | Status record schema | **Stay on schema 2** with the new members: old readers see "provider mismatch" or a true record of their provider; schema 3 would blind every older reader for no safety gain |
| 2 | Kinds | **Overlay exit only** for now; the native sidecar later if asked for |
| 3 | Which providers | **Any two or three** of Mullvad, PIA, NordVPN |
| 4 | Ship before NordVPN's memory is measured | **No**: build behind the setting; if NordVPN misses the target, ship Mullvad and PIA first. Measured live on 2026-11-20 (65 MB peak against 70 MB) and switched on in release builds after it |
| 5 | Every provider's credentials in one container | **Accept**, opt-in, with the wider exposure stated in the docs next to the setting |
| 6 | The proxy on a multi-provider exit | **Refused** for now |
| 7 | Failover to another provider | **No**: failover stays within the target's provider |
| 8 | The provider after a restart | **The last active one** (`tunnel-provider.json`), not `PROVIDER`, so a restart doesn't move everyone |
| 9 | The interface name | **`vpn`** by default with `PROVIDERS` |
| 10 | PIA port forwarding on a multi-provider exit | **Allowed** while PIA is active, torn down before any other provider |
