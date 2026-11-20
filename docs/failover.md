# Automatic failover

Failover is an extra for an exit on the native backend. When the server you
chose keeps failing, the exit moves to a **backup** server of the same
provider, says so everywhere it reports status, and tries your server again
later. It is **experimental and off by default**.

It changes nothing about the guarantee of the way in it runs on. A backup is
a server like any other: the exit switches to it through the same checks and
verifies it the same way, and between two servers forwarded traffic meets
the exit's unreachable fallback, as in any switch. Failover never sends
traffic outside the tunnel to keep it flowing.

Without failover, Molebridge never picks another server by itself, except
when the provider retires the one you chose
([a server the provider retires](architecture.md#a-server-the-provider-retires)):
it retries your server on its backoff ([retries](operations.md#retries)) and
reports that it is failing.

## Status

The policy and the exit's wiring have unit tests, and the system rig in CI
runs six drills against fake Mullvad servers: a failover, the return, a
failed return, a host network that is down (no failover), every backup
failing, and a panel request during an episode. The live drill on a real
provider has **not run**. [Testing](testing.md) is the record of what ran on
real hosts; the drills and the live drill still to run are in the design
record's [testing section](design/failover.md).

## Where it works

- **Ways in:** the [NetBird exit](netbird-exit.md) on the native backend
  (Mullvad, PIA, NordVPN), and the [native sidecar](native-sidecar.md).
- **Not with gluetun.** With `TUNNEL_BACKEND=gluetun` (a gluetun NetBird
  exit or a gluetun sidecar) the exit refuses to start with failover on:
  gluetun reconnects by itself.
- **Not on a [multi-provider exit](multi-provider.md).** The exit refuses
  `FAILOVER` with `PROVIDERS` set.
- The [proxy](proxy.md) is unaffected: it refuses new connections while a
  failover switch runs, then serves through the backup.

## Turn it on

The settings are the exit's. The bundled Compose files don't pass them, so
set them on the `exit` service in a `compose.override.yaml` (with
`COMPOSE_FILE` set, add the override to the list):

```yaml
services:
  exit:
    environment:
      FAILOVER: same-country      # off, on, same-city, same-country or servers
      FAILOVER_AFTER: "300"       # seconds, 120 to 3600
      FAILOVER_RETURN: auto       # auto or manual
      # FAILOVER_SERVERS: se-got-wg-002,se-sto-wg-001   # with FAILOVER=servers only
```

Then recreate the exit (`docker compose up -d --force-recreate exit`,
[recovery](operations.md#recovery)). The panel has no control for any of
these: failover is a property of the exit, like `SERVER`.

| Setting | Default | Meaning |
|---|---|---|
| `FAILOVER` | `off` | `off`; `same-city` or `same-country`, backups from the provider's server list near the selected server; `servers`, the list in `FAILOVER_SERVERS`; `on`, the same as `same-city`. |
| `FAILOVER_SERVERS` | empty | With `FAILOVER=servers`, required: 1 to 8 server names valid for the provider, comma-separated, in order of preference, none of them `SERVER` and none twice. Refused with any other mode. A name the current server list doesn't have is skipped when a backup is chosen, never refused at start. |
| `FAILOVER_AFTER` | `300` | Seconds the selected server must keep failing before the exit moves, 120 to 3600, plain decimal. |
| `FAILOVER_RETURN` | `auto` | `auto` tries the selected server again on a schedule; `manual` stays on the backup until you pick a server. |

[Configuration](configuration.md) lists them with the exit's other settings.

### Which mode

- **`same-city`** (and `on`) keeps the location you chose. It needs the
  selected server to have been verified on this exit once, with 0.11.0 or
  later, so that the exit knows its city: a server never verified here has
  no backups in this mode or in `same-country`.
- **`same-country`** finds more backups. Use it, or a list, with PIA: most
  PIA regions are alone in their city, so `same-city` finds few or none.
- **`servers`** uses exactly the servers you name, in your order. It is the
  only mode that works for a server never verified on this exit.

In the two location modes the backups are the servers the list gives for
that city or country, in name order starting after the selected server's
name, so the choice is the same on every pass and after a restart. If the
selected PIA region offers port forwarding, only regions that offer it are
backups. The selected server itself and servers already tried in this
episode are never backups.

## When it moves

The exit counts only failures that belong to the server:

| Failure | Reason in the log and the record |
|---|---|
| A switch that failed: the change failed, or verification timed out with another server live | `switch-failed` |
| A handshake missing or 180 seconds old or older on the selected server | `handshake-failed` |
| An egress check with no usable answer while the tunnel received nothing but the exit's own handshake requests coming back unanswered, or PIA's silent tunnel | `tunnel-silent` |
| A PIA registration repair that ended without verifying | `repair-failed` |

These never count, and each resets the count: a request waiting for a
prerequisite (routing, NetBird, a fresh server list), a refused request (an
invalid or unlisted server, or a login the provider refused), an egress
answer that doesn't confirm the egress (it might be traffic leaving the wrong
way, and moving would hide it), an egress check that got no answer while the
tunnel still received traffic (the provider's check service is down, not the
server), a routing, NetBird or lease failure, and any verified check.

The exit moves when all of these hold on one pass:

1. The selected server is not a panel request made in the last 150 seconds.
   A new request gets its full window, counted from the request.
2. Counted failures have followed each other, with no reset, for at least
   `FAILOVER_AFTER` seconds.
3. There were at least 3 of them in that window. With the default 300
   seconds that is, for a switch that fails, the change and its re-applies
   at 1 and 3 minutes; for a live server that stops answering, the periodic
   checks about a minute apart. Failover never makes the exit check sooner
   than it would anyway.
4. The host's own network answers outside the tunnel: the exit makes an
   HTTPS request over the host's route to the provider's server-list host
   (PIA: the region's registration API first), with a 5-second limit. If it
   gets no answer, every server would fail the same way, so nothing happens
   and the count is kept.
5. A backup remains that this episode hasn't tried.

## An episode

From the first move until the exit is back on your server, or you pick a
server, is one **episode**.

- **A backup that doesn't verify** within the switch timeout (60 seconds) is
  marked tried, and the next one is tried at once. A backup that verifies
  stays.
- **At most 3 backups** are tried in one episode. If none verifies, the
  episode is **exhausted**: the exit goes back to your server and retries it
  on its usual backoff, and no new episode starts for 30 minutes.
- **A backup that later keeps failing** is counted by the same rule, and the
  next untried backup is tried; with none left, the episode is exhausted.
- Each failover switch waits until 90 seconds have passed since the exit's
  last change, as any repair does; the immediate return to a verified
  backup after a failed return is the one exception.

### Returning to your server

With `FAILOVER_RETURN=auto` the exit tries your server again 15 minutes after
the backup verified, then after 30, 60 and 120 minutes, and every 120 minutes
after that. Only one server can be live at a time, so each try is a switch:
devices on the exit lose their open connections for it, as in any switch.

Before a try, the exit checks what it can without switching, and waits for
the next slot if a check fails: your server must be in a fresh server list,
and with PIA its region's registration API must answer. Mullvad and NordVPN
have no way to test a WireGuard server without switching to it.

If your server verifies, the episode ends. If it doesn't, the exit switches
straight back to the backup that last verified.

With `FAILOVER_RETURN=manual` the exit stays on the backup until you pick a
server in the panel, or the backup itself keeps failing.

### What ends an episode

- Your server verified on a return.
- A new target: any pick in the panel, including your own server again or
  **Retry**, which is applied at once; a changed `SERVER`; or failover
  turned off (the exit restarts with the new settings and drops the saved
  episode).
- Your server leaving the provider's list: the
  [retired-server move](architecture.md#a-server-the-provider-retires) takes
  over, and failover then works on the server that replaced it.

Your choice is never rewritten. `state/panel/desired.json` and `SERVER` keep
naming your server throughout, and so do the record's `requested_server` and
`configured_server`. The episode is kept in `failover.json`, in
`state/applier/` or `PRIVATE_STATE_DIR` ([state
files](configuration.md#state-files)), so a restart resumes it. After a
reboot a return that is due runs at once, and a `FAILOVER_AFTER` window in
progress starts over.

## What it shows

**The panel.** A connected exit on a backup reads **connected to backup**,
with a note:

```text
Connected to backup se-got-wg-002. se-got-wg-001 has kept failing since 18:00 UTC; trying it again at 18:15 UTC.
```

With `FAILOVER_RETURN=manual` the note ends "pick it again to return."
instead. The exit's tab says "backup" beside the place. An exhausted episode
shows the usual failed state with "No backup verified; retrying
se-got-wg-001." An exit with `SERVER` set fails over too; the panel still
offers no switching controls, and shows the backup and the return time.

While a failover switch runs the panel shows "switching", and a pick gets 409
"A switch is in progress; wait for it to finish." as for any switch. On a
backup, picking is open.

**`molebridge status`** prints `state: ok (connected to backup)` and
`reasons: failover`. A failed or unknown verdict during an exhausted episode
ends its reasons with `failover-exhausted`.

**Everything that runs only on `ok`** keeps working on a backup, because the
traffic is verified in the tunnel: `/readyz` answers 200, the proxy serves,
PIA's port forwarding runs, and the Gatus push is up, with the label in its
message. The label and reason say the server isn't the one you chose.
`/api/status` carries the verdict's `failover` member (`from`, `to`, `since`,
`next_return_at`), and the record's own `failover` member has the phase and
the servers tried ([the status record](architecture.md#the-status-record)).

**PIA's forwarded port changes.** The port belongs to a registration, so a
failover to another region, and the return, each end the old port and bind a
new one; `forwarded_port` changes and [`port-sync`](tools-reference.md#port-sync)
follows it.

**An older reader** (a Switchyard, `molebridge status` or a bridge from before
failover) shows an exit on a backup as `failed`, "verification failed", never
as connected. Upgrade a separate Switchyard before you turn failover on.

**The log** tells each step on one line:

```text
applier: the selected server has kept failing for <n> s (<reason>); moving to backup <server>
applier: backup <server> did not verify; trying the next
applier: no backup verified; staying on the selected server
applier: trying the selected server again
applier: the selected server still fails; back to backup <server>
applier: the selected server verified again; failover ended
applier: a new selection ends the failover
applier: the host's network does not answer; not failing over
```

## Refusals

A bad setting stops the exit at start, with one line and nothing changed
(`check-config` reports the same):

| Message | Cause |
|---|---|
| `molebridge-exit: FAILOVER must be off, on, same-city, same-country or servers` | Another value |
| `molebridge-exit: FAILOVER=servers needs FAILOVER_SERVERS` | The list is empty |
| `molebridge-exit: FAILOVER_SERVERS is only for FAILOVER=servers` | A list with another mode |
| `molebridge-exit: FAILOVER_SERVERS lists more than 8 servers` | Too many names |
| `molebridge-exit: FAILOVER_SERVERS is too long` | Over 1024 characters |
| `molebridge-exit: FAILOVER_SERVERS has a name that isn't a server name for the provider` | A name in the wrong form, such as a Mullvad hostname on a PIA exit |
| `molebridge-exit: FAILOVER_SERVERS must not list SERVER` | The configured server is in the list |
| `molebridge-exit: FAILOVER_SERVERS lists a server twice` | A repeat |
| `molebridge-exit: FAILOVER_AFTER must be 120 to 3600 seconds` | Out of range, or not a plain number |
| `molebridge-exit: FAILOVER_RETURN must be auto or manual` | Another value |
| `molebridge-exit: FAILOVER needs TUNNEL_BACKEND=native: gluetun reconnects by itself` | Failover on with the gluetun backend |
| `molebridge-exit: FAILOVER is for single-provider exits; a multi-provider exit (PROVIDERS) has none` | Failover on with `PROVIDERS` |

[Troubleshooting](troubleshooting.md#failover) covers an exit that fails over
when you don't expect it, or doesn't when you do.
