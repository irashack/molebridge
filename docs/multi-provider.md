# Multi-provider exit

A multi-provider exit is one [NetBird exit](netbird-exit.md) that can carry
Mullvad, PIA or NordVPN, one at a time. In Switchyard you pick the provider
and the server in one step. Everyone using the exit shares its current
provider: to put devices on different providers at the same time, run
single-provider exits side by side, which stay exactly as they are. It is an
extra, and **experimental**.

Its guarantee is the NetBird exit's: forwarded traffic leaves through the
tunnel or not at all. A change of provider is a switch. The exit never has
two providers' tunnels up: it takes the old tunnel down, and between the two
forwarded traffic meets the exit's unreachable fallback. A change that fails
never falls back to the previous provider; it stays failed, fail-closed, and
retries on the provider you picked.

## Status

**Built, but switched off in release builds.** Every piece described on this
page is built and covered by unit tests and by system rig drills in CI
against fake Mullvad, PIA and NordVPN networks. Only builds with the `drill`
tag accept it: the drills, the system rig's `molebridge-drill`, and
`molebridge init` run as `go run -tags drill ./cmd/molebridge init`. The live
pass with three real accounts has **not run**. Memory was measured once, on
a test host with all three providers: 52 MB idle and 64 MB at peak, against
a 70 MB target (a NordVPN-only exit on the same image used 50 MB and 59 MB).
A later release turns it on once the live pass has run; its changelog will
say so. [Testing](testing.md) is the record of what ran on real hosts, and
the [design record](design/multi-provider.md) lists the drills.

A release build refuses it everywhere, with these lines:

- the exit, at start and in `check-config`: `molebridge-exit: PROVIDERS is
  set, but multi-provider exits are not available in this release yet; see
  docs/design/multi-provider.md`;
- the panel, for a single exit: `molebridge panel: PROVIDERS is set, but
  multi-provider exits are not available in this release yet; see
  docs/design/multi-provider.md`, and in `PANEL_EXITS`: `molebridge panel:
  PANEL_EXITS: multi-provider exits are not available in this release yet;
  see docs/design/multi-provider.md, in '<entry>'`;
- `molebridge init`: `molebridge init: a multi-provider exit is not available
  in this release yet; see docs/design/multi-provider.md.`

The panel and `init` follow the exit's switch, so a release never offers a
provider its exit can't change to. The rest of this page describes what a
build with the feature on does.

## Limits

- **The NetBird exit on the native backend only.** Not the sidecar, not
  gluetun, and not with the [proxy](proxy.md), [failover](failover.md) or the
  [network exchange](exchange.md): see [refusals](#refusals).
- **Every provider's credentials are in one container.** The exit holds each
  provider's tunnel key and, with `pia` in the set, PIA's login. A
  compromised multi-provider exit gives away all of them, not one. Where that
  matters, run single-provider exits side by side instead.
- **PIA recovers slowly.** In the system rig, a tunnel lost right after a
  change came back in about 1.5 seconds on Mullvad and NordVPN and about
  90 seconds on PIA; a change from Mullvad to PIA interrupted between
  removing the old tunnel and creating the new one needed a second attempt
  and finished about 65 seconds later (PIA to NordVPN: 5 seconds). The likely
  cause, PIA's login and key registration running again on each recovery, has
  not been confirmed. These are fake networks; real PIA has not been timed.
- Two providers' configs holding the same key are not refused.

## Set it up

`molebridge init` on a drill build writes it ([setup](setup.md) has the rest
of init). Its first question takes two or three of `mullvad`, `pia` and
`nordvpn`, comma-separated (`"provider": "mullvad,nordvpn"` in an answers
file); choose `netbird-exit`, with or without `switchyard`. The first
provider is where the tunnel starts the first time. `init` writes
`compose.yaml`'s `exit` with two differences: it passes `PROVIDERS`, and it
mounts one tunnel config per provider, `tunnel/wg_confs/<provider>.conf`,
read-only, in place of the whole `tunnel/wg_confs` directory, so Compose
refuses to start if one of them is missing. The `.env` holds `PROVIDERS` in
the order you gave, `PROVIDER` set to the first, `EXIT_IF=vpn`, and PIA's
port-forwarding settings when `pia` is one of them. The panel gets
`PROVIDERS` too.

Without `init`, an override for `compose.yaml` sets the same four on the
`exit` service, and `PROVIDERS` and `PROVIDER` on `switchyard`:

```yaml
services:
  exit:
    environment:
      PROVIDERS: mullvad,pia,nordvpn
      PROVIDER: mullvad
      EXIT_IF: vpn
      NB_EXTRA_IFACE_BLACKLIST: vpn
  switchyard:
    environment:
      PROVIDERS: mullvad,pia,nordvpn
      PROVIDER: mullvad
```

### The settings

| Setting | Meaning |
|---|---|
| `PROVIDERS` | Two or three of `mullvad`, `pia` and `nordvpn`, comma-separated, each once. Set, the exit is a multi-provider exit; empty, it is a single-provider exit as before. |
| `PROVIDER` | Required, one of `PROVIDERS`: where the tunnel starts the first time. Later starts come back on the provider the exit was last on, kept in `tunnel-provider.json`, so a restart doesn't move everyone. |
| `EXIT_IF` | The one interface name every provider's tunnel uses: `vpn` by default with `PROVIDERS`. |
| `NB_EXTRA_IFACE_BLACKLIST` | The same name, so NetBird keeps ICE off the tunnel ([the blacklist](operations.md#netbird-interface-blacklist)). |
| `PIA_PORT_FORWARD`, `PIA_PORT_FORWARD_TARGET` | As for a PIA exit, applying while PIA is in use. The forwarded port is removed before the tunnel leaves PIA, and no port is forwarded while another provider is in use. |
| `SERVER` | Optional, as `<provider>/<server>`: [below](#locking-it-to-one-server). |

[Configuration](configuration.md) lists them with the exit's other settings.

### The tunnel configs

Each provider has its own config, `tunnel/wg_confs/<provider>.conf`
(`mullvad.conf`, `pia.conf`, `nordvpn.conf`), not `<EXIT_IF>.conf`. Make each
as for a single exit of that provider ([setup](setup.md)), with
`prepare-config`, `prepare-config --pia` or `prepare-config --nordvpn`, and
the output path named. The exit checks each at start against its own
provider's form ([the tunnel config](configuration.md#the-tunnel-config)); a
missing or refused one stops the start, and any other `.conf` file in the
directory is ignored with a warning. With `pia` in the set, PIA's login goes in
`secrets/pia/username` and `secrets/pia/password`, as for a PIA exit.

## Using it in Switchyard

The exit's page has a row of provider tabs above the server list, one per
provider. The provider in use is marked "in use", and the list below it is
that provider's servers, read from `state/applier/relays-<provider>.json`.
The tabs are links (`?provider=<id>`), so the page works without JavaScript.

Another provider's tab lists its servers with a warning before you pick:

```text
Picking a PIA server moves every device on this exit from Mullvad to PIA.
```

The two-tap confirm repeats it. The provider is the exit's, not yours, so
everyone using the exit moves with it. A pick sends the provider with the
server, and the panel checks the server against that provider's list:
otherwise it answers 400 `unknown provider` or 400 `unknown or unlisted
server`. Saved and recent servers are kept per provider.

The status line names the provider with the server ("Connected: PIA,
ex_example"), and PIA's forwarded port shows only while PIA is in use. A
switch in progress, the 409 for a second one, the set-in-configuration lock
and sign-in work as for any exit ([Switchyard](switchyard.md)).

In a Switchyard that serves several exits, write such an exit in
`PANEL_EXITS` as `id=mullvad+pia[+nordvpn][:label]`: two or three providers
joined by `+`, each once, an overlay exit (`/overlay` may be written, nothing
else). The default label joins the providers' names, such as "Mullvad + PIA
+ NordVPN". One panel can serve multi-provider and single-provider exits;
the single-provider views are unchanged. Metrics label the exit's provider
`mullvad+pia` (the providers joined by `+`).

## What happens on a change of provider

1. The exit records the attempt, with the provider, before it changes
   anything.
2. The provider in use lets go of what it holds beyond the tunnel. For PIA:
   the forwarded port's firewall table is removed (if it can't be, the change
   is refused and retried, so a forwarded port never points into another
   provider's tunnel), its registration is forgotten, and forwarding stops.
3. The target provider prepares outside the tunnel. PIA logs in and
   registers the target config's key; Mullvad and NordVPN need nothing.
4. The exit writes the new provider to `tunnel-provider.json`, then replaces
   the whole tunnel: the old link goes, and the new one comes up on the same
   interface name with the new provider's key, addresses and peer.
5. The exit verifies the new server with that provider's own egress check,
   for up to 60 seconds. A failure is retried on the usual backoff
   ([retries](operations.md#retries)), on the new provider.

A refusal before step 4 (PIA refusing the login or the registration, or the
forwarding table that can't be removed) leaves the previous provider's
tunnel as it was. If the tunnel is lost during or after a change, the exit's
recovery brings back the provider in `tunnel-provider.json`, never the
previous one. A change interrupted by a restart is finished on the new
provider.

The status record stays schema 2 and names the exit's providers in
`providers`, the request's in `requested_provider`, and the target's in
`selection.target_provider` ([the status
record](architecture.md#the-status-record)). `molebridge status` judges it
for `PROVIDERS`, and `check-config` prints every provider's config. Each
provider's server list is refreshed on its own schedule, one at a time, and
only the list of the provider in use stays in memory. `relays.json` is not
written, so an older reader expecting one provider's list there finds none
rather than the wrong one. A reader that knows one provider shows such an
exit as "provider mismatch", or, while its own provider is in use, a true
record of it; never connected on a server it didn't ask for.

## Locking it to one server

`SERVER` on a multi-provider exit names the provider: `SERVER=nordvpn/nl9001.nordvpn.com`
locks the exit to that provider's server, as `SERVER` does on any exit
([a server set in configuration](configuration.md#a-server-set-in-configuration)).
Switchyard shows it read-only. A bare name is refused, and when it fits the
naming of one or more of `PROVIDERS` the message suggests each:

```text
Invalid SERVER "nl9001.nordvpn.com"; with PROVIDERS set, SERVER is <provider>/<server> with one of mullvad, pia, nordvpn, for example "nordvpn/nl9001.nordvpn.com"; no change applied.
```

A Mullvad hostname is also a valid PIA region id in form, so both may be
offered; put the right provider in front.

## Moving back to one provider

The stored NetBird profile keeps the interface blacklist the peer enrolled
with, so a multi-provider exit's profile excludes `vpn`, not a
single-provider exit's default `EXIT_IF` (`mullvad`, `pia` or `nordvpn`).
To move the exit back to one provider on the same NetBird profile:

1. Set `PROVIDER`, and remove `PROVIDERS`, on the exit and the panel.
2. Either keep `EXIT_IF=vpn` and `NB_EXTRA_IFACE_BLACKLIST=vpn`, and rename
   that provider's config to `tunnel/wg_confs/vpn.conf`; nothing else is
   needed.
3. Or set `EXIT_IF` and `NB_EXTRA_IFACE_BLACKLIST` to the new name, and,
   with the exit stopped, run [`fix-blacklist`](operations.md#netbird-interface-blacklist)
   with the new `EXIT_IF`. Otherwise the exit refuses to start, because the
   profile doesn't exclude the tunnel interface.

Then recreate the exit and the panel ([recovery](operations.md#recovery)).
The leftover `relays-<provider>.json` files and `tunnel-provider.json` are
not read by a single-provider exit.

## Refusals

With the feature on, the exit refuses at start, with one line and nothing
changed:

| Message | Cause |
|---|---|
| `molebridge-exit: PROVIDERS must be two or three of mullvad, pia and nordvpn, comma-separated, each once` | Fewer than two, more than three, an unknown id or a repeat |
| `molebridge-exit: PROVIDERS takes native providers only (mullvad, pia, nordvpn), not <id>` | A `gluetun-*` provider in the list |
| `molebridge-exit: PROVIDERS needs TUNNEL_BACKEND=native: a gluetun exit carries one provider` | The gluetun backend |
| `molebridge-exit: PROVIDERS is for the overlay exit (EXIT_KIND=overlay); a sidecar carries one provider` | A sidecar |
| `molebridge-exit: PROVIDER is required with PROVIDERS: the provider the tunnel starts on the first time` | `PROVIDER` unset |
| `molebridge-exit: PROVIDER must be one of PROVIDERS` | `PROVIDER` not in the list |
| `molebridge-exit: FAILOVER is for single-provider exits; a multi-provider exit (PROVIDERS) has none` | [Failover](failover.md) on |
| `molebridge-exit: EXCHANGE_URL is not supported on a multi-provider exit (PROVIDERS) yet` | The [network exchange](exchange.md) |

A missing or refused `<provider>.conf` stops the start with the same lines a
single exit's tunnel config gives ([troubleshooting](troubleshooting.md#startup)).

The panel refuses `PROVIDERS` and `PROVIDER` with the exit's messages, after
`molebridge panel: `, and in `PANEL_EXITS`:
`PANEL_EXITS: a multi-provider exit takes two or three of mullvad, pia and nordvpn, each once, in '<entry>'`
and `PANEL_EXITS: a multi-provider exit is an overlay exit, in '<entry>'`.
Such an exit can't be in `PANEL_PROXY_STATUS`
(`PANEL_PROXY_STATUS: '<id>' is a multi-provider exit; the proxy does not run beside one`)
or `PANEL_NETWORK_EXITS`
(`PANEL_NETWORK_EXITS: '<id>' is a multi-provider exit, which the network exchange does not carry`).

The proxy refuses to start with `PROVIDERS` set: `molebridge proxy: refusing
to start: PROVIDERS is set: the proxy is not supported on a multi-provider
exit`.

`molebridge init` refuses several providers with the sidecar, the proxy,
`port-sync` or a `gluetun-*` provider, more than three, or one listed twice,
and writes nothing then. For example: `molebridge init: the proxy can't run
on a multi-provider exit: it serves one provider's tunnel and refuses to
start with PROVIDERS set. Leave the proxy out, or choose one provider.`
