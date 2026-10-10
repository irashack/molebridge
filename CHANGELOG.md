# Changelog

Molebridge is experimental. Each release lists what was tested; the full
record is in [docs/testing.md](docs/testing.md). Upgrade by following
[operations](docs/operations.md#upgrades).

## 0.6.1 (2026-10-10)

A tunnel config check fix in the routing image and `tools/molebridge.py
check`. Update every native exit; the gluetun backend's guard doesn't read
the tunnel config.

- **The routing image now refuses field names in any spelling but the
  generators'.** `address`, `privatekey`, `allowedIPs` and every other
  spelling that differs from [the table](docs/configuration.md#the-tunnel-config)
  are refused with `unsupported field on line <n>`. `wg-quick` and `wg` read
  field names in any case, and so did the check, but `10-exit-routing` reads
  only `Address`: a lowercase `address` passed the check, then the rule
  installer missed it, and Mullvad and NordVPN exits stopped with
  `10-exit-routing: tunnel configuration needs an IPv4 Address`. With PIA,
  the rule installer run on its own and `tools/molebridge.py check` took
  such a file as an addressless config, leaving rules 94 and 98 to the
  applier, while `wg-quick` would still have assigned the address (the
  image's own check refused it there, as `Address on line <n> is not
  supported for PIA`). `10-exit-routing` now refuses an `Address` in
  another case (`10-exit-routing: tunnel configuration spells Address
  another way; write it as Address`), and `tools/molebridge.py check`
  refuses a PIA config with an address or peer in any case. Configs the
  generators wrote are unaffected.

Tested with `pytest -q panel tools` on macOS and `tools/check-exit-image.sh`
on OrbStack (Docker Engine 29.4.0). On the rootless Podman host in
[testing](docs/testing.md#the-routing-image-on-rootless-podman-at-0086fac),
the new check accepted all six live native configs (four Mullvad, one PIA,
one NordVPN); no live exit has run this release.

## 0.6.0 (2026-10-10)

- Add optional `SERVER`: a server hostname, or a PIA region id. When set,
  configuration wins over `desired.json` for native Mullvad, PIA, NordVPN
  and the gluetun backend, including gluetun restart restoration. Invalid
  or unknown names report a quoted failure rather than using a panel choice.
- Switchyard shows configured exits read-only, refuses selection posts and
  exposes the setting through `/api/status`, using the applier's existing
  status snapshot. Empty `SERVER` keeps panel selection unchanged.
- **Molebridge's own routing image.** The `wireguard` container is built
  from a digest-pinned Alpine 3.24.2 with `bash`, `iproute2`,
  `wireguard-tools` and `tini`, instead of LinuxServer's WireGuard image. Its
  entrypoint checks the settings and the tunnel config before anything
  changes, installs the routing contract before the tunnel exists (a failed
  install now stops the container instead of letting the tunnel come up),
  brings the tunnel up under supervision, retrying after 2 seconds and
  doubling to 60 while the container stays up and not ready, and stops
  within about 7 seconds, leaving the rules in place. Only `<EXIT_IF>.conf`
  is used. See [architecture](docs/architecture.md#start-supervision-and-stop).
- **The tunnel config is checked against what the generators write.**
  `DNS`, `PreUp`, `PostDown`, `SaveConfig`, `FwMark`, a `Table` other than
  `off` and any other field are refused with a message that names the line
  (and the field, when it is one Molebridge accepts) and never prints the
  file. `molebridge-exit --check-config`
  (`docker compose run --rm --no-deps wireguard --check-config`) checks
  without changing anything. `tools/prepare-tunnel-config.py` now refuses
  more than one address per family and prefixes other than `/32` and
  `/128`. See [the tunnel config](docs/configuration.md#the-tunnel-config).
- **Native exits now repair drift.** Every `ROUTING_RECONCILE_INTERVAL`
  seconds (2 by default, even, 2 to 60) the exit puts back a deleted rule,
  fallback or tunnel route and removes an inserted rule at priorities 0–98
  or a foreign route in the exit table; a lost tunnel interface is brought
  back. Single deletions are contained by the remaining protections
  meanwhile; nothing is promised about traffic before an insertion is
  removed. See [drift and repair](docs/architecture.md#drift-and-repair).
- **New native rule 98**, `from <tunnel address> ipproto icmp unreachable`
  (`ipv6-icmp` for IPv6), backs up rule 94. With PIA the applier owns rules
  94 and 98: it adds both before changing the address, removes the old pair
  last, and repairs them on every pass.
- **Owner record.** The exit writes `/run/molebridge/exit-owner` on a new
  `exit-run` volume every 2 seconds. NetBird's gate and the applier count it
  as live only from the same boot and network namespace and at most 6
  seconds old; without it the applier reports `routing_ok` false and its
  health check fails. See [the owner record](docs/architecture.md#the-owner-record).
- **NetBird's gate stays in front of NetBird on native exits too.** It waits
  for the owner record and the whole contract, runs NetBird as its child in
  its own process group, and stops it as soon as the owner record isn't live
  or the guards have been incomplete for `GUARD_GRACE` seconds (30 by
  default, 5 to 30). Recovery is still `tools/molebridge.py recover`.
- **Compose.** `wireguard`: `cap_drop: [ALL]` with `NET_ADMIN` and
  `DAC_READ_SEARCH` (which lets rootful Docker read your mode-0600 tunnel
  config), `no-new-privileges`, read-only root, a tmpfs on `/run`, the
  `exit-run` volume, 15 seconds to stop. `netbird`: `init: true`, 15 seconds
  to stop, the routing settings, and `routing/contract-rules` and `exit-run`
  mounted read-only. `applier`: `exit-run` read-only. `PUID` and `PGID` are
  no longer read. NetBird 0.80.0.
- `routing/gluetun-rules` is now `routing/contract-rules`; the old name stays
  as a link until 0.7.0. The gluetun backend's `guard` runs the image's own
  entrypoint; `/custom-cont-init.d/10-exit-routing` stays in the image as a
  link until 0.7.0.

Upgrading from 0.5.3: build the routing image and check your tunnel config
with it before you recover; see [operations](docs/operations.md#upgrades).

Tested live on rootless Podman only, at `0086fac` (this release's code):
- six native exits (Mullvad, PIA, NordVPN) and a gluetun exit were upgraded
  in place;
- on the NordVPN exit: drift repair, tunnel loss, a stale owner record and
  `SERVER`.
No client traffic ran during the drills. Docker has no live pass with the
routing image: CI builds it and runs its start, repair, bring-up failure
and stop cases (`tools/check-exit-image.sh`) and the namespace drills under
busybox sh. See [the routing image on rootless Podman](docs/testing.md#the-routing-image-on-rootless-podman-at-0086fac).

## 0.5.3 (2026-10-09)

Applier only, like 0.5.2. Update every exit; a Switchyard panel on 0.5.1 or
0.5.2 works with 0.5.3 exits.

- **A failed switch no longer outlives a request that has been met.** A
  failed switch kept its message ("Peer update failed; choose a server again
  to retry.", "Switch verification timed out; …", "Routing changed during the
  switch; …") until someone chose a server again, even when the requested
  server was live and passing every check. With PIA this left an exit
  `failed` indefinitely: when a tunnel's handshake went stale, the applier
  re-registered the region on its own; if PIA's API refused that while the
  tunnel recovered on its existing registration, the handshake stayed fresh,
  so no later re-registration ran and the message stayed. Now, once a check
  has published the failure, the first later check that finds the requested
  server live and passing every check reports `ok` and logs that it cleared
  the failure. A failure while another server is live, or while any check
  fails, stays until a new request, as before; nothing is applied again
  automatically. See [architecture](docs/architecture.md) and
  [troubleshooting](docs/troubleshooting.md).

Tested: unit tests for clearing a met failure, publishing it first, and
keeping it while another server is live, a check fails, a request is
pending or none is set, including PIA's refused re-registration followed by
a recovered tunnel. The PIA case was seen live and cleared there by
selecting the same region again; the fix itself was not run on a live exit
before release.

## 0.5.2 (2026-10-09)

Applier only: the panel, routing, NetBird gate and Compose files are
unchanged from 0.5.1 apart from the panel's version string. Update every
exit; a Switchyard panel on 0.5.1 works with 0.5.2 exits.

- **One unanswered egress check no longer fails an exit.** Each health check
  asks the provider's egress check (Mullvad's `am.i.mullvad.net`, PIA's
  status call, NordVPN's insights, or the IP echo services at the `tunnel`
  tier) through the tunnel, with a 10-second limit and, until now, no second
  try. One connection that timed out made a healthy exit report `failed`
  until the next check a minute later, and turned Switchyard's `/readyz`,
  which needs every exit verified, red with it. Live exits saw this up to a
  few times an hour, each time one connection that timed out while the next,
  seconds later, succeeded. Now a check that gets no usable answer asks once
  more after 10 seconds. An answer that does not confirm the egress still
  fails at once, and now ends the check before any further request, so a
  later timeout can't turn it into a retry. Routing protection, NetBird's
  mode, the peer count and a missing or stale handshake fail without a second
  try, as before. A switch still verifies through its own loop and never
  reports `ok` before a check passes. No retry follows a first attempt that
  took over 15 seconds, and the second attempt starts no request after 30
  seconds, so a check stays well inside the 150 seconds after which a result
  counts as unknown. The applier logs each retry. See
  [status reporting](docs/architecture.md#status-reporting).
- Mullvad's check stops at the first family Mullvad says is not its exit,
  and the `tunnel` tier at the first family that fails, with echo answers
  that disagree, or that the catalogue doesn't list as the server's exit,
  failing before the host's own address is measured.
- With the gluetun backend, measuring the host's own address now ends within
  its 10 seconds in all: before, each of up to four addresses, the TLS
  handshake and each read had 10 seconds of their own.
- At the `tunnel` tier, a failed measurement of the host's own address is no
  answer: it is asked once more and then reports "Tunnel inspection or egress
  check failed." instead of "Tunnel egress did not pass the tunnel checks.",
  which now means the answers failed the checks.

Tested: unit tests for the retry, for each case that must not retry
(including a negative answer followed by a request that times out), and for
the time bounds (including NordVPN's cache retry inside a second attempt),
with Mullvad, PIA, NordVPN, the `tunnel` tier and each egress check through
gluetun. Not run on a live exit before release.

## 0.5.1 (2026-10-08)

Switchyard and documentation only: the applier, routing, NetBird gate and
Compose files are unchanged from 0.5.0.

- **gluetun exits look like gluetun.** In the provider style, an exit on the
  gluetun backend takes gluetun's dark slate, with the provider behind it as
  the accent: Mullvad's yellow, NordVPN's blue, Surfshark's teal, and a
  colour each for FastestVPN, IVPN and Windscribe. Before, a Mullvad or
  NordVPN exit through gluetun looked like the native one, and the other four
  providers had no colours at all, so their pages lost their card
  backgrounds.
- **Switchyard finishes a switch in place.** The page no longer reloads when
  a switch completes or fails, or when another tab switches the exit: the
  current exit crossfades to the new server where the browser supports view
  transitions. A failed switch now shows the server the exit is actually
  on, which the pin and latency follow; before, the page could keep showing
  the server that failed.
- **Switchyard shows how fresh the status is** ("checked 20 s ago", live),
  and offers **Copy** for a verified egress address.
- **Smoother panel.** Latency values no longer resize chips and rows when
  they arrive; their signal bars grow in. The first measurement shows
  placeholder rows, and Retest keeps the previous answers dimmed instead of
  collapsing the list. Countries unfold when opened (where the browser
  supports animating `<details>`), the exit tabs' points swing over, and
  pressing a switch or filter gives feedback. All of it stops when the
  system asks for reduced motion.
- **Panel fixes.** Searching after a country's "Fastest" line appeared
  could throw and stop filtering. A status poll no longer replaces a
  button that has keyboard focus. Saved and Fastest show NordVPN's and
  gluetun's short server names. Choosing the current PIA region works with
  JavaScript too, as the docs said. While switching, the page names the
  applier's real limit (90 seconds with gluetun, not "about a minute").
  Arming a region on a phone no longer adds a line. Servers from gluetun's
  list show their country's flag. Sign-in and error pages in the provider
  style now have their colours.
- **Documentation review.** Corrections across the guides after a review
  against the code: recreating gluetun's namespace with `recover` after
  rotating its key or changing its post-rules, which verification steps
  apply to the gluetun backend, the gate's real timing, the switch
  timeouts, backups with gluetun, and stale testing claims. New diagrams in
  [architecture](docs/architecture.md), new screenshots, and testing
  records for NordVPN and the gluetun backend on rootless Podman.
- `tools/preview-panel.py --exits` adds a NordVPN exit and two gluetun exits
  (Mullvad and Surfshark) to the preview.

Tested: unit tests, and the panel in the local preview
(`tools/preview-panel.py`) on desktop and phone widths, light and dark,
both styles, with switches that succeed and fail. Not yet on a live exit.

Upgrading from 0.5.0: pull, then recover; nothing in `.env` changes. Only
the panel behaves differently, so a Switchyard can move to 0.5.1 while its
exits stay on 0.5.0.

## 0.5.0 (2026-10-08)

- **Provider registry.** Everything Molebridge knows per VPN provider is now
  one entry in `molebridge/providers.py`, which the applier, the panel and
  the doctor read. Nothing changes for Mullvad or PIA exits.
- **Egress tiers.** `result.json` gains `egress_tier`: `provider` when the
  provider's own endpoint confirmed the egress (`exit_confirmed`, unchanged),
  `tunnel` when only Molebridge's tunnel checks did, for a provider without
  its own check, or null. The panel labels a tunnel-verified exit "tunnel
  checks only", and `/readyz` passes for both. No native provider uses the `tunnel` tier;
  FastestVPN, IVPN, Surfshark and Windscribe through the gluetun backend do.
  It is covered by unit tests only. See
  [status reporting](docs/architecture.md#status-reporting).
- **NordVPN, experimental.** `PROVIDER=nordvpn` with
  `EXIT_IF=nordvpn` and `COMPOSE_FILE=compose.yaml:compose.nordvpn.yaml`.
  `tools/nordvpn-key.py` fetches the account's NordLynx key once, from an
  access token read from a mode-0600 file or standard input, and writes the
  tunnel config; the exit stores no token. One key and the address
  `10.5.0.2/32` work on every server; IPv4 only, so forwarded IPv6 hits the
  unreachable fallback, as with PIA. The panel lists servers by country and
  city, and labels NordVPN's virtual locations. The applier identifies the
  current server by the live peer's endpoint, because NordVPN shares server
  keys within a location, and confirms egress with NordVPN's insights check,
  asking again for up to a minute when a cached answer looks stale. See
  [providers](docs/providers.md#how-nordvpn-differs).
- The applier's `/tmp` grows from 16 MB to 48 MB, room for NordVPN's server
  list download (up to 32 MiB). It uses memory only while a download is
  there.
- **Bounded latency probing in the panel.** Opening a country times every
  server in it up to 128, and a larger country (NordVPN has some) on a fixed
  sample of 128; one request names at most 256 servers. The panel runs one
  latency request per exit and four in all, answering 429 with `Retry-After`
  beyond that, and a page sends one request at a time. See
  [Switchyard](docs/switchyard.md). Covered by unit tests; not run live.

Tested: unit tests for the registry, both tiers and NordVPN, including the
NordVPN parsers against fixtures with documentation addresses, and one live
NordVPN pass at `036e1cc` on macOS with OrbStack: key setup, the server list,
switches, NordVPN-confirmed egress from a client, IPv6 blocked
([testing](docs/testing.md#nordvpn-pass-at-036e1cc)). Not run live: the
insights cache retry, the `tunnel` tier, the panel with NordVPN's list,
rootless Podman, and the fail-closed drills.

- **Experimental gluetun backend.** With `compose.gluetun.yaml`, gluetun
  owns the tunnel and brings its WireGuard providers; the panel can select
  servers for FastestVPN, IVPN, Mullvad, NordVPN, Surfshark and Windscribe
  through gluetun, shown with the provider's name and "via gluetun". Live
  passes with NordVPN on Docker; other providers and rootless Podman are
  untested. What it consists of:
  - Molebridge's routing image runs beside gluetun as a guard sidecar. It
    installs the same fail-closed rules plus rules 88/89 and a host table for
    NetBird's control traffic, and rules 91/92 so that what the exit itself
    sends to the overlay, such as the ICMP errors path MTU discovery needs,
    uses NetBird's overlay route and never gluetun's tunnel, and rules
    102-104 so that what the exit itself sends leaves only through gluetun's
    tunnel (gluetun's WireGuard socket excepted), even while gluetun
    reconnects. It puts
    everything back every few seconds as gluetun recreates its interface.
  - NetBird's gate refuses settings that turn off NetBird's control mark,
    waits for the whole guard (checked with the guard's own definitions),
    and stops NetBird, exiting non-zero, if it runs without the mark or the
    guard stays broken. Its deadlines run on the kernel's boot clock.
  - The applier reads gluetun's own server list (read-only, never
    downloaded), selects servers through gluetun's control server, and
    verifies the peer, the handshake, the guard and egress: Mullvad's and
    NordVPN's own checks, the tunnel checks for the others. It puts the last
    verified server back after gluetun restarts, and asks gluetun to
    refresh its server list once at start when that list is old.
  - `python3 tools/molebridge.py gluetun-auth` writes gluetun's role file
    and the applier's API key, which is full gluetun administration;
    `gluetun-post-rules` writes gluetun's firewall post-rules, in forms
    gluetun's own rule parser accepts. Neither calls the container engine,
    so both work with Docker and podman-compose; `gluetun-post-rules` reads
    `.env`. `doctor` and `recover`
    support the gluetun file.

  See [providers](docs/providers.md#the-gluetun-backend),
  [architecture](docs/architecture.md#gluetun-backend) and
  [configuration](docs/configuration.md#gluetun-backend). The default
  backend is unchanged.
- **A standalone guide** to [gluetun as a NetBird exit
  node](docs/gluetun-netbird-exit.md), with only Molebridge's routing guard
  and NetBird gate beside gluetun, no panel or applier: the rules, the gate,
  gluetun's settings and post-rules, choosing servers through gluetun's
  control server, and drills that need no applier.
- `recover` waits up to 180 seconds for the applier to verify the exit
  before it runs the doctor, and names the step that failed.

Tested, for the gluetun backend: unit tests for the guard and gate against a
stand-in for iproute2, the validator, the post-rules and the applier against
fakes of the kernel and gluetun's control server, and namespace drills with
gluetun's and NetBird's rules simulated, forwarded packets carrying marks 0,
0x1bd00, 0x1bd21 and 51820, and the exit's ICMP errors to clients; gluetun's
behavior was read in the v3.41.3 source. Live passes with NordVPN on Docker at
`a3bb14f` ([testing](docs/testing.md#gluetun-backend-pass-at-a3bb14f)), and at
`4933360` for the standalone form
([testing](docs/testing.md#gluetun-backend-at-4933360-and-the-standalone-form)).

Documentation fixes:

- **Rootless Podman direct path.** Publishing NetBird's WireGuard port keeps
  remote devices relayed under rootless Podman with pasta;
  [operations](docs/operations.md#exits-on-a-private-container-network) now
  gives `wireguard` its own pasta network that forwards the port. Tested as
  a Quadlet unit on one Debian host with a LAN client; a remote client, the
  podman-compose form and Docker are untested.
- **Restrictive Wi-Fi.** [Troubleshooting](docs/troubleshooting.md#clients)
  covers a healthy exit with a device that loads nothing on a network that
  breaks NetBird's QUIC relay connection, and how to make the NetBird
  client prefer WebSocket. Confirmed on macOS only.
- **DNS.** [Operations](docs/operations.md#dns) corrects what a DNS leak
  test shows through a Mullvad exit, from one observation (PIA untested),
  and says that a NetBird nameserver group served by the exit gets no
  answers.

Upgrading from 0.4.1: pull, then recover. Existing Mullvad and PIA exits
need no `.env` changes. NordVPN and the gluetun backend are new opt-in
paths: see [providers](docs/providers.md#how-nordvpn-differs) and
[the gluetun backend](docs/providers.md#the-gluetun-backend).

## 0.4.1 (2026-10-08)

A security release: overlay traffic is never delivered to the exit itself,
and NetBird must run in the configuration Molebridge supports. See the
[security advisory](https://github.com/irashack/molebridge/security/advisories/GHSA-7642-v6p6-wjfj)
for this release.

- **Overlay traffic is never delivered to the exit itself.** Routing
  initialization replaces the kernel's priority-0 `lookup local` rule with
  `not iif wt0 lookup local` at priority 1, in both address families. Packets
  arriving over NetBird are routed into the tunnel like any other forwarded
  traffic, or dropped; loopback and the host's other interfaces keep local
  delivery. NetBird's entrypoint gate and the applier's routing check require
  the new rule. See [architecture](docs/architecture.md#routing-contract).
- **NetBird must run with kernel WireGuard and its kernel firewall.**
  Molebridge supports only NetBird's daemon mode, the default profile and the
  settings in [configuration](docs/configuration.md#env). `compose.yaml` sets
  `NB_DISABLE_USERSPACE_ROUTING=true`. NetBird's entrypoint gate refuses to
  start it when that is missing, when userspace or netstack mode is forced,
  when a NetBird profile other than the default one could be used
  (`NB_CONFIG`, `NB_PROFILE`, foreground mode, or an active profile other
  than `default`), when Rosenpass is enabled in the environment or the stored
  profile, or when the stored profile names a WireGuard interface other than
  `OVERLAY_IF`. The applier's health check and the doctor fail unless the
  overlay interface is a kernel WireGuard link and NetBird's kernel firewall
  is in place; `result.json` gains `netbird_native`. See
  [architecture](docs/architecture.md#netbird-requirements).
- **Rosenpass, NetBird SSH, DNS nameservers and domain routes are not
  supported on the exit peer.** Leave them off for it; Rosenpass stops NetBird
  from starting. See [requirements](docs/prerequisites.md#netbird).
- The exit no longer answers pings to its own overlay address. NetBird 0.79.0
  doesn't use them.

Upgrading from 0.4.0: NetBird refuses to start after the upgrade if your
setup uses a setting 0.4.1 no longer supports, so check these first. The
fixes are in [troubleshooting](docs/troubleshooting.md#startup).

- Your Compose override and `secrets/netbird.env` set none of the NetBird
  variables the gate refuses ([configuration](docs/configuration.md#env)),
  such as `NB_FORCE_USERSPACE_FIREWALL`, `NB_USE_NETSTACK_MODE`,
  `NB_CONFIG`, `NB_PROFILE` or `NB_FOREGROUND_MODE`.
- Rosenpass is off. If you ever brought the peer up with
  `--enable-rosenpass`, turn it off in the stored profile.
- The peer uses NetBird's default profile, and that profile names the same
  interface as `OVERLAY_IF`. If you changed `OVERLAY_IF` after the peer
  enrolled, change one of them back.
- NetBird SSH, DNS nameservers, domain routes and Rosenpass are off for the
  exit peer in your NetBird dashboard
  ([requirements](docs/prerequisites.md#netbird)).

Then pull and recover, which rebuilds the routing image and recreates
NetBird with `NB_DISABLE_USERSPACE_ROUTING=true`, which `compose.yaml` now
sets. No `.env` changes are needed. The doctor checks the NetBird settings
and the stored profile afterwards.

Tested: unit tests for the routing validator, the gate and the health check,
and the isolated namespace drills in `tools/check-routing.sh`, which cover
local delivery from the overlay in both address families. A live PIA test
exit with Docker ran the routing and NetBird checks at `0f9511a`; see
[testing](docs/testing.md#routing-and-netbird-checks-at-0f9511a). The gate's
other refusals on a running peer, a Mullvad exit and rootless Podman with
these checks are untested; the NetBird settings were checked against the
0.79.0 source.

## 0.4.0 (2026-10-07)

- **Optional sign-in for the panel** with OpenID Connect. Set
  `PANEL_OIDC_ISSUER` and the panel signs people in through your identity
  provider, and each person sees only the exits their groups grant
  (`PANEL_ADMIN_GROUPS`, `PANEL_ACCESS`). A sign-in lasts `PANEL_SESSION_TTL`
  seconds (one hour by default). See
  [panel access](docs/access.md#sign-in-with-openid-connect) and
  [per-person exits](docs/switchyard.md#per-person-exits).
- **The panel now makes HTTPS requests to the identity provider** when sign-in
  is on, and the panel container needs a route to it. The ID token's signature
  is not checked; the panel relies on the verified TLS connection to the token
  endpoint instead, as OpenID Connect Core 1.0 section 3.1.3.7 allows. See
  [architecture](docs/architecture.md#sign-in) for what that trusts.
- **A PIA exit registers on its own after PIA's API comes back.** When a
  recreated tunnel's first registration failed (for example while PIA's
  login API was down), the applier never retried, because the tunnel had no
  address yet and the retry waited for one. It now retries the requested
  region every five minutes until it registers, as it already did for a
  stale handshake.

Without `PANEL_OIDC_ISSUER` the panel behaves as in 0.3.0, with no login. The
new settings are in [configuration](docs/configuration.md#panel-sign-in).
Upgrading from 0.3.0: pull, then recover. No `.env` changes are needed.

Tested: unit and integration tests against a fake issuer, and a live pass with
Pocket ID v2.16.0 as a public client: an admin sign-in, a switch verified by
the applier, and the signed-out behavior through a proxy. Sign-in by someone
granted only some exits has not been observed live; see
[testing](docs/testing.md#sign-in-pass-at-62a0170). The PIA retry: unit
tests, and a live exit that registered by itself once PIA's login API
recovered; see [testing](docs/testing.md#pia-registration-retry-at-8587542).

## 0.3.0 (2026-09-27)

- **PIA as a second provider** (`PROVIDER=pia`). You pick a region, not a
  server. The applier holds the PIA login and registers the tunnel key on
  each switch. IPv4 only. Optional port forwarding to one overlay device is
  off by default. See [providers](docs/providers.md).
- **Switchyard, one panel for several exits** (`PANEL_EXITS`). There is one
  tab per exit, each showing its state and where it exits. See
  [the panel guide](docs/switchyard.md).
- **Provider styling.** Each exit is drawn in its provider's colors and
  layout: Mullvad's country → city → server tree, and PIA's flat region list.
  `PANEL_STYLE=dashboard` keeps the previous neutral look.
- The panel's default title is now **Switchyard**. Set `PANEL_TITLE` to keep
  the old one.
- The panel shows latency as signal bars, and an empty state when a search
  matches nothing.
- `tools/preview-panel.py` serves the panel against fake exits, for working on
  its look.

Upgrading from 0.2.0: pull, then recover. The applier image must be rebuilt
because it gained nftables. Existing Mullvad deployments need no `.env`
changes.

Tested: PIA on the rootless Podman host (first start, recreation, a client
held on the exit through a tunnel-down drill, IPv6 and LAN isolation, region
switches); Switchyard serving a Mullvad and a PIA exit on that host. Not
tested live: PIA port forwarding (it is covered by the isolated drills only).

## 0.2.0 (2026-09-25)

A panel release. Routing, the tunnel configuration, Compose networking and
the NetBird container are unchanged.

- Saved servers: pin with the star, and recent servers are listed too. They
  are stored in each browser, never on the exit.
- A "Fastest" row in each fully measured country.
- Switch progress, a Retry button for failed switches, and protection against
  re-requesting a switch that is already running.
- Hosting filters (Mullvad-owned, RAM-only), shown only when they would narrow
  the list.
- Light and dark themes (`PANEL_THEME`).
- Screen-reader announcements, Escape to cancel, visible focus and
  reduced-motion support.

## 0.1.0 (2026-09-24)

First public release: a Mullvad exit for a NetBird mesh, run as one Compose
project.

- Forwarded client traffic can leave only through the WireGuard tunnel.
  Unreachable fallback routes for each address family and a terminal routing
  rule keep it closed if the tunnel, its route or its lookup rule disappears.
- A privileged applier checks each request against its own relay catalogue.
  The panel has no capabilities and only writes the desired server.
- Freshness-aware status (`/readyz`), host-side `doctor` and `recover`, and
  optional Gatus pushes.
- Docker Engine with Compose, or rootless Podman with podman-compose.
