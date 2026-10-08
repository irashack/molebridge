# Changelog

Molebridge is experimental. Each release lists what was tested; the full
record is in [docs/testing.md](docs/testing.md). Upgrade by following
[operations](docs/operations.md#upgrades).

## Unreleased

- **gluetun exits look like gluetun.** In the provider style, an exit on the
  gluetun backend takes gluetun's dark slate, with the provider behind it as
  the accent: Mullvad's yellow, NordVPN's blue, Surfshark's teal, and a
  colour each for FastestVPN, IVPN and Windscribe. Before, a Mullvad or
  NordVPN exit through gluetun looked like the native one, and the other four
  providers had no colours at all, so their pages lost their card
  backgrounds. Checked in the local preview only.
- `tools/preview-panel.py --exits` adds a NordVPN exit and two gluetun exits
  (Mullvad and Surfshark) to the preview.
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
  style have colours again.

Checked in the local preview on desktop and phone widths, light and dark,
both styles, with switches that succeed and fail; not yet on a live exit.

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
