# Changelog

Molebridge is experimental. Each release lists what was tested; the full
record is in [docs/testing.md](docs/testing.md). Upgrade by following
[operations](docs/operations.md#upgrades).

## Unreleased

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

Upgrading from 0.4.0: pull, then recover, which rebuilds the routing image. If
you ever brought the peer up with `--enable-rosenpass`, or changed
`OVERLAY_IF` after the peer enrolled, fix the stored profile first
([troubleshooting](docs/troubleshooting.md#startup)).

Tested: unit tests for the routing validator, the gate and the health check,
and the isolated namespace drills in `tools/check-routing.sh`, which cover
local delivery from the overlay in both address families. The NetBird
settings were checked against the 0.79.0 source. Not yet run on a live exit;
see [testing](docs/testing.md#not-yet-tested).

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
