# Changelog

Molebridge is experimental. Each release lists what was tested; the full
record is in [docs/testing.md](docs/testing.md). Upgrade by following
[operations](docs/operations.md#upgrades).

## Unreleased

- **A PIA exit registers on its own after PIA's API comes back.** When a
  recreated tunnel's first registration failed (for example while PIA's
  login API was down), the applier never retried, because the tunnel had no
  address yet and the retry waited for one. It now retries the requested
  region every five minutes until it registers, as it already did for a
  stale handshake.

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
