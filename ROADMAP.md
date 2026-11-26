# Roadmap

Where Molebridge is going, what is built, and ideas that are not scheduled.
Nothing in the backlog is built; each entry says what it would take as far as
we know today.

## Direction

Molebridge runs a commercial VPN tunnel as a self-hosted service, reached in
more than one way. It began as a NetBird exit node, but most of what it is
doesn't depend on NetBird: the core (the provider tunnels, the server
catalogs, the admission pipeline, the routing contract, fail-closed repair,
the status record and its verdict) and Switchyard. The sidecars and the proxy
use that core with no NetBird at all.

Each way in is defined by what it guarantees, not by its protocol:

| Way in | What uses the tunnel | Guarantee |
|---|---|---|
| NetBird exit | whole devices | fail-closed for the traffic the exit receives |
| Sidecar (gluetun or native) | whole containers | fail-closed, by gluetun's firewall or by the native sidecar's routing contract and firewall |
| Proxy | programs that opt in | every connection the proxy opens leaves through the tunnel, or fails; nothing about traffic not sent to it |

Three rules follow, and the project's
[properties](AGENTS.md#preserve-the-properties) carry them:

- **The guarantee comes first.** Wherever a way in is described, configured
  or shown in Switchyard, its guarantee is stated before anything else.
- **No way in weakens another.** A new way in brings its own checks and live
  passes. A best-effort way in is never offered as a sidecar mode or an exit
  setting, so that "fail-closed" keeps meaning what it means today.
- **The core stays shared.** A way in reuses the provider tunnels, the
  admission pipeline and the verdict rather than growing its own.

**What is built.** The menu exists: you pick the ways in and the extras, and
the core underneath is the same ([the menu](docs/menu.md)). All three ways in
are built, each experimental and labeled on its own; the extras are
Switchyard, `port-sync`, failover, the network exchange and the
multi-provider exit. In the order they came:

- exchanging requests and status over the network, so that more ways in
  don't mean more shared directories (0.10.0, run live in every release's
  acceptance since: [the network exchange](docs/exchange.md));
- an image without NetBird, `ghcr.io/irashack/molebridge-core` (0.12.0; the
  sidecars on it since 0.13.0);
- in 0.14.0: the proxy, with a status file of its own instead of a change to
  the exit's record ([the proxy](docs/proxy.md)); Switchyard's view of it;
  `molebridge init`, which writes the Compose file from three questions
  ([setup](docs/setup.md#molebridge-init)) and offers the proxy from the
  release after 0.14.0; NetBird moved behind one boundary in the exit, with
  no change of behavior; and automatic failover ([failover](docs/failover.md));
- the multi-provider exit, one NetBird exit carrying Mullvad, PIA or
  NordVPN one at a time, experimental and in release builds since 0.14.2
  ([multi-provider exit](docs/multi-provider.md)).

`EXIT_KIND` and `TUNNEL_BACKEND` keep their meaning: `init` only writes them,
and the shipped Compose files stay valid, so existing exits need no change.

**What is left.** Live passes for what has run only in CI: a stack written by
`init` started on a host, the proxy in a native sidecar's namespace and with
PIA and NordVPN, failover on a real provider, and the multi-provider exit's
memory during a server-list refresh and traffic on its forwarded port
([its page](docs/multi-provider.md) says where it stands). Each way in is
tested once against the core's contracts, not in every combination.

Two decisions shape the work (maintainer, 2026-11-19):

- **Two images**: one without NetBird, for the
  sidecars and the proxy, and one with it, for the NetBird exit. Mounting the
  operator's own NetBird image instead of bundling one is not planned for
  now, and NetBird is never run as a separate container outside the
  supervisor's control: the supervisor starting NetBird only when the
  routing contract holds, and stopping it when the lease lapses, is what
  makes the exit fail closed.
- **Go stays the language.** Go is already memory safe, Molebridge builds
  without cgo, and what the project depends on (the NetBird client, gluetun,
  wgctrl, netlink and nftables) is Go. The failures that matter here are
  logic failures, a leaking rule or a lapsed lease shown as live, which no
  language prevents and the drills and live passes catch. Now that the ways
  in have clean boundaries, one could be rewritten behind its contract if
  measurements give a reason; a userspace tunnel for the proxy is the likely
  candidate. No rewrite happens alongside the change of core.

## Done

- **One status record and one verdict** (0.7.0): every reader judges the
  applier's record the same way ([status reporting](docs/architecture.md#status-reporting)).
- **One admission pipeline** (0.7.0): every change of server, with retries
  on a backoff ([the admission pipeline](docs/architecture.md#the-admission-pipeline)).
- **A sidecar mode** (0.7.0, experimental): Switchyard for an ordinary
  gluetun container ([gluetun sidecar](docs/gluetun-sidecar.md)). It has
  had live passes with NordVPN only, on rootless Podman and on Kubernetes, the
  latest the upgrade to 0.9.4 ([testing](docs/testing.md#094));
  [testing](docs/testing.md) records the gaps that keep it experimental.
- **A native sidecar** (0.9.0, experimental, run live with PIA on Kubernetes): Molebridge's own
  tunnel for containers that share the exit's namespace, with a routing contract
  and an nftables firewall that keep their traffic in it, so an application can use
  PIA over WireGuard, plus `molebridge port-sync` for qBittorrent
  ([the native sidecar](docs/native-sidecar.md)). Its live acceptance on
  Kubernetes is recorded from 0.9.0 on ([testing](docs/testing.md#090)); it
  hasn't run under Docker or Podman Compose.
- **The gluetun forms on Kubernetes** (0.9.1, documented, not packaged): the
  preflight from the image, and what a pod needs
  ([the gluetun exit](docs/gluetun-netbird-exit.md#kubernetes)); the server-list
  refresh says why it waits, and `fix-blacklist` makes the profile edits an
  enrolled exit needs when it moves runtime.
- **One signed image, pull and run** (0.8.0, experimental, live-tested on
  rootless Podman and Kubernetes, not on Docker): the Python and the routing shell were ported to one
  Go binary (`routing/gluetun-preflight`, which runs inside gluetun, is the
  one script left), published as a signed multi-architecture image with a
  signed Compose bundle, so there is nothing to build and no Python on the
  host. NetBird runs inside the exit container, which makes a native exit two
  containers instead of four ([setup](docs/setup.md),
  [architecture](docs/architecture.md)).
- **Repair driven by the kernel's notifications** (0.8.0): a changed rule,
  route, link or address starts a repair at once, and the 30-second pass is
  the fallback ([drift and repair](docs/architecture.md#drift-and-repair)).
  The live drills' repair times are in [testing](docs/testing.md).
- **Running without Switchyard** (0.8.0, partly): the panel is its own
  container, so `docker compose up -d exit` starts an exit alone, and
  `molebridge status` reads the verdict from inside it
  ([health](docs/operations.md#health)). The Compose files still define the
  panel, and an exit with `SERVER` set has not been run this way on a live host.
- **Exchanging requests and status over the network** (0.10.0, experimental):
  an exit and its panel that share no filesystem exchange the same files over
  HTTP; the exit makes outbound requests only, and an exit the exchange
  hasn't heard from shows as `exit-unreachable`, never as connected
  ([the network exchange](docs/architecture.md#the-network-exchange)). Run
  live on Kubernetes with a NordVPN exit and the panel on different nodes
  ([testing](docs/testing.md#v0100-rc2-2026-11-03-released)); the gluetun
  form and the native sidecar have not run it.

- **An image without NetBird** (0.12.0): `ghcr.io/irashack/molebridge-core`,
  built from the same Dockerfile and promoted with the image that has NetBird
  from one candidate, each with its own SBOM and scan. It refuses
  `EXIT_KIND=overlay` at start. The sidecar Compose files use it after
  0.12.0 ([#47](https://github.com/irashack/molebridge/issues/47)).

## Built, still experimental

These were backlog entries. They are built; what each still lacks is on its
own page.

### A proxy on the exit

Built in 0.14.0: `molebridge proxy`, SOCKS5 and HTTP `CONNECT` in a native
exit's namespace for programs that opt in, the username choosing a country,
a city or a server, with sessions and benched servers, in its own container
with no capabilities, keys or credentials, and a status file of its own
([the proxy](docs/proxy.md)). Every connection it opens leaves through the
tunnel, or fails. It has been drilled live on a Mullvad NetBird exit only;
PIA, NordVPN and the native sidecar's namespace have not been drilled.

### Automatic failover

Built in 0.14.0, off by default: when the selected server keeps failing, a
native exit moves to a backup in the same city, the same country or a list
you give, and comes back ([failover](docs/failover.md)). Its live drill on a
real provider has not run. The rules and the choices that were the
maintainer's to make are in [its design](docs/design/failover.md).

### One exit for several providers

Built, and experimental: one NetBird exit that carries Mullvad, PIA or
NordVPN, one at a time, so that a device stays on one peer while Switchyard
picks the provider and the server in one step. Single-provider exits stay as
they are. It passed one live pass on 2026-11-20 and is in release builds
since 0.14.2; what has not run is on [its page](docs/multi-provider.md), and
the contract it was built to is [its design](docs/design/multi-provider.md).
Since acceptance policy 20 every candidate needs the live multi-provider
drill (`multi-provider-live`).
gluetun exits are out of scope: gluetun owns their tunnel.

## Backlog

### Publishing the lease apart from the status record

On a native exit the supervisor rewrites the whole `result.json` every 2
seconds to change one check, `owner_record` (its `at` and `expires_at`). That
write no longer fsyncs, but it is still a full-file rewrite for a single
value. Publishing the lease in its own small file would make
`result.json` change only once per inspection, about every 60 seconds. What it
would take: a reader contract first. Every reader judges `owner_record` from
`result.json` today (the panel, `molebridge status`, and readers
outside this repository such as Switchyard and health bridges, some in other
pods). So the new file needs a schema, a path every reader can mount, and a
rule for how the verdict combines the two files when one is stale or missing.
Readers that know only `result.json` must still never see a lapsed lease as
live. A schema 2 reader that doesn't know the new file would see a check that
stopped moving, so the change probably needs a schema 3, or `result.json` would
have to keep carrying the check for old readers, which saves nothing.

### Smaller memory with large server catalogs

Measured at 0.8.0, a Mullvad or PIA exit idled at 67–78 MB, but a NordVPN exit
used about 190 MB and a gluetun exit about 120 MB ([resources](docs/testing.md#resources-at-080-on-rootless-podman)),
against a target of 70 MB. The likely cause was the server catalog: the whole
provider file was decoded into memory before it was filtered, and Go kept much
of that heap afterwards.

0.9.3 changes the parsing, measured in Go tests and benchmarks, not on a live
exit. The strict checks stay (bounded size, strict UTF-8, duplicate keys
refused, the last good catalog kept when a refresh fails), but the parts
nobody reads are checked without being built. The NordVPN list is read one
server at a time and joined to its tables of groups, services, locations
and technologies after the end of the document, in whatever order its members
come: on a synthetic list of 6,500 servers (7.6 MiB) the parse's heap peak fell
from 54 to 12 MiB. From gluetun's `servers.json` (7.4 MB) only the configured
provider's block is built: with Mullvad selected, a read allocates 8 MiB instead
of 43 and peaks at 8 MiB instead of 30. A download that announces its length, and the gluetun file,
are read into one buffer instead of about twice their size. The exit returns
the freed memory to the system after every catalog parse, including the
startup read of `relays.json` and each read of gluetun's file, where before it
did so only after a download. Failed refreshes now back off from one minute to
an hour instead of downloading the list again every minute. No soft memory
limit is set.

What remains: measure a NordVPN and a gluetun exit again, idle and during a
refresh, the same way as before, and how much of each is NetBird's share,
which Molebridge cannot shrink. Their live memory has not been measured since
these changes. Done means NordVPN and gluetun exits under the target, with server
choice and refresh unchanged.

### Verifying a sidecar's tunnel-tier egress

A gluetun sidecar with FastestVPN, IVPN, Surfshark or Windscribe is shown as
switched, never verified, because nothing in plain gluetun's namespace can
measure the host's own address. The panel could measure it instead, as an
opt-in, if it can show that it and gluetun leave the host by the same path,
with fresh bounded measurements, and still work without a panel.
