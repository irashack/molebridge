# Roadmap

Where Molebridge is going, and ideas that are not scheduled. Nothing in the
backlog is built; each entry says what it would take as far as we know today.

## Direction

Molebridge runs a commercial VPN tunnel as a self-hosted service, reached in
more than one way. It began as a NetBird exit node, and that stays the main
way in, but most of what it is doesn't depend on NetBird: the provider
tunnels, the server catalogs, the admission pipeline, the routing contract,
the status record and its verdict, and Switchyard. The sidecars already use
that core with no NetBird at all.

Each way in is defined by what it guarantees, not by its protocol:

| Way in | What uses the tunnel | Guarantee |
|---|---|---|
| NetBird exit | whole devices | fail-closed for the traffic the exit receives |
| Sidecar (gluetun or native) | whole containers | fail-closed, by gluetun's firewall or by the native sidecar's routing contract and firewall |
| Proxy ([backlog](#a-proxy-on-the-exit)) | applications or connections that opt in | the proxy's own connections leave only through the tunnel; nothing about traffic not sent to it |

Three rules follow, and the project's
[properties](AGENTS.md#preserve-the-properties) carry them:

- **The guarantee comes first.** Wherever a way in is described, configured
  or shown in Switchyard, its guarantee is stated before anything else.
- **No way in weakens another.** A new way in brings its own checks and live
  passes. A best-effort way in is never offered as a sidecar mode or an exit
  setting, so that "fail-closed" keeps meaning what it means today.
- **The core stays shared.** A way in reuses the provider tunnels, the
  admission pipeline and the verdict rather than growing its own.

The order of work: exchanging requests and status over the network first,
so that more ways in don't mean more shared directories (built in 0.10.0, not
yet run live: [the network exchange](docs/architecture.md#the-network-exchange));
then a status record that can
describe a way in using many servers at once; then [the
proxy](#a-proxy-on-the-exit). Meanwhile a device on a Mullvad exit can already
reach Mullvad's own per-server proxies ([Mullvad's SOCKS5
proxies](docs/mullvad-socks5.md)).

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

## Backlog

### Publishing the lease apart from the status record

On a native exit the supervisor rewrites the whole `result.json` every 2
seconds to change one check, `owner_record` (its `at` and `expires_at`). That
write no longer fsyncs, but it is still a full-file rewrite for a single
value. Publishing the lease in its own small file would make
`result.json` change only once per inspection, about every 60 seconds. What it
would take: a reader contract first. Every reader judges `owner_record` from
`result.json` today (the panel, `molebridge status`, `port-sync`, and readers
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

### One exit for several providers

Today each exit has one provider, fixed at start by `PROVIDER`, so using
Mullvad, PIA and NordVPN means three exits and three NetBird peers. Moving a
device from one provider to another means choosing a different exit node in
the NetBird app and then the server in Switchyard. A multi-provider exit
would be one peer: the device stays on it, and Switchyard picks the provider
and the server in one step. It would be an opt-in kind of exit for the native
providers. Single-provider exits stay as they are, and existing setups need
no change.

It looks feasible, but a provider change is more than today's server switch,
which keeps the tunnel and changes its peer (and, for PIA, its address). What
it would take:

- Replacing the tunnel's whole configuration (key, addresses, MTU, routes)
  through the mutation owner, and making the tunnel-recovery loop rebuild the
  current provider's tunnel. Today recovery recreates the tunnel from the
  configuration the exit started with, on the last peer set.
- A target that names a provider and a server, through the same admission
  pipeline, with each provider's own registration, key handling and egress
  check. Attempt records would need the provider as well as the server, and
  readers of the status record, which already names its provider, would have
  to accept one that changes; today a reader rejects a record whose provider
  differs from its own setting.
- Per-provider routing differences handled at a switch, such as PIA's
  return-path rules and its port forwarding, which must be gone before
  another provider's tunnel is up.
- One tunnel interface name for every provider, the simplest way to keep
  NetBird's interface exclusion and the routing contract stable (the
  exclusion list could also name several).
- Every provider's credentials and tunnel configs in one container, which
  widens what a compromised exit holds, and every provider's server catalog
  in one process, which depends on the memory work above.
- A panel that offers the provider as well as the server.
- A live pass with switches in both directions between every pair of
  providers, and the tunnel-loss and repair drills run on each.

gluetun exits are out of scope: gluetun owns their tunnel. Everyone using a
multi-provider exit shares its current provider. To put different devices on
different providers at the same time, run single-provider exits beside it.

### Automatic failover

Today Molebridge never picks another server: it retries the one you chose.
A failover would move an exit to a backup server when its own keeps failing,
and back again. The admission pipeline already separates the operator's
choice (the primary target) from the server it applies, so a backup would
go through the same gates and checks. What it takes: rules for when to fail
over and when to return, which backups are acceptable, how the panel shows
it, and a live pass.

### Verifying a sidecar's tunnel-tier egress

A gluetun sidecar with FastestVPN, IVPN, Surfshark or Windscribe is shown as
switched, never verified, because nothing in plain gluetun's namespace can
measure the host's own address. The panel could measure it instead, as an
opt-in, if it can show that it and gluetun leave the host by the same path,
with fresh bounded measurements, and still work without a panel.

### A proxy on the exit

A device on a Mullvad exit can already use [Mullvad's SOCKS5
proxies](docs/mullvad-socks5.md) to send one application out through another
server, but only by naming that server's proxy, and only from a NetBird
device. A proxy run by Molebridge would let an application ask for a country,
a city or a server in the proxy username (`de`, `us-nyc`, `se-sto-wg-001`),
keep one server per named session, and skip servers that fail, as
[mullpod](https://github.com/SkanaviLabs/mullpod) does with its own
in-process tunnel. The users this fits are mostly programs: agents, scrapers,
browser tests and CI jobs that want a stable or changing location per task.

It guarantees nothing about traffic that isn't sent to it, so it would be a
way in of its own ([direction](#direction)), never a sidecar mode. What it
would take:

- Its own container with no capabilities, keys or credentials, so the exit's
  listening surface doesn't grow. If it shares the exit's namespace, every
  connection it opens must be bound to the tunnel interface: the routing
  contract sends only traffic from NetBird, or bound to the tunnel, to the
  exit table, and an unbound connection from the namespace leaves by the host
  ([testing](docs/testing.md#mullvads-socks5-proxies-through-an-exit)). A
  failed or missing binding has to fail the connection, never fall back.
- Listening on NetBird's interface or loopback only, with a password from a
  mounted file, because Mullvad's proxies take none and anyone who reaches the
  port reaches every server.
- The proxy names derived from the relay list (`relays.json` has no field for
  them), validated like the rest of the catalog.
- A status record that can say "the tunnel is up, these servers answered,
  these are benched" without a reader taking it for a verified fail-closed
  exit, and a Switchyard view of sessions and benched servers instead of a
  server switch.
- The standard library only: SOCKS5, HTTP `CONNECT`, sessions and the
  benching are small enough not to need a module.
- For PIA and NordVPN, a proxy for the exit's current server only: they offer
  no proxy per server that Molebridge knows of.
- A live pass: clients selecting servers by every kind of name, a session
  kept and moved, a benched server, a server switch of the exit, tunnel loss,
  and an nftables counter on every interface but the tunnel showing no
  packet from the proxy.
