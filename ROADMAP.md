# Roadmap

Ideas that are not scheduled. Nothing in the backlog is built; each entry
says what it would take as far as we know today.

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

### Exchanging requests and status over the network

The panel and an exit talk through files: the panel writes
`state/panel/desired.json`, the exit writes `state/applier/` (`result.json`,
`relays.json`), and each mounts the other's directory. That ties them to one
filesystem. On Kubernetes it means a volume shared between the exit's pod and
the panel's, often in different namespaces, so one panel serving several
exits mounts every exit's state. A node-local volume pins all of them to one
node. A network filesystem with root squashing (most NFS exports) can't hold
the exit's root-owned 0600 files, and user-namespaced pods
(`hostUsers: false`) may not be able to mount NFS at all, because it lacks
the ID-mapped mounts they need (not yet checked).

Over the network, each exit would keep only its own state (the NetBird
profile, the applier directory) on a volume of its own, which any
single-writer block volume can hold. The panel would keep its requests on
another. Neither would mount the other's, so each could be scheduled
independently. Moving an exit would mean moving one private volume.

What it would take, keeping the [privilege split](AGENTS.md#preserve-the-properties):

- The exit fetches its request from the panel: an outbound, bounded HTTP GET
  answered by one server name and a request ID. It validates the answer as
  untrusted input, exactly as it treats `desired.json` today. The panel still
  can't change routing, and the exit opens no port the panel can drive.
- The panel reads each exit's status record and relay catalog from a small
  read-only endpoint on the exit, with the same schema and verdict rules as
  `result.json`. Or the exit posts them to the panel, which then stores them
  without authority. Choose whichever keeps the exit's listening surface
  smaller, and say how the panel authenticates the exit it reads (a per-exit
  token from a mounted file, never in the request URL).
- A rule for a stale or unreachable peer, matching today's file rules: an
  unreachable panel is the same as no new request; an unreachable exit is
  shown as unknown, never as connected, and a lapsed lease is never shown as
  live.
- The file exchange stays the default for Compose and single-host setups, and
  `molebridge status` keeps reading the record locally. The network exchange
  is opt-in per exit.
- An exit that starts with an empty applier directory recovers from the
  panel's request alone, so a move carries only the NetBird profile (and the
  tunnel credentials, already mounted from files).
- The isolation check and the host checks updated for the new mounts, and a
  live pass on Kubernetes with an exit and the panel on different nodes,
  including the switch, tunnel-loss and repair drills.

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
  configuration the exit started with.
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
