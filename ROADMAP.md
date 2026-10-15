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
  had live passes with NordVPN on rootless Podman only, the latest an upgrade
  to 0.8.0; [testing](docs/testing.md) records the gaps that keep it
  experimental.
- **A native sidecar** (0.9.0, experimental, not yet run live): Molebridge's own
  tunnel for containers that share the exit's namespace, with a routing contract
  and an nftables firewall that keep their traffic in it, so an application can use
  PIA over WireGuard, plus `molebridge port-sync` for qBittorrent
  ([the native sidecar](docs/native-sidecar.md)). Its live acceptance on
  Kubernetes is still to be recorded ([testing](docs/testing.md#090)).
- **One signed image, pull and run** (0.8.0, experimental, live-tested on
  rootless Podman only): the Python and the routing shell were ported to one
  Go binary (`routing/gluetun-preflight`, which runs inside gluetun, is the
  one script left), published as a signed multi-architecture image with a
  signed Compose bundle, so there is nothing to build and no Python on the
  host. NetBird runs inside the exit container, which makes a native exit two
  containers instead of four ([setup](docs/setup.md),
  [architecture](docs/architecture.md)).
- **Repair driven by the kernel's notifications** (0.8.0): a changed rule,
  route, link or address starts a repair at once, and the 30-second pass is
  the fallback ([drift and repair](docs/architecture.md#drift-and-repair)).
  Live, a deleted rule was back in 8 to 23 ms ([testing](docs/testing.md#080)).
- **Running without Switchyard** (0.8.0, partly): the panel is its own
  container, so `docker compose up -d exit` starts an exit alone, and
  `molebridge status` reads the verdict from inside it
  ([health](docs/operations.md#health)). The Compose files still define the
  panel, and an exit with `SERVER` set has not been run this way on a live host.

## Backlog

### Smaller memory with large server catalogs

A Mullvad or PIA exit idles at 67–78 MB, but a NordVPN exit uses about
190 MB and a gluetun exit about 120 MB ([resources](docs/testing.md#resources-at-080-on-rootless-podman)),
against a target of 70 MB. The likely cause, not yet profiled, is the
server catalog: the whole provider file is decoded into memory before it is
filtered, and Go keeps much of that heap afterwards. What it would take:
profile first, idle and during a refresh; then decode the file as a stream
and keep only the fields that picking and showing a server need. NordVPN's
list joins servers to separate tables of groups, services, locations and
technologies, so streaming can't assume the order of the document. The
strict checks must stay: bounded size, strict UTF-8, duplicate keys refused,
and the last good catalog kept when a refresh fails. Possibly also set a soft
memory limit in the image, and measure how much of each exit is NetBird's
share, which Molebridge cannot shrink. Done means NordVPN and gluetun exits under
the target, measured the same way, with server choice and refresh unchanged.

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
