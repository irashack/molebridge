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
against a target of 70 MB. The difference is the server catalog: the whole
provider file is parsed into memory, and Go keeps much of that heap after
parsing. What it would take: decode the file as a stream, keep only the
fields that picking and showing a server need, possibly set a soft memory
limit in the image, and measure how much of each exit is NetBird's share,
which Molebridge cannot shrink. Done means NordVPN and gluetun exits under
the target, measured the same way, with server choice and refresh unchanged.

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
