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

### One exit for several providers

Today each exit has one provider, fixed at start by `PROVIDER`, so using
Mullvad, PIA and NordVPN means three exits and three NetBird peers. A
multi-provider exit would be one peer that Switchyard can move between
providers as well as between servers. It looks feasible, because a switch
already tears one tunnel down and brings another up under the same
fail-closed contract, and a different provider is a bigger version of that.
What it would take:

- A target that names a provider and a server, through the same admission
  pipeline, with each provider's own registration, key handling and egress
  check.
- One fixed tunnel interface name for every provider, because NetBird's
  stored interface blacklist must keep excluding it; today the name follows
  the provider.
- Per-provider routing differences handled at a switch, such as PIA's
  return-path rules and its port forwarding, which must be gone before
  another provider's tunnel is up.
- Every provider's credentials and tunnel configs in one container, which
  widens what a compromised exit holds, and every provider's server catalog
  in one process, which depends on the memory work above.
- A panel that offers the provider as well as the server, and a status
  record whose provider can change.
- A live pass with switches in both directions between every pair of
  providers, and the tunnel-loss and repair drills run on each.

Everyone using that exit then shares one provider. Separate exits, one per
provider, would stay supported for anyone who wants different devices on
different providers at the same time.

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
