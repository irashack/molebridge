# Operations

Commands assume Docker Compose from the repository root. Rootless Podman has
its own section below, because the `doctor` and `recover` helpers only work
with Docker.

## Health

The applier rewrites `state/applier/result.json` about once a minute. The exit
counts as healthy only when all of these hold:

- a recent handshake;
- egress confirmed by the provider (Mullvad's `am.i.mullvad.net` for each
  address family the tunnel has; PIA's `connected: true`; NordVPN's
  `protected: true`), or, for a provider without such a check, by the
  [tunnel checks](architecture.md#status-reporting);
- a server list less than 24 hours old that includes the current server;
- the NetBird interface present, as a kernel WireGuard link, with NetBird's
  kernel firewall in place;
- every routing rule and fallback route in place, including the
  local-delivery rule that replaces the kernel's priority-0 rule.

A result older than 150 seconds, malformed or dated in the future counts as
unknown, whatever it says.

- `/healthz` on the panel only checks that the panel process is up.
- `/readyz` returns 200 for a fresh, verified connection and 503 otherwise.
  Point your monitoring at this one.
- `python3 tools/molebridge.py doctor` checks the Compose configuration
  (including the NetBird settings the entrypoint gate refuses), file
  permissions, the identity volume, that every container in the exit's
  namespace shares it (three with the default backend, four with gluetun), the ICE blacklist, the NetBird gate's own checks of its
  settings and stored profiles, and the applier's own checks. It doesn't
  prove that client traffic is forwarded; [verification](verification.md)
  does that.

### Gatus

To push health to [Gatus](https://gatus.io), set `GATUS_URL` and
`GATUS_ENDPOINT`, and put `GATUS_TOKEN=…` in `secrets/applier.env` (mode 0600).
Use HTTPS unless the connection is local and trusted. In Gatus, treat a
missing push as a failure: a stopped applier can't report that it's down.

## Recovery

Recreating `wireguard` alone leaves `netbird` and `applier` in the old network
namespace, where they carry no traffic; the same goes for `gluetun` and the
three containers that join it. Docker doesn't restart unhealthy containers on
its own. The recovery helper recreates them all together, with the panel:

```sh
python3 tools/molebridge.py recover
```

It checks the configuration, the files and the identity volume first, and
builds both local images before touching the running exit, so a failed build
changes nothing. It then stops the namespace users, recreates the containers
(four with the default backend, five with gluetun), waits up to 180 seconds
for them to become healthy, then polls for up to about 180 seconds more for
the applier to verify the exit (with the gluetun backend it may first put
your last server back), and runs doctor.
A failure names the step, or the applier's checks that still fail, for
example `The applier reports: verified Mullvad egress (docs/troubleshooting.md).` With the gluetun
backend it recreates `gluetun`, `guard`, `netbird`, `applier` and the panel.
It never deletes a volume or enrolls a new peer. If it fails after
recreating, the exit hasn't passed every check, but the containers it
recreated keep running and the tunnel may carry traffic; read the reported
failure and the panel's status before you rely on the exit, fix the problem,
and run it again. Keep a way into the host that doesn't depend on this
exit.

NetBird won't start until the routing guards exist, on every start, including
after a host reboot. An applier stranded in an old namespace reports
unhealthy, so the problem is visible, but only recovery fixes it.

## Upgrades

Read the [changelog](../CHANGELOG.md) first. Then:

```sh
git fetch --tags && git checkout <new release>
docker compose pull netbird control-panel
python3 tools/molebridge.py recover
```

Recovery rebuilds the routing and applier images. An uncached rebuild can pick
up newer Debian packages; to refresh them on purpose, run `docker compose build
--no-cache applier` first. Keep `.env`, `state/`, `tunnel/`, `secrets/` and the
`netbird-data` volume.

Compare `.env.example` with the previous release's (`git diff <old>..<new> --
.env.example`) for new or changed settings. If you keep local Compose
overrides, check them against the new `compose.yaml`. After any change to
routing, images or the applier, run the [verification](verification.md)
drills again.

To roll back, check out the previous release and run `recover` the same way.
State files have stayed readable across releases so far, but take the
[backup](#backups) first in case one changes.

## Backups

The state worth keeping is small:

| What | Why | If lost |
|---|---|---|
| `netbird-data` volume | The peer's identity | The exit enrolls as a new peer; recreate its route and group membership |
| `tunnel/wg_confs/*.conf` | The tunnel private key | Mullvad: generate a new device config. PIA: generate a new key; the applier registers it again on its own. NordVPN: run `tools/nordvpn-key.py` again with a new access token |
| `secrets/` | Setup key, PIA login, Gatus token; with gluetun, the provider's WireGuard key, the role file and the API key | Re-create them; for gluetun, `gluetun-auth --rotate` writes a new role file and key |
| `.env` | Settings | Re-create it |
| `state/panel/desired.json` | The chosen server | Pick again in the panel |

`state/applier/` rebuilds itself, except one file with the gluetun backend:
`gluetun-selection.json` remembers the last server the applier put and the
last one it verified, which it puts back after gluetun restarts when the
panel's request is absent or was refused. Without it, the request in
`state/panel/desired.json` is still applied again; only that fallback is
lost. Saved and recent servers in
the panel live in each browser, not on the exit. The key files, `secrets/` and
the volume are secrets: back them up only to encrypted storage.

The volume is the one item that isn't a plain file. Stop `netbird` so the copy
is consistent, then archive it (the volume name is `<project>_netbird-data`,
`molebridge_netbird-data` by default):

```sh
docker compose stop netbird
docker run --rm -v molebridge_netbird-data:/data:ro -v "$PWD":/backup \
  docker.io/library/busybox tar czf /backup/netbird-data.tgz -C /data .
docker compose start netbird
```

On Podman, `podman volume export molebridge_netbird-data > netbird-data.tar`
does the same. To restore on a fresh install, fill the volume before the
first start:

```sh
docker volume create molebridge_netbird-data
docker run --rm -v molebridge_netbird-data:/data -v "$PWD":/backup \
  docker.io/library/busybox tar xzf /backup/netbird-data.tgz -C /data
```

Compose then warns that it didn't create the volume, and uses it anyway. On
Podman, use `podman volume create` and `podman volume import`. Put back `.env`, `tunnel/` and `secrets/` with mode 0600 files in 0700
directories. Then check that the peer appears in NetBird under its old name,
rather than as a new peer.

## DNS

Molebridge configures no DNS. Devices keep the resolver they already use, and
their traffic leaves through the provider.

With Mullvad, plain DNS (port 53) from a device appears not to reach that
resolver. This is observed, not documented by Mullvad, from one device check
and the exit's connection table: an iPhone set to Quad9 sent its lookups through a
Mullvad exit, the exit's connection table showed them addressed to 9.9.9.9
port 53, and mullvad.net/check reported no DNS leak and named the Mullvad
server itself as the resolver. The Mullvad server answers plain DNS that
passes through it with its own resolver, whichever server the device asked.
A leak test therefore shows Mullvad, not your usual resolver. PIA has not been
tested; don't assume its servers behave the same way.

### When a leak test flags DNS

The check is reporting lookups that the provider's server did not answer.
There are two ways that happens:

- **A resolver on the local network**, such as a home router or a hotel
  gateway, reached outside the exit. This is a real leak.
- **Encrypted DNS**, such as DNS over HTTPS or TLS from a browser's secure-DNS
  setting, iCloud Private Relay or a configuration profile. It goes through the
  exit, but the server can't redirect it, so the check names the outside
  resolver.

The DNS list in the check's result tells which: a resolver run by your local
network or ISP is the first case, and the service you configured for
encrypted DNS is the second. To see where a device's plain DNS goes, run this
on the exit, inside the namespace
([how to get a shell there](verification.md#inside-the-namespace)), with the
device's overlay address in place of `<device overlay IP>`:

```sh
grep <device overlay IP> /proc/net/nf_conntrack | grep 'dport=53 '
```

Each line is one lookup flow from that device. The `dst=` address is the
resolver the device asked. If you use encrypted DNS and want a clean check,
use Mullvad's own encrypted DNS service.

### Why there is no DNS option

Molebridge has no option to send DNS through the provider. One way to build
it would be a resolver in the exit's namespace forwarding over the tunnel,
plus a NetBird nameserver group. That would apply even when the exit isn't
selected, and DNS would fail whenever the tunnel is down. A resolver that only
works inside the tunnel, pushed through NetBird, also gives slow, flaky DNS
off the exit rather than none, because NetBird eventually gives up on it and
falls back.

That design can't work on this exit now in any case. The exit no longer
answers anything addressed to itself that arrives over NetBird: a packet
that arrives on the overlay interface never reaches a process on the exit
([architecture](architecture.md#netbird-requirements)). A NetBird nameserver
group served by the exit therefore gets no answers. Point NetBird's
nameservers at a resolver somewhere else.

## Direct connections

Check how devices reach the exit with `docker compose exec netbird netbird
status -d`. `P2P` is good. `Relayed` works, but it adds a relay server's round
trip to every packet.

The exit peer must keep ICE off the tunnel interface
([setup step 5](setup.md#5-keep-ice-off-the-tunnel-interface)); doctor checks
it. To see what a peer is doing, raise the log level, read the local and
remote candidates, then put it back:

```sh
docker compose exec netbird netbird debug log level debug
docker compose exec netbird netbird debug log level info
```

Treat candidate addresses as private.

### Exits on a private container network

Rootless engines and Docker's default bridge put the exit's namespace on a
private network. The peer's only host candidate is then an address that
nothing outside the host can reach, and whether STUN finds a usable public
candidate depends on the engine's NAT. On the tested rootless host it found
none. Devices then fall back to a relay silently: the exit works, just more
slowly, and nothing reports a fault.

The fix is to get a UDP port to the peer and tell NetBird to use and advertise
it. How you get the port there depends on the engine. Put the change for
`wireguard` in a `compose.override.yaml`. Compose reads that file
automatically unless `COMPOSE_FILE` is set, as it is for PIA and NordVPN; then
add it to the list
(`COMPOSE_FILE=compose.yaml:compose.pia.yaml:compose.override.yaml`).

**Docker:** publish the port on the `wireguard` service.

```yaml
services:
  wireguard:
    ports:
      - "51825:51825/udp"
```

**Rootless Podman with pasta:** don't publish the port. Publishing it holds
the host port, so pasta can't bind it for NetBird's outgoing STUN; remote
devices stay relayed and only devices on the same LAN connect directly. Give
`wireguard` its own pasta network that forwards the port instead, with
`network_mode` and no `ports:` entry for that port. Use your host's LAN
address in place of `198.51.100.10`:

```yaml
services:
  wireguard:
    network_mode: "pasta:-4,-a,10.0.2.100,-n,24,-g,10.0.2.2,-I,eth0,-u,198.51.100.10/51825:51825"
```

The pasta options are:

- `-4` uses IPv4 only on the host side.
- `-a 10.0.2.100 -n 24 -g 10.0.2.2` gives the namespace a fixed private
  address and gateway.
- `-I eth0` keeps the interface name `eth0`, which `--external-ip-map` refers
  to below.
- `-u 198.51.100.10/51825:51825` forwards that UDP port, bound to that one LAN
  address only.

The namespace gets no `--map-host-loopback`, so it can't reach the host's
loopback. Nothing else may share `wireguard`'s network for this to work.
`netbird` and `applier` join its namespace, and `control-panel` is already on
its own network.

Recreate the stack so the change applies (`recover`, or the Podman commands
below), then set NetBird's side, using your `EXIT_IF` in place of `mullvad`:

```sh
docker compose exec netbird netbird down
docker compose exec netbird netbird up \
  --extra-iface-blacklist mullvad \
  --wireguard-port 51825 \
  --external-ip-map 198.51.100.10/eth0
```

- The published or forwarded port and `--wireguard-port` must match. Pick a free one; a
  NetBird client on the host itself already uses 51820.
- `--external-ip-map` is the address the peer advertises instead of the
  container's: the host's LAN address for devices on the same LAN, or your
  public address, with the port forwarded, for devices on the Internet.
- A published or forwarded port is new exposure. Prefer the LAN address unless remote
  devices really need the direct path.
- The remote candidate may show as `prflx`. Rootless port forwarding rewrites
  the source address, and ICE handles that; it isn't a fault.

What was tested: on Debian with passt 0.0~git20261002 and Podman 5.8.6, with
the `wireguard` container as a Quadlet unit using the `Network=pasta:` form of
the options above. One pasta process then owns
the port. NetBird's outgoing STUN leaves from a socket bound to the LAN
address and port, the STUN server reported the public mapping on that same
port, and a LAN datagram arrived with its real source address. `ss -ulnp` on
the host showed the port held by pasta, not by `rootlessport`; the pasta log
had no `Dropping datagram`; NetBird no longer logged `wait for gathering timed
out`; and NetBird showed a P2P pair. A LAN client connected directly. On
2026-10-08 a phone on cellular, off Wi-Fi, also got a direct (P2P) path, with
host and server-reflexive (`srflx`) candidates, to two exits set up this way,
one Mullvad and one NordVPN, and held it through a speed test. The
podman-compose form shown above, Docker with this method, and rootless Docker
are untested.

## Rootless Podman

Tested on Debian 13, rootless Podman 5.4, podman-compose 1.6 on amd64. The
helpers in `tools/molebridge.py` need `docker compose`'s JSON output, which
podman-compose doesn't have, so use these commands instead. The gluetun
backend's `gluetun-post-rules` is the exception: it reads `.env` directly
and works the same under Podman. Replace
`molebridge` with your `COMPOSE_PROJECT_NAME` if you changed it.

Before the first start, load the kernel module and set `PANEL_USER=0:0`
([requirements](prerequisites.md#rootless-podman)).

With the gluetun backend, the applier refuses `secrets/gluetun/api_key` if its
mode allows anything beyond `0600`, so a group-readable file with an ACL
doesn't work. Under podman-compose the container's root is your own user, and
the file `gluetun-auth` writes works as it is. If you remap the container's
root to another host ID, as some Quadlet setups do, the file must belong to
that ID with mode `0600`.

**Setup** is [setup](setup.md) with `podman-compose` in place of `docker
compose`:

```sh
podman-compose build wireguard applier
podman-compose up -d wireguard netbird applier
podman logs molebridge-wireguard 2>&1 | grep 10-exit-routing
```

**Upgrade or recover.** Build first, so a failed build leaves the exit
running, then recreate all four together:

```sh
podman-compose pull netbird control-panel
podman-compose build wireguard applier
podman-compose up -d --force-recreate wireguard netbird applier control-panel
```

With the gluetun backend, build `guard applier` and recreate `gluetun guard
netbird applier control-panel` instead; recreate all five together, since a
new `gluetun` container is a new namespace.

podman-compose has no `--wait`, so check health yourself. The three
`readlink` values must be identical, and `--doctor` prints five PASS/FAIL
lines:

```sh
for c in wireguard netbird applier control-panel; do
  podman inspect --format '{{.State.Health.Status}}' molebridge-$c
done
for c in wireguard netbird applier; do
  podman exec molebridge-$c readlink /proc/self/ns/net
done
podman exec molebridge-applier python -m applier.apply --doctor
```

`--doctor` doesn't check the ICE blacklist. Read that one field from the peer
profile yourself. The same file holds the peer's private key, so print
nothing else from it:

```sh
awk '/"IFaceBlackList"/ {p=1} p {print} p && /\]|null/ {exit}' \
  "$(podman volume inspect molebridge_netbird-data --format '{{.Mountpoint}}')/default.json"
```

Nor does it run the NetBird gate's checks of NetBird's settings and stored
profiles. Run them in the `netbird` container; they print one line,
`NetBird gate: configuration accepted` or the reason for a refusal (see
[troubleshooting](troubleshooting.md#startup)), and nothing from the
profiles:

```sh
podman exec molebridge-netbird sh /usr/local/bin/molebridge-wait-for-guards --check-config
```

Never run `down -v`: the named volume is the peer's identity.

**Starting at boot.** Rootless containers start at boot only through a
systemd user session. This lingering user unit is the tested arrangement:

```sh
loginctl enable-linger "$USER"
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/molebridge.service <<'UNIT'
[Unit]
Description=Molebridge rootless Podman project
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=%h/molebridge
ExecStart=/usr/bin/podman-compose up -d
ExecStop=/usr/bin/podman-compose stop
TimeoutStartSec=900
TimeoutStopSec=180

[Install]
WantedBy=default.target
UNIT
systemctl --user daemon-reload
systemctl --user enable --now molebridge.service
```

Set `WorkingDirectory` to your checkout. On the tested host, a reboot brought
the exit back healthy in 76 seconds with no intervention. That's one reboot
on one host, so check health and the namespaces after a reboot anyway.
Podman doesn't act on failing healthchecks: a stranded `netbird` or `applier`
stays stranded until you recreate all four.

Expect relayed devices on rootless Podman until you follow
[exits on a private container network](#exits-on-a-private-container-network).

## Rotating keys

**Mullvad.** Generate a config for a new device on mullvad.net, run
`tools/prepare-tunnel-config.py` on it, then `recover`. Once the exit works,
remove the old device on mullvad.net.

**PIA.** Move `tunnel/wg_confs/pia.conf` aside, run
`tools/prepare-tunnel-config.py --pia`, then `recover`. The applier registers
the new key in the saved region on its own. To change the PIA password, rewrite
`secrets/pia/password` and restart the applier.

**NordVPN.** NordVPN's API returns the account's one NordLynx key; how to make
it issue a new one hasn't been checked. To rebuild the config, move
`tunnel/wg_confs/nordvpn.conf` aside, run `tools/nordvpn-key.py` with a new
access token as in [setup](setup.md#2-create-the-tunnel-config), then
`recover`. The applier applies the saved server again on its own.

## Removing

1. In NetBird, delete the exit route and the access policy.
2. On rootless Podman, disable the boot unit first:
   `systemctl --user disable --now molebridge.service`.
3. `docker compose down`. Add `-v` to also delete the peer's identity volume.
4. If a separate Switchyard serves this exit, remove the exit from its
   `PANEL_EXITS` and its volume mounts.
5. Delete the peer in NetBird. With Mullvad, also delete the device on
   mullvad.net.
6. Delete `.env`, `tunnel/wg_confs/`, `secrets/` and `state/`, or keep them
   if you might reinstall.
