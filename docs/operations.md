# Operations

Commands assume Docker Compose from the repository root. Rootless Podman has
its own section below, because the `doctor` and `recover` helpers only work
with Docker.

## Health

The applier rewrites `state/applier/result.json` about once a minute. The exit
counts as healthy only when all of these hold:

- a recent handshake;
- egress confirmed by the provider (Mullvad's `am.i.mullvad.net` for each
  address family the tunnel has; PIA's `connected: true`);
- a server list less than 24 hours old that includes the current server;
- the NetBird interface present;
- every routing rule and fallback route in place.

A result older than 150 seconds, malformed or dated in the future counts as
unknown, whatever it says.

- `/healthz` on the panel only checks that the panel process is up.
- `/readyz` returns 200 for a fresh, verified connection and 503 otherwise.
  Point your monitoring at this one.
- `python3 tools/molebridge.py doctor` checks the Compose configuration, file
  permissions, the identity volume, that all three namespace containers share
  one namespace, the ICE blacklist, and the applier's own checks. It doesn't
  prove that client traffic is forwarded; [verification](verification.md)
  does that.

### Gatus

To push health to [Gatus](https://gatus.io), set `GATUS_URL` and
`GATUS_ENDPOINT`, and put `GATUS_TOKEN=…` in `secrets/applier.env` (mode 0600).
Use HTTPS unless the connection is local and trusted. In Gatus, treat a
missing push as a failure: a stopped applier can't report that it's down.

## Recovery

Recreating `wireguard` alone leaves `netbird` and `applier` in the old network
namespace, where they carry no traffic. Docker doesn't restart unhealthy
containers on its own. The recovery helper recreates all four together:

```sh
python3 tools/molebridge.py recover
```

It checks the deployment and identity volume first, and builds both local
images before touching the running exit, so a failed build changes nothing.
It then stops the namespace users, recreates all four containers, waits for
health and runs doctor. It never deletes a volume or enrolls a new peer. If
it fails after recreating, the exit stays down until you fix the reported
problem and run it again. Keep a way into the host that doesn't depend on this
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
| `tunnel/wg_confs/*.conf` | The tunnel private key | Mullvad: generate a new device config. PIA: generate a new key; the applier registers it again on its own |
| `secrets/` | Setup key, PIA login, Gatus token | Re-create them |
| `.env` | Settings | Re-create it |
| `state/panel/desired.json` | The chosen server | Pick again in the panel |

`state/applier/` is a cache and rebuilds itself. Saved and recent servers in
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

Molebridge leaves DNS alone. Devices keep resolving through whatever resolver
they already use, while their traffic leaves through the provider. A DNS leak
test may therefore show your usual resolver. On a tested iPhone using local
DNS, mullvad.net/check reported no DNS or WebRTC leak, but that depends on
the device and its network.

Molebridge has no option to send DNS through the provider. One way to build
it would be a resolver in the exit's namespace forwarding over the tunnel,
plus a NetBird nameserver group. That would apply even when the exit isn't
selected, and DNS would fail whenever the tunnel is down.

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

The fix is to publish a UDP port and tell NetBird to use and advertise it.
Add the port to the `wireguard` service, for example in a
`compose.override.yaml`. Compose reads that file automatically unless
`COMPOSE_FILE` is set, as it is for PIA; then add it to the list
(`COMPOSE_FILE=compose.yaml:compose.pia.yaml:compose.override.yaml`).

```yaml
services:
  wireguard:
    ports:
      - "51825:51825/udp"
```

Recreate the stack so the port is published (`recover`, or the Podman
commands below), then set NetBird's side, using your `EXIT_IF` in place of
`mullvad`:

```sh
docker compose exec netbird netbird down
docker compose exec netbird netbird up \
  --extra-iface-blacklist mullvad \
  --wireguard-port 51825 \
  --external-ip-map 198.51.100.10/eth0
```

- The published port and `--wireguard-port` must match. Pick a free one; a
  NetBird client on the host itself already uses 51820.
- `--external-ip-map` is the address the peer advertises instead of the
  container's: the host's LAN address for devices on the same LAN, or your
  public address, with the port forwarded, for devices on the Internet.
- A published port is new exposure. Prefer the LAN address unless remote
  devices really need the direct path.
- The remote candidate may show as `prflx`. Rootless port forwarding rewrites
  the source address, and ICE handles that; it isn't a fault.

## Rootless Podman

Tested on Debian 13, rootless Podman 5.4, podman-compose 1.6 on amd64. The
helpers in `tools/molebridge.py` need `docker compose`'s JSON output, which
podman-compose doesn't have, so use these commands instead. Replace
`molebridge` with your `COMPOSE_PROJECT_NAME` if you changed it.

Before the first start, load the kernel module and set `PANEL_USER=0:0`
([requirements](prerequisites.md#rootless-podman)).

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

podman-compose has no `--wait`, so check health yourself. The three
`readlink` values must be identical, and `--doctor` prints four PASS/FAIL
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
