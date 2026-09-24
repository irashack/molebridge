# Operations

## Switching servers

Open the panel. **Current exit** shows the chosen server, its egress IP, and a
status: connected, switching, failed or unknown/stale. **Fastest from …** lists the
lowest-latency cities with a Switch button. **Locations** groups every Mullvad
WireGuard server by country and city, with a filter (press `/`).

A switch takes two clicks: the first arms the button, the second (within four
seconds) confirms. Without JavaScript a single click submits. The applier then
swaps the tunnel's peer and waits for a fresh handshake and a Mullvad-confirmed
egress, normally a few seconds. The panel follows along and refreshes when it
finishes. The initial peer is identified from the running interface without an
initial panel selection.

Every device using the exit shares the one server, and open connections through
the exit drop at the switch.

If a switch fails, the panel shows the failure and the request is not retried
continuously. Select the same server again to retry, or select another one.
If the request is waiting for a fresh catalogue, the overlay interface or tunnel
routing before any peer change, its diagnostic says it will retry automatically.
The saved selection stays pending through these startup failures.
The applier never chooses another server on its own. A failed probe means the
path was not verified; an approved working tunnel can still carry traffic while
the check endpoint is unavailable. Routing prevents fallback through the host.

Missing or more-than-150-second-old applier checks show unknown/stale. The page
polls every 30 seconds when settled and every two seconds while switching;
failed browser polls clear the connected indication. Diagnostics describe the
last check, not a live handshake age.

## Latency

Numbers are the TCP handshake time from the exit host to each server's port 443.
That is the round trip your host adds on its way to Mullvad, not the latency
through the tunnel. They are measured only while a panel page is open:

- on page load, one server per city plus the current server;
- when you open a country, every server in it;
- when the filter narrows to 64 servers or fewer, those servers;
- when you press Retest, the per-city check again, ignoring the cache.

Results are cached in memory for 15 minutes. With no panel open, nothing is
measured.

## Relay list

The applier fetches Mullvad's published relay list at startup and every six
hours. It keeps the last good catalogue if a fetch fails, retries after a
minute and publishes a sanitized error for the panel. A catalogue older than
24 hours cannot authorize switching or a healthy result. The panel's mount is
read-only; it can only submit a desired server name.

## Embedding in a dashboard

`/embed` is a compact view (current exit, top five, locations) for iframe
widgets. Allow your dashboard's origin to frame it:

```sh
PANEL_FRAME_ANCESTORS=https://dashboard.example.net
```

For Glance or Dynacat:

```yaml
- type: iframe
  title: Molebridge
  title-url: https://exit.example.net
  source: https://exit.example.net/embed
  height: 460
```

If your proxy authenticates with a session cookie, the frame needs a live
session for the panel's hostname. When it has lapsed the frame is blank; open
the panel directly once to sign in. The dashboard and the panel must be on the
same site (for example two subdomains of `example.net`) for the browser to send
that cookie inside the frame.

## Installing on a phone

The panel is an installable web app. On iPhone, open it in Safari and choose
Share → Add to Home Screen; on Android, use the browser's Install app option. It
opens full screen, and its status refreshes whenever you return to it.

On iOS a home-screen app keeps cookies separate from Safari, so it signs in to
your proxy on its own the first time and whenever that session expires. This
has been tested with a passkey sign-in through a NetBird reverse proxy.

## DNS

Molebridge leaves DNS alone. Clients keep resolving names with whatever
resolver they already use, while traffic leaves through Mullvad. A DNS leak
test may therefore show your usual resolver. On a tested iPhone with local
DNS, mullvad.net/check reported no DNS or WebRTC leak, but that depends on the
client and network.

Sending DNS through Mullvad instead would need a resolver inside the exit's
namespace forwarding to Mullvad's resolver over the tunnel, plus a NetBird
nameserver group. That would apply even when the exit is not selected, and DNS
would fail whenever the tunnel is down. Molebridge does not provide it.

## Direct connections

The exit peer must keep ICE off the Mullvad tunnel interface. `compose.yaml`
sets it at the first enrollment through `NB_EXTRA_IFACE_BLACKLIST`; for a peer
enrolled before that variable existed, the flag
`netbird up --extra-iface-blacklist mullvad` sets it
([setup](setup.md#5-keep-ice-off-the-tunnel-interface)). Either way it is
stored in the peer's own configuration inside the `netbird-data` volume, where
it survives restarts, recreation and the recovery helper, and where `NB_*`
environment variables can no longer change it. Without it, clients are relayed
and the exit's tunnel address can be offered to peers as an ICE candidate.
No `netbird` command prints the stored value; `python3 tools/molebridge.py
doctor` checks it, and the [Podman section](#rootless-podman) shows how to read
the field by hand.

To see what a peer is doing, raise the client log level, read the discovered
local candidates and the remote ones, then put the level back:

```sh
docker compose exec netbird netbird debug log level debug
docker compose exec netbird netbird debug log level info
```

Treat candidate addresses as private; they identify your network.

### Exits on a private container network

A second, independent reason clients end up relayed. If the engine puts the
exit's namespace on a private container bridge, as every rootless setup and
Docker's default bridge do, the peer's only host candidate is that bridge
address, which nothing outside the host can reach. The namespace is also
behind the engine's NAT, so the peer gathers no server-reflexive candidate of
its own. Every client then falls back to the relay silently: the exit works,
it is just slower, so nothing reports a fault.

Two settings fix it, alongside publishing the port:

```yaml
  wireguard:
    ports:
      - "51825:51825/udp"
```

```sh
docker compose exec netbird netbird down
docker compose exec netbird netbird up \
  --extra-iface-blacklist mullvad \
  --wireguard-port 51825 \
  --external-ip-map 198.51.100.10/eth0
```

- The published port and `--wireguard-port` must be the same number. Pick one
  that is free on the host; a NetBird client running on the host itself
  already holds 51820.
- `--external-ip-map <address>/<interface>` is what the peer advertises in
  place of the unreachable container address. For clients on the same LAN that
  is the host's LAN address; for clients arriving over the Internet it is the
  router's public address, with that UDP port forwarded to the host.
- Publishing a UDP port is new exposure. Do it deliberately, and prefer the
  LAN address unless remote clients actually need the direct path.
- The remote candidate may then resolve as `prflx`. Rootless port forwarding
  rewrites the source address, and ICE's peer-reflexive mechanism covers that;
  it is expected, not a fault.

## Health

The applier rewrites `state/applier/result.json` about every minute. Healthy
requires a recent handshake, confirmed Mullvad egress, a fresh catalogue matching
the observed peer, an existing overlay interface, and intact routing rules and
fallback routes for both address families. Each family configured on the tunnel
must also have its tunnel default, its return-path rule for the live tunnel
address, and pass its own egress probe; the ICMP source sysctl must be set. An
IPv4-only tunnel does not require IPv6 egress. Missing, malformed and
future-dated status is not trusted.

`/healthz` checks the panel process. `/readyz` returns 200 only for fresh
verified connectivity, otherwise 503. The host-side doctor checks configuration,
permissions, the existing identity volume, namespace agreement and applier state:

```sh
python3 tools/molebridge.py doctor
```

For optional Gatus monitoring, configure `GATUS_URL` and `GATUS_ENDPOINT`,
and store `GATUS_TOKEN` in `secrets/applier.env` (mode 0600). Prefer HTTPS;
use HTTP only over a trusted local transport. Configure missing pushes as
failures in the monitoring service: a stopped applier cannot send a failure.

## Restarts and recovery

A WireGuard container recreation can leave NetBird and the applier in an old
namespace. Docker does not restart unhealthy containers by itself. Explicit
Compose dependency updates request dependent restarts, but they do not cover
all runtime crashes. Use the supported host-side recovery command:

```sh
python3 tools/molebridge.py recover
```

NetBird waits for both terminal routing guards before launching on every start,
including daemon and host restarts. The applier's Docker healthcheck fails if
its WireGuard interface or peer is missing, even when old rules and a freshly
written failure result remain in an orphaned namespace. This makes the fault
visible to a supervisor; recovery still needs to rejoin both namespace dependents.

It validates the existing deployment and identity volume, builds both derived
images before interrupting traffic, stops namespace dependents, recreates all
four containers together, waits for health and runs doctor. It never deletes a
volume or intentionally re-enrolls a peer. A failed build leaves the running
exit alone. A failure after recreation can leave the exit unavailable; fix the
reported issue and rerun recovery. Keep an independent host access path.

Recovery is explicit. There is no bundled Docker-socket watchdog. Recovery
after a host reboot has not been tested yet; see [testing](testing.md).

## Upgrades

Keep `.env` and the named NetBird identity volume. After pulling reviewed
source/image pin changes:

```sh
docker compose pull netbird control-panel
python3 tools/molebridge.py recover
```

The helper rebuilds the routing and applier images from their pinned bases.
An uncached applier build can update Debian tool packages; use `docker compose
build --no-cache applier` when intentionally refreshing them, then recover.
Rerun [verification](verification.md) after routing, image or applier changes.

`doctor` checks the settings a working exit depends on, including the
`wireguard` sysctls in your Compose file and the exit interface in the peer's
ICE interface blacklist; fix whatever it reports before relying on the upgrade.

## Rootless Podman

Tested on Debian 13 with rootless Podman 5.4 and podman-compose 1.6 on amd64,
through a deployment-specific Compose file carrying the same services, mounts
and settings as `compose.yaml`; the bundled file itself validates with
`podman-compose config` there but has not been started unchanged on that
host. `tools/molebridge.py` drives `docker compose` and reads its JSON output,
which `podman-compose config` does not offer, so on Podman the commands below
replace `doctor` and `recover`. Substitute your project name for `molebridge`
if you changed `COMPOSE_PROJECT_NAME`.

**Before the first start**, load the `wireguard` module and set
`PANEL_USER=0:0` as described in [prerequisites](prerequisites.md#host).

**Setup** follows [setup](setup.md) with `podman-compose` in place of
`docker compose`:

```sh
podman-compose build wireguard applier
podman-compose up -d wireguard netbird applier
podman-compose ps
podman logs molebridge-wireguard 2>&1 | grep 10-exit-routing
```

**Upgrade or recover.** Rebuild first, so a failed build leaves the running
exit alone, then recreate all four containers together; recreating `wireguard`
alone strands `netbird` and `applier` in its old namespace:

```sh
podman-compose pull netbird control-panel
podman-compose build wireguard applier
podman-compose up -d --force-recreate wireguard netbird applier control-panel
```

podman-compose has no `--wait`; poll health instead, then confirm the three
namespace users agree and the applier's own checks pass:

```sh
for c in wireguard netbird applier control-panel; do
  podman inspect --format '{{.State.Health.Status}}' molebridge-$c
done
for c in wireguard netbird applier; do
  podman exec molebridge-$c readlink /proc/self/ns/net
done
podman exec molebridge-applier python -m applier.apply --doctor
```

The three `readlink` values must be identical. `--doctor` prints four fixed
PASS/FAIL lines covering routing, egress, the catalogue and freshness. It does
not check the ICE blacklist, so read that one field from the peer profile
yourself; the file also holds the peer's private key, so never print more of
it:

```sh
awk '/"IFaceBlackList"/ {p=1} p {print} p && /\]|null/ {exit}' \
  "$(podman volume inspect molebridge_netbird-data --format '{{.Mountpoint}}')/default.json"
```

Never use `down -v`: the named volume is the peer's identity.

**Boot.** `restart: unless-stopped` restarts a container whose process dies,
but rootless containers start at boot only through a systemd user session.
The tested arrangement is a lingering user unit that brings the project up:

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

Set `WorkingDirectory` to your checkout. This unit is installed and active on
the tested host, but no reboot has been exercised with the exit present, so
unattended boot on Podman is **experimental**: after a reboot, run the health
and namespace checks above before trusting the exit. Podman does not act on a
failing healthcheck, so a stranded `netbird` or `applier` stays stranded until
you recreate all four containers as in the upgrade step.

**Direct connections.** A rootless project sits on a private bridge behind
the engine's NAT, so expect relayed clients until you follow
[Exits on a private container network](#exits-on-a-private-container-network),
confirming the symptom in `netbird status -d` first.

## Rotating the Mullvad key

Generate a new configuration for a new device on mullvad.net, run
`tools/prepare-tunnel-config.py` on it, then:

```sh
python3 tools/molebridge.py recover
```

Once the exit works, remove the old device on mullvad.net.

## Removing

1. Delete the exit route and access policy in NetBird.
2. `docker compose down` (add `-v` to also delete the peer's identity volume).
3. Delete the peer in NetBird and the device on mullvad.net.
4. Delete `tunnel/wg_confs/mullvad.conf` and `secrets/`.
