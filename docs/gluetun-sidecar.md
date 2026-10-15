# The gluetun sidecar

Experimental. Use this when you want an ordinary gluetun container that
other containers share (`network_mode: service:gluetun`), with Switchyard to
choose and check its server. Your applications send their own traffic
through gluetun's tunnel. Nothing is forwarded for other devices: there is no
NetBird peer and no Molebridge routing contract. That is the NetBird exit,
the `overlay` kind (`compose.yaml` or
[`compose.gluetun.yaml`](gluetun-netbird-exit.md)). The sidecar is the
`sidecar` kind, `EXIT_KIND=sidecar`. If you want Molebridge to build the tunnel
itself, and to keep your applications' traffic in it, with PIA over WireGuard or
Mullvad or NordVPN, use the [native sidecar](native-sidecar.md) instead.

**What has been tested.** At 0.8.0 a sidecar with gluetun and NordVPN, upgraded from 0.7.0
on rootless Podman with Quadlet units, reported healthy; nothing else was run on it, and the
attachment procedure has no 0.8.0 record. Mullvad, the four
[tunnel-tier providers](#tunnel-tier-providers), Docker, podman-compose and an application left
in gluetun's old namespace are untested, and `compose.sidecar.yaml` is validated with
`docker compose config` only. The older passes are in [testing](testing.md#080).

## What is checked, and by whom

| Property | Checked by | How |
|---|---|---|
| The server gluetun uses, its peer and handshake | the exit | The peer through WireGuard's netlink interface in gluetun's namespace, against gluetun's server list |
| Egress through the tunnel | the exit | Mullvad's and NordVPN's own checks; see [tunnel-tier providers](#tunnel-tier-providers) for the others |
| Your applications' traffic stays in the tunnel, including DNS and during a reconnect | gluetun's firewall | **Not checked by Molebridge** |
| Your applications are in gluetun's current namespace | you, with the attachment procedure | [below](#checking-that-containers-share-gluetuns-namespace) |
| The control server is authenticated and stays inside the namespace | gluetun's role file, the preflight before every gluetun start, and the exit at start | The exit refuses to start if the control server's port has a listener beyond loopback ([troubleshooting](troubleshooting.md#gluetun-backend)); that port is never published ([host checks](operations.md#host-checks)) |
| gluetun starts without the overlay's post-rules | the preflight, in gluetun's own container | `MOLEBRIDGE_KIND=sidecar` refuses to start gluetun while the post-rules file is mounted |

gluetun's firewall is what keeps your applications' traffic in the tunnel
when the tunnel is down or reconnecting. Molebridge installs no routes or
firewall rules here and doesn't inspect gluetun's. Check your applications'
egress and DNS yourself after setup and after changes. There is no
automatic failover to another server.

### Tunnel-tier providers

Mullvad and NordVPN confirm that traffic leaves through their network. For
FastestVPN, IVPN, Surfshark and Windscribe, Molebridge's check compares the
tunnel's egress address with this host's own address, measured outside the
tunnel. A sidecar has no way to take that measurement, so with these four the
panel shows a switch as made with its egress unverified, never as connected
("switched, egress unverified", with the note "Switched; the egress couldn't
be compared with this host's address."), and `molebridge status` says
`unknown`. This is covered by unit tests only.

### The exit's privileges

The exit runs in gluetun's namespace with `NET_ADMIN`: kernel WireGuard
answers peer, handshake and endpoint queries only to a process with
`CAP_NET_ADMIN` over the namespace. With it, the exit could also change
gluetun's routes and firewall and read the live WireGuard private key. That
is the same authority the overlay exit holds in its own namespace. It
also has `NET_RAW`, for binding egress checks to the tunnel interface on
kernels before 5.7, and `DAC_OVERRIDE`, to read the mode-0600 API key and
write state directories owned by your user under rootful Docker. It drops
every other capability, runs read-only with `no-new-privileges`, and holds
the control server's API key, which is full gluetun administration. The
panel holds no key and no capabilities. It has no NetBird to start and no
routing contract to install, so its supervisor has nothing to clean up when
it stops.

## Set up

You need Docker with Compose 2.24 or later, or rootless Podman with
podman-compose (untested for this form). No Python is needed.

1. From the verified, extracted bundle ([setup](setup.md#1-download-and-verify)):

   ```sh
   cp .env.sidecar.example .env
   mkdir -p state/panel state/applier secrets/gluetun
   chmod 700 state state/panel state/applier secrets secrets/gluetun
   IMAGE=$(grep -o 'ghcr.io/irashack/molebridge[^ "]*' compose.sidecar.yaml | head -1)
   ```

   Set `PANEL_USER` to the uid:gid that owns `state/` (`0:0` and
   `PANEL_ALLOW_ROOT=1` under rootless Podman), as in
   [configuration](configuration.md#overrides).

2. Edit `.env`. `GLUETUN_PROVIDER` is gluetun's provider id, one of
   `fastestvpn`, `ivpn`, `mullvad`, `nordvpn`, `surfshark` or `windscribe`.
   `EXIT_IF` is gluetun's tunnel interface name; leave it at `wg0`. Set
   `GLUETUN_WIREGUARD_ADDRESSES` if your provider assigned your key an
   address, and for the first start only `GLUETUN_SERVER_COUNTRIES`, as in
   [the gluetun backend's settings](configuration.md#gluetun-backend).

3. Put the provider's WireGuard private key in
   `secrets/gluetun/wireguard_private_key`, one line, mode 0600. Then write
   gluetun's role file and the exit's copy of its API key:

   ```sh
   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/secrets/gluetun:/out" "$IMAGE" gluetun-auth /out
   ```

   This writes `secrets/gluetun/auth.toml` and `secrets/gluetun/api_key`,
   both mode 0600, and prints neither. gluetun mounts only the role file and
   the exit only the key. Before every gluetun start,
   `routing/gluetun-preflight` refuses a role file other than the one this
   command writes, so gluetun never logs part of a malformed one.

4. Add your applications in a Compose file of your own, for example
   `compose.apps.yaml`:

   ```yaml
   services:
     downloader:
       image: <your image, pinned>
       network_mode: service:gluetun
       depends_on:
         gluetun:
           condition: service_healthy
           restart: true
   ```

   Then, in `.env`, set `COMPOSE_FILE=compose.sidecar.yaml:compose.apps.yaml`
   and list every such service in `SIDECAR_APPS`, comma-separated:
   `SIDECAR_APPS=downloader`. Remove `COMPOSE_PROFILES=example` and
   `example-app` once yours are in; until then the example application, a
   busybox that only sleeps, stands in. `SIDECAR_APPS` is a label on the exit
   container; nothing checks it for you, but the
   [attachment procedure](#checking-that-containers-share-gluetuns-namespace)
   uses the same list.

   To reach an application from the host, publish its port on the `gluetun`
   service and open it in gluetun's firewall with
   `GLUETUN_FIREWALL_INPUT_PORTS`. Never publish port 8000: that is the
   control server, and the [published-ports host check](operations.md#host-checks)
   shows whether it is. Your applications share the namespace's loopback, where
   the control server listens; it answers only with the API key, so keep the key
   out of their mounts.

5. Start and check:

   ```sh
   docker compose config --quiet
   docker compose up -d gluetun
   docker compose run --rm --no-deps exit check-config
   docker compose up -d
   docker compose exec exit molebridge status
   ```

   `check-config` joins gluetun's namespace, so gluetun has to be running first.

6. Open `http://127.0.0.1:8095` (or your `PANEL_PORT`). Remote access needs
   an SSH tunnel, an authenticating proxy or
   [Switchyard sign-in](access.md#sign-in-with-openid-connect). Choose a
   server and check that the panel confirms it. Your applications'
   connections may drop during a switch.

## Checking that containers share gluetun's namespace

The exit can't see whether your applications are in gluetun's current namespace, and
neither can any container: a restart that gives gluetun a new namespace leaves the
others in the old one, with the same container ids. So `app_attachment` stays
`not-checked`. The check is a script you run on the host, from outside every container
([operations](operations.md#checking-that-containers-share-gluetuns-namespace) has the
script and what it compares). For a sidecar, name gluetun, the exit and every service in
`SIDECAR_APPS`:

```sh
sh attach.sh molebridge-sidecar-gluetun molebridge-sidecar-exit my-downloader my-other-app
```

Name each application's container yourself: a stopped or missing container only fails the
check if you name it, and a list built from `docker compose ps` leaves it out.

Every line must be `PASS`; a `FAIL` names the member that is not in gluetun's current
namespace, which you recreate together with gluetun ([recovery](#recovery)). Run it after
every start, recreation or reboot, and after any gluetun update.

## Recovery

If gluetun is recreated on its own, the exit and your applications stay in its old
namespace, where they have no tunnel. A `docker restart gluetun` does the same while
keeping gluetun's id. Recreate them together, gluetun first:

```sh
docker compose up -d --force-recreate
```

recreates every service in the project, including the applications in
`compose.apps.yaml` when that file is in `COMPOSE_FILE`. Applications you run elsewhere
need their own recreate command, after gluetun; to list every container that joins
gluetun, including ones outside the project, use the command in
[operations](operations.md#recovery). Then run the attachment procedure above, and read
`docker compose exec exit molebridge status`: operational recovery and verified egress
are two different things, and with a [tunnel-tier provider](#tunnel-tier-providers)
`status` stays `unknown` by design.

Nothing here deletes a volume.

## Rootless Podman

podman-compose has not been run with this form. Under Quadlet there is no Compose file
to read, and this repository ships no units: give the exit and each application
`Network=container:<gluetun container>`, with `After=` and `BindsTo=` on gluetun's unit,
and recover by restarting the units together, which recreates the containers, gluetun's
first:

```sh
systemctl --user restart gluetun.service exit.service <app>.service
```

Then run the attachment procedure with `ENGINE=podman`
([operations](operations.md#checking-that-containers-share-gluetuns-namespace)). A
restart of gluetun alone gives it a new namespace and doesn't recover the others: with
`BindsTo=` systemd stops them, as the
[0.7.0 pass](testing.md#070-on-rootless-podman-at-d5a234a) saw after a `podman restart`,
and without it they stay in the old namespace. Either way the attachment check fails until
all of them are restarted together. The attachment procedure has not been run on Podman
in this form.

## Removing

`docker compose down` stops and removes the containers. Add `-v` to also delete gluetun's
data and server-list volumes. Delete `secrets/`, `state/` and `.env`, or keep them if you
might reinstall.
