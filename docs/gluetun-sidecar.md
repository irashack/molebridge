# The gluetun sidecar

**Your applications' traffic leaves through gluetun's tunnel, or not at all,
as far as gluetun's firewall keeps it there.** Molebridge installs no routes
or firewall rules in this form and doesn't inspect gluetun's: what it adds is
choosing gluetun's server and checking the peer, the handshake and, for
Mullvad and NordVPN, the egress ([what is checked](#what-is-checked-and-by-whom)).

**Experimental.** It has run live with NordVPN only, on Kubernetes and on
rootless Podman with Quadlet units
([what was tested](#limits-and-what-wasnt-tested)).

## Who it is for

Use this when you want an ordinary [gluetun](https://github.com/qdm12/gluetun)
container that other containers share (`network_mode: service:gluetun`),
with Switchyard to choose and check its server. Your applications send their
own traffic through gluetun's tunnel. Nothing is forwarded for other
devices: there is no NetBird peer and no Molebridge routing contract. That is
the NetBird exit ([natively](netbird-exit.md) or [with
gluetun](gluetun-netbird-exit.md)).

Choose it for gluetun's providers: FastestVPN, IVPN, Mullvad, NordVPN,
Surfshark and Windscribe. If you want Molebridge to build the tunnel itself,
and to keep your applications' traffic in it with a routing contract and a
firewall it checks, with PIA over WireGuard or Mullvad or NordVPN, use the
[native sidecar](native-sidecar.md) instead; its page compares the two.
[The menu](menu.md) compares every way in.

## What you run

`compose.sidecar.yaml` with `.env.sidecar.example`, or the same services
written by `molebridge init` with the `sidecar` way in and a `gluetun-<id>`
provider ([setup](setup.md#molebridge-init)). The exit is the `sidecar` kind,
`EXIT_KIND=sidecar` with `TUNNEL_BACKEND=gluetun`.

| Service | Image | Role |
|---|---|---|
| `gluetun` | `docker.io/qmcgaw/gluetun:v3.41.3`, pinned by digest | Owns the namespace, the tunnel and its firewall. Starts through `routing/gluetun-preflight` with `MOLEBRIDGE_KIND=sidecar`. The engine's default capabilities plus `NET_ADMIN` |
| `exit` | `ghcr.io/irashack/molebridge-core` | Joins gluetun's namespace, reads gluetun's server list and selects servers through its control server, checks the peer, handshake and egress, and writes the status record. `NET_ADMIN`, `NET_RAW` and `DAC_OVERRIDE` ([its privileges](#the-exits-privileges)) |
| your applications | yours | `network_mode: service:gluetun`, listed in `SIDECAR_APPS`. `example-app`, a busybox that only sleeps, stands in under the `example` profile |
| `switchyard` | `ghcr.io/irashack/molebridge-core` | The panel, optional |

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
egress and DNS yourself after setup and after changes.

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
[Setup](setup.md) has the steps every way in shares; these are the gluetun
sidecar's. If `molebridge init` wrote your `compose.yaml`, `.env` and
`routing/gluetun-preflight`, skip the copy in step 1 and use its files where
the steps name `compose.sidecar.yaml`.

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
       restart: "no"
       depends_on:
         gluetun:
           condition: service_healthy
           restart: true
   ```

   Then, in `.env`, set `COMPOSE_FILE=compose.sidecar.yaml:compose.apps.yaml`
   (podman-compose doesn't read it from `.env`: pass the files with `-f`,
   [rootless Podman](prerequisites.md#rootless-podman))
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
   docker compose pull
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

## Starting at boot

`depends_on` holds your applications back only when `docker compose up`
starts them. After a reboot or an engine restart, Docker starts every
`restart: unless-stopped` or `restart: always` container by itself, without
waiting for anything, and an application in gluetun's namespace can then run
before gluetun has set up its firewall, while the namespace still has the
host's routes. So give your applications `restart: "no"`, as `example-app`
has, and start the stack at boot with Compose, which waits for gluetun to be
healthy. gluetun and the exit keep `unless-stopped`. The native sidecar's
[starting at boot](native-sidecar.md#starting-at-boot) has a systemd unit
for this; use it with this directory and Compose file. Then run the
[attachment check](#checking-that-containers-share-gluetuns-namespace).
This boot order has not been tested with the gluetun sidecar.

## Choosing and switching servers

gluetun starts on the server its `GLUETUN_SERVER_*` settings give it. Choose a
server in the panel, or set `SERVER` in `.env` to one hostname from the
catalog to keep the exit on it
([a server set in configuration](configuration.md#a-server-set-in-configuration)).
The exit puts the selection to gluetun's control server, which restarts its
VPN in-process, so your applications' connections may drop; after gluetun
restarts, the exit puts your last selection back. The server list is
gluetun's, as current as gluetun's updater keeps it; on a first start set
`GLUETUN_SERVER_COUNTRIES` to your own country, as [the gluetun NetBird
exit's first start](gluetun-netbird-exit.md#the-first-start) explains for
both forms. There is no automatic failover: the exit refuses to start with
`FAILOVER` on, as gluetun reconnects by itself.

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

## Kubernetes

The gluetun sidecar runs in one pod with the applications, like the exit's
[Kubernetes form](gluetun-netbird-exit.md#kubernetes): write the preflight with
the `gluetun-preflight` tool into an `emptyDir`, keep gluetun's server list on a
persistent volume, leave the pod out of user namespaces, and set
`WIREGUARD_ALLOWED_IPS=0.0.0.0/0` when the pod has IPv6 and the provider carries
none (the IPv6 loop was first seen with this form). The NetBird notes there
don't apply. Molebridge ships no manifests. A gluetun sidecar with NordVPN has run
as one pod on k0s with Cilium, beside an application that only waits; no drill was
run there ([testing](testing.md)).

## Removing

`docker compose down` stops and removes the containers. Add `-v` to also delete gluetun's
data and server-list volumes. Delete `secrets/`, `state/` and `.env`, or keep them if you
might reinstall.
## Limits and what wasn't tested

**What was tested.** A sidecar with gluetun and NordVPN has been upgraded to
each release and reported healthy, on Kubernetes and on rootless Podman with
Quadlet units, with the application's public address NordVPN's, not the
host's. No drill has been run on it, and the attachment procedure has no
record since the Go rewrite. The passes are in [testing](testing.md).

**Not tested:** Mullvad and the four [tunnel-tier
providers](#tunnel-tier-providers), Docker, podman-compose, the boot order
in [starting at boot](#starting-at-boot), and an application left in
gluetun's old namespace. `compose.sidecar.yaml` is validated with
`docker compose config` only.

- **gluetun's firewall is the guarantee.** Molebridge doesn't check that your
  applications' traffic, DNS included, stays in the tunnel while it is down or
  reconnecting. Check your applications' egress and DNS yourself after setup
  and after changes.
- **Egress is verified for Mullvad and NordVPN only.** With the other four
  providers `molebridge status` stays `unknown` by design.
- **Attachment is yours to check**
  ([below](#checking-that-containers-share-gluetuns-namespace)).
- **No PIA.** gluetun drives PIA over OpenVPN only; use the
  [native sidecar](native-sidecar.md).
- **No automatic failover**, and no NetBird.
