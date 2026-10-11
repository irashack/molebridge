# The gluetun sidecar

Experimental. Use this when you want an ordinary gluetun container that
other containers share (`network_mode: service:gluetun`), with Switchyard to
choose and check its server. Your applications send their own traffic
through gluetun's tunnel. Nothing is forwarded for other devices: there is no
NetBird peer and no Molebridge routing contract. That is the NetBird exit,
the `overlay` kind (`compose.yaml` or
[`compose.gluetun.yaml`](gluetun-netbird-exit.md)). The sidecar is the
`sidecar` kind, `EXIT_KIND=sidecar`.

**What has been tested.** One live pass, at `d5a234a` on rootless Podman 5.8
with Quadlet units and gluetun with NordVPN
([testing](testing.md#070-on-rootless-podman-at-d5a234a)): a selection
verified by NordVPN's own check, the Compose-less doctor, the control server
on loopback refusing requests without the key, the preflight refusing a
malformed role file without printing the key, and the selection restored
after gluetun restarted. Unit tests cover the host doctor and recovery
against canned Docker and Podman inspect output
(`tools/test_sidecar_tools.py`). CI runs the doctor's namespace probe and
recovery against Docker, with a busybox container owning the namespace in
gluetun's place (`tools/check-sidecar-doctor.py`), with Compose and with
the container names given directly as [under Quadlet](#rootless-podman);
that script also passed on Docker Desktop 29 on macOS. Docker with a VPN
provider, podman-compose, every provider but NordVPN (so the
[tunnel tier](#tunnel-tier-providers)), and an application left in gluetun's
old namespace on a live host are untested.

## What is checked, and by whom

| Property | Checked by | How |
|---|---|---|
| The server gluetun uses, its peer and handshake | the applier | `wg show` in gluetun's namespace, against gluetun's server list |
| Egress through the tunnel | the applier | Mullvad's and NordVPN's own checks; see [tunnel-tier providers](#tunnel-tier-providers) for the others |
| Your applications' traffic stays in the tunnel, including DNS and during a reconnect | gluetun's firewall | **Not checked by Molebridge** |
| Your applications are in gluetun's current namespace | the host doctor, `tools/molebridge.py doctor` | [below](#the-doctor) |
| The control server is authenticated and stays inside the namespace | gluetun's role file, its start check, and the host doctor | [below](#the-doctor) |

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
be compared with this host's address."), and `recover` ends with exit status `3` ([recovery](#recovery)). This is
covered by unit tests only.

### The applier's privileges

The applier runs in gluetun's namespace with `NET_ADMIN`: kernel WireGuard
answers `wg show` (peers, handshake, endpoint) only to a process with
`CAP_NET_ADMIN` over the namespace. With it, the applier could also change
gluetun's routes and firewall and read the live WireGuard private key. That
is the same authority the overlay applier holds in its own namespace. It
also has `NET_RAW`, for binding egress checks to the tunnel interface on
kernels before 5.7, and `DAC_OVERRIDE`, to read the mode-0600 API key and
write state directories owned by your user under rootful Docker. It drops
every other capability, runs read-only with `no-new-privileges`, and holds
the control server's API key, which is full gluetun administration. The
panel holds no key and no capabilities.

## Set up

You need Docker with Compose 2.24 or later, or rootless Podman with
podman-compose (untested), and Python 3.10 or later on the host for
`tools/molebridge.py`.

1. In a checkout of a Molebridge release with `compose.sidecar.yaml`:

   ```sh
   cp .env.sidecar.example .env
   mkdir -p state/panel state/applier secrets/gluetun
   chmod 700 state state/panel state/applier secrets secrets/gluetun
   ```

   Set `PANEL_USER` to the uid:gid that owns `state/` (`0:0` under rootless
   Podman), as in [configuration](configuration.md#env).

2. Edit `.env`. `GLUETUN_PROVIDER` is gluetun's provider id, one of
   `fastestvpn`, `ivpn`, `mullvad`, `nordvpn`, `surfshark` or `windscribe`.
   `EXIT_IF` is gluetun's tunnel interface name; leave it at `wg0`. Set
   `GLUETUN_WIREGUARD_ADDRESSES` if your provider assigned your key an
   address, and for the first start only `GLUETUN_SERVER_COUNTRIES`, as in
   [the gluetun backend's settings](configuration.md#gluetun-backend).

3. Put the provider's WireGuard private key in
   `secrets/gluetun/wireguard_private_key`, one line, mode 0600. Then write
   gluetun's role file and the applier's copy of its API key:

   ```sh
   python3 tools/molebridge.py gluetun-auth
   ```

   This writes `secrets/gluetun/auth.toml` and `secrets/gluetun/api_key`,
   both mode 0600, and prints neither. gluetun mounts only the role file and
   the applier only the key. Before every gluetun start,
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
   busybox that only sleeps, stands in. The doctor fails with
   `No applications declared` when `SIDECAR_APPS` is empty, and when a
   service joins gluetun's namespace without being listed.

   To reach an application from the host, publish its port on the `gluetun`
   service and open it in gluetun's firewall with
   `GLUETUN_FIREWALL_INPUT_PORTS`. Never publish port 8000: that is the
   control server, and the doctor fails if it is published. Your
   applications share the namespace's loopback, where the control server
   listens; it answers only with the API key, so keep the key out of their
   mounts.

5. Start and check:

   ```sh
   docker compose config --quiet
   docker compose up -d
   python3 tools/molebridge.py doctor
   ```

6. Open `http://127.0.0.1:8095` (or your `PANEL_PORT`). Remote access needs
   an SSH tunnel, an authenticating proxy or
   [Switchyard sign-in](access.md#sign-in-with-openid-connect). Choose a
   server and check that the panel confirms it. Your applications'
   connections may drop during a switch.

## The doctor

`python3 tools/molebridge.py doctor` reads the kind from the applier's
`EXIT_KIND` in the configuration Compose resolves. For a sidecar it checks:

- the configuration: gluetun starts through the role-file check, mounts its
  role file and no post-rules or API key, keeps its control server on
  `127.0.0.1:8000` and doesn't publish port 8000; the applier has
  `TUNNEL_BACKEND=gluetun`, a `gluetun-*` provider matching gluetun's, the
  capabilities above and nothing more, and mounts the key read-only and no
  role file or tunnel key; the panel holds no secret or capability;
  `SIDECAR_APPS` names every service in gluetun's namespace;
- the secret files, mode 0600, and the role file's form;
- namespace membership, from the engine: gluetun runs, gluetun's port 8000
  isn't published, and the applier and every application run with
  `container:<ID>` as their network mode, for gluetun's current ID;
- namespace identity. A container ID survives a restart that gives gluetun a
  new namespace, so the engine's record isn't proof. The doctor starts a
  throwaway probe joined to gluetun by its ID, then one joined to the
  applier and to each application, and compares the namespace each finds:

  ```sh
  docker run --rm --pull never --network container:<ID> --entrypoint readlink \
    --cap-drop ALL --read-only --security-opt no-new-privileges \
    localhost/molebridge-netns-probe:local /proc/self/ns/net
  ```

  The probe image is the routing image, built from this checkout's
  `routing/Dockerfile` and tagged `localhost/molebridge-netns-probe:local`
  the first time the doctor needs it; `recover` rebuilds it. It needs nothing
  from your applications' images, not even a shell. The IDs and start times
  are read before and after the probes and must not change;
- the applier's own checks, as `docker compose exec applier python -m
  applier.apply --doctor` prints them.

Every failure is one fixed line, such as
`The downloader container is not in gluetun's current network namespace; run recover.`
The doctor never prints inspect output or the configuration.

## Recovery

If gluetun is recreated on its own, the applier and your applications stay
in its old namespace, where they have no tunnel. A `docker restart gluetun`
does the same while keeping gluetun's ID. Recreate them together:

```sh
python3 tools/molebridge.py recover
```

It checks the configuration and the secret files, builds the applier and
probe images before touching anything, stops the applier and every
application in `SIDECAR_APPS`, recreates gluetun, the applier and those
applications together, and waits up to 180 seconds for them to become
healthy and up to about 180 seconds more for the applier. Then it runs the
doctor. Its exit status:

- `0`: recovered and verified;
- `3`: recovered and operational, but not verified. Every check passed but
  the applier's `verified ...` egress check, which it names in a line
  starting `UNVERIFIED Recovered and operational, but not verified:`. With a
  [tunnel-tier provider](#tunnel-tier-providers) this is the expected result:
  `recover` doesn't wait for a verification that can't come;
- `1`: recovery failed. The line starting `FAIL` names the step or check.

It never deletes a volume.

## Rootless Podman

`tools/molebridge.py` runs through `podman-compose` and `podman` when you
pass `--engine podman`, set `MOLEBRIDGE_ENGINE=podman`, or have
podman-compose and no `docker` command. It reads podman-compose's
configuration with PyYAML (`python3-yaml`), which podman-compose itself
uses. podman-compose has no `--wait`, so `recover` relies on its wait for the
applier. Podman reports a joined container's network mode as
`container:<ID>`, as Docker does, and the probe joins by ID the same way.
None of this has run on a live Podman host yet; `COMPOSE_PROFILES` support
varies between podman-compose versions, so with Podman remove the example
profile and list your own applications.

**Quadlet.** Without Compose there is no configuration to read, so name the
containers instead. This runs the same membership check, identity probe,
start-time check, published-port check and the applier's own checks (through
`podman exec <applier> python -m applier.apply --doctor`); it doesn't check
the configuration or the secret files:

```sh
python3 tools/molebridge.py doctor --kind sidecar --engine podman \
  --gluetun <gluetun container> --applier <applier container> \
  --apps <app container>,<app container> \
  --probe-image <an image with readlink>
```

`--probe-image` can name an image already on the host, such as the applier's
or the routing image; without it, or when the engine doesn't have that image,
the doctor builds the routing image from this checkout as with Compose. On
success it prints:

```
PASS namespace membership of the applier and every named application, unpublished control server, the applier's checks and recent provider check
Without Compose the configuration and secret files aren't checked; traffic protection is gluetun's firewall, which Molebridge doesn't check (docs/gluetun-sidecar.md).
```

It exits `0` when every check passes and `1` with one `FAIL` line otherwise,
where a namespace failure ends `restart gluetun, the applier and every
application together.` `recover` has no Quadlet mode. Give each application
and the applier `Network=container:<gluetun container>`, with `After=` and
`BindsTo=` on gluetun's unit, and recover by restarting the units together,
which recreates the containers, gluetun's first:

```sh
systemctl --user restart gluetun.service applier.service <app>.service
```

Then run the doctor above. A restart of gluetun's unit alone gives gluetun a
new namespace and leaves the others in the old one.

## Removing

`docker compose down` stops and removes the containers. Add `-v` to also
delete gluetun's data and server-list volumes. Delete `secrets/`, `state/`
and `.env`, or keep them if you might reinstall.
