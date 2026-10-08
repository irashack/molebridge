# Setup

This takes an empty checkout to a working exit. It assumes everything in
[requirements](prerequisites.md) is ready. Run the commands from the
repository root on the host. On rootless Podman, use `podman-compose` wherever
this page says `docker compose`.

Plan for about half an hour, most of it in the NetBird dashboard.

## 1. Get the code and configure

Check out a release tag, or a specific commit you've looked at, rather than
whatever `main` happens to be:

```sh
git clone https://github.com/irashack/molebridge.git
cd molebridge
git checkout v0.4.1      # the latest release

cp .env.example .env
mkdir -p state/panel state/applier secrets tunnel/wg_confs
chmod 700 secrets tunnel/wg_confs
```

Edit `.env`. The settings you must set:

| Setting | Value |
|---|---|
| `OVERLAY_CIDR` | Your NetBird peer range |
| `OVERLAY6_CIDR` | Your NetBird IPv6 range, if you have one |
| `PUID`, `PGID` | The output of `id -u` and `id -g` |
| `PANEL_USER` | `PUID:PGID` on Docker; `0:0` on rootless Podman |
| `NB_HOSTNAME` | The peer name the exit should have in NetBird |
| `NB_MANAGEMENT_URL` | Your management URL, if you self-host NetBird |
| `PROVIDER`, `EXIT_IF`, `COMPOSE_FILE` | For PIA only: `pia`, `pia`, `compose.yaml:compose.pia.yaml` |

Everything else can wait; [configuration](configuration.md) lists every
setting. Create `state/panel` as the same user as `PUID`/`PGID`.

## 2. Create the tunnel config

**Mullvad.** Convert the file you downloaded, then delete the original:

```sh
python3 tools/prepare-tunnel-config.py ~/Downloads/<your-file>.conf &&
  rm ~/Downloads/<your-file>.conf
```

This writes `tunnel/wg_confs/mullvad.conf` with mode 0600. It keeps the key,
the tunnel addresses and the starting server, and drops the DNS line.
WireGuard's own routing is replaced by the exit table that the routing script
guards. Nothing secret is printed.

**PIA.** Generate a key, then store the login, one value per file:

```sh
python3 tools/prepare-tunnel-config.py --pia

mkdir -p secrets/pia && chmod 700 secrets/pia
(umask 077; printf '%s' 'p1234567' > secrets/pia/username)
(umask 077; read -rs pia_password && printf '%s' "$pia_password" > secrets/pia/password)
```

Replace `p1234567` with your username, and type the password at the prompt,
so it stays out of your shell history. `--pia` writes `tunnel/wg_confs/pia.conf`,
which holds only the private key, and refuses to overwrite an existing one.

## 3. Add the NetBird setup key

Open `secrets/netbird.env` in an editor, so the key never lands in shell
history:

```sh
(umask 077 && ${EDITOR:-vi} secrets/netbird.env)
```

Write one line: `NB_SETUP_KEY=` followed by the key.

## 4. Start the exit, without a route yet

```sh
docker compose build wireguard applier
docker compose up -d wireguard netbird applier
docker compose ps
docker compose logs wireguard | grep 10-exit-routing
```

The log should end with `rules installed`, and `wireguard` and `netbird`
should become healthy. With Mullvad, `applier` becomes healthy too, once it
has verified the starting server. With PIA, `applier` stays unhealthy until
you pick a region in step 7, because a fresh PIA tunnel has no peer yet. If
the routing script refuses to start, it names the setting it rejected
([troubleshooting](troubleshooting.md#startup)).

In the NetBird dashboard, check that the peer appears under `NB_HOSTNAME` and
is in `exit-nodes`. Then delete `secrets/netbird.env`: the peer's identity now
lives in the `netbird-data` volume. Revoke the setup key if it was reusable.

## 5. Keep ICE off the tunnel interface

This step is required. NetBird shares a network namespace with the tunnel, so
by default it looks for connection candidates on the tunnel interface too.
That has two effects. Direct connections fail and clients fall back to a
relay. Worse, the exit's VPN tunnel address can be offered to other peers.

A peer enrolled with this repository's `compose.yaml` already has the tunnel
interface blacklisted: `NB_EXTRA_IFACE_BLACKLIST` sets it on the first
enrollment. Check it:

```sh
python3 tools/molebridge.py doctor
```

Doctor checks the blacklist before the provider checks. On a PIA exit, the
provider checks fail until you pick a region in step 7; that's expected here.
If doctor reports the interface missing from the blacklist, set it with the
flag. This is needed for a peer enrolled with an older Compose file, or
re-enrolled without the variable:

```sh
docker compose exec netbird netbird down
docker compose exec netbird netbird up --extra-iface-blacklist mullvad
```

Use your `EXIT_IF` in place of `mullvad` (`pia` for PIA).

The setting is stored in the peer's own configuration in the `netbird-data`
volume. It survives restarts and recreation, and environment variables can't
change it afterwards. [Architecture](architecture.md#routing-contract) explains
the failure in more detail.

On rootless Podman, doctor isn't available. Read the one field by hand, as
shown in [operations](operations.md#rootless-podman).

## 6. Check the namespace

Run the checks in [verification](verification.md#inside-the-namespace) now,
while no device can route through the exit yet. With PIA, the egress check
needs a region, so come back to it after step 7.

## 7. Start the panel

Choose an [access method](access.md). Behind a proxy, set `PANEL_PUBLIC_HOSTS`
to its public hostname. For SSH forwarding you can leave it empty. Then:

```sh
docker compose up -d control-panel
```

A proxy on the host should forward to `http://127.0.0.1:${PANEL_PORT}` (8095
by default). The first page load can take a few seconds while the applier
fetches the server list.

With PIA, choose a region now. Until you do, the exit reports "No PIA region
is registered yet" and carries no traffic.

## 8. Create the route and try a device

In NetBird, create the exit-node route and the access policy described in
[requirements](prerequisites.md#netbird). On a device in `exit-users`, select
the exit in the NetBird client and open the provider's check page:

- Mullvad: <https://mullvad.net/check> should show a Mullvad server in the
  starting server's city.
- PIA: PIA's own "what is my IP" page, or any IP check, should show an
  address in the region you picked.

Then run the [client checks](verification.md#from-a-client), and finish with
`python3 tools/molebridge.py doctor`. A passing doctor isn't a leak test; the
[verification](verification.md) drills are.


Next: [Switchyard](switchyard.md) covers using the panel, and
[operations](operations.md) covers upgrades, recovery and boot on Podman.
