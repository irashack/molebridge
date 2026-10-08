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
git checkout v0.5.0      # the latest release

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
| `PROVIDER`, `EXIT_IF`, `COMPOSE_FILE` | For PIA only: `pia`, `pia`, `compose.yaml:compose.pia.yaml`. For NordVPN only (experimental): `nordvpn`, `nordvpn`, `compose.yaml:compose.nordvpn.yaml` |

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

**NordVPN** (experimental). In your Nord Account, open
NordVPN, then Advanced settings, and choose "Get access token". Then fetch
the key with the token on standard input, typed at the prompt so it stays
out of your shell history and every command line:

```sh
(read -rs nord_token && printf '%s' "$nord_token" |
  python3 tools/nordvpn-key.py - tunnel/wg_confs/nordvpn.conf)
```

Or save the token to a mode-0600 file first, and delete it afterwards:

```sh
(umask 077 && ${EDITOR:-vi} secrets/nordvpn-token)
python3 tools/nordvpn-key.py secrets/nordvpn-token tunnel/wg_confs/nordvpn.conf &&
  rm secrets/nordvpn-token
```

The tool asks NordVPN for the account's NordLynx private key and writes
`tunnel/wg_confs/nordvpn.conf` with mode 0600: the key and the address
`10.5.0.2/32`, with no peer. It prints `wrote the NordVPN tunnel config (mode
0600)` and nothing secret, refuses a token file readable by others, and never
overwrites an existing config. The token isn't needed again; revoke it in
your Nord Account if you won't make another config. Set `EXIT_TABLE` in the
environment for a table other than `51821`, as for the
[config helper](configuration.md#tunnel-config-helper).

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

The log should end with a line that starts `10-exit-routing: rules
installed`, and `wireguard` and `netbird`
should become healthy. With Mullvad, `applier` becomes healthy too, once it
has verified the starting server. With PIA, `applier` stays unhealthy until
you pick a region in step 7, because a fresh PIA tunnel has no peer yet; the
same goes for NordVPN until you pick a server. If
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
provider checks fail until you pick a region in step 7, and on a NordVPN exit
until you pick a server; that's expected here.
If doctor reports the interface missing from the blacklist, set it with the
flag. This is needed for a peer enrolled with an older Compose file, or
re-enrolled without the variable:

```sh
docker compose exec netbird netbird down
docker compose exec netbird netbird up --extra-iface-blacklist mullvad
```

Use your `EXIT_IF` in place of `mullvad` (`pia` for PIA, `nordvpn` for
NordVPN).

The setting is stored in the peer's own configuration in the `netbird-data`
volume. It survives restarts and recreation, and environment variables can't
change it afterwards. [Architecture](architecture.md#routing-contract) explains
the failure in more detail.

On rootless Podman, doctor isn't available. Read the one field by hand, as
shown in [operations](operations.md#rootless-podman).

## 6. Check the namespace

Run the checks in [verification](verification.md#inside-the-namespace) now,
while no device can route through the exit yet. With PIA, the egress check
needs a region, and with NordVPN a server, so come back to it after step 7.

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
is registered yet; choose one in the panel." and carries no traffic. With
NordVPN, choose a server; until then it reports "No NordVPN server is selected
yet; choose one in the panel."

## 8. Create the route and try a device

In NetBird, create the exit-node route and the access policy described in
[requirements](prerequisites.md#netbird). On a device in `exit-users`, select
the exit in the NetBird client and open the provider's check page:

- Mullvad: <https://mullvad.net/check> should show a Mullvad server in the
  starting server's city.
- PIA: PIA's own "what is my IP" page, or any IP check, should show an
  address in the region you picked.
- NordVPN: NordVPN's own IP check page should say you are protected, at an
  address in the city you picked.

Then run the [client checks](verification.md#from-a-client), and finish with
`python3 tools/molebridge.py doctor`. A passing doctor isn't a leak test; the
[verification](verification.md) drills are.

## With the gluetun backend instead

**Experimental:** live passes with NordVPN, on Docker and on rootless
Podman ([testing](testing.md#gluetun-backend-pass-at-a3bb14f)). With this path gluetun owns the tunnel
and brings its provider support ([providers](providers.md#the-gluetun-backend)).
The steps above still apply, with these changes:

1. In `.env`, set `COMPOSE_FILE=compose.gluetun.yaml`, `EXIT_IF=wg0`,
   `GLUETUN_PROVIDER` (one of `fastestvpn`, `ivpn`, `mullvad`, `nordvpn`,
   `surfshark`, `windscribe`), `GLUETUN_WIREGUARD_ADDRESSES` if your provider
   assigned your key an address, and `HOST_IF` on rootless Podman. For the
   first start, set `GLUETUN_SERVER_COUNTRIES` to your own country, as
   gluetun names it (`Netherlands`, `United States`), and leave the city and
   hostname empty. gluetun only knows its built-in server list then, which
   can be years old: it refuses to start when a hostname or city isn't in
   it, and picks among that list's servers, some of which may be gone. A
   whole country is unlikely to be gone, and nearby servers answer best.
   Left empty, gluetun picks from every country. The settings are in
   [configuration](configuration.md#gluetun-backend). `PROVIDER` doesn't
   apply.
2. Instead of a tunnel config, put the provider's WireGuard private key in a
   file and write gluetun's role file, the API key and gluetun's firewall
   post-rules:

   ```sh
   mkdir -p secrets/gluetun && chmod 700 secrets/gluetun
   (umask 077 && ${EDITOR:-vi} secrets/gluetun/wireguard_private_key)
   python3 tools/molebridge.py gluetun-auth
   python3 tools/molebridge.py gluetun-post-rules
   ```

   The key file holds one line, the private key. Add `--ipv4-only` to the
   last command if gluetun later logs that it found no working ip6tables.
   Neither helper calls the container engine, so both work the same with
   podman-compose; `gluetun-post-rules` reads `.env`, with a setting
   exported in your shell taking precedence.
3. The NetBird setup key is the same.
4. Start with `docker compose build guard applier` and `docker compose up -d
   gluetun guard netbird applier`, and read `docker compose logs guard`: it
   should say `every rule and route in place`. `netbird` starts once `guard`
   is healthy.
5. Use `wg0` (your `EXIT_IF`) in the blacklist commands.
6. and 7. are the same. The panel shows the provider's name "via gluetun",
   and the date of gluetun's server data in Diagnostics. On a first start
   that data is gluetun's built-in list; once gluetun's tunnel carries
   traffic (a fresh handshake), the applier asks gluetun to refresh it, Diagnostics says `updating server
   list`, and a minute or two after it finishes the panel lists the current
   servers. Choose a server after that. gluetun starts on any server (or
   the one from `GLUETUN_SERVER_*`); picking one in the panel takes over.
8. Create the route and try a device the same way. For providers other
   than Mullvad and NordVPN, the panel shows a connected exit as "tunnel
   checks only": there is no provider check. For the checks before you rely
   on it, use the gluetun ones that
   [verification](verification.md) points to, not its default-backend drills.

Next: [Switchyard](switchyard.md) covers using the panel, and
[operations](operations.md) covers upgrades, recovery and boot on Podman.
