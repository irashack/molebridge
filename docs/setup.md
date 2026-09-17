# Setup

Assumes everything in [prerequisites](prerequisites.md). Commands run from the
repository root on the host.

## 1. Configure

```sh
cp .env.example .env
mkdir -p state/panel state/applier secrets tunnel/wg_confs
chmod 700 secrets tunnel/wg_confs
```

Edit `.env`. At minimum set `OVERLAY_CIDR` (and `OVERLAY6_CIDR` if you use IPv6
overlay), `PUID`/`PGID` (from `id -u` and `id -g`), `NB_HOSTNAME`, and
`NB_MANAGEMENT_URL` if you self-host NetBird. Every setting is described in
[configuration](configuration.md).

On Linux, LinuxServer's image only runs container init scripts owned by root:

```sh
sudo chown -R root:root routing
```

(Not needed on OrbStack.)

## 2. Create the tunnel config

```sh
tools/prepare-tunnel-config.py ~/Downloads/<mullvad-download>.conf
rm ~/Downloads/<mullvad-download>.conf
```

This writes `tunnel/wg_confs/mullvad.conf` (mode 0600). It keeps the key,
tunnel addresses and chosen server, drops the DNS line, and replaces
WireGuard's automatic routing with the exit table that `routing/10-exit-routing`
guards. It prints no key material.

## 3. Add the NetBird setup key

Create `secrets/netbird.env` with an editor, so the key never appears in shell
history or process arguments:

```sh
(umask 077 && ${EDITOR:-vi} secrets/netbird.env)
```

It contains one line: `NB_SETUP_KEY=` followed by the key.

## 4. Start the exit (no route yet)

```sh
docker compose up -d wireguard netbird applier
docker compose ps
docker compose logs wireguard | grep 10-exit-routing
```

All three should become healthy, and the log should end with `rules installed`.
If the routing script refuses to start, it names the setting it rejected.

In NetBird, confirm the peer `NB_HOSTNAME` appears and is in `exit-nodes`. Then
delete `secrets/netbird.env` (the peer's identity now lives in the
`netbird-data` volume) and revoke the setup key if it was reusable.

## 5. Verify before trusting it

Run the namespace checks in [verification](verification.md#inside-the-namespace)
now, before any client can route through the exit.

## 6. Create the route and try a client

Create the exit node route and access policy from
[prerequisites](prerequisites.md#netbird). On a device in `exit-users`, select
the exit in the NetBird client and open <https://am.i.mullvad.net>. It should
report a Mullvad exit IP in the starting server's city. Then run the
[client checks](verification.md#from-a-client).

## 7. Start the panel

Set `PANEL_PUBLIC_HOSTS` to the hostname your authenticating proxy serves the
panel on, then:

```sh
docker compose up -d control-panel
```

Point the proxy at `http://127.0.0.1:${PANEL_PORT}`. The panel fetches Mullvad's
relay list on start; the first load may take a few seconds.

Until you choose a server in the panel it shows **No server selected**, while the
tunnel keeps using the server from your download. Pick a server once so the
panel and applier agree on the current choice.

Next: [operations](operations.md) covers switching, dashboard embedding,
installing on a phone, and failure handling.
