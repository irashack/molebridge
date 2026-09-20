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

The routing init script is bundled root-owned in its image. Your checkout can
remain owned by your normal user. Make sure `state/panel` is owned and writable
by the `PUID`/`PGID` selected above; create it as that user.

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
docker compose build wireguard applier
docker compose up -d wireguard netbird applier
docker compose ps
docker compose logs wireguard | grep 10-exit-routing
```

All three should become healthy, and the routing log should show `rules installed`.
If the routing script refuses to start, it names the setting it rejected.
The WireGuard healthcheck requires a completed routing initialization before
NetBird can start. Applier health checks freshness and routing, not client DNS
or end-to-end connectivity.

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

Choose an [authenticated access method](access.md). For a proxy, set
`PANEL_PUBLIC_HOSTS` to its public hostname. For the SSH-forwarding example it
can be empty. Then:

```sh
docker compose up -d control-panel
```

If using a host-side proxy, point it at `http://127.0.0.1:${PANEL_PORT}`. The
applier fetches the catalogue and identifies the downloaded config's running
peer; the first load may take a few seconds. The panel reads that state and
does not maintain its own catalogue. No initial selection is needed.

Run `python3 tools/molebridge.py doctor` once the stack is running, then
complete the real client checks; a passing doctor alone is not a leak test.

Next: [operations](operations.md) covers switching, dashboard embedding,
installing on a phone, and failure handling.
