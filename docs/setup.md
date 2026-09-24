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
overlay), `PUID`/`PGID` (from `id -u` and `id -g`), `PANEL_USER`, `NB_HOSTNAME`,
and `NB_MANAGEMENT_URL` if you self-host NetBird. Every setting is described in
[configuration](configuration.md). On Docker, `PANEL_USER` is your
`PUID:PGID`; on rootless Podman it is `0:0`.

The routing init script is bundled root-owned in its image. Your checkout can
remain owned by your normal user. Make sure `state/panel` is owned and writable
by the `PUID`/`PGID` selected above; create it as that user.

## 2. Create the tunnel config

```sh
tools/prepare-tunnel-config.py ~/Downloads/<mullvad-download>.conf &&
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
or end-to-end connectivity. The peer enrolls with the Mullvad interface
already excluded from ICE (step 5 explains why that matters).

In NetBird, confirm the peer `NB_HOSTNAME` appears and is in `exit-nodes`. Then
delete `secrets/netbird.env` (the peer's identity now lives in the
`netbird-data` volume) and revoke the setup key if it was reusable.

## 5. Keep ICE off the tunnel interface

Required, not a tuning step. The exit peer shares its network namespace with
the Mullvad tunnel, so by default NetBird gathers ICE candidates on the tunnel
interface too. `compose.yaml` excludes it from the first enrollment:
`NB_EXTRA_IFACE_BLACKLIST=mullvad` binds NetBird's `--extra-iface-blacklist`
flag on the first `netbird up`, so a peer enrolled with this file has the
exclusion before it exchanges a candidate with anyone.

The environment variable works only at enrollment. NetBird stores the
blacklist in the peer's own configuration, and that stored value wins over
`NB_*` environment variables once the peer has enrolled. A peer enrolled with
an older `compose.yaml`, or re-enrolled without the variable, gets the
exclusion from the flag instead:

```sh
docker compose exec netbird netbird down
docker compose exec netbird netbird up --extra-iface-blacklist mullvad
```

Two things go wrong without it, and the second is the serious one:

- **P2P stops being attempted.** A candidate gathered on the tunnel interface
  can never complete a STUN exchange: traffic sourced from the tunnel address
  either goes into the tunnel, which is not a path to the signalling server,
  or leaves the host with a source address nothing will answer. NetBird logs
  `wait for gathering timed out`, then `ICE retries exhausted (3/3), switching
  to hourly retry`, and makes no further direct attempt for an hour. Every
  client is relayed in the meantime.
- **The tunnel address can leak into signalling.** With the interface in play,
  NetBird can offer the exit's Mullvad tunnel address to peers as an ICE
  candidate. Keeping that address inside the tunnel is the point of the
  product.

The setting lives in the `netbird-data` volume (`IFaceBlackList` in the stored
client configuration; `default.json` on NetBird 0.78), so it survives restarts
and recreation. It does **not** survive a re-enrollment made with a Compose
file that lacks the variable: re-apply the flag any time the peer identity is
recreated that way. No `netbird` command prints the stored blacklist
(`netbird debug config` omits it); `python3 tools/molebridge.py doctor` reads
that one field from the profile and fails, naming the commands above, when
the exit interface is missing.

## 6. Verify before trusting it

Run the namespace checks in [verification](verification.md#inside-the-namespace)
now, before any client can route through the exit.

## 7. Create the route and try a client

Create the exit node route and access policy from
[prerequisites](prerequisites.md#netbird). On a device in `exit-users`, select
the exit in the NetBird client and open <https://am.i.mullvad.net>. It should
report a Mullvad exit IP in the starting server's city. Then run the
[client checks](verification.md#from-a-client).

## 8. Start the panel

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
