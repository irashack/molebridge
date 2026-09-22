# Configuration

## `.env`

Non-secret settings, read by `compose.yaml`. Start from `.env.example`.

| Setting | Default | Purpose |
|---|---|---|
| `COMPOSE_PROJECT_NAME` | `molebridge` | Deployment identity used for container names, networks and the NetBird identity volume. Keep it unchanged after installation; see [rename upgrade notes](operations.md#upgrading-from-switchyard). |
| `OVERLAY_CIDR` | required | NetBird peer network range. Replies to this range return over the overlay. |
| `OVERLAY6_CIDR` | empty | IPv6 overlay range, if enabled. |
| `OVERLAY_IF` | `wt0` | NetBird's interface name inside the namespace. Compose passes it as `NB_INTERFACE_NAME` and uses it for the startup gate, routing and health checks. |
| `EXIT_TABLE` | `51821` | Dedicated table (256..2147483647). Must match the tunnel config; rerun `tools/prepare-tunnel-config.py` with `EXIT_TABLE` exported if you change it. The helper does not source `.env`. |
| `NB_HOSTNAME` | `molebridge-exit` | NetBird peer name. |
| `NB_MANAGEMENT_URL` | `https://api.netbird.io` | NetBird management server. |
| `PUID`, `PGID` | `1000` | Host user and group that own `state/`. |
| `PANEL_USER` | `1000:1000` | The panel's `user:` inside its container, as `uid:gid`. On an engine that maps container uids to host uids directly, set it to your `PUID:PGID`. On a rootless engine that remaps them, container root is already your host user and an unmapped uid cannot read the 0700 state tree: use `0:0`. The panel still holds no capabilities. |
| `TZ` | `Etc/UTC` | Container time zone. |
| `PANEL_PORT` | `8095` | Loopback port for the panel. |
| `PANEL_PUBLIC_HOSTS` | empty | Comma-separated names the panel is served under, with the port when it is not 80/443: the public hostname and, if your proxy rewrites the upstream `Host`, that name too (for example `host.docker.internal:8095`). Requests for any other name get 421; loopback names are always accepted. Form posts are accepted only from these origins. |
| `PANEL_FRAME_ANCESTORS` | empty | Space-separated `https://` origins allowed to embed the panel. Empty forbids framing. |
| `PANEL_TITLE` | `Molebridge` | Page and app name. |
| `PANEL_SHORT_TITLE` | `Molebridge` | Home-screen icon label. |
| `PANEL_HOST_LABEL` | `this exit` | Used in "Fastest from …". |
| `PANEL_HOME_URL`, `PANEL_HOME_LABEL` | empty, `Home` | Optional back link in the page header. |
| `GATUS_URL` | empty | Gatus base URL for health pushes; empty disables them. |
| `GATUS_ENDPOINT` | `molebridge` | Gatus external endpoint key. |

## Secret files

All mode 0600 and ignored by git. Document them by name only; never paste their
contents anywhere.

| File | Contents | Needed |
|---|---|---|
| `tunnel/wg_confs/mullvad.conf` | Mullvad private key, tunnel addresses (one IPv4, at most one IPv6), starting server | Always |
| `secrets/netbird.env` | `NB_SETUP_KEY` | Until the peer first enrolls |
| `secrets/applier.env` | `GATUS_TOKEN` | Only with `GATUS_URL` |

## State files

Under `state/`, written with temp-file-and-rename. None hold secrets.

| File | Writer | Reader | Contents |
|---|---|---|---|
| `applier/relays.json` | applier | panel (read-only) | `fetched_at` and validated `relays`: hostname → `hostname`, `country`, `city`, `location_code`, `public_key`, `ipv4_addr_in` |
| `applier/relay-error.json` | applier | panel (read-only) | Sanitized last refresh error and timestamp, or an empty object after success |
| `panel/desired.json` | panel | applier (read-only) | `server`, `requested_at`, `request_id`. Each selection gets a new ID so the same server can be retried. Old two-field requests remain readable. |
| `applier/result.json` | applier | panel (read-only) | Observed `server`, `requested_server`, acknowledged `request_id`, `status` (`unknown`/`applying`/`ok`/`failed`), `message`, egress fields (`egress_ip` is IPv4; `egress_ips` maps `4`/`6` to separately checked addresses), `mullvad_exit_ip`, `handshake_age_s`, `unreachable_fallback`, `routing_ok`, `checked_at` |

Routing initialization reads only the `Address` line of the tunnel config, for
the return-path rule; `compose.yaml` sets `net.ipv4.icmp_errors_use_inbound_ifaddr`
on the `wireguard` service for the same reason, and the applier and doctor
require both. See [architecture](architecture.md#routing-contract).

The old `panel/relays.json` and `applier/.last-server` files are ignored. Public
applier snapshots are mode 0644 so the non-root panel can read them; requests
are mode 0600. The panel cannot write the applier directory. Catalogue refresh
is every six hours (one-minute retry on failure), maximum catalogue age is 24
hours, and maximum status age is 150 seconds. These are fixed safety defaults.

## Panel endpoints

| Path | Purpose |
|---|---|
| `/` | Full panel |
| `/embed` | Compact view for iframes |
| `POST /select` | Choose a server (CSRF token and origin check required) |
| `/api/status` | Desired server and applier result |
| `/api/latency` | `scope=cities`, `country=<name>`, or `hosts=<a,b>` (64 at most); `fresh=1` ignores the cache |
| `/manifest.webmanifest` | Web app manifest |
| `/healthz` | Liveness |
| `/readyz` | 200 only for a fresh verified connected state; 503 otherwise |
