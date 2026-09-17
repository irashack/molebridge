# Configuration

## `.env`

Non-secret settings, read by `compose.yaml`. Start from `.env.example`.

| Setting | Default | Purpose |
|---|---|---|
| `OVERLAY_CIDR` | required | NetBird peer network range. Replies to this range return over the overlay. |
| `OVERLAY6_CIDR` | empty | IPv6 overlay range, if enabled. |
| `OVERLAY_IF` | `wt0` | NetBird's interface name inside the namespace. |
| `EXIT_TABLE` | `51821` | Routing table for forwarded traffic. Must match the tunnel config; rerun `tools/prepare-tunnel-config.py` with `EXIT_TABLE` set if you change it. |
| `NB_HOSTNAME` | `switchyard-exit` | NetBird peer name. |
| `NB_MANAGEMENT_URL` | `https://api.netbird.io` | NetBird management server. |
| `PUID`, `PGID` | `1000` | Host user and group that own `state/`. The panel runs as this user. |
| `TZ` | `Etc/UTC` | Container time zone. |
| `PANEL_PORT` | `8095` | Loopback port for the panel. |
| `PANEL_PUBLIC_HOSTS` | empty | Comma-separated hostnames the panel is published on. Form posts are accepted only from these origins (or the request's own `Host`). |
| `PANEL_FRAME_ANCESTORS` | empty | Space-separated `https://` origins allowed to embed the panel. Empty forbids framing. |
| `PANEL_TITLE` | `Mullvad exit` | Page and app name. |
| `PANEL_SHORT_TITLE` | `Exit` | Home-screen icon label. |
| `PANEL_HOST_LABEL` | `this exit` | Used in "Fastest from …". |
| `PANEL_HOME_URL`, `PANEL_HOME_LABEL` | empty, `Home` | Optional back link in the page header. |
| `GATUS_URL` | empty | Gatus base URL for health pushes; empty disables them. |
| `GATUS_ENDPOINT` | `switchyard` | Gatus external endpoint key. |

## Secret files

All mode 0600 and ignored by git. Document them by name only; never paste their
contents anywhere.

| File | Contents | Needed |
|---|---|---|
| `tunnel/wg_confs/mullvad.conf` | Mullvad private key, tunnel addresses, starting server | Always |
| `secrets/netbird.env` | `NB_SETUP_KEY` | Until the peer first enrolls |
| `secrets/applier.env` | `GATUS_TOKEN` | Only with `GATUS_URL` |

## State files

Under `state/`, written with temp-file-and-rename. None hold secrets.

| File | Writer | Reader | Contents |
|---|---|---|---|
| `panel/relays.json` | panel | applier | `fetched_at` and `relays`: hostname → `hostname`, `country`, `city`, `location_code`, `public_key`, `ipv4_addr_in` |
| `panel/desired.json` | panel | applier | `server`, `requested_at`. The chosen server; back it up if you care. |
| `applier/result.json` | applier | panel | `server`, `status` (`applying`/`ok`/`failed`), `message`, `egress_ip`, `egress_city`, `egress_country`, `mullvad_exit_ip`, `handshake_age_s`, `unreachable_fallback`, `checked_at` |

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
