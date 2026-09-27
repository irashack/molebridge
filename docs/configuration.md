# Configuration

## `.env`

Start from `.env.example`. These are non-secret settings read by Compose,
except `PANEL_EXITS`, which you set on a separate Switchyard container.

| Setting | Default | Purpose |
|---|---|---|
| `PROVIDER` | `mullvad` | `mullvad` or `pia`; see [providers](providers.md). Keep it unchanged after installation. |
| `EXIT_IF` | `mullvad` | Tunnel interface name, and the tunnel config's file name under `tunnel/wg_confs/`. Use `pia` with PIA. A custom name needs an explicit output path when you run the [config helper](#tunnel-config-helper). |
| `COMPOSE_FILE` | `compose.yaml` | Set to `compose.yaml:compose.pia.yaml` for PIA, which mounts the PIA login into the applier. |
| `PIA_PORT_FORWARD` | `off` | PIA only. `on` forwards one PIA port to `PIA_PORT_FORWARD_TARGET` and lists only regions that offer it. Opens a port to the Internet; see [port forwarding](providers.md#port-forwarding). |
| `PIA_PORT_FORWARD_TARGET` | empty | PIA only. The overlay IPv4 address of the one device that receives the forwarded port. Required when forwarding is on; refused otherwise. |
| `COMPOSE_PROJECT_NAME` | `molebridge` | Deployment identity used for container names, networks and the NetBird identity volume. Keep it unchanged after installation: changing it creates a fresh identity volume and enrolls a new peer. |
| `OVERLAY_CIDR` | required | NetBird peer network range. Replies to this range return over the overlay. |
| `OVERLAY6_CIDR` | empty | IPv6 overlay range, if enabled. |
| `OVERLAY_IF` | `wt0` | NetBird's interface name inside the namespace. Compose passes it as `NB_INTERFACE_NAME` and uses it for the startup gate, routing and health checks. |
| `EXIT_TABLE` | `51821` | Dedicated table (256..2147483647). Must match the table in the tunnel config's `PostUp` and `PreDown` hooks; see the [config helper](#tunnel-config-helper). |
| `NB_HOSTNAME` | `molebridge-exit` | NetBird peer name. |
| `NB_MANAGEMENT_URL` | `https://api.netbird.io` | NetBird management server. |
| `PUID`, `PGID` | `1000` | Host user and group that own `state/`. |
| `PANEL_USER` | `1000:1000` | The panel's `user:` inside its container, as `uid:gid`. On an engine that maps container uids to host uids directly, set it to your `PUID:PGID`. On a rootless engine that remaps them, container root is already your host user and an unmapped uid cannot read the 0700 state tree: use `0:0`. The panel still holds no capabilities. |
| `TZ` | `Etc/UTC` | Container time zone. |
| `PANEL_PORT` | `8095` | Loopback port for the panel. |
| `PANEL_PUBLIC_HOSTS` | empty | Comma-separated names the panel is served under, with the port when it is not 80/443: the public hostname and, if your proxy rewrites the upstream `Host`, that name too (for example `host.docker.internal:8095`). Unlisted names get 421, except on `/healthz`; loopback names are accepted. Form posts require an allowed origin. |
| `PANEL_FRAME_ANCESTORS` | empty | Space-separated origins matching `https://[a-z0-9.-]+`: lowercase `https://` and host, with no port, path, trailing slash or wildcard. Example: `https://dashboard.example.net https://home.example.net`. Invalid entries are ignored; no accepted entries means framing is forbidden. |
| `PANEL_TITLE` | `Switchyard` | Page and app name. |
| `PANEL_SHORT_TITLE` | `Switchyard` | Home-screen icon label. |
| `PANEL_HOST_LABEL` | `this exit` | Used in "Fastest from …". |
| `PANEL_HOME_URL`, `PANEL_HOME_LABEL` | empty, `Home` | Optional back link in the page header. |
| `PANEL_THEME` | `auto` | `auto` follows each viewer's light or dark system setting; `dark` or `light` fixes it. Any other value means `auto`. Set `dark` when an always-dark dashboard embeds the panel. |
| `PANEL_STYLE` | `provider` | `provider` uses the provider's colors; `dashboard` uses the neutral Catppuccin palette and JetBrains Mono. Any other value means `provider`. Mullvad's tree and PIA's region list keep their layout in either style. |
| `PANEL_EXITS` | empty | Set on a separate Switchyard container serving several exits. `compose.yaml` does not pass it to the bundled panel. See [several exits in one panel](switchyard.md#several-exits-in-one-panel). |
| `GATUS_URL` | empty | Gatus base URL for health pushes; empty disables them. |
| `GATUS_ENDPOINT` | `molebridge` | Gatus external endpoint key. |

## Tunnel config helper

The helper accepts a Mullvad source file or `--pia`, followed by an optional
output path:

```text
python3 tools/prepare-tunnel-config.py downloaded.conf [OUTPUT]
python3 tools/prepare-tunnel-config.py --pia [OUTPUT]
```

Omit `[OUTPUT]` to use `tunnel/wg_confs/mullvad.conf` or, with `--pia`,
`tunnel/wg_confs/pia.conf`. For a custom `EXIT_IF`, give the matching path,
such as `tunnel/wg_confs/exitvpn.conf`. The helper does not read `EXIT_IF` or
source `.env`; pass a non-default table through the environment, for example
`EXIT_TABLE=51822 python3 tools/prepare-tunnel-config.py --pia`.

`--pia` generates a key and refuses to overwrite an existing config. To change
an existing PIA exit to table `51822` while keeping its key, set
`EXIT_TABLE=51822` in `.env` and edit only these two lines in its tunnel config:

```ini
PostUp = ip route replace default dev %i table 51822
PreDown = ip route del default dev %i table 51822
```

Keep the file mode 0600. For Mullvad, change the table in both hooks too,
including their `ip -6` commands if present. Apply the change with
[recovery](operations.md#recovery), then run [verification](verification.md).

## Secret files

All mode 0600 and ignored by git. Document them by name only; never paste their
contents anywhere.

| File | Contents | Needed |
|---|---|---|
| `tunnel/wg_confs/mullvad.conf` | Mullvad private key, tunnel addresses (one IPv4, at most one IPv6), starting server | With Mullvad |
| `tunnel/wg_confs/pia.conf` | PIA tunnel private key only; no address or peer | With PIA |
| `secrets/pia/username`, `secrets/pia/password` | The PIA login, one value per file | With PIA |
| `secrets/netbird.env` | `NB_SETUP_KEY` | Until the peer first enrolls |
| `secrets/applier.env` | `GATUS_TOKEN` | Only with `GATUS_URL` |

## State files

Under `state/`, written with temp-file-and-rename. None hold secrets.

| File | Writer | Reader | Contents |
|---|---|---|---|
| `applier/relays.json` | applier | panel (read-only) | `fetched_at`, `provider` and validated `relays`. Mullvad: hostname → `hostname`, `country`, `city`, `location_code`, `public_key`, `ipv4_addr_in`, and when Mullvad publishes them well formed, `owned` and `stboot` (booleans) and `provider` (text, at most 64 characters). PIA: region id → `hostname` (the id), `country`, `city`, `location_code`, `ipv4_addr_in` (the latency target), `port_forward`, `geo` and `servers` (`ip`, `cn`). A snapshot for another provider is ignored. |
| `applier/tunnel.json` | PIA applier | PIA applier | Current registration (`region`, `cn`, `server_ip`, `server_port`, `server_key`, `peer_ip`, `server_vip`, `registered_at`), read to match the live peer and reconcile tunnel state. No secret. |
| `applier/relay-error.json` | applier | panel (read-only) | Sanitized last refresh error and timestamp, or an empty object after success |
| `panel/desired.json` | panel | applier (read-only) | `server`, `requested_at`, `request_id`. Each selection gets a new ID so the same server can be retried. Old two-field requests remain readable. |
| `applier/result.json` | applier | panel (read-only) | Observed `server`, `requested_server`, acknowledged `request_id`, `status` (`unknown`/`applying`/`ok`/`failed`), `message`, egress fields (`egress_ip` is IPv4; `egress_ips` maps `4`/`6` to separately checked addresses), `provider`, `exit_confirmed` (the provider confirmed the egress), `mullvad_exit_ip` (Mullvad only), `port_forward`, `forwarded_port` and `port_forward_error` (PIA only), `handshake_age_s`, `unreachable_fallback`, `routing_ok`, `checked_at` |

Routing initialization reads only the `Address` line of the tunnel config, for
the return-path rule (a PIA config has none; the applier installs the rule per
registration); `compose.yaml` sets `net.ipv4.icmp_errors_use_inbound_ifaddr`
on the `wireguard` service for the same reason, and the applier and doctor
require both. See [architecture](architecture.md#routing-contract).

The old `panel/relays.json` and `applier/.last-server` files are ignored. Public
applier snapshots are mode 0644 so the non-root panel can read them; requests
are mode 0600. The panel cannot write the applier directory. Catalogue refresh
is every six hours (one-minute retry on failure), maximum catalogue age is 24
hours, and maximum status age is 150 seconds. These are fixed safety defaults.

## Panel endpoints

In multi-exit mode, use `?exit=<id>` to select an exit. `/` without it returns
303 to `/?exit=<id>`, using the last-exit cookie or the first configured exit;
`/embed` redirects the same way. `/api/status` and `/api/latency` need an exit
ID in this mode; a missing or unknown ID returns 404. A single-exit panel
ignores the exit parameter.

| Path | Purpose |
|---|---|
| `/`, `/?exit=<id>` | Full panel for the exit |
| `/embed`, `/embed?exit=<id>` | Compact view for iframes |
| `POST /select` | Choose a server; requires a CSRF token and allowed origin, plus the `exit` form field in multi-exit mode |
| `/api/exits` | Configured exits with status summaries; an empty list in single-exit mode |
| `/api/status?exit=<id>` | Desired server and applier result; omit `exit` for a single-exit panel |
| `/api/latency?exit=<id>` | Latency for the exit; omit `exit` for a single-exit panel. Add `scope=cities`, `country=<name>`, or `hosts=<a,b>` (64 at most); `fresh=1` ignores the cache |
| `/manifest.webmanifest` | Web app manifest |
| `/healthz` | Panel liveness; returns 200 before the Host check |
| `/readyz`, `/readyz?exit=<id>` | 200 only when all exits, or the named exit, have a fresh verified connected state; 503 otherwise. An unknown ID in multi-exit mode returns 404 |
