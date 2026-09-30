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

### Panel sign-in

Optional OpenID Connect sign-in; the procedure is in
[panel access](access.md#sign-in-with-openid-connect). Everything here is off
unless `PANEL_OIDC_ISSUER` is set. Setting `PANEL_OIDC_CLIENT_ID`,
`PANEL_ACCESS`, `PANEL_ADMIN_GROUPS` or `PANEL_PUBLIC_URL` without it stops the
panel at start. `compose.yaml` passes `PANEL_OIDC_ISSUER`,
`PANEL_OIDC_CLIENT_ID`, `PANEL_PUBLIC_URL`, `PANEL_ADMIN_GROUPS` and
`PANEL_SESSION_TTL` from `.env`. The other three are for a separate Switchyard
container, where you set them in its own environment.

| Setting | Default | Purpose |
|---|---|---|
| `PANEL_OIDC_ISSUER` | empty | The issuer, exactly as its discovery document states it. `https`, or `http` only to a loopback test issuer. Empty means no login. |
| `PANEL_OIDC_CLIENT_ID` | empty | The client ID registered at the issuer. Required with the issuer. |
| `PANEL_OIDC_CLIENT_SECRET_FILE` | empty | Path, inside the panel container, to a file holding the client secret, for a confidential client. The panel sends it with HTTP Basic authentication. Unset means a public client, with no secret on disk. |
| `PANEL_PUBLIC_URL` | empty | The canonical `https` origin people open, such as `https://exit.example.net`, with no path. Its host is accepted like a `PANEL_PUBLIC_HOSTS` entry. The redirect URI to register at the issuer is this plus `/auth/callback`. Required with the issuer. |
| `PANEL_OIDC_SCOPES` | `openid profile email groups` | Scopes to request. Must include `openid`. |
| `PANEL_OIDC_GROUPS_CLAIM` | `groups` | The claim that lists a person's groups. |
| `PANEL_ADMIN_GROUPS` | empty | Comma-separated groups whose members see every exit. |
| `PANEL_ACCESS` | empty | Comma-separated `group=exit` pairs. Repeat a group to grant it several exits. Every exit must be in `PANEL_EXITS`, so a single-exit panel uses `PANEL_ADMIN_GROUPS` only. Group names can't contain spaces, commas or `=`. |
| `PANEL_SESSION_TTL` | `3600` | Seconds a sign-in lasts, from 300 to 604800. Not extended by use. |

With the issuer set, at least one of `PANEL_ADMIN_GROUPS` and `PANEL_ACCESS`
must name a group.

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
ignores the exit parameter. With [sign-in](access.md#sign-in-with-openid-connect)
on, the cookie and the first exit are chosen among the exits the person is
granted.

| Path | Purpose |
|---|---|
| `/`, `/?exit=<id>` | Full panel for the exit |
| `/embed`, `/embed?exit=<id>` | Compact view for iframes |
| `POST /select` | Choose a server; requires a CSRF token and allowed origin, plus the `exit` form field in multi-exit mode |
| `/api/exits` | Configured exits with status summaries; an empty list in single-exit mode. With sign-in, only the exits the person is granted |
| `/api/status?exit=<id>` | Desired server and applier result; omit `exit` for a single-exit panel |
| `/api/latency?exit=<id>` | Latency for the exit; omit `exit` for a single-exit panel. Add `scope=cities`, `country=<name>`, or `hosts=<a,b>` (64 at most); `fresh=1` ignores the cache |
| `/manifest.webmanifest` | Web app manifest |
| `/healthz` | Panel liveness; returns 200 before the Host check |
| `/readyz`, `/readyz?exit=<id>` | 200 only when all exits, or the named exit, have a fresh verified connected state; 503 otherwise. An unknown ID in multi-exit mode returns 404 |

With sign-in on, these are added, and they answer 404 when it is off:

| Path | Purpose |
|---|---|
| `/login?next=<path>` | Starts sign-in and redirects to the issuer. Only `/` and `/embed`, each with an optional `?exit=<id>`, are accepted as `next`; anything else lands on `/`. Someone who already has a session is redirected to `next` |
| `/auth/callback` | Where the issuer sends the browser back. Sets the session cookie and redirects to `next`, or shows "Not allowed" (403), "Sign-in failed" (400) |
| `POST /logout` | Ends the session. Requires the CSRF token. Redirects to `/signed-out` |
| `/signed-out` | A page confirming the sign-out, with a sign-in link |

Without a session:

| Path | Answer |
|---|---|
| `/` | 303 to `<PANEL_PUBLIC_URL>/login?next=...`, always the absolute canonical address |
| `/embed` | 200, a small "Signed out" page whose link opens sign-in in a new tab |
| `/api/status`, `/api/exits`, `/api/latency` | 401 with `{"error": "sign in required"}` |
| `POST /select` | 401 `sign in required` |
| `/healthz`, `/static/*`, `/manifest.webmanifest`, `/readyz` without `?exit=` | As without sign-in |

`/readyz?exit=<id>` needs a session granted that exit. For anyone else it
answers 404 `unknown exit`, as for an exit that doesn't exist. The same holds
for an exit the person isn't granted on the page, the embed, `/api/status` and
`/api/latency` (404 `unknown exit`) and on `POST /select` (400 `unknown exit`).
The Host check comes first for all of these except `/healthz`.
