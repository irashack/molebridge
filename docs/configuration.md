# Configuration

## `.env`

Start from `.env.example`. These are non-secret settings read by Compose,
except `PANEL_EXITS`, which you set on a separate Switchyard container.

| Setting | Default | Purpose |
|---|---|---|
| `PROVIDER` | `mullvad` | `mullvad`, `pia` or `nordvpn` (experimental); see [providers](providers.md). Keep it unchanged after installation. |
| `SERVER` | empty | Optional provider server hostname, or a PIA region id. When set, configuration wins; the applier ignores panel requests and Switchyard shows the exit read-only. See [a server set in configuration](#a-server-set-in-configuration). |
| `EXIT_IF` | `mullvad` | Tunnel interface name, and the tunnel config's file name under `tunnel/wg_confs/`. Use `pia` with PIA and `nordvpn` with NordVPN. A custom name needs an explicit output path when you run the [config helper](#tunnel-config-helper). |
| `COMPOSE_FILE` | `compose.yaml` | Set to `compose.yaml:compose.pia.yaml` for PIA, which mounts the PIA login into the applier, or to `compose.yaml:compose.nordvpn.yaml` for NordVPN, which gives the applier 512 MB of memory for NordVPN's server list. |
| `PIA_PORT_FORWARD` | `off` | PIA only. `on` forwards one PIA port to `PIA_PORT_FORWARD_TARGET` and lists only regions that offer it. Opens a port to the Internet; see [port forwarding](providers.md#port-forwarding). |
| `PIA_PORT_FORWARD_TARGET` | empty | PIA only. The overlay IPv4 address of the one device that receives the forwarded port. Required when forwarding is on; refused otherwise. |
| `COMPOSE_PROJECT_NAME` | `molebridge` | Deployment identity used for container names, networks and the NetBird identity volume. Keep it unchanged after installation: changing it creates a fresh identity volume and enrolls a new peer. |
| `OVERLAY_CIDR` | required | NetBird peer network range. Replies to this range return over the overlay. |
| `OVERLAY6_CIDR` | empty | IPv6 overlay range, if enabled. |
| `OVERLAY_IF` | `wt0` | NetBird's interface name inside the namespace. Compose passes it as `NB_INTERFACE_NAME` and uses it for the startup gate, routing and health checks. Keep it unchanged after the peer enrolls: the peer's stored profile keeps the name, and the gate refuses a profile for another interface ([troubleshooting](troubleshooting.md#startup)). |
| `EXIT_TABLE` | `51821` | Dedicated table (256..2147483647). Must match the table in the tunnel config's `PostUp` and `PreDown` hooks, or the `wireguard` container refuses the config; see the [config helper](#tunnel-config-helper). |
| `NB_HOSTNAME` | `molebridge-exit` | NetBird peer name. |
| `NB_MANAGEMENT_URL` | `https://api.netbird.io` | NetBird management server. |
| `PANEL_USER` | `1000:1000` | The panel's `user:` inside its container, as `uid:gid`. On an engine that maps container uids to host uids directly, set it to your host user's `uid:gid` (`id -u` and `id -g`), the user that owns `state/`. On a rootless engine that remaps them, container root is already your host user and an unmapped uid cannot read the 0700 state tree: use `0:0`. The panel still holds no capabilities. |
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

`PUID` and `PGID`, which releases up to 0.5.3 used for the routing image, are
no longer read; an `.env` that still sets them works unchanged.

`compose.yaml` also sets fixed NetBird settings that aren't in `.env`.
`NB_DISABLE_DNS=true` stops NetBird configuring the namespace's resolver.
`NB_DISABLE_USERSPACE_ROUTING=true` is part of Molebridge's supported NetBird
configuration. NetBird's entrypoint gate refuses to start without it. It also
refuses:

- `NB_FORCE_USERSPACE_FIREWALL`, `NB_FORCE_USERSPACE_ROUTER`,
  `NB_ENABLE_ROSENPASS` or `WT_ENABLE_ROSENPASS` set to a value NetBird reads
  as true (Go's `strconv.ParseBool`: `1`, `t`, `T`, `TRUE`, `true`, `True`);
- `NB_USE_NETSTACK_MODE` or `NB_WG_KERNEL_DISABLED` set to `true`, the only
  value NetBird acts on for these two;
- `NB_CONFIG`, `WT_CONFIG`, `NB_PROFILE` or `WT_PROFILE` set to anything,
  or an active profile other than NetBird's `default` one: Molebridge
  supports only the default profile, at its default location;
- `NB_FOREGROUND_MODE` or `WT_FOREGROUND_MODE` set to a value NetBird reads
  as true: Molebridge supports only NetBird's daemon mode, which the image's
  entrypoint uses;
- an empty `NB_INTERFACE_NAME` (Compose sets it from `OVERLAY_IF`), or a
  `WT_INTERFACE_NAME` that names another interface;
- a default profile (or a legacy `/etc/netbird/config.json` or
  `/etc/wiretrustee/config.json`, which NetBird copies into it) with
  Rosenpass on, with a `WgIface` other than `OVERLAY_IF` (none, or an empty
  one, means `wt0`), with either field repeated, with a field name outside
  printable ASCII, or that isn't valid JSON.

See [architecture](architecture.md#netbird-requirements) and
[troubleshooting](troubleshooting.md#startup).

### Repair and gate timing

These are read with the default backend, by the services the table names. `compose.yaml` doesn't pass them from `.env`, and the
defaults suit most exits. To change one, set it on the named service in a
`compose.override.yaml`, and add that file to `COMPOSE_FILE` if you set
`COMPOSE_FILE` ([an example](operations.md#exits-on-a-private-container-network)).

| Setting | Service | Default | Purpose |
|---|---|---|---|
| `ROUTING_RECONCILE_INTERVAL` | `wireguard` | `2` | Seconds between repair passes ([drift and repair](architecture.md#drift-and-repair)): an even number, 2 to 60. The tunnel interface is checked every 2 seconds whatever this is. |
| `GUARD_GRACE` | `netbird` | `30` | Seconds the routing guards may be seen incomplete before the gate stops NetBird, 5 to 30. The owner record has no grace. |
| `OWNER_RECORD` | `wireguard`, `netbird`, `applier` | `/run/molebridge/exit-owner` | Where the [owner record](architecture.md#the-owner-record) is written and read, on the `exit-run` volume. Leave it unless you move the volume; it must be the same path in all three. |

The gluetun backend's guard reads `ROUTING_RECONCILE_INTERVAL` with its own
range; see [below](#gluetun-backend).

### A server set in configuration

Set `SERVER` in `.env` to a name from your provider's relay catalogue: a
server hostname for native Mullvad, native NordVPN and the gluetun backend,
or a region id for PIA. Use the exact name, without spaces, a port, a URL or
a comma-separated list. Leave it empty to keep the existing panel behavior.

When `SERVER` is set, configuration wins. The applier ignores
`state/panel/desired.json` entirely and converges to this server, including
after tunnel recreation. With gluetun it also restores this server after a
gluetun restart, ahead of the saved panel selection. This is not a default
the panel can override. Switchyard shows the exit as "Set in configuration"
with the configured name and no switching controls.

The applier treats `SERVER` as untrusted input. It uses the same name
validation as a desired-state request and requires membership in a fresh
trusted catalogue for the configured provider. PIA's port-forwarding filter
still applies. If no fresh catalogue is available, the request waits and
retries when one becomes available. An invalid or unknown name reports a
failed status with the name quoted, for example:

```text
Invalid SERVER "--bad"; no change applied.
Unknown SERVER "absent.example.test"; not in a fresh trusted relay catalogue; no change applied.
```

These errors do not fall back to a panel request. Fix the setting and apply
your configuration change with [recovery](operations.md#recovery). A failed
application of a valid configured server retries on the periodic check;
Molebridge does not choose another server. Removing `SERVER` returns control
to the panel, including any `desired.json` request left there.

`SERVER` goes only to the applier. It publishes `configured_server` in
`result.json` (null when unset); the panel reads that file through its existing
read-only mount, without reading the applier's environment or holding its
credentials. A stale result still identifies the exit as read-only, while
its connection status becomes unknown. Before the first result is available,
the panel cannot know the setting; the applier still ignores its requests.

With gluetun, `GLUETUN_SERVER_*` filters still control gluetun's first
connection, before the applier runs. `SERVER` takes over once the applier has
a fresh catalogue and can apply it. It has no effect in the three-container
[standalone setup](gluetun-netbird-exit.md), which has no applier.

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

## gluetun backend

Experimental. Its live passes used NordVPN, on Docker and on rootless
Podman ([testing](testing.md#gluetun-backend-pass-at-a3bb14f)); the design is in
[architecture](architecture.md#gluetun-backend) and what differs for you in
[providers](providers.md#the-gluetun-backend). Set
`COMPOSE_FILE=compose.gluetun.yaml` in `.env`; this file replaces
`compose.yaml`. `OVERLAY_CIDR`, `OVERLAY6_CIDR`, `OVERLAY_IF`, `EXIT_TABLE`,
`NB_HOSTNAME`, `NB_MANAGEMENT_URL` and the panel settings above keep their
meaning. `PROVIDER` and the PIA settings don't apply.

| Setting | Default | Purpose |
|---|---|---|
| `EXIT_IF` | `wg0` | The name gluetun gives its tunnel interface (its `VPN_INTERFACE`): letters, digits and underscores only. The guard and NetBird's ICE blacklist use the same value. `.env.example` sets `mullvad` for the default backend; set `wg0` or keep it, as long as it fits. |
| `GLUETUN_PROVIDER` | required | gluetun's `VPN_SERVICE_PROVIDER`. The panel can select servers for `fastestvpn`, `ivpn`, `mullvad`, `nordvpn`, `surfshark` and `windscribe`; the applier refuses any other. `compose.gluetun.yaml` gives the applier and the panel `PROVIDER=gluetun-<this value>`. |
| `GLUETUN_WIREGUARD_ADDRESSES` | empty | gluetun's `WIREGUARD_ADDRESSES`, the tunnel address your provider assigned to your key. Most providers need it; gluetun fills it in for NordVPN. |
| `GLUETUN_SERVER_COUNTRIES`, `GLUETUN_SERVER_CITIES`, `GLUETUN_SERVER_HOSTNAMES` | empty | gluetun's `SERVER_COUNTRIES`, `SERVER_CITIES` and `SERVER_HOSTNAMES`: the server gluetun starts with. For a first start, set only `GLUETUN_SERVER_COUNTRIES`, to your own country as gluetun names it: gluetun picks among the servers in its data, and on a fresh install that is its built-in list, where some servers may be gone; a whole country rarely is. Empty lets gluetun pick from every country. A value must name a server, city or country in the data gluetun has when it starts, which on a fresh install is its built-in list, years old for some providers; otherwise gluetun refuses to start (`the hostname specified is not valid`, or the same for a country or city). When `SERVER` is set, the applier converges to it and restores it after gluetun restarts. Otherwise a selection in the panel replaces these filters while gluetun runs, and the applier restores your last verified selection after a restart. |
| `GLUETUN_UPDATER_PERIOD` | `24h` | gluetun's `UPDATER_PERIOD`: how often gluetun refreshes the server list the panel shows. gluetun first refreshes one period after it starts, so the applier also asks it for one refresh when it starts, once gluetun's tunnel has a fresh handshake, if the data is older than this period or than 7 days. `0` turns both off; the list then keeps the date of gluetun's built-in data and soon shows as stale. |
| `HOST_IF` | `eth0` | The namespace's interface toward the host. Docker names it `eth0`; rootless Podman with pasta copies the host's interface name, such as `enp3s0`. The host table copies this interface's default and on-link routes, and the post-rules accept output on it. |
| `HOST_TABLE` | `51822` | Molebridge's table for NetBird's control traffic (256..2147483647). Must differ from `EXIT_TABLE`; 51820 (gluetun) and 7120 (NetBird) are taken. |
| `CONTROL_MARK` | `0x1bd00` | NetBird's control-plane mark, in lowercase hexadecimal with the low byte zero. `compose.gluetun.yaml` passes it to NetBird as `NB_FWMARK_BASE`, which moves NetBird's whole mark range; change it only if another program on the host uses those marks. |
| `NB_WIREGUARD_PORT` | `51820` | NetBird's WireGuard port, opened in gluetun's firewall. |

`compose.gluetun.yaml` also sets fixed values: gluetun with `VPN_TYPE=wireguard`,
`WIREGUARD_IMPLEMENTATION=kernelspace`, its control server on
`127.0.0.1:8000` inside the namespace and its server list at
`/gluetun/servers/servers.json` (`STORAGE_FILEPATH`), in a volume of its
own; `TUNNEL_BACKEND=gluetun` for the guard, NetBird's gate and the applier;
and for the applier `GLUETUN_CONTROL_URL`, `GLUETUN_API_KEY_FILE` and
`GLUETUN_SERVERS_FILE`, where it finds the control server, the API key and
the read-only server list. The guard reads `ROUTING_RECONCILE_INTERVAL`
(seconds between full passes, 1–60, default 2); it aims to rewrite the fwmark
record for the gate every 2 seconds whatever that interval is. The gate
reads `FWMARK_GRACE` (seconds without a good fwmark record before the gate
stops NetBird, 5–30, default 30). Neither is passed through from `.env`: to
change them, set `ROUTING_RECONCILE_INTERVAL` on the `guard` service and
`FWMARK_GRACE` on the `netbird` service in a `compose.override.yaml`, and add
that file to `COMPOSE_FILE`. With
this backend the gate also refuses `NB_USE_LEGACY_ROUTING`,
`NB_SKIP_SOCKET_MARK` and `NB_DISABLE_CUSTOM_ROUTING` set to a true value,
and an `NB_FWMARK_BASE` other than `CONTROL_MARK`.

Before the first start:

1. Put the provider's WireGuard private key in
   `secrets/gluetun/wireguard_private_key`, one line, mode 0600.
2. Run `python3 tools/molebridge.py gluetun-auth`. It generates an API key
   and writes it twice, both mode 0600: into `secrets/gluetun/auth.toml`,
   gluetun's role file, with one role allowed exactly `PUT
   /v1/vpn/settings`, `GET /v1/vpn/status`, `GET /v1/publicip/ip`, and
   `GET` and `PUT /v1/updater/status` (to refresh the server list); and
   into `secrets/gluetun/api_key`, which only the applier mounts. The key is
   never printed. Run it again with `--rotate` to replace both, then run `python3 tools/molebridge.py recover`, which recreates gluetun and everything that shares its namespace (on rootless Podman, the [Podman commands](operations.md#rootless-podman)). Compose refuses to start without the
   role file: without one, gluetun answers several routes with no
   authentication, including one that stops the VPN.
3. Run `python3 tools/molebridge.py gluetun-post-rules` to write
   `tunnel/gluetun/post-rules.txt` from these settings; add `--ipv4-only` if
   gluetun logs that it found no working ip6tables. The command reads
   `.env` itself, and like Compose lets a setting exported in your shell
   win over `.env`; it doesn't call the container engine, so it is the same
   with Docker and with podman-compose. Write the values literally: it
   refuses a `$` reference. Run it again after
   changing `HOST_IF`, `EXIT_IF`, `OVERLAY_IF`, `CONTROL_MARK` or
   `NB_WIREGUARD_PORT`, then run `python3 tools/molebridge.py recover`, which recreates gluetun and everything that shares its namespace (on rootless Podman, the [Podman commands](operations.md#rootless-podman)).

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

Keep the file mode 0600. For Mullvad and NordVPN, change the table in both
hooks too, including their `ip -6` commands if present. Apply the change with
[recovery](operations.md#recovery), then run [verification](verification.md).

A NordVPN config comes from `tools/nordvpn-key.py` instead, which takes the
access token from a mode-0600 file or, with `-`, from standard input, never
from its arguments or the environment:

```text
python3 tools/nordvpn-key.py TOKEN_FILE OUTPUT
python3 tools/nordvpn-key.py - OUTPUT
```

`OUTPUT` has no default; use `tunnel/wg_confs/nordvpn.conf` (or your
`EXIT_IF`). It reads `EXIT_TABLE` from the environment like the helper above,
and never overwrites an existing file. [Setup](setup.md#2-create-the-tunnel-config)
shows both forms.

## The tunnel config

The `wireguard` container reads one file, `tunnel/wg_confs/<EXIT_IF>.conf`
(`/config/wg_confs/<EXIT_IF>.conf` inside the container). Any other `.conf`
file in that directory is ignored, with the warning `molebridge-exit:
warning: <n> other .conf file(s) in /config/wg_confs are ignored; only
<EXIT_IF>.conf is used`.

Before anything changes, the container checks the file against what
Molebridge's own generators write: `tools/prepare-tunnel-config.py` for
Mullvad, the same with `--pia` for PIA, and `tools/nordvpn-key.py` for
NordVPN. Anything else is refused, including fields `wg-quick` itself would
accept. The file must be a regular file, not a symlink, readable by the
container, at most 4 KiB, with no NUL bytes and no carriage returns (so no
Windows line endings). Each line is blank, a comment starting with `#`, a
section header written exactly `[Interface]` or `[Peer]`, or `Field = value`
with a field from this table. Use the field names exactly as shown; each
may appear once.

| Field | Rule |
|---|---|
| `[Interface]` | Once, first. |
| `PrivateKey` | Required. A WireGuard key: 44 characters of base64 ending in `=`. |
| `Address` | Mullvad and NordVPN: required. PIA: must be absent; the applier sets the address. Comma-separated: one IPv4 address and, for Mullvad only, at most one IPv6 address, each with `/32` or `/128` or no prefix. IPv4 without leading zeroes. |
| `MTU` | Required, 1280 to 1500. The generators write 1420. |
| `Table` | Required, `off`. |
| `PostUp` | Required, exactly `ip route replace default dev %i table <EXIT_TABLE>`, followed by `; ip -6 route replace default dev %i table <EXIT_TABLE>` when the config has an IPv6 address. |
| `PreDown` | Required, exactly `ip route del default dev %i table <EXIT_TABLE>`, followed by `; ip -6 route del default dev %i table <EXIT_TABLE>` when the config has an IPv6 address. |
| `[Peer]` | Mullvad: once, after `[Interface]`. PIA and NordVPN: must be absent; the applier sets the peer. |
| `PublicKey` | Required in `[Peer]`. A WireGuard key. |
| `Endpoint` | Required in `[Peer]`. An IPv4 address without leading zeroes and a port, 1 to 65535, such as `192.0.2.10:51820`. |
| `AllowedIPs` | Required in `[Peer]`. `0.0.0.0/0`, followed by `, ::/0` exactly when the config has an IPv6 address. |
| `PersistentKeepalive` | Optional in `[Peer]`, 1 to 65535. The generator writes 25. |

So `DNS`, `ListenPort`, `FwMark`, `SaveConfig`, `PreUp`, `PostDown`,
`PresharedKey`, a `Table` other than `off` and every other field are refused,
as is a second `[Peer]`. A refusal stops the container with status 1 before
it changes any routing or creates the tunnel, and logs one line:

```text
molebridge-exit: the tunnel config /config/wg_confs/mullvad.conf is not supported: unsupported field on line 4; regenerate it with tools/prepare-tunnel-config.py (docs/setup.md)
```

The reason is one of `unsupported field on line <n>`, `<field> on line <n> is
not valid`, `<field> is missing`, `<field> appears more than once`,
`[Interface] on line <n> is not supported; it must come once, first`,
`[Peer] on line <n> is not supported`, `[Interface] is missing`, `[Peer] is
missing`, `[Peer] is not supported for this provider` or `Address on line <n>
is not supported for PIA`. The field names come from the table above, never
from the file: no message quotes the config, which holds the private key. The
end names the generator for your `PROVIDER` (`tools/prepare-tunnel-config.py
--pia` for PIA, `tools/nordvpn-key.py` for NordVPN). The generators write the
same file as in earlier releases, and the table change
[above](#tunnel-config-helper) keeps the hooks in the required form, so a
config made with them and not otherwise edited passes.
`tools/prepare-tunnel-config.py` now also refuses a Mullvad file with more
than one address in a family (`Interface Address has more than one address
in a family`) or a prefix other than `/32` and `/128` (`Interface Address
must be host addresses (/32 and /128)`).

To check a config without starting anything, run
`docker compose run --rm --no-deps wireguard --check-config`
([setup](setup.md#4-start-the-exit-without-a-route-yet)).

## Secret files

All mode 0600 and ignored by git. Document them by name only; never paste their
contents anywhere.

| File | Contents | Needed |
|---|---|---|
| `tunnel/wg_confs/mullvad.conf` | Mullvad private key, tunnel addresses (one IPv4, at most one IPv6), starting server | With Mullvad |
| `tunnel/wg_confs/pia.conf` | PIA tunnel private key only; no address or peer | With PIA |
| `tunnel/wg_confs/nordvpn.conf` | NordLynx private key and the address `10.5.0.2/32`; no peer | With NordVPN |
| `secrets/pia/username`, `secrets/pia/password` | The PIA login, one value per file | With PIA |
| `secrets/netbird.env` | `NB_SETUP_KEY` | Until the peer first enrolls |
| `secrets/applier.env` | `GATUS_TOKEN` | Only with `GATUS_URL` |
| `secrets/gluetun/wireguard_private_key` | The provider's WireGuard private key | With the [gluetun backend](#gluetun-backend) |
| `secrets/gluetun/auth.toml` | gluetun's control-server role, with the API key; written by `tools/molebridge.py gluetun-auth` | With the gluetun backend |
| `secrets/gluetun/api_key` | The same API key, for the applier. It is full gluetun administration | With the gluetun backend |

The NordVPN access token is not one of these: it is needed only while
`tools/nordvpn-key.py` runs. If you saved it to a file for that, delete it
afterwards.

## State files

Under `state/`, written with temp-file-and-rename. None hold secrets.

| File | Writer | Reader | Contents |
|---|---|---|---|
| `applier/relays.json` | applier | panel (read-only) | `fetched_at`, `provider` and validated `relays`. Mullvad: hostname → `hostname`, `country`, `city`, `location_code`, `public_key`, `ipv4_addr_in`, and when Mullvad publishes them well formed, `owned` and `stboot` (booleans) and `provider` (text, at most 64 characters). PIA: region id → `hostname` (the id), `country`, `city`, `location_code`, `ipv4_addr_in` (the latency target), `port_forward`, `geo` and `servers` (`ip`, `cn`). NordVPN: hostname → `hostname`, `country`, `country_code`, `city`, `location_code`, `public_key` (shared by the servers of a location), `ipv4_addr_in` (the entry address and endpoint), `virtual` (boolean), and `load` (0–100) when NordVPN publishes it well formed. gluetun backend: also `source` (`gluetun`) and `data_timestamp` (when gluetun's data for the provider last changed); hostname → `id` and `hostname` (the same), `selection_filter` (`hostnames`), `public_key`, `ipv4_addr_in` (the first IPv4 address, the latency target), `ipv4_addrs` and `ipv6_addrs` (every address gluetun may connect to), `country`, `city`, and `region` and `categories` where gluetun lists them. A snapshot for another provider is ignored. |
| `applier/gluetun-selection.json` | gluetun applier | gluetun applier | `desired`, `last_put` and `last_successful`: server hostnames, used to put the last verified server back after gluetun restarts when `SERVER` is unset. With `SERVER`, configuration wins. No secret. |
| `applier/tunnel.json` | PIA applier | PIA applier | Current registration (`region`, `cn`, `server_ip`, `server_port`, `server_key`, `peer_ip`, `server_vip`, `registered_at`), read to match the live peer and reconcile tunnel state. No secret. |
| `applier/relay-error.json` | applier | panel (read-only) | Sanitized last refresh error and timestamp, or an empty object after success |
| `panel/desired.json` | panel | applier (read-only) | `server`, `requested_at`, `request_id`. Ignored entirely when `SERVER` is set. Otherwise each selection gets a new ID so the same server can be retried. Old two-field requests remain readable. |
| `applier/result.json` | applier | panel (read-only) | Observed `server`, `configured_server` (the `SERVER` setting, null when unset; invalid values longer than 256 characters are truncated for reporting), `requested_server`, acknowledged `request_id`, `status` (`unknown`/`applying`/`ok`/`failed`), `message`, egress fields (`egress_ip` is IPv4; `egress_ips` maps `4`/`6` to separately checked addresses), `provider`, `exit_confirmed` (the provider confirmed the egress), `egress_tier` (`provider`, `tunnel` or null; see [status reporting](architecture.md#status-reporting)), `mullvad_exit_ip` (Mullvad only), `port_forward`, `forwarded_port` and `port_forward_error` (PIA only), `handshake_age_s`, `unreachable_fallback`, `routing_ok`, `netbird_native` (NetBird runs kernel WireGuard with its kernel firewall), `checked_at`, and with the gluetun backend `server_list_update` (`updating`, `failed` or null: the refresh of gluetun's server list the applier starts). A result with `netbird_native` false never counts as connected. |

Routing installs the return-path rule and its backstop (rules 94 and 98)
from the tunnel config's `Address` line (a PIA config has none; the applier
installs both per registration); `compose.yaml` sets
`net.ipv4.icmp_errors_use_inbound_ifaddr` on the `wireguard` service for the
same reason, and the applier and doctor require both. See
[architecture](architecture.md#routing-contract).

The old `panel/relays.json` and `applier/.last-server` files are ignored. Public
applier snapshots are mode 0644 so the non-root panel can read them; requests
are mode 0600. The panel cannot write the applier directory. Catalogue refresh
is every six hours (one-minute retry on failure), maximum catalogue age is 24
hours, and maximum status age is 150 seconds. A server list download may take
20 seconds and 10 MiB, except NordVPN's: 60 seconds and 32 MiB. With the
gluetun backend nothing is downloaded: the applier reads gluetun's server
file, up to 32 MiB, every minute when it changed and at least every six
hours. The validated `relays.json` may be 10 MiB, NordVPN's and gluetun's
16 MiB; the applier refuses to write a
larger one and keeps the last good catalogue, reporting it in
`relay-error.json` like any failed refresh, and neither the applier nor the
panel reads a larger one. These are fixed safety defaults, set per provider
in `molebridge/providers.py`.

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
| `POST /select` | Refused with 403 `Exit is set in configuration; change SERVER to choose another server.` for an exit set in configuration. Otherwise choose a server; requires a CSRF token and allowed origin, plus the `exit` form field in multi-exit mode |
| `/api/exits` | Configured exits with status summaries; an empty list in single-exit mode. With sign-in, only the exits the person is granted |
| `/api/status?exit=<id>` | Desired server and applier result, plus `view.selection_mode` (`configuration` or `panel`) and `view.configured_server` (name or null). In configuration mode `desired` is null; omit `exit` for a single-exit panel |
| `/api/latency?exit=<id>` | Latency for the exit; omit `exit` for a single-exit panel. Add `scope=cities`, `country=<name>` (up to 128 servers, a fixed sample beyond that; the answer's `country` gives `probed` and `total`), or `hosts=<a,b>` (64 at most); 256 servers per request in all; `fresh=1` ignores the cache. 429 with `Retry-After` while that exit already has a request running or four are running panel-wide |
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
