# Configuration

## `.env`

Start from `.env.example`. These are non-secret settings read by Compose.
There are eighteen, and each is commented in the file. Everything else has a
default in the binary and appears here as an [override](#overrides).

| Setting | Default | Purpose |
|---|---|---|
| `PROVIDER` | `mullvad` | `mullvad`, `pia` or `nordvpn` (experimental); see [providers](providers.md). Keep it unchanged after installation. |
| `EXIT_IF` | `mullvad` | The tunnel interface name, and the tunnel config's file name under `tunnel/wg_confs/`. Use `pia` with PIA and `nordvpn` with NordVPN. A custom name needs an explicit output path when you run `prepare-config` ([tools](tools-reference.md#prepare-config)). |
| `SERVER` | empty | Optional provider server hostname, or a PIA region id. When set, configuration wins; the exit ignores panel requests and Switchyard shows the exit read-only. See [a server set in configuration](#a-server-set-in-configuration). |
| `OVERLAY_CIDR` | required | NetBird peer network range, an IPv4 CIDR written with its network address (`192.0.2.0/24`, not `192.0.2.5/24`), no leading zeroes, not `/0`. Replies to this range return over the overlay. |
| `OVERLAY6_CIDR` | empty | IPv6 overlay range, if enabled, also written with its network address (`/1` to `/128`). |
| `NB_HOSTNAME` | `molebridge-exit` | NetBird peer name. |
| `NB_MANAGEMENT_URL` | `https://api.netbird.io` | NetBird management server. |
| `PIA_PORT_FORWARD` | `off` | PIA only. `on` forwards one PIA port to `PIA_PORT_FORWARD_TARGET` (in a [native sidecar](#native-sidecar), to the namespace itself) and lists only regions that offer it. Opens a port to the Internet; see [port forwarding](providers.md#port-forwarding). The exit also reads `1`, `true` and `yes` as on and `0`, `false` and `no` as off, in any case; any other value stops it with `PIA_PORT_FORWARD must be on or off`. |
| `PIA_PORT_FORWARD_TARGET` | empty | PIA only. The overlay IPv4 address of the one device that receives the forwarded port; it must lie inside `OVERLAY_CIDR`. Required when forwarding is on; refused otherwise. A native sidecar refuses it in every case: its forwarded port reaches the namespace itself. |
| `PANEL_PORT` | `8095` | Host loopback port for the panel. Compose reads it; the panel listens on 8080 inside its container. |
| `PANEL_PUBLIC_HOSTS` | empty | Comma-separated names the panel is served under, with the port when it is not 80/443: the public hostname and, if your proxy rewrites the upstream `Host`, that name too (for example `host.docker.internal:8095`). Unlisted names get 421, except on `/healthz`; loopback names are accepted. Form posts require an allowed origin. |
| `PANEL_EXITS` | empty | Several exits in one Switchyard, as `id=provider[/kind][:label]`, where `kind` is `overlay` (the default) or `sidecar`, and the provider is a native one (`mullvad`, `pia`, `nordvpn`: with `sidecar`, a [native sidecar](#native-sidecar)) or a `gluetun-*` one (a [gluetun sidecar](#gluetun-sidecar)). Empty means this one exit. `compose.yaml` passes it to the bundled panel; each exit's state must then be mounted under `/state/<id>` in a `compose.override.yaml`. See [several exits in one panel](switchyard.md#several-exits-in-one-panel). |
| `PANEL_OIDC_ISSUER`, `PANEL_OIDC_CLIENT_ID`, `PANEL_PUBLIC_URL`, `PANEL_ADMIN_GROUPS` | empty | Optional sign-in, off while the issuer is empty. See [panel sign-in](#panel-sign-in). |
| `GATUS_URL` | empty | Gatus base URL for health pushes, starting `http://` or `https://`; empty disables them. The token (`GATUS_TOKEN`) goes in `secrets/applier.env`; with no token nothing is pushed. Over `http://` the token crosses the network unencrypted; use `https://`. The exit warns at start about an `http://` URL whose host isn't `localhost` or a loopback address ([Gatus](operations.md#gatus)). |
| `TZ` | `Etc/UTC` | Container time zone. |

`.env.gluetun.example`, `.env.sidecar.example` and `.env.native-sidecar.example`
have the same shape for the other three forms; see [gluetun backend](#gluetun-backend),
[gluetun sidecar](#gluetun-sidecar) and [native sidecar](#native-sidecar).

### Overrides

These work when you add them to `.env` (Compose passes them on) or, for the
ones marked "override file", when you set them on the named service in a
`compose.override.yaml`. Compose reads that file by itself unless
`COMPOSE_FILE` is set, as it is for the gluetun forms; then add it to the
list ([an example](operations.md#exits-on-a-private-container-network)). A
default shown here is the one in the binary or in the Compose file; where
they differ the row says so.

| Setting | Service | Default | Purpose |
|---|---|---|---|
| `COMPOSE_PROJECT_NAME` | Compose | `molebridge` | Deployment identity used for container names, networks and the NetBird identity volume. Keep it unchanged after installation: changing it creates a fresh identity volume and enrolls a new peer. |
| `OVERLAY_IF` | exit | `wt0` | NetBird's interface name inside the namespace. Compose also passes it as `NB_INTERFACE_NAME`; the exit refuses to start when the two differ. Keep it unchanged after the peer enrolls: the peer's stored profile keeps the name, and the exit refuses a profile for another interface ([troubleshooting](troubleshooting.md#startup)). Interface names here and in `EXIT_IF` and `HOST_IF` are 1 to 15 characters: letters, digits and `_`, plus `.` and `-` after the first. `OVERLAY_IF` and `EXIT_IF` must differ. |
| `EXIT_TABLE` | exit | `51821` | Dedicated routing table (256 to 2147483647, canonical decimal). Must match the table in the tunnel config's `PostUp` and `PreDown` lines, or the exit refuses the config; see [the tunnel config](#the-tunnel-config). |
| `PANEL_USER` | switchyard | `1000:1000` | The panel's `user:` inside its container, as `uid:gid`. On an engine that maps container uids to host uids directly, set it to your host user's `uid:gid` (`id -u` and `id -g`), the user that owns `state/`. On a rootless engine that remaps them, container root is already your host user and an unmapped uid cannot read the 0700 state tree: use `0:0` with `PANEL_ALLOW_ROOT=1`. The panel still holds no capabilities. |
| `PANEL_ALLOW_ROOT` | switchyard | empty | Your statement that root in the panel container is deliberate (`PANEL_USER=0:0` on a rootless engine). The panel treats empty as unset and refuses to run as uid 0 unless this is exactly `1`; see [the panel's isolation check](#the-panels-isolation-check). |
| `PANEL_FRAME_ANCESTORS` | switchyard | empty | Space-separated origins matching `https://[a-z0-9.-]+`: lowercase `https://` and host, with no port, path, trailing slash or wildcard. Example: `https://dashboard.example.net https://home.example.net`. Invalid entries are ignored; no accepted entries means framing is forbidden. |
| `PANEL_TITLE` | switchyard | `Switchyard` | Page and app name. |
| `PANEL_SHORT_TITLE` | switchyard | `Switchyard` | Home-screen icon label. |
| `PANEL_HOST_LABEL` | switchyard | `this exit` (`this gluetun` in `compose.sidecar.yaml`, `this tunnel` in `compose.native-sidecar.yaml`) | Used in "Fastest from …". |
| `PANEL_HOME_URL`, `PANEL_HOME_LABEL` | switchyard | empty, `Home` | Optional back link in the page header. |
| `PANEL_THEME` | switchyard | `auto` | `auto` follows each viewer's light or dark system setting; `dark` or `light` fixes it. Any other value means `auto`. Set `dark` when an always-dark dashboard embeds the panel. |
| `PANEL_STYLE` | switchyard | `provider` | `provider` uses the provider's colors; `dashboard` uses the neutral Catppuccin palette and JetBrains Mono. Any other value means `provider`. Mullvad's tree and PIA's region list keep their layout in either style. |
| `PANEL_SESSION_TTL` | switchyard | `3600` | Seconds a sign-in lasts; see [panel sign-in](#panel-sign-in). |
| `GATUS_ENDPOINT` | exit | `molebridge` | Gatus external endpoint key. |
| `ROUTING_RECONCILE_INTERVAL` | exit | `30` | Seconds between full repair passes, 2 to 60; see [repair and lease timing](#repair-and-lease-timing). |
| `GUARD_GRACE` | exit | `30` | Seconds without an accepted lease renewal before the supervisor stops NetBird, 5 to 30; see [repair and lease timing](#repair-and-lease-timing). |

`PUID`, `PGID` and `OWNER_RECORD`, which earlier releases used, are gone:
Molebridge no longer reads them, and an `.env` that still sets them works.
`COMPOSE_FILE=compose.yaml:compose.pia.yaml` and
`COMPOSE_FILE=compose.yaml:compose.nordvpn.yaml` are different. Compose itself
reads `COMPOSE_FILE`, those files no longer exist, and the project won't load
while `.env` points at them. Remove the line (keep it only for a gluetun form),
and use `PROVIDER` and `EXIT_IF` to choose the provider
([upgrading from 0.7](operations.md#upgrading-from-07x)).

### What Compose fixes for NetBird

`compose.yaml` sets these on the `exit` service; they are not in `.env`.
`NB_DISABLE_DNS=true` stops NetBird configuring the namespace's resolver.
`NB_LOG_LEVEL=info`. `NB_INTERFACE_NAME` takes `OVERLAY_IF`,
`NB_EXTRA_IFACE_BLACKLIST` takes `EXIT_IF`, and `NB_HOSTNAME` and
`NB_MANAGEMENT_URL` are the settings above. `NB_DISABLE_USERSPACE_ROUTING=true`
is part of Molebridge's supported NetBird configuration, and the exit
refuses to start NetBird without it.

NetBird's settings are validated before the NetBird client starts, and again
after `netbird up`. A refusal is one line, `NetBird gate: refusing to start
NetBird: <reason> (see docs/troubleshooting.md)`. The line still says "NetBird
gate", the name of the 0.7 container that printed it; there is no gate
container now. Besides `NB_DISABLE_USERSPACE_ROUTING`, the exit refuses:

- `NB_FORCE_USERSPACE_FIREWALL`, `NB_FORCE_USERSPACE_ROUTER`,
  `NB_ENABLE_ROSENPASS` or `WT_ENABLE_ROSENPASS` set to a value NetBird reads
  as true (Go's `strconv.ParseBool`: `1`, `t`, `T`, `TRUE`, `true`, `True`);
- `NB_USE_NETSTACK_MODE` or `NB_WG_KERNEL_DISABLED` set to `true`, the only
  value NetBird acts on for these two;
- `NB_CONFIG`, `WT_CONFIG`, `NB_PROFILE` or `WT_PROFILE` set to anything,
  or an active profile other than NetBird's `default` one: Molebridge
  supports only the default profile, at its default location;
- `NB_FOREGROUND_MODE` or `WT_FOREGROUND_MODE` set to a value NetBird reads
  as true: Molebridge supports only NetBird's daemon mode, which the exit
  starts;
- an empty `NB_INTERFACE_NAME` (Compose sets it from `OVERLAY_IF`), or a
  `WT_INTERFACE_NAME` that names another interface;
- a default profile (or a legacy `/etc/netbird/config.json` or
  `/etc/wiretrustee/config.json`, which NetBird copies into it) with
  Rosenpass on, with a `WgIface` other than `OVERLAY_IF` (none, or an empty
  one, means `wt0`), with either field repeated, with a field name outside
  printable ASCII, or that isn't valid JSON;
- a stored profile whose `IFaceBlackList` doesn't exclude the tunnel
  interface. That refusal names the repair tool `fix-blacklist`
  ([operations](operations.md#netbird-interface-blacklist)).

Two names are the exit's own and don't come from NetBird: `NB_STATE_DIR`
(default `/var/lib/netbird`) is where the exit looks for the stored profile,
which is where the `netbird-data` volume is mounted, and `NB_LOG_FILE` keeps
NetBird's default of `console,/var/log/netbird/client.log` unless you set it
(the gluetun form reads its log).

See [architecture](architecture.md#netbird-and-its-checks) and
[troubleshooting](troubleshooting.md#startup).

### Other settings the Compose files fix

These are read by the binary, set in the Compose files, and not meant to be
changed in `.env`:

| Setting | Value | Meaning |
|---|---|---|
| `TUNNEL_BACKEND` | `native` (`compose.yaml`, `compose.native-sidecar.yaml`) or `gluetun` | Who owns the tunnel. Unset means `native`; `wireguard` is read as `native`; any other value stops the exit with `TUNNEL_BACKEND must be native or gluetun`. |
| `EXIT_KIND` | `overlay`, or `sidecar` in `compose.sidecar.yaml` and `compose.native-sidecar.yaml` | See [gluetun sidecar](#gluetun-sidecar) and [native sidecar](#native-sidecar). With `native` it selects the native sidecar; with `gluetun` and a `gluetun-*` provider, the gluetun sidecar. |
| `STATE_DIR` | `/state` | Where the exit and the panel find `applier/` and `panel/`. The exit refuses to start unless `<STATE_DIR>/applier` is a directory it can write. |
| `MOLEBRIDGE_KIND` | `overlay` or `sidecar`, on the `gluetun` service of the two gluetun files | Read by `routing/gluetun-preflight`, which refuses to start gluetun without a matching post-rules file (`overlay`) or with one (`sidecar`). |

Four more have defaults the Compose files leave alone: `TUNNEL_CONF_DIR`
(`/config/wg_confs`), `MOLEBRIDGE_RUN_DIR` (`/run`, where the supervisor keeps
its heartbeat and lease files), `PIA_SECRETS_DIR` (`/run/secrets/pia`) and
`PRIVATE_STATE_DIR` (unset: the files only the exit reads stay in
`<STATE_DIR>/applier`; see [keeping the published files in
memory](#keeping-the-published-files-in-memory)).
`MOLEBRIDGE_PANEL_LISTEN` replaces the panel's listen address, `0.0.0.0:8080`,
for its tests; Compose never sets it. `MOLEBRIDGE_GENERATION`,
`MOLEBRIDGE_RTNL_NOTIFY_LOCKED` and `MOLEBRIDGE_DRILL_CPUPROFILE` are
internal to the supervisor and the test drills.

### Repair and lease timing

| Setting | Default | Purpose |
|---|---|---|
| `ROUTING_RECONCILE_INTERVAL` | `30` | Seconds between full repair passes: whole seconds, 2 to 60. A change to a rule, route, link or address in the namespace starts a repair pass at once; the full pass is the fallback that backs it up, and also runs at once when the kernel reports that events were lost ([drift and repair](architecture.md#drift-and-repair)). The 0.7 default was 2 and its pass was the repair; here a shorter interval only narrows the window for a change the kernel doesn't announce. The tunnel interface is checked every 2 seconds whatever this is. |
| `GUARD_GRACE` | `30` | The length of the lease: seconds the supervisor waits for an accepted renewal from the worker before it stops NetBird, whole seconds from 5 to 30. The worker renews every 2 seconds, so 5 is the shortest a healthy exit always meets. It is how long the exit tolerates its routing owner not answering ([the lease](architecture.md#the-lease)); 0.7's gate had a setting of the same name and range. |
| `FWMARK_GRACE` | `30` | gluetun overlay exits only: seconds NetBird may go without carrying the control-plane mark before it is stopped, 5 to 30. |

`compose.yaml` passes the first two from `.env` as overrides. The other
settings of a time-based kind are fixed in the binary: the worker's renewal
every 2 seconds, the 10-second bound on one kernel operation, a 3-second
bound on a monitor's step, and the 15-second stop budget
([architecture](architecture.md#the-stop-sequence)).

### A server set in configuration

Set `SERVER` in `.env` to a name from your provider's relay catalog: a
server hostname for native Mullvad, native NordVPN and the gluetun backend,
or a region id for PIA. Use the exact name, without spaces, a port, a URL or
a comma-separated list. Leave it empty to keep the existing panel behavior.

When `SERVER` is set, configuration wins. The exit ignores
`state/panel/desired.json` entirely and converges to this server, including
after tunnel recreation. With gluetun it also restores this server after a
gluetun restart, ahead of the saved panel selection. This is not a default
the panel can override. Switchyard shows the exit as "Set in configuration"
with the configured name and no switching controls.

The exit treats `SERVER` as untrusted input. It uses the same name
validation as a desired-state request and requires membership in a fresh
trusted catalog for the configured provider. PIA's port-forwarding filter
still applies. If no fresh catalog is available, the request waits and
retries when one becomes available. An invalid or unknown name reports a
failed status with the name quoted, for example:

```text
Invalid SERVER "--bad"; no change applied.
Unknown SERVER "absent.example.test"; not in a fresh trusted relay catalogue; no change applied.
```

These errors do not fall back to a panel request. Fix the setting and apply
your configuration change with [recovery](operations.md#recovery). A failed
application of a valid configured server is retried after 1, 2, 4 and 8
minutes, then every 15 ([retries](operations.md#retries)); Molebridge does
not choose another server. Whether the exit is on its `SERVER` and verified
is reported by the panel, `/readyz` and `molebridge status`; the container's
health check doesn't fail over it ([health](operations.md#health)). Removing
`SERVER` returns control to the panel, including any `desired.json` request
left there.

`SERVER` goes only to the exit. It publishes `configured_server` in
`result.json` (null when unset); the panel reads that file through its existing
read-only mount, without reading the exit's environment or holding its
credentials. A stale result still identifies the exit as read-only, while
its connection status becomes unknown. Before the first result is available,
the panel cannot know the setting; the exit still ignores its requests.

With gluetun, `GLUETUN_SERVER_*` filters still control gluetun's first
connection, before the exit runs. `SERVER` takes over once the exit has a
fresh catalog and can apply it.

### Panel sign-in

Optional OpenID Connect sign-in; the procedure is in
[panel access](access.md#sign-in-with-openid-connect). Everything here is off
unless `PANEL_OIDC_ISSUER` is set. Setting `PANEL_OIDC_CLIENT_ID`,
`PANEL_ACCESS`, `PANEL_ADMIN_GROUPS` or `PANEL_PUBLIC_URL` without it stops the
panel at start. The Compose files pass `PANEL_OIDC_ISSUER`,
`PANEL_OIDC_CLIENT_ID`, `PANEL_PUBLIC_URL`, `PANEL_ADMIN_GROUPS` and
`PANEL_SESSION_TTL` from `.env`. The other four are for a Switchyard that
serves several exits: set them in its own environment, in an override file.

| Setting | Default | Purpose |
|---|---|---|
| `PANEL_OIDC_ISSUER` | empty | The issuer, exactly as its discovery document states it. `https`, or `http` only to a loopback test issuer. Empty means no login. |
| `PANEL_OIDC_CLIENT_ID` | empty | The client ID registered at the issuer. Required with the issuer. |
| `PANEL_OIDC_CLIENT_SECRET_FILE` | empty | Path, inside the panel container, to a file holding the client secret, for a confidential client. The panel sends it with HTTP Basic authentication. Unset means a public client, with no secret on disk. This is the one credential a panel may hold ([the host check](operations.md#host-checks)). |
| `PANEL_PUBLIC_URL` | empty | The canonical `https` origin people open, such as `https://exit.example.net`, with no path. Its host is accepted like a `PANEL_PUBLIC_HOSTS` entry. The redirect URI to register at the issuer is this plus `/auth/callback`. Required with the issuer. |
| `PANEL_OIDC_SCOPES` | `openid profile email groups` | Scopes to request. Must include `openid`. |
| `PANEL_OIDC_GROUPS_CLAIM` | `groups` | The claim that lists a person's groups. |
| `PANEL_ADMIN_GROUPS` | empty | Comma-separated groups whose members see every exit. |
| `PANEL_ACCESS` | empty | Comma-separated `group=exit` pairs. Repeat a group to grant it several exits. Every exit must be in `PANEL_EXITS`, so a single-exit panel uses `PANEL_ADMIN_GROUPS` only. Group names are 1 to 128 characters and can't contain spaces, commas or `=`. |
| `PANEL_SESSION_TTL` | `3600` | Seconds a sign-in lasts, from 300 to 604800. Not extended by use. |

With the issuer set, at least one of `PANEL_ADMIN_GROUPS` and `PANEL_ACCESS`
must name a group.

### The panel's isolation check

Switchyard is the one component that must hold nothing: no capabilities, no
way to write what the exit publishes. It runs no subprocess and writes only the
desired server name. At every start it checks its own isolation and, when any
of these is false, prints one line per problem to standard error and exits with
status 1 before it listens:

- **No capabilities.** Its effective capability set (`CapEff` in
  `/proc/self/status`) is empty, as `cap_drop: [ALL]` makes it. If it can't
  read the set, it refuses too.
- **Not root.** It is not uid 0, unless `PANEL_ALLOW_ROOT` is exactly `1`
  (empty counts as unset; the Compose files pass it through empty). Set
  `PANEL_USER` to the uid and gid that own `state/panel`. On a rootless engine
  that remaps uids, container root is already your host user and another uid
  can't read the state tree, so you set `PANEL_USER=0:0` and
  `PANEL_ALLOW_ROOT=1` together.
- **The exit's state is read-only.** Every exit's `applier` state directory
  (`/state/applier`, or `/state/<id>/applier` with `PANEL_EXITS`) is on a
  read-only mount. Only the `panel/` directory, where requests are written, may
  be writable. A directory that isn't there passes; one it can't examine is
  refused.

Each refusal is one fixed line starting `molebridge panel: refusing to start:`
([troubleshooting](troubleshooting.md#the-panel)). The check cannot see what
else was mounted into the panel container, so keeping tunnel configs,
credentials and gluetun's secrets out of it is a host check
([operations](operations.md#host-checks)); the one credential the panel may
hold is the sign-in client secret file.

`MOLEBRIDGE_PANEL_ISOLATION_CHECK=off` turns the check off. It exists for the
panel's script tests and for running the panel by hand outside a container;
the Compose files never set it, and the panel prints `molebridge panel: the isolation self-check is switched off; do not run a deployed panel this way`
when it is set. Don't set it on a deployed panel: with it off, nothing
verifies that the panel holds no capabilities and can't write the exit's
records.

## gluetun backend

Experimental. Live passes used NordVPN only; what ran at 0.8.0 is in
[testing](testing.md#080), earlier passes in
[testing](testing.md#gluetun-backend-pass-at-a3bb14f). The design is in [architecture](architecture.md#gluetun-backend) and
what differs for you in [providers](providers.md#the-gluetun-backend). Copy
`.env.gluetun.example` to `.env`; it sets `COMPOSE_FILE=compose.gluetun.yaml`,
and that file replaces `compose.yaml`. `OVERLAY_CIDR`, `OVERLAY6_CIDR`,
`OVERLAY_IF`, `EXIT_TABLE`, `NB_HOSTNAME`, `NB_MANAGEMENT_URL` and the panel
settings above keep their meaning. `PROVIDER` and the PIA settings don't apply.

| Setting | Default | Purpose |
|---|---|---|
| `GLUETUN_PROVIDER` | required | gluetun's `VPN_SERVICE_PROVIDER`. The panel can select servers for `fastestvpn`, `ivpn`, `mullvad`, `nordvpn`, `surfshark` and `windscribe`; the exit refuses any other. `compose.gluetun.yaml` gives the exit and the panel `PROVIDER=gluetun-<this value>`. |
| `EXIT_IF` | `wg0` | The name gluetun gives its tunnel interface (its `VPN_INTERFACE`): letters, digits and underscores only. The routing contract and NetBird's ICE blacklist use the same value. (The native default is `mullvad`.) |
| `GLUETUN_WIREGUARD_ADDRESSES` | empty | gluetun's `WIREGUARD_ADDRESSES`, the tunnel address your provider assigned to your key. Most providers need it; gluetun fills it in for NordVPN. |
| `GLUETUN_SERVER_COUNTRIES`, `GLUETUN_SERVER_CITIES`, `GLUETUN_SERVER_HOSTNAMES` | empty | gluetun's `SERVER_COUNTRIES`, `SERVER_CITIES` and `SERVER_HOSTNAMES`: the server gluetun starts with. For a first start, set only `GLUETUN_SERVER_COUNTRIES`, to your own country as gluetun names it: gluetun picks among the servers in its data, and on a fresh install that is its built-in list, where some servers may be gone; a whole country rarely is. Empty lets gluetun pick from every country. A value must name a server, city or country in the data gluetun has when it starts, which on a fresh install is its built-in list, years old for some providers; otherwise gluetun refuses to start (`the hostname specified is not valid`, or the same for a country or city). When `SERVER` is set, the exit converges to it and restores it after gluetun restarts. Otherwise a selection in the panel replaces these filters while gluetun runs, and the exit restores your last verified selection after a restart. |
| `GLUETUN_UPDATER_PERIOD` | `24h` | gluetun's `UPDATER_PERIOD`: how often gluetun refreshes the server list the panel shows. gluetun first refreshes one period after it starts, so the exit also asks it for one refresh when it starts, once gluetun's tunnel has a fresh handshake, if the data is older than this period or than 7 days. `0` turns both off; the list then keeps the date of gluetun's built-in data and soon shows as stale. Hours, minutes and seconds only, such as `24h`, `1h30m` or `90s`; anything else stops the exit at start with `invalid GLUETUN_UPDATER_PERIOD`. |
| `HOST_IF` | `eth0` | The namespace's interface toward the host. Docker names it `eth0`; rootless Podman with pasta copies the host's interface name, such as `enp3s0`. It can't be `lo`, `OVERLAY_IF` or `EXIT_IF`. The host table copies this interface's default and on-link routes, and the post-rules accept output on it. A [native sidecar](#native-sidecar) reads it too, with no host table. |
| `HOST_TABLE` | `51822` | Molebridge's table for NetBird's control traffic (256 to 2147483647). Must differ from `EXIT_TABLE`; neither may be 51820 (gluetun) or 7120 (NetBird). |
| `CONTROL_MARK` | `0x1bd00` | NetBird's control-plane mark, in lowercase hexadecimal with the low byte zero. `compose.gluetun.yaml` passes it to NetBird as `NB_FWMARK_BASE`, which moves NetBird's whole mark range; change it only if another program on the host uses those marks. A [native sidecar](#native-sidecar) uses it for the exit's own host-path sockets, with the same format. |
| `NB_WIREGUARD_PORT` | `51820` | NetBird's WireGuard port, opened in gluetun's firewall. |
| `FWMARK_GRACE` | `30` | See [repair and lease timing](#repair-and-lease-timing). |

`compose.gluetun.yaml` also sets fixed values: gluetun with `VPN_TYPE=wireguard`,
`WIREGUARD_IMPLEMENTATION=kernelspace`, its control server on
`127.0.0.1:8000` inside the namespace and its server list at
`/gluetun/servers/servers.json` (`STORAGE_FILEPATH`), in a volume of its
own; `TUNNEL_BACKEND=gluetun` for the exit; and for the exit
`GLUETUN_CONTROL_URL` (`http://127.0.0.1:8000`), `GLUETUN_API_KEY_FILE`
(`/run/secrets/gluetun/api_key`) and `GLUETUN_SERVERS_FILE`
(`/gluetun-servers/servers.json`), where it finds the control server, the API
key and the read-only server list. With this backend the exit also refuses
`NB_USE_LEGACY_ROUTING`, `NB_SKIP_SOCKET_MARK` and `NB_DISABLE_CUSTOM_ROUTING`
set to a true value, and an `NB_FWMARK_BASE` other than `CONTROL_MARK`.

Before the first start:

1. Put the provider's WireGuard private key in
   `secrets/gluetun/wireguard_private_key`, one line, mode 0600.
2. Run the `gluetun-auth` tool ([tools](tools-reference.md#gluetun-auth)). It
   generates an API key and writes it twice, both mode 0600: into
   `secrets/gluetun/auth.toml`, gluetun's role file, with one role allowed
   exactly `PUT /v1/vpn/settings`, `GET /v1/vpn/status`, `GET
   /v1/publicip/ip`, and `GET` and `PUT /v1/updater/status` (to refresh the
   server list); and into `secrets/gluetun/api_key`, which only the exit
   mounts. The key is never printed. Run it again with `--rotate` to replace
   both, then recreate gluetun and the exit ([recovery](operations.md#recovery)).
   Compose refuses to start without the role file: without one, gluetun
   answers several routes with no authentication, including one that stops
   the VPN.
3. Run the `gluetun-post-rules` tool ([tools](tools-reference.md#gluetun-post-rules))
   to write `tunnel/gluetun/post-rules.txt` from these settings; add
   `--ipv4-only` if gluetun logs that it found no working ip6tables. It does
   not read `.env`: pass the settings that differ from the defaults with
   `-e`. Only `HOST_IF`, `EXIT_IF`, `OVERLAY_IF` and `NB_WIREGUARD_PORT` appear
   in the file; run it again after changing one of them, then recreate gluetun
   and the exit.

## gluetun sidecar

Experimental; see [the gluetun sidecar](gluetun-sidecar.md) for setup and
what has been tested. Copy `.env.sidecar.example` to `.env`; it sets
`COMPOSE_FILE=compose.sidecar.yaml`. `GLUETUN_PROVIDER`, `EXIT_IF`,
`GLUETUN_WIREGUARD_ADDRESSES`, `GLUETUN_SERVER_*`, `GLUETUN_UPDATER_PERIOD`,
`SERVER`, the panel settings and the Gatus settings mean what they mean
above. The NetBird, overlay, table and mark settings don't apply.

| Setting | Default | Purpose |
|---|---|---|
| `SIDECAR_APPS` | empty | The Compose services of your applications that use the tunnel, comma-separated, each with `network_mode: service:gluetun`. `compose.sidecar.yaml` puts it on the exit container as the label `io.molebridge.sidecar-apps`, a record of your list that `docker inspect` shows. Nothing in Molebridge reads or checks it, and neither does the [attachment procedure](operations.md#checking-that-containers-share-gluetuns-namespace): you name every container to check, and one you leave out is not checked. `.env.sidecar.example` sets `example-app`. |
| `GLUETUN_FIREWALL_INPUT_PORTS` | empty | gluetun's `FIREWALL_INPUT_PORTS`: ports your applications listen on, comma-separated, which you also publish on the `gluetun` service. Never 8000, the control server. |
| `COMPOSE_PROFILES` | empty | `.env.sidecar.example` sets `example`, which runs the example application, a busybox that only sleeps; remove it once yours are listed. |

`compose.sidecar.yaml` sets `EXIT_KIND=sidecar` on the exit and the panel;
it isn't read from `.env`. `EXIT_KIND` is `overlay` when unset, as in
`compose.yaml` and `compose.gluetun.yaml`. The exit refuses to start with any
other value. With `TUNNEL_BACKEND=gluetun` a sidecar needs a `gluetun-*`
provider; with `TUNNEL_BACKEND=native` it is the [native sidecar](#native-sidecar)
(before 0.9.0 the exit refused that combination). A separate Switchyard names
the kind in `PANEL_EXITS` instead, as `id=<provider>/sidecar`. The exit's and
the panel's kind must agree, or the panel shows "kind mismatch".

## Native sidecar

Experimental, new in 0.9.0; see [the native sidecar](native-sidecar.md) for setup
and what has been tested. Copy `.env.native-sidecar.example` to `.env`; it sets
`COMPOSE_FILE=compose.native-sidecar.yaml`. `PROVIDER`, `EXIT_IF`, `SERVER`,
the tunnel config, the PIA login, the panel settings and the Gatus settings
mean what they mean for a native overlay exit. The NetBird and overlay settings
don't apply: `OVERLAY_CIDR`, `OVERLAY6_CIDR` and `OVERLAY_IF` are refused when
set, and `NB_*` and `WT_*` are ignored. Tables 51820 and 7120 are not reserved,
because no gluetun and no NetBird runs.

| Setting | Default | Purpose |
|---|---|---|
| `SIDECAR_LAN_CIDRS` | empty | The networks the applications may reach outside the tunnel, as comma-separated IPv4 and IPv6 prefixes written with their network addresses: no `/0`, no duplicates, at most 16 entries in all, spaces around an entry dropped. In Compose, the engine's network; in Kubernetes, the pod and Service ranges and anything that connects to the application. Anything in the namespace can reach these without the tunnel, and a resolver inside them answers outside it ([DNS](native-sidecar.md#dns)). The refusals are in [the native sidecar](native-sidecar.md#settings). `.env.native-sidecar.example` sets the documentation range `198.51.100.0/24`; replace it. |
| `SIDECAR_HOST_RESOLVERS` | empty | Up to three resolver IP addresses, comma-separated, that the exit's own lookups ask (port 53) in place of `/etc/resolv.conf`'s, for when the namespace's resolvers are reachable only through the tunnel ([DNS](native-sidecar.md#dns)). Setting it also drops the applications' DNS (ports 53 and 853) to `SIDECAR_LAN_CIDRS`. No port, name or zone; no duplicates |
| `PROVIDER`, `EXIT_IF` | `pia`, `pia` in `.env.native-sidecar.example` | As in `.env`; `EXIT_IF` names the tunnel interface and its config file. |
| `HOST_IF` | `eth0` | The namespace's interface toward the host (not `lo`, not `EXIT_IF`). The deletion check judges the exit's control-marked path against it (that path may leave by it or by the tunnel interface) and the watcher follows it; the firewall does not use it. An override in `.env`. |
| `EXIT_TABLE` | `51821` | The exit table, whole number 256 to 2147483647; also the tunnel device's firewall mark, so it must differ from `CONTROL_MARK`. An override. |
| `CONTROL_MARK` | `0x1bd00` | The mark on the exit's own host-path sockets (the provider's login and downloads, PIA's registration, the Gatus push, and their name lookups): lowercase hexadecimal, leading `0x`, no leading zero, low byte zero. Set in the exit's environment only; the Compose file doesn't pass it. |
| `PIA_PORT_FORWARD` | `off` | `on` forwards one PIA port to the namespace itself ([port forwarding](native-sidecar.md#port-forwarding)). `PIA_PORT_FORWARD_TARGET` is refused. |
| `COMPOSE_PROFILES` | `example` in `.env.native-sidecar.example` | `example` runs a busybox that only sleeps, standing in for your applications; remove it once yours are in. `port-sync` runs the port-sync service. |
| `PORT_SYNC_URL` | `http://127.0.0.1:8080` | Where the `port-sync` service reaches qBittorrent's Web API. Passed from `.env` by the Compose file; the other port-sync settings below are fixed there. |

`compose.native-sidecar.yaml` sets `EXIT_KIND=sidecar` and `TUNNEL_BACKEND=native`
on the exit, and `EXIT_KIND=sidecar` on the panel; neither is read from `.env`.
The combinations the exit accepts are:

| `EXIT_KIND` | `TUNNEL_BACKEND` | `PROVIDER` | Result |
|---|---|---|---|
| `overlay` | `native` | `mullvad`, `pia`, `nordvpn` | A native overlay exit |
| `overlay` | `gluetun` | `gluetun-*` | A gluetun overlay exit |
| `sidecar` | `gluetun` | `gluetun-*` | A gluetun sidecar |
| `sidecar` | `native` | `mullvad`, `pia`, `nordvpn` | A native sidecar |

Anything else is refused: `PROVIDER must be mullvad, pia or nordvpn` for a
`gluetun-*` provider with the native backend, and
`TUNNEL_BACKEND=gluetun needs a gluetun provider (PROVIDER=gluetun-<name>)` for
a native provider with gluetun.

### The port-sync role

`molebridge port-sync` is a separate container with no capabilities, in the
namespace of the application whose port it sets
([tools reference](tools-reference.md#port-sync)). It reads
`STATE_DIR/applier/result.json` and writes nothing.

| Setting | Default | Purpose |
|---|---|---|
| `PORT_SYNC_CLIENT` | required | The only value is `qbittorrent`. |
| `PORT_SYNC_URL` | `http://127.0.0.1:8080` | qBittorrent's Web API: an `http` URL to a loopback IP address, with no user name, path, query or fragment. |
| `PORT_SYNC_USERNAME_FILE`, `PORT_SYNC_PASSWORD_FILE` | empty | Files holding qBittorrent's Web UI login, one value per file, at most 1 KiB, not empty. Set both or neither. With neither, the role sends no login and relies on qBittorrent's setting that skips authentication for clients on localhost. |
| `PORT_SYNC_INTERVAL` | `30` | Seconds between passes: a whole number from 10 to 300. |
| `STATE_DIR` | `/state` | Where the role finds `applier/result.json`; mount the exit's `state/applier` read-only. |

## The tunnel config

The exit reads one file, `tunnel/wg_confs/<EXIT_IF>.conf`
(`/config/wg_confs/<EXIT_IF>.conf` inside the container). Any other `.conf`
file in that directory is ignored, with the warning `molebridge-exit:
warning: <n> other .conf file(s) in /config/wg_confs are ignored; only
<EXIT_IF>.conf is used`. Only a native exit reads it; the gluetun forms take
the provider's key from `secrets/gluetun/wireguard_private_key`.

Before anything changes, the exit checks the file against what Molebridge's
own tools write: `prepare-config` for Mullvad, the same with `--pia` for PIA,
and the same with `--nordvpn`, or `nordvpn-key`, for NordVPN
([tools](tools-reference.md)). Anything else is
refused, including fields `wg-quick` itself would accept; the exit does not
run `wg-quick`, or any other program, to bring the tunnel up. The file must
be a regular file, not a symlink, readable by the container, at most 4 KiB,
with no NUL bytes and no carriage returns (so no Windows line endings). Each
line is blank, a comment starting with `#`, a section header written exactly
`[Interface]` or `[Peer]`, or `Field = value` with a field from this table.
Use the field names exactly as shown; each may appear once. Case matters:
`wg-quick` would read `address` or `ADDRESS` as `Address`, but the exit refuses
any spelling but the one in the table with `unsupported field on line <n>`.

| Field | Rule |
|---|---|
| `[Interface]` | Once, first. |
| `PrivateKey` | Required. A WireGuard key: 44 characters of base64 ending in `=`. |
| `Address` | Mullvad and NordVPN: required. PIA: must be absent; the exit sets the address. Comma-separated: one IPv4 address and, for Mullvad only, at most one IPv6 address, each with `/32` or `/128` or no prefix. IPv4 without leading zeroes. |
| `MTU` | Required, 1280 to 1500. The tools write 1420. |
| `Table` | Required, `off`. |
| `PostUp` | Required, exactly `ip route replace default dev %i table <EXIT_TABLE>`, followed by `; ip -6 route replace default dev %i table <EXIT_TABLE>` when the config has an IPv6 address. |
| `PreDown` | Required, exactly `ip route del default dev %i table <EXIT_TABLE>`, followed by `; ip -6 route del default dev %i table <EXIT_TABLE>` when the config has an IPv6 address. |
| `[Peer]` | Mullvad: once, after `[Interface]`. PIA and NordVPN: must be absent; the exit sets the peer. |
| `PublicKey` | Required in `[Peer]`. A WireGuard key. |
| `Endpoint` | Required in `[Peer]`. An IPv4 address without leading zeroes and a port, 1 to 65535, such as `192.0.2.10:51820`. |
| `AllowedIPs` | Required in `[Peer]`. `0.0.0.0/0`, followed by `, ::/0` exactly when the config has an IPv6 address. |
| `PersistentKeepalive` | Optional in `[Peer]`, 1 to 65535. The tools write 25. |

`PostUp` and `PreDown` stay in the file because the tools write them and the
exit checks them, but the exit never runs them. It reads them as the route
operations they stand for (the default route into the exit table) and does
those itself, through the kernel's netlink interface.

So `DNS`, `ListenPort`, `FwMark`, `SaveConfig`, `PreUp`, `PostDown`,
`PresharedKey`, a `Table` other than `off` and every other field are refused,
as is a second `[Peer]`. A refusal stops the container with status 1 before
it changes any routing or creates the tunnel, and logs one line:

```text
molebridge-exit: the tunnel config /config/wg_confs/mullvad.conf is not supported: unsupported field on line 4; regenerate it with prepare-config (docs/setup.md)
```

The reason is one of `unsupported field on line <n>`, `<field> on line <n> is
not valid`, `<field> is missing`, `<field> appears more than once`,
`[Interface] on line <n> is not supported; it must come once, first`,
`[Peer] on line <n> is not supported`, `[Interface] is missing`, `[Peer] is
missing`, `[Peer] is not supported for this provider` or `Address on line <n>
is not supported for PIA`. The field names come from the table above, never
from the file: no message quotes the config, which holds the private key. The
end names the tool for your `PROVIDER` (`prepare-config --pia` for PIA,
`prepare-config --nordvpn` for NordVPN).

To change the exit table of an existing exit while keeping its key, set
`EXIT_TABLE` in `.env` and edit only these two lines in its tunnel config
(here for table `51822`):

```ini
PostUp = ip route replace default dev %i table 51822
PreDown = ip route del default dev %i table 51822
```

Keep the file mode 0600. For Mullvad and NordVPN, change the table in both
hooks too, including their `ip -6` commands if present. Apply the change with
[recovery](operations.md#recovery), then run [verification](verification.md).
A new config made by the tools takes the table from `-e EXIT_TABLE=<n>`.

To check a config without starting anything, run
`docker compose run --rm --no-deps exit check-config`
([setup](setup.md#5-check-then-start)).

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
| `secrets/gluetun/auth.toml` | gluetun's control-server role, with the API key; written by `gluetun-auth` | With the gluetun backend |
| `secrets/gluetun/api_key` | The same API key, for the exit. It is full gluetun administration | With the gluetun backend |

Neither NordVPN's downloaded config nor its access token is one of these:
each is needed only while `prepare-config --nordvpn` or `nordvpn-key` runs.
Delete the download afterwards, and the token file if you saved one. `secrets/netbird.env` and `secrets/applier.env` reach the exit
through `env_file`, so their permissions are a host check
([operations](operations.md#host-checks)). The supervisor hands `NB_SETUP_KEY`
only to `netbird up`, the command that enrolls, not to NetBird's daemon, its
liveness probes or the worker, and hands NetBird only its own `NB_*` and
`WT_*` settings, so `GATUS_TOKEN` and PIA's files never reach NetBird. The
supervisor itself, PID 1, keeps both in its environment for the life of the
container, so root in the container (and on the host) can read them in
`/proc/1/environ`, and the engine keeps them in the container's configuration
(`docker inspect`). Once the peer has enrolled, delete `secrets/netbird.env`
as [setup](setup.md#5-check-then-start) says, then recreate the exit
(`docker compose up -d --force-recreate exit`) so that neither holds the key
any more.

## State files

Under `state/`, written with temp-file-and-rename. None hold secrets. These
names, paths, fields and timestamp formats are the same as in 0.7.0: a 0.7.0
Switchyard reads a 0.8.0 exit, and a bridge that reads `result.json` keeps
working. With `PRIVATE_STATE_DIR` set, the three files only the exit reads
(`attempt.json`, `gluetun-selection.json` and `tunnel.json`) are in that
directory instead of `applier/`
([below](#keeping-the-published-files-in-memory)). For a healthy
`result.json` of each exit kind, see [the example
records](architecture.md#example-records).

| File | Writer | Reader | Contents |
|---|---|---|---|
| `applier/relays.json` | exit | panel (read-only) | `fetched_at`, `provider` and validated `relays`. Mullvad: hostname → `hostname`, `country`, `city`, `location_code`, `public_key`, `ipv4_addr_in`, and when Mullvad publishes them well formed, `owned` and `stboot` (booleans) and `provider` (text, at most 64 characters). PIA: region id → `hostname` (the id), `country`, `city`, `location_code`, `ipv4_addr_in` (the latency target), `port_forward`, `geo` and `servers` (`ip`, `cn`). NordVPN: hostname → `hostname`, `country`, `country_code`, `city`, `location_code`, `public_key` (shared by the servers of a location), `ipv4_addr_in` (the entry address and endpoint), `virtual` (boolean), and `load` (0–100) when NordVPN publishes it well formed. gluetun backend: also `source` (`gluetun`) and `data_timestamp` (when gluetun's data for the provider last changed); hostname → `id` and `hostname` (the same), `selection_filter` (`hostnames`), `public_key`, `ipv4_addr_in` (the first IPv4 address, the latency target), `ipv4_addrs` and `ipv6_addrs` (every address gluetun may connect to), `country`, `city`, and `region` and `categories` where gluetun lists them. A snapshot for another provider is ignored. |
| `applier/gluetun-selection.json` | exit | exit | `desired`, `last_put`, `last_applied` and `last_successful`: server hostnames: the panel's last request, the last server put, the last one live after a change, and the last one verified. The last verified one (for a tunnel-tier sidecar, the last one live) is put back after gluetun restarts when `SERVER` is unset and the panel's request is absent or refused. With `SERVER`, configuration wins. No secret. |
| `applier/attempt.json` | exit | exit | The [admission pipeline](architecture.md#the-admission-pipeline)'s current attempt: `source`, `target` and its identity, `state` (`idle`, `pending`, `rejected`, `attempting`, `unverified` or `failed`), the outcome and message, the number of changes, `backoff_step`, `next_action` and its time and the last change's time (on the boot clock, with `boot_id`), `mutation_certainty`, the owner generation already given a re-apply, and the last refused panel request. Mode 0600. Missing or unreadable means idle; see [retries](operations.md#retries) before deleting it. No secret. |
| `applier/tunnel.json` | exit (PIA) | exit (PIA) | Current registration (`region`, `cn`, `server_ip`, `server_port`, `server_key`, `peer_ip`, `server_vip`, `registered_at`), read to match the live peer and reconcile tunnel state. No secret. |
| `applier/relay-error.json` | exit | panel (read-only) | Sanitized last refresh error and timestamp, or an empty object after success |
| `panel/desired.json` | panel | exit (read-only) | `server`, `requested_at`, `request_id`. Ignored entirely when `SERVER` is set. Otherwise each selection gets a new ID so the same server can be retried. Old two-field requests remain readable. |
| `applier/result.json` | exit's supervisor | panel (read-only) | The status record, schema 2 ([the status record](architecture.md#the-status-record)): `schema`, `kind`, `backend`, `provider`, `status` (`unknown`/`applying`/`ok`/`failed`), `message`, `checked_at`, observed `server`, `requested_server`, `configured_server` (the `SERVER` setting, null when unset; invalid values longer than 256 characters are truncated for reporting), acknowledged `request_id`, `selection` (`source`, `outcome`, `attempt`, `target`, `next_action`, `next_action_at`), `checks` (`routing`, `traffic_protection`, `netbird`, `owner_record`, `peer`, `handshake`, `egress`, `app_attachment`, each with a `state` and, when measured, `at`), egress fields (`egress_ip` is IPv4; `egress_ips` maps `4`/`6` to the addresses of the passing families; `egress_city`, `egress_country`), `port_forward`, `forwarded_port` and `port_forward_error` (PIA only), and with the gluetun backend `server_list_update` (`updating`, `failed`, a waiting reason since 0.9.1, `waiting-for-tunnel`, `waiting-for-vpn`, `waiting-for-control-server` or `waiting-to-retry`, or null: the refresh of gluetun's server list the exit starts; [architecture](architecture.md#the-exit-with-gluetun)). Records written before 0.7.0 have no `schema` and carry `routing_ok`, `netbird_native`, `exit_confirmed`, `egress_tier`, `handshake_age_s` and `unreachable_fallback` instead of `checks`; the panel still reads them. |

**`owner_record` in 0.8.0.** The check keeps its meaning, "the exit's owner is
live", and carries one new member on a native exit: `expires_at`, the lease
expiry the supervisor accepted, on the wall clock, in the same timestamp
format as `at`. A passing check is
`{"state": "pass", "at": "…", "expires_at": "…"}`; a failing one has no
`expires_at`. A 0.8.0 reader treats `expires_at` as an extra upper bound on
the check, never an extension: a record without it is judged as in 0.7.0, and
a malformed one, or one that has passed, fails the check. A 0.7.0 reader
ignores the member. For the gluetun backend and the sidecar the check stays
`n/a`, as schema 2 fixes it; their liveness shows in the other checks. Schema
2 itself is unchanged.

Between full inspections, which publish about every 60 seconds, the supervisor
rewrites `result.json` every 2 seconds on a native exit, changing only the
`owner_record` check. `checked_at` and every other check's time stay those of
the last full inspection, so a reader that judges by those times still sees
old evidence as old.

Routing installs the return-path rule and its backstop (rules 94 and 98)
from the tunnel config's `Address` line (a PIA config has none; the exit
installs both per registration); `compose.yaml` sets
`net.ipv4.icmp_errors_use_inbound_ifaddr` on the `exit` service for the
same reason, and the exit warns when it is not `1`. See
[architecture](architecture.md#routing-contract).

### Keeping the published files in memory

`state/applier` holds two kinds of file:

- **Published**: `result.json`, `relays.json` and `relay-error.json`, which
  the panel and other readers read. The exit rebuilds them. It publishes a
  status record when it starts and again after each inspection, and it
  downloads the server list at start (with gluetun, reads gluetun's file).
- **Private**: `attempt.json`, `gluetun-selection.json` (gluetun backend)
  and `tunnel.json` (PIA). Only the exit reads them, and they carry its
  state across a restart ([retries](operations.md#retries),
  [backups](operations.md#backups)).

A native exit rewrites `result.json` every 2 seconds. To keep those writes
off your disk, move the private files out and put `state/applier` in
memory:

1. Stop the exit.
2. Set `PRIVATE_STATE_DIR` on the exit to an absolute path on persistent
   storage, and mount a directory there, for example in a
   `compose.override.yaml`:

   ```yaml
   services:
     exit:
       environment:
         PRIVATE_STATE_DIR: /state/exit
       volumes:
         - ./state/exit:/state/exit
   ```

3. Move whichever of the three private files exist from `state/applier/`
   to the new directory (`state/exit/` above).
4. Mount a tmpfs on `state/applier` on the host, with the owner and mode the
   directory has now (`stat -c '%u:%g %a' state/applier`), mounted before
   the containers start (an `/etc/fstab` line), and at least 40 MiB: the
   largest server list is 16 MiB and is written beside the old one before
   the rename. Every container that reads the exit's files keeps its
   existing mount of `state/applier`. On Kubernetes, an `emptyDir` with
   `medium: Memory` works only when every reader is in the exit's pod.
5. Start the exit.

The exit refuses to start when `PRIVATE_STATE_DIR` is not an absolute path
without `.` or `..` elements or a trailing slash, when it is under
`<STATE_DIR>/panel` or `<STATE_DIR>/applier`, or when the directory can't be written. It creates a
missing directory with mode 0700. Setting it to `<STATE_DIR>/applier` is the
same as leaving it unset. An older release doesn't read the setting. If you
roll back, move the files back first, or the exit starts idle
([retries](operations.md#retries)) and, with gluetun, without its last
verified server.

With `state/applier` in memory, a host restart loses only what the exit
rebuilds. Until its first server-list download succeeds (it retries every
minute), the exit has no server list, so its peer check fails with the
reason `catalogue-stale` (the panel shows `no fresh server list`).

This was tested with the unit tests at the commit that added it. No exit
has been run live this way ([testing](testing.md)).

The old `panel/relays.json` and `applier/.last-server` files are ignored. Public
exit snapshots are mode 0644 so the non-root panel can read them; requests
are mode 0600. The panel cannot write the applier directory. Catalog refresh
is every six hours (after a failure, retries from one minute doubling to an hour, or to five minutes while there is no catalog under 24 hours old), maximum catalog age is 24
hours, and maximum status age is 150 seconds. A server list download may take
20 seconds and 10 MiB, except NordVPN's: 60 seconds and 32 MiB. With the
gluetun backend nothing is downloaded: the exit reads gluetun's server
file, up to 32 MiB, every minute when it changed and at least every six
hours. The validated `relays.json` may be 10 MiB, NordVPN's and gluetun's
16 MiB; the exit refuses to write a larger one and keeps the last good
catalog, reporting it in `relay-error.json` like any failed refresh, and
neither the exit nor the panel reads a larger one. These are fixed safety
defaults, set per provider in `internal/providers`.

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
| `POST /select` | Refused with 403 `Exit is set in configuration; change SERVER to choose another server.` for an exit set in configuration, then with 409 `A switch is in progress; wait for it to finish.` while the exit's state is switching. Otherwise choose a server; requires a CSRF token and allowed origin, plus the `exit` form field in multi-exit mode. A stale or unreadable status doesn't block a switch |
| `/api/exits` | Configured exits with status summaries; an empty list in single-exit mode. With sign-in, only the exits the person is granted |
| `/api/status?exit=<id>` | Desired server, the exit's result and `verdict`: `state` (`ok`, `failed`, `applying` or `unknown`), `label`, `reasons`, `message`, `tier`, every check's state in `checks` (`pass`, `fail`, `unknown`, `n/a`, `not-checked` or `legacy`), `not_checked_by`, `schema`, `kind`, `configured_server`, `next_action` and `next_action_at`. In configuration mode `desired` is null; omit `exit` for a single-exit panel. Deprecated, still sent in 0.8.0: `view` (`state`, `label`, `tier`, `selection_mode`, `configured_server`), and in `result` for a schema-2 record `routing_ok`, `netbird_native`, `exit_confirmed`, `egress_tier`, `handshake_age_s` and `unreachable_fallback`, derived from the verdict and null where unknown or not applicable |
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
