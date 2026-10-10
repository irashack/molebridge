# Troubleshooting

Messages are quoted as the panel, `result.json` or the container logs print
them. For a full check of a running exit, use `python3 tools/molebridge.py
doctor` (Docker) or `podman exec <project>-applier python -m applier.apply
--doctor` (Podman).

Don't paste raw diagnostics into issues. They contain addresses, peer names
and sometimes keys. Never share the output of `wg showconf` or `wg show ...
dump`.

## Startup

**`wireguard` never gets healthy, and its log repeats `molebridge-exit:
tunnel bring-up failed (exit <status>); retrying in <n> s`.** `wg-quick up`
failed, and its own output is discarded because it can echo parts of the
config. The container keeps retrying, after 2 seconds and then up to every
60, and stays unhealthy; forwarded traffic is dropped meanwhile. On rootless
Podman the usual cause is the WireGuard module: a rootless container can't
load kernel modules, so load `wireguard` on the host and make it persist, as
shown in [prerequisites](prerequisites.md#host), then recreate the project.
To rule out the config and settings, run `docker compose run --rm --no-deps
wireguard --check-config`.

**`molebridge-exit: …` or `10-exit-routing: …`, and the container exits.**
The exit checks its settings and the tunnel config before touching anything,
and names what it rejected, for example `OVERLAY_CIDR must use the network
address`, `PROVIDER must be mullvad, pia or nordvpn` or
`ROUTING_RECONCILE_INTERVAL must be an even number of seconds, 2..60`. Fix
`.env`, your Compose override or the tunnel config and start again. If the
log ends with `molebridge-exit: the routing contract could not be installed;
no tunnel was started`, the `10-exit-routing:` line before it says why. No
tunnel exists then, and temporary priority-80 rules already added stay in
place.

**`molebridge-exit: the tunnel config /config/wg_confs/mullvad.conf is not
supported: <reason>; regenerate it with tools/prepare-tunnel-config.py
(docs/setup.md)`.** The config has something the generators don't write: a
`DNS`, `PreUp`, `PostDown`, `SaveConfig` or `FwMark` line, a `Table` other
than `off`, hooks for another table, a second address in a family, a field
name in another case such as `address` for `Address`, and so on.
`<reason>` names the line number (and the field, when it is one Molebridge
accepts), never the line's text; [the
tunnel config](configuration.md#the-tunnel-config) lists every reason and
what is accepted. Regenerate the config with the command the message names
(for NordVPN and PIA, move the old file aside first: neither tool
overwrites one), or, for hooks on another table, write them exactly as
[configuration](configuration.md#tunnel-config-helper) shows. When the file
itself is the problem, the line reads `the tunnel config <path> is missing;
regenerate it with …`, or says that it `is not a regular file` (a symlink,
for example), `is larger than 4 KiB` or `has NUL or carriage-return bytes`
(Windows line endings). A config for another
interface name is ignored, with `molebridge-exit: warning: <n> other .conf
file(s) in /config/wg_confs are ignored; only mullvad.conf is used`.

**`molebridge-exit: the tunnel config /config/wg_confs/mullvad.conf can't be
read (on Docker the container needs DAC_READ_SEARCH; see docs/setup.md)`.**
Container root can't read your mode-0600 file. On rootful Docker,
`compose.yaml` grants `DAC_READ_SEARCH` for this; an override that drops it
breaks the start. When the container can't search `tunnel/wg_confs` itself,
the line reads `molebridge-exit: the tunnel config directory /config/wg_confs
can't be searched (on Docker the container needs DAC_READ_SEARCH; see
docs/setup.md)`. A container root remapped
to another host ID needs read access of its own; see
[setup](setup.md#2-create-the-tunnel-config).

**`molebridge-exit: cannot write the owner record /run/molebridge/exit-owner;
not ready`.** The entrypoint can't write to `/run/molebridge`: the
`exit-run` volume is mounted read-only there, or the directory isn't
writable by container root. The container keeps running but isn't ready
while this lasts, and NetBird's gate stops NetBird. Use the `wireguard`
service from the current `compose.yaml`, which mounts the volume writable
there.

**Stopping `wireguard` logs `molebridge-exit: cleanup incomplete: <what
remains> the routing guards stay in place` and the container exits with
status 1.** Within the 7 seconds it allows itself, the entrypoint couldn't
remove the tunnel interface, or a `wg-quick` or `ip` process it started
outlived its deadline. The rules and the fallback stay in the namespace, so forwarded
traffic still can't leave by another route. Run recovery, which recreates
the namespace.

**NetBird logs `failed to create ipv4 raw socket: operation not permitted`.**
The `netbird` service needs `NET_RAW`. Docker grants it by default; Podman
does not. `compose.yaml` adds it, so this means a modified Compose file.

**NetBird's log stops at `NetBird gate: native backend: waiting for the
exit's owner record (/run/molebridge/exit-owner) and the whole guard (rules
1-98, exit table 51821)`.** NetBird won't start until the exit's owner record
is live and, in both address families, the whole routing contract is in
place, with no other `lookup local` rule (such as the kernel's own
priority-0 rule) that could match the overlay interface
([architecture](architecture.md#netbirds-gate)). So the `wireguard`
container isn't running or didn't finish starting. Check its log first.
Every 30 seconds the gate logs `NetBird gate: still waiting after <n>
s:` and what is missing: an owner-record reason (see below), `rules;` or
`exit;` for a family, or `IPv4: rule 1 or 97;`. `ip rule` inside the
namespace shows which rule is missing or left over.

**NetBird keeps restarting, and its log says `NetBird gate: refusing to start
NetBird: <reason> (see docs/troubleshooting.md)`.** The gate in front of
NetBird's entrypoint refuses settings Molebridge doesn't support on the exit
([architecture](architecture.md#netbird-requirements)). The reasons:

- `<name> is set; Molebridge needs kernel WireGuard and NetBird's kernel
  firewall`, for `NB_FORCE_USERSPACE_FIREWALL`, `NB_FORCE_USERSPACE_ROUTER`,
  `NB_USE_NETSTACK_MODE` or `NB_WG_KERNEL_DISABLED`. Remove the variable from
  your Compose override or `secrets/netbird.env`, then recreate `netbird`.
  [Configuration](configuration.md#env) lists the values each one is
  refused with.
- `NB_CONFIG is set; Molebridge supports only NetBird's default profile`,
  or the same for `WT_CONFIG`, `NB_PROFILE` or `WT_PROFILE`. Remove the
  variable; the profile belongs in the `netbird-data` volume at its default
  path.
- `NB_FOREGROUND_MODE is set; Molebridge supports only NetBird's daemon
  mode`, or the same for `WT_FOREGROUND_MODE`. Remove the variable; the
  image's entrypoint runs NetBird as a daemon.
- `NB_INTERFACE_NAME is empty`, or `WT_INTERFACE_NAME is set and differs
  from the guarded interface <name>`. Set the interface through
  `OVERLAY_IF` in `.env` only, and remove `WT_INTERFACE_NAME`.
- `the active NetBird profile is not the default profile (<file>)`. Someone
  switched the peer to another NetBird profile. Switch back without starting
  NetBird by removing the active-profile record, which makes NetBird use
  `default` again:

  ```sh
  docker compose run --rm --no-deps --entrypoint rm netbird /var/lib/netbird/active_profile.json
  docker compose up -d netbird
  ```

  On rootless Podman, remove `active_profile.json` from the volume's
  mountpoint instead (see below for the path).
- `NB_DISABLE_USERSPACE_ROUTING must be "true" (compose.yaml sets it)`.
  Something overrides the value in `compose.yaml`; remove the override.
- `NB_ENABLE_ROSENPASS is set; Rosenpass cannot work on this exit`, or the
  same for `WT_ENABLE_ROSENPASS`. Remove the variable.
- `Rosenpass is enabled in a stored NetBird profile (RosenpassEnabled)`. The
  peer was once brought up with `--enable-rosenpass`, and its profile in the
  `netbird-data` volume keeps the setting. Turn it off in the profile without
  printing the file, which holds the peer's private key, then start NetBird:

  ```sh
  docker compose run --rm --no-deps --entrypoint sed netbird -i \
    's/"RosenpassEnabled": true/"RosenpassEnabled": false/' /var/lib/netbird/default.json
  docker compose up -d netbird
  ```

  On rootless Podman, run the same `sed -i` on
  `"$(podman volume inspect molebridge_netbird-data --format '{{.Mountpoint}}')/default.json"`.
  The gate checks the default profile, `default.json`, and the legacy
  `/etc/netbird/config.json` and `/etc/wiretrustee/config.json` in the
  container if they exist.
- `a stored NetBird profile (<file>) uses a WireGuard interface other than
  <name> (WgIface)`. The peer's profile keeps the interface name it enrolled
  with (`wt0` if it names none), and it no longer matches `OVERLAY_IF`,
  usually because `OVERLAY_IF` changed after enrollment. Either set
  `OVERLAY_IF` back, or change the stored name to match, the same way as for
  Rosenpass above, for example from `wt0` to `mesh0`:

  ```sh
  docker compose run --rm --no-deps --entrypoint sed netbird -i \
    's/"WgIface": "wt0"/"WgIface": "mesh0"/' /var/lib/netbird/default.json
  ```

  NetBird writes the field whenever it loads a profile, so one without it
  is rare; it means `wt0`, so keep `OVERLAY_IF=wt0` for such a profile.
- `OVERLAY_CIDR is not set for NetBird; compose.yaml passes the routing
  settings to it (docs/operations.md#upgrades)`, or `the routing contract
  definitions are missing (/usr/local/bin/molebridge-contract-rules);
  compose.yaml mounts routing/contract-rules there`. The `netbird` service
  comes from a Compose file or unit older than the routing image it runs
  with. Use the current `compose.yaml`, or add what it passes to `netbird`
  to your own; see [upgrades](operations.md#upgrades). A setting the exit
  itself would refuse, such as an invalid `OVERLAY_CIDR`, is refused here
  with the same message, and `GUARD_GRACE must be 5..30 seconds` when
  [`GUARD_GRACE`](configuration.md#repair-and-gate-timing) is out of range.
- `cannot read the stored NetBird profile <file>`, `the stored NetBird
  profile <file> is not a valid JSON object`, `the stored NetBird profile
  <file> repeats WgIface or RosenpassEnabled` or `the stored NetBird profile
  <file> has a field name outside printable ASCII`, and the same for the
  active profile state (`cannot read the active NetBird profile state
  <file>`, `... is not a valid JSON object`). NetBird doesn't write files
  like these; the file was edited by hand or damaged. Fix the JSON or the
  repeated field, keeping one `WgIface` and at most one `RosenpassEnabled`
  set to `false`.

`python3 tools/molebridge.py doctor` reports the Compose settings as `The
netbird service sets <name>; Molebridge needs kernel WireGuard, NetBird's
kernel firewall and no Rosenpass (docs/troubleshooting.md).`, `The netbird
service sets <name>; Molebridge supports only NetBird's default profile
(docs/troubleshooting.md).`, `The netbird service sets <name>; Molebridge
supports only NetBird's daemon mode (docs/troubleshooting.md).`, `The
netbird service sets WT_INTERFACE_NAME to another interface than
NB_INTERFACE_NAME (docs/troubleshooting.md).` or `The netbird service must set
NB_DISABLE_USERSPACE_ROUTING=true (compose.yaml).` It then runs the gate's
own checks in the running `netbird` container and shows the gate's refusal
line, if any.

With the [gluetun backend](architecture.md#gluetun-backend) the gate also
refuses `<name> is set; the gluetun backend needs NetBird to mark its control
traffic`, for `NB_USE_LEGACY_ROUTING`, `NB_SKIP_SOCKET_MARK` or
`NB_DISABLE_CUSTOM_ROUTING`, and `NB_FWMARK_BASE must equal CONTROL_MARK
(<mark>)`. Remove the variable, or set the mark only through `CONTROL_MARK`
in `.env`. It also refuses settings the guard would refuse (`OVERLAY_CIDR`,
`EXIT_IF`, the tables and `CONTROL_MARK`, with the guard's own message),
`the guard's rule definitions are missing (<file>)` when
`routing/contract-rules` isn't mounted (a deployment that still mounts
`routing/gluetun-rules` at `/usr/local/bin/molebridge-gluetun-rules` keeps
working until 0.7.0), `FWMARK_GRACE must be 5..30 seconds`,
and `cannot read the boot clock (/proc/uptime and the boot id)`.

**NetBird exits with `NetBird gate: stopping NetBird: <reason> (see
docs/troubleshooting.md)`.** With the default backend, the gate stopped
NetBird because the exit's [owner
record](architecture.md#the-owner-record) or its guards went. The container
exits with status 1 and its restart policy starts it again; the gate then
waits as at first start. The reasons:

- `the owner record expired (written <n> s ago)`: the `wireguard`
  container's entrypoint stopped writing it, because the container stopped,
  was paused or hung. Check `docker compose ps wireguard` and its log. If
  it runs again in the same namespace, NetBird comes back once the record is
  fresh; if `wireguard` was recreated, run recovery.
- `the owner record is from another network namespace`: `wireguard` was
  restarted or recreated into a new namespace, and `netbird` is still in the
  old one. Run `python3 tools/molebridge.py recover`, or the Podman commands
  in [operations](operations.md#rootless-podman).
- `no valid owner record at /run/molebridge/exit-owner`: the file is
  missing or isn't in the expected form, usually because `netbird` and
  `wireguard` don't share the `exit-run` volume. Use the current
  `compose.yaml`.
- `the owner record is from another boot`, `the owner record is from the
  future` or `the owner record went backwards`: these shouldn't happen on a
  running host; run recovery.
- `routing guards not intact for 30 seconds: <what>`: rules or the exit
  table stayed wrong, and the exit's repair pass didn't put them right. Look
  for `10-exit-routing:` lines in the `wireguard` log, such as
  `10-exit-routing: IPv4 routing still differs after repair; the temporary
  guard stays if it is in`.
- `cannot read the boot clock`, `cannot read this network namespace` or
  `the boot clock changed identity`: these shouldn't happen; run recovery.

**gluetun backend: NetBird exits with `NetBird gate: stopping NetBird:
<reason> (see docs/troubleshooting.md)`.** The gate stopped NetBird because
its control traffic could have used the provider tunnel:

- `NetBird logged that it runs without advanced routing, so its control
  traffic would be unmarked`: NetBird's start-up check of socket marks and
  `ip rule` support failed. Check NetBird's log just before this line and
  that the `netbird` service still has `NET_ADMIN`.
- `wt0 has not carried the control mark 0x1bd00 for 30 seconds (last
  reported: <value>)`: `absent` or `nothing` means the overlay interface
  didn't come up, or the `guard` container isn't running (it reports the
  mark; check `docker compose ps guard` and its log); `off` or another mark
  means NetBird runs without its control mark.
- `routing guards not intact for 30 seconds: <what>`: the guard's rules
  disappeared and weren't restored; check the `guard` log.

- `the boot clock changed identity`: the kernel's boot id changed under a
  running gate, which shouldn't happen; restart the stack.

**gluetun backend: NetBird's log stops at `NetBird gate: gluetun backend:
waiting for the whole guard (rules 1-97 with control mark 0x1bd00, exit
table 51821, host table 51822)`.** The guard isn't ready, or something else
changed rules at priorities 0–97 or the exit or host table. The guard's log
ends with `10-exit-routing: not ready:` and what is missing; `no IPv4
default route through eth0 in the main table` means `HOST_IF` doesn't name
the namespace's interface toward the host
([configuration](configuration.md#gluetun-backend)). The gate and the guard
check the same definitions, so if the guard reports every rule in place
and the gate still waits, check that the NetBird container has the same
`OVERLAY_CIDR`, `OVERLAY6_CIDR`, `EXIT_IF`, `EXIT_TABLE`, `HOST_IF`,
`HOST_TABLE` and `CONTROL_MARK` as the guard (`compose.gluetun.yaml` passes
them).

**gluetun backend: the guard's log says `not ready: ... eth0 is not in this
namespace` or `no IPv4 default route through eth0 in the main table`.**
The guard's namespace lost its host interface or its default route,
usually because the engine restarted `gluetun` into a new namespace and
left `guard`, `netbird` and `applier` in the old one. NetBird's gate keeps
waiting and says so every 30 seconds. Recreate the stack with `python3
tools/molebridge.py recover`. `kill switch (rule 104) held until host table
51822 has eth0's routes` is normal for a moment at start.

**gluetun backend: gluetun stops at start with `the hostname specified is
not valid`** (or the country or city). `GLUETUN_SERVER_*` names a server
that isn't in the data gluetun has when it starts, which on a fresh install
is its built-in list. Set only `GLUETUN_SERVER_COUNTRIES`, to your own
country, and choose the server in the panel once the list has been
refreshed.

**gluetun backend: on a first start gluetun restarts its VPN several times
before it connects.** Its built-in server list is old, and it picked servers
that no longer answer; its health check restarts the VPN with another one.
Setting `GLUETUN_SERVER_COUNTRIES` to your own country makes a working
server likelier. The applier waits for a working tunnel before asking
gluetun to refresh the list.

**gluetun backend: the panel lists old servers, or Diagnostics says
`server list update failed`.** The applier asks gluetun to refresh its
server list once at start when the data is old, after gluetun's tunnel has a
fresh handshake. A failure means gluetun's updater couldn't fetch the provider's list
through the tunnel; gluetun's log says why. gluetun tries again every
`GLUETUN_UPDATER_PERIOD`, and recreating the applier starts another
refresh. A role file written before the applier could refresh the list
lacks the updater routes: run `python3 tools/molebridge.py gluetun-auth
--rotate`, then run `python3 tools/molebridge.py recover`.

**gluetun backend: gluetun exits with `molebridge: not starting gluetun:
...`.** The role-file check refused `secrets/gluetun/auth.toml`: it is
missing, edited, or written by an older version with fewer routes. Run
`python3 tools/molebridge.py gluetun-auth --rotate`, then run `python3 tools/molebridge.py recover`. The
check never prints the file, which holds the API key.

**gluetun backend: the panel says "gluetun did not accept the server
selection; choose a server again to retry."** The applier's request to gluetun's control server failed:
gluetun isn't running, the API key in `secrets/gluetun/api_key` doesn't
match the one in `secrets/gluetun/auth.toml` (run `python3
tools/molebridge.py gluetun-auth --rotate`, then run `python3 tools/molebridge.py recover`), or gluetun refused
the server. `python3 tools/molebridge.py
doctor` checks that the control server answers with the key.

## The panel

**`421 unknown host; publish the panel under PANEL_PUBLIC_HOSTS`.** The
request's `Host` isn't loopback or listed in `PANEL_PUBLIC_HOSTS`. Add the
public hostname. If your proxy rewrites `Host` when it connects upstream (to
`host.docker.internal:8095`, for example), add that name and port too.

**`403 origin is not a published panel host` or `invalid or missing csrf
token` when switching.** The browser's `Origin` must be a listed host, and
the CSRF cookie must reach the panel. Check that the proxy passes cookies and
doesn't strip `Origin`, and that you opened the panel by the name listed in
`PANEL_PUBLIC_HOSTS`.

**"No fresh trusted relay catalogue; selections are unavailable."** The panel
can't read a catalogue less than 24 hours old. Either the applier hasn't
fetched one yet (give it a minute after first start), the provider's API is
unreachable from the exit, or the panel can't read `state/applier/`. The last
one usually means `PANEL_USER` is wrong: it must be your host user's
`uid:gid` on Docker and `0:0` on rootless Podman.

**The dashboard frame is blank.** Most often your proxy's session for the
panel's hostname has expired: open the panel directly once to sign in. (With
the panel's own [sign-in](#sign-in) the frame shows a "Signed out" page with a
link instead.) If
that doesn't help, check that `PANEL_FRAME_ANCESTORS` lists the dashboard's origin, and that the
dashboard and the panel are on the same site, so the browser sends the
proxy's cookie inside the frame.

**The status says "status stale" or "awaiting status".** The panel has no
usable result from the applier: none in the last 150 seconds, or one that is
malformed or dated in the future. Check that the `applier` container is
running and healthy, and that the host's clock is right.

## Sign-in

This applies only when `PANEL_OIDC_ISSUER` is set; see
[panel access](access.md#sign-in-with-openid-connect). Sign-in has had one live
pass, with one provider, so most of this list comes from the code rather than
from failures seen in use.

**The panel stops at start.** The last line of the container's log is the
setting it refused, with one of these messages (`<name>` is the setting):

- `<name> is set but PANEL_OIDC_ISSUER is not; set both or neither`, for
  `PANEL_OIDC_CLIENT_ID`, `PANEL_ACCESS`, `PANEL_ADMIN_GROUPS` or
  `PANEL_PUBLIC_URL`
- `PANEL_OIDC_ISSUER must be an https URL (http only for a loopback test issuer)`
- `PANEL_OIDC_CLIENT_ID is required with PANEL_OIDC_ISSUER`
- `PANEL_OIDC_CLIENT_SECRET_FILE cannot be read: <reason>` and
  `PANEL_OIDC_CLIENT_SECRET_FILE is empty`
- `PANEL_PUBLIC_URL must be the https origin people open, such as https://exit.example.net`
- `PANEL_OIDC_SCOPES must include openid`
- `PANEL_ADMIN_GROUPS: '<group>' is not a valid group name`
- `PANEL_ACCESS: entries are group=exit, with no spaces, commas or = in the group, in '<entry>'`
- `PANEL_ACCESS: '<exit>' is not an exit in PANEL_EXITS, in '<entry>'`. A
  single-exit panel has no exits to name, so use `PANEL_ADMIN_GROUPS` there.
- `With PANEL_OIDC_ISSUER set, PANEL_ADMIN_GROUPS or PANEL_ACCESS must name at least one group`
- `PANEL_SESSION_TTL must be a whole number of seconds` and
  `PANEL_SESSION_TTL must be between 300 and 604800 seconds`

**"Sign-in unavailable".** The page says "The identity provider could not be
reached. Try again in a minute." The panel couldn't read the provider's
discovery document. The log has a line `sign-in unavailable: <reason>`, such as
`discovery: the issuer could not be reached`, `discovery: the issuer answered
HTTP <code>`, or `discovery: the issuer in the discovery document does not
match PANEL_OIDC_ISSUER`. Check that the panel container can open an HTTPS
connection to the issuer and trusts its certificate, and that
`PANEL_OIDC_ISSUER` is written exactly as the discovery document's `issuer`.

**"Sign-in failed".** The page says "The sign-in could not be completed. Start
it again from the panel." The log has `sign-in failed: <reason>`. Common ones:

- `callback: this browser did not start a sign-in, or it expired`. The browser
  came back without a valid `__Host-molebridge_login` cookie: the sign-in took
  more than 10 minutes, the panel restarted meanwhile, the same return link
  was opened twice, cookies are blocked, or
  the browser began at a different address from `PANEL_PUBLIC_URL`. Start again
  from `PANEL_PUBLIC_URL`.
- `callback: the sign-in state does not match`. The return belongs to a
  different sign-in than the one this browser started last, for example from a
  second tab. Start again.
- `token: the issuer could not be reached`. The provider answered discovery but
  not the token request, so this shows as "Sign-in failed", not "Sign-in
  unavailable". Check the panel container's route to the issuer.
- `token: the issuer answered HTTP <code>`. The provider refused the code. Check
  that the redirect URL registered there is `PANEL_PUBLIC_URL` plus
  `/auth/callback`, exactly, and that the client is a public client (or that
  `PANEL_OIDC_CLIENT_SECRET_FILE` holds its secret).
- `token: the ID token was issued by another issuer` and `token: the ID token is
  for another client`. `PANEL_OIDC_ISSUER` or `PANEL_OIDC_CLIENT_ID` doesn't
  match what the provider put in the token.
- `token: the issuer sent no groups claim` or `userinfo: the issuer sent no
  groups claim` (with `groups` replaced by `PANEL_OIDC_GROUPS_CLAIM`). The
  provider isn't sending groups. Check that `PANEL_OIDC_SCOPES` includes the
  scope that adds them and that the client is allowed to use it.

**"Not allowed".** The page says "This account is not allowed to use this
panel." The log has `sign-in failed: access: this account is not in a group
that may use this panel`: the person's groups match neither
`PANEL_ADMIN_GROUPS` nor `PANEL_ACCESS`. Compare the group names exactly.
The same page appears, with `sign-in failed: access: the identity provider
refused the sign-in`, when the provider itself turned the person away.

**Someone changed groups and still sees the old exits.** A session keeps the
groups it was created with until it ends, at most `PANEL_SESSION_TTL` seconds
after sign-in. To apply a change now, restart the panel, which signs everyone
out, or have the person sign out and in.

**The dashboard shows "Signed out".** The panel session ended, or was never
started in this browser. Choose **Sign in**, which opens in a new tab, then
reload the dashboard.

## Switching

**"Tunnel handshake is missing or stale; check the account and
connectivity."** The provider isn't answering the tunnel. Possible causes:

- The Mullvad account ran out of time, or the device was removed from the
  account. Check the account page.
- The PIA or NordVPN subscription lapsed.
- Outbound UDP to the provider is blocked. Check the host's firewall and
  [the ports it needs](prerequisites.md#network).
- The selected server is down. If another server works, that's the cause.

**"Peer update failed; choose a server again to retry."** The applier couldn't
apply the server. With PIA, a rejected login or registration shows this way
too: check the files in `secrets/pia/` (one value per file, no extra
whitespace), then select the region again. If one PIA region keeps failing
while others work, the problem is on PIA's side.

**"Switch verification timed out; choose a server again to retry."** The peer
changed, but the handshake, the routing checks or the egress check didn't all
pass in time: 60 seconds with the default backend, 90 with gluetun. Try
again, or try another server.

These two messages, and "Routing changed during the switch; choose a server
again after recovery." and gluetun's "gluetun did not accept the server
selection; choose a server again to retry.", clear by themselves when a
later check finds the requested server live and passing every check; the
applier logs
`applier: the requested server passed every check; clearing the earlier
failure`. With PIA that happens when an automatic re-registration was
refused but the tunnel came back on the existing registration. While
another server is live, or a check fails, the message stays until you
choose again.

**"No PIA region is registered yet; choose one in the panel."** It's a fresh
PIA install. Pick a region.

**"No NordVPN server is selected yet; choose one in the panel."** It's a
fresh NordVPN install, or its tunnel was recreated before any selection.
Pick a server.

**"Tunnel egress is not confirmed as NordVPN."** NordVPN's insights check
said the traffic wasn't protected. If the egress address in Diagnostics is
the selected server's own address, NordVPN may be serving an answer it cached
before that address was a VPN exit for you; it caches for up to an hour, and
the applier asks again for up to a minute before reporting this. Try again
later, or pick another server. See
[providers](providers.md#how-nordvpn-differs).

**"Tunnel inspection or egress check failed."** The applier couldn't read
the tunnel's state, or the egress check got no usable answer: a timeout, a
refused connection, an HTTP error or a malformed reply. Usually that answer
was missing twice, 10 seconds apart, and the log shows `egress check got no
answer twice`; a first attempt that took over 15 seconds, or one during a
switch, is not asked again (see [status
reporting](architecture.md#status-reporting) for when the applier asks once
more). An occasional one usually means the provider's check service, or the
path to it through the tunnel, dropped a connection; the next check a minute
later normally passes. If it persists, compare the handshake age in
Diagnostics.

**"Tunnel egress did not pass the tunnel checks."** Only for a provider
without its own egress check, which today means FastestVPN, IVPN, Surfshark
and Windscribe through the gluetun backend: the IP echo services
disagreed, or answered with the host's own address or one the server list
doesn't name. See [status reporting](architecture.md#status-reporting).

**"Waiting for a fresh trusted relay catalogue; request will retry
automatically."** The selection is saved and will be applied once the
applier has a current catalogue. If this persists, the provider's API is
unreachable from the exit.

**"Routing protection is incomplete; run the recovery helper."** A routing
rule or fallback route is missing, usually after part of the stack was
recreated. Run recovery (below). The kernel's priority-0 `lookup local` rule
reappearing counts too. With the default backend, so does an owner record
that isn't live: `wireguard` stopped, paused or hung, or recreated into
another namespace than the applier's. If `wireguard` comes back in the same
namespace, the next check clears it; otherwise run recovery.

**"NetBird is not running kernel WireGuard with its kernel firewall on the
overlay interface; see the troubleshooting guide."** A selection waits with
"Waiting for NetBird to run kernel WireGuard with its kernel firewall; request
will retry automatically.", and the applier's `--doctor` prints `FAIL NetBird
kernel WireGuard and kernel firewall`. The exit is never reported as
connected in this state. The applier found one of these:

- **The overlay interface isn't a kernel WireGuard link.** NetBird found no
  usable WireGuard kernel module and fell back to userspace WireGuard. Inside
  the namespace, `ip -d link show wt0` shows `wireguard` on its details line
  when it's right. Load the module on the host as in
  [requirements](prerequisites.md#host), then run recovery.
- **NetBird's kernel firewall isn't visible.** `nft list tables` inside the
  namespace should show `table ip netbird` (NetBird's nftables backend) or
  `table ip filter` holding chains named `NETBIRD-…` (its iptables backend).
  The check looks for those names, so a renamed table (`NB_NFTABLES_TABLE`)
  fails it, and so would iptables rules in the legacy backend, which `nft`
  can't see. The pinned NetBird image is Alpine-based, and Alpine's
  `iptables` uses the nftables backend by default; the recorded passes saw
  NetBird's iptables tables through `nft` and the check passed, but not
  every firewall backend or override has been tried.

## Clients

**Clients get no connectivity at all after you restarted or recreated
`wireguard` alone.** `netbird` and `applier` are still attached to the old
network namespace. NetBird's gate stops NetBird there with `the owner record
is from another network namespace`, and the applier reports routing
protection as incomplete. Recreate all four containers together:
`python3 tools/molebridge.py recover` on Docker, or the Podman commands in
[operations](operations.md#rootless-podman).

**Everything works, but slowly: clients are relayed.** Run `netbird status
-d` inside the `netbird` container and look at `Connection type`. `Relayed`
has four common causes:

- **A phone with NetBird's "Force relay connection" setting on.** It's on by
  default on mobile; turn it off under Settings → Advanced.
- **The exit interface missing from the peer's ICE blacklist.** The log shows
  `ICE retries exhausted`. Doctor checks for this; the fix is in
  [setup](setup.md#5-keep-ice-off-the-tunnel-interface).
- **The exit on a private container bridge** with no reachable candidate. This
  is normal for rootless setups; see
  [exits on a private container network](operations.md#exits-on-a-private-container-network).
- **Rootless Podman with pasta, where you published the NetBird WireGuard
  port.** Remote devices are always relayed, while devices on the same LAN
  still connect directly through `--external-ip-map`, which hides the fault.
  The published port holds the host port, so pasta can't bind it for NetBird's
  outgoing STUN. The passt or pasta log shows `Dropping datagram` for port
  3478, and the NetBird log shows `wait for gathering timed out` every 5
  minutes. Observed on Debian with passt 0.0~git20261002 and Podman 5.8.6;
  Docker is untested. Remove the published port and forward it through a pasta
  network instead, as described in
  [exits on a private container network](operations.md#exits-on-a-private-container-network).

**The exit is healthy, but a device loads nothing on a restrictive network
(hotel Wi-Fi).** The panel and doctor report the exit as fine. On the exit, the device sits at Connecting
and its handshakes time out. On the device, the relay connection drops every
few seconds to minutes.

The cause is NetBird's relay transport, not Molebridge. The NetBird client
prefers QUIC to reach the relay. Some networks break long-lived UDP flows:
QUIC connects, then dies. The client falls back to WebSocket only when QUIC
cannot connect or a datagram is too large. This is NetBird client behavior and affects any NetBird
setup whose relay offers QUIC.

On the device, with a NetBird desktop client 0.79.0 or later, tell the client
to prefer WebSocket:

```sh
sudo netbird service reconfigure --service-env NB_RELAY_TRANSPORT=prefer-ws
```

The setting survives restarts and upgrades. To undo it:

```sh
sudo netbird service reconfigure --service-env ""
```

Run `netbird status -d` on the device to confirm. The relay line ends with
`via ws` once the client uses WebSocket. `NB_RELAY_TRANSPORT` accepts `auto`
(the default), `quic`, `ws`, `prefer-quic` and `prefer-ws`. This was confirmed
on macOS; other platforms are untested.

**A video call or download stalls after a few seconds, then sometimes
recovers.** One possible cause is path MTU: oversized replies whose ICMP error
never reaches the sender. Namespace step 6 in
[verification](verification.md#inside-the-namespace) checks for it; the ICMP
source sysctl and rule 94 must both be in place.

**The client shows its real IPv6 address.** Its IPv6 is bypassing the exit.
Check that the account has IPv6 overlay and that the exit has a `::/0` route.
NetBird is meant to block IPv6 on a client when it can't carry it, so if both
are missing and the client still leaks, disable IPv6 on that client and
check its NetBird version. See [verification](verification.md#from-a-client).

**Names don't resolve while the exit is selected.** Molebridge doesn't handle
DNS. The client keeps its own resolver. If that resolver is a private address
the client can only reach through the exit (for example, a server on the exit
host's LAN), the exit sends it into the tunnel, where it goes nowhere. Use a
resolver the client can reach directly, or NetBird's DNS settings.

**A device can't reach addresses on the exit host's LAN.** That's by design.
Forwarded traffic goes only into the tunnel.
