# Troubleshooting

Messages are quoted as the panel, `result.json` or the container logs print
them. Read the exit's log with `docker compose logs exit` (`podman logs
molebridge-exit` on Podman); its own lines start `molebridge-exit: `, NetBird's
output starts `netbird: `. The exit's lines carry no time of their own,
because the container engine records one for each line: add `-t` to see it
(`docker compose logs -t exit`, `podman logs -t molebridge-exit`; on Kubernetes
`kubectl logs --timestamps`). Use it whenever the order or spacing of events
matters, such as how long a switch took or how often a line repeats. The exit
never waits for the log: when the log
driver stops reading, it drops lines rather than stall, and once the driver
reads again it says how many with `molebridge-exit: log: <n> lines were
dropped while the log sink was slow`. For a check of a running exit, use
`docker compose exec exit molebridge status`. If the exit refuses to start, run
`docker compose run --rm --no-deps exit check-config`, which validates what the
exit validates at start and changes nothing.

Don't paste raw diagnostics into issues. They contain addresses, peer names
and sometimes keys. Never share the output of `wg showconf` or `wg show ...
dump`.

## Startup

**The exit never gets healthy, and its log repeats `molebridge-exit: tunnel
bring-up failed (<reason>); retrying in <n> s`.** The worker could not create or
configure the tunnel interface. The reason is the failing step and the kernel's
error. The worker keeps retrying, after 2 seconds and then up to every 60, and
the exit stays unhealthy; forwarded traffic is dropped meanwhile. On rootless
Podman the usual cause is the WireGuard module: a rootless container can't load
kernel modules, so load `wireguard` on the host and make it persist, as shown in
[requirements](prerequisites.md#rootless-podman), then recreate the exit. To
rule out the config and settings, run `check-config` as above.

**The exit stays unhealthy, and its log says `molebridge-exit: not operational:
<reason>`.** The worker writes the health check's heartbeat only while the exit is
operational, and says why it isn't, at most once a minute for each reason:

- `the NetBird profile check refused`: the stored profile lacks the tunnel interface
  in its blacklist, or isn't right; see [below](#netbirds-settings-and-profile).
- `NetBird has not been started yet`: the contract isn't verified yet, or NetBird is
  still starting.
- `the routing contract is not verified`: see `not ready:` further down. A native
  sidecar says it too when its tunnel interface is down.
- `the sidecar firewall is not as installed`: a native sidecar's firewall differs from
  what the exit installed; see [a native sidecar](#a-native-sidecar).
- `NetBird is not running`.
- `the pipeline reports the namespace is not intact (<what>)`. `<what>` is one or more
  of, separated by `;`: `no readable status record`, `the last record is not a completed
  check`, `not exactly one tunnel peer` (a gluetun sidecar), `the tunnel interface has no
  WireGuard device`, `the tunnel addresses cannot be read`, `IPv4 routing is not intact`,
  `IPv6 routing is not intact`, `icmp_errors_use_inbound_ifaddr is not 1`, `the overlay
  interface is not kernel WireGuard`, `NetBird's kernel firewall is not present`,
  `the sidecar firewall is not as installed` (a native sidecar) and `the
  record may be stale`. With PIA, before you choose a region, expect `IPv4 routing is not
  intact`: a fresh PIA tunnel has no address yet.

The unhealthy exit keeps trying; none of these stops it.

**`molebridge-exit: <setting> ...`, and the container exits.** The exit checks
its settings and the tunnel config before touching anything, and names what it
rejected. Fix `.env`, your Compose override or the tunnel config and start
again. The refusals, by setting:

| Message | Cause |
|---|---|
| `EXIT_KIND must be overlay or sidecar` | A setting other than `overlay` or `sidecar`; the Compose files set it |
| `TUNNEL_BACKEND must be native or gluetun` | The Compose files set it |
| `PROVIDER must be mullvad, pia or nordvpn` | An unknown provider on the native backend, including a native sidecar, or a `gluetun-*` provider with it |
| `PROVIDER must be one of: <ids>` | An unknown provider on the gluetun backend |
| `TUNNEL_BACKEND=gluetun needs a gluetun provider (PROVIDER=gluetun-<name>)` | A native provider with the gluetun backend |
| `invalid interface name`, `overlay and exit interfaces must differ` | `OVERLAY_IF` or `EXIT_IF`: up to 15 characters, letters, digits and underscore first, then also `.` and `-`. A native sidecar has no `OVERLAY_IF` and reads only the first message, for `EXIT_IF` |
| `with gluetun, EXIT_IF may hold only letters, digits and underscores` | gluetun's own rule for `VPN_INTERFACE` |
| `EXIT_TABLE must be numeric`, `EXIT_TABLE must be canonical decimal`, `EXIT_TABLE must be 256..2147483647` | The same three for `HOST_TABLE`. A native sidecar has no `HOST_TABLE` |
| `HOST_TABLE and EXIT_TABLE must differ`, `tables 51820 (gluetun) and 7120 (NetBird) are taken` | gluetun backend |
| `OVERLAY_CIDR is for the overlay kind; a sidecar has no overlay`, and the same for `OVERLAY6_CIDR` and `OVERLAY_IF` | A native sidecar with one of the three set |
| `OVERLAY_CIDR must be an IPv4 CIDR`, `OVERLAY_CIDR must use the network address`, `invalid IPv4 prefix`, `IPv4 default routes and leading zeroes are forbidden`, `IPv4 address needs four octets`, `invalid IPv4 octet`, `IPv4 leading zeroes are forbidden` | `OVERLAY_CIDR` is required and must be a network address such as `192.0.2.0/24` |
| `OVERLAY6_CIDR must be an IPv6 CIDR`, `OVERLAY6_CIDR must use the network address`, `invalid IPv6 prefix`, `invalid OVERLAY6_CIDR` | The same for the IPv6 range |
| `invalid HOST_IF`, `HOST_IF must name the namespace's host interface, not lo, the overlay or the tunnel` | gluetun backend and native sidecar |
| `CONTROL_MARK must be lowercase hexadecimal like 0x1bd00`, `... , low byte zero` | gluetun backend and native sidecar |
| `CONTROL_MARK and EXIT_TABLE must differ` | Native sidecar |
| `SIDECAR_LAN_CIDRS must have at most 16 entries`, `SIDECAR_LAN_CIDRS: empty entry is not a network prefix`, `SIDECAR_LAN_CIDRS: <entry> is not a network prefix`, `SIDECAR_LAN_CIDRS: <entry> is a default route`, `SIDECAR_LAN_CIDRS: <entry> must use the network address`, `SIDECAR_LAN_CIDRS: <entry> is duplicated` | Native sidecar; see [a native sidecar](#a-native-sidecar) |
| `SIDECAR_HOST_RESOLVERS must have at most 3 entries`, `SIDECAR_HOST_RESOLVERS: "<entry>" is not a resolver address`, `SIDECAR_HOST_RESOLVERS: <entry> is duplicated` | Native sidecar: bare IP addresses only, at most three ([DNS](native-sidecar.md#dns)) |
| `ROUTING_RECONCILE_INTERVAL must be 2..60 seconds` | Whole seconds |
| `GUARD_GRACE must be 5..30 seconds` | Whole seconds, canonical decimal; the lease's length |
| `NetBird has no stored profile yet, so NB_EXTRA_IFACE_BLACKLIST must name the tunnel interface <if> (compose.yaml sets it to EXIT_IF); the new profile's interface blacklist is built from it` | A first enrollment with `NB_EXTRA_IFACE_BLACKLIST` removed or overridden to something that doesn't cover `EXIT_IF` |
| `NB_EXTRA_IFACE_BLACKLIST is not a list NetBird can read (comma-separated, with CSV quoting); NetBird would ignore it`, `... has an empty entry, which NetBird reads as every interface` | The same setting, malformed (`WT_EXTRA_IFACE_BLACKLIST` is read too) |
| `NB_INTERFACE_NAME (<a>) must equal OVERLAY_IF (<b>), the interface the routing contract guards` | Both are set from `OVERLAY_IF` in the Compose files |

If the log ends with `molebridge-exit: the routing contract could not be
installed; no tunnel was started`, the line before it says why: `the routing
contract could not be installed: <family problems> (<cause>); the temporary guard
(priority 80) stays`, where a problem is a family and a part (`IPv4 rules`, `IPv4 exit`, with
gluetun `IPv4 host` or `IPv4 nodefault`, and `unprotected` for a tunnel address
without its return-path rules; the same for IPv6). No tunnel exists then, and the temporary priority-80 rules
already added stay in place, so nothing is forwarded. A native sidecar has no
temporary guard: its line is `the routing contract could not be installed: <cause>`,
and the firewall, installed first, holds the applications meanwhile.

**`molebridge-exit: the tunnel config /config/wg_confs/mullvad.conf is not
supported: <reason>; regenerate it with prepare-config (docs/setup.md)`.** The
config has something the tools don't write: a `DNS`, `PreUp`, `PostDown`,
`SaveConfig` or `FwMark` line, a `Table` other than `off`, hooks for another
table, a second address in a family, a field name in another case such as
`address` for `Address`, and so on. `<reason>` names the line number (and the
field, when it is one Molebridge accepts), never the line's text; [the tunnel
config](configuration.md#the-tunnel-config) lists every reason and what is
accepted. Regenerate the config with the command the message names (for PIA,
and for NordVPN with `nordvpn-key`, move the old file aside first: neither
overwrites one), or, for
hooks on another table, write them exactly as
[configuration](configuration.md#the-tunnel-config) shows. The message ends
`regenerate it with prepare-config --pia (docs/setup.md)` for PIA and
`regenerate it with prepare-config --nordvpn (docs/setup.md)` for NordVPN. When the file
itself is the problem, the line reads `the tunnel config <path> is missing;
regenerate it with …`, or says that it `is not a regular file` (a symlink, for
example), `is larger than 4 KiB` or `has NUL or carriage-return bytes` (Windows
line endings). A config for another interface name is ignored, with
`molebridge-exit: warning: <n> other .conf file(s) in /config/wg_confs are
ignored; only mullvad.conf is used`.

**`molebridge-exit: the tunnel config /config/wg_confs/mullvad.conf can't be
read (on Docker the exit container needs DAC_OVERRIDE to read a mode-0600 tunnel
config, and the Compose files grant it; see docs/setup.md)`.**
Container root can't read your mode-0600 file. The Compose files grant
`DAC_OVERRIDE`, which is what lets container root read it, and an override that
drops `DAC_OVERRIDE` breaks the start. When the container can't search
`tunnel/wg_confs` itself, the line reads `molebridge-exit: the tunnel config
directory /config/wg_confs can't be searched (on Docker the exit container needs
DAC_OVERRIDE to read a mode-0600 tunnel config, and the Compose files grant it;
see docs/setup.md)`.
A container root remapped to another host ID needs read access of its own; see
[setup](setup.md#3-create-the-tunnel-config).

**`molebridge-exit: the state directory /state/applier is missing; mount the
state volume (docs/setup.md)`, or `... can't be read`, `... is missing and can't
be created`, `... is not writable`, `... is not a directory`.** The exit publishes
into `state/applier`. The first is what `check-config` says when the directory
doesn't exist; at a real start the exit creates a missing one and probes it with a
temporary file. The others end `(on Docker the container needs DAC_OVERRIDE; see
docs/setup.md)`: on rootful Docker container root is not the user that owns
`state/`, and `DAC_OVERRIDE` is what lets it write there. Create `state/applier`
as your own user (the `mkdir` in [setup](setup.md#2-configure)); Compose would
create a missing bind directory root-owned.

**Stopping the exit logs `molebridge-exit: cleanup incomplete: <what remains>
still there; the routing guards stay in place` and the container exits with
status 1.** Within the 13 seconds it allows itself, the supervisor couldn't end
the worker (`the worker`) or NetBird (`NetBird`), or the cleanup child couldn't
remove an interface. `<what remains>` then also names the cleanup: `the cleanup
(exit 1)` (its own line before it, `molebridge-exit: cleanup: <reason>`, says
why), `the cleanup (it ran past its time)`, `the cleanup (could not start)`,
`the cleanup (it could not be started in time)` or `the cleanup (not run while a
process of this exit survives)`. A complete stop ends with `molebridge-exit:
stopped (<reason>, exit <n>); the routing guards stay in place` and, after a
failed attempt to write the status record, `molebridge-exit: the status record
could not be written in time (is the state volume stuck?)`. The rules and the
fallback stay in the namespace, so forwarded traffic still can't leave by another
route. Recreate the exit ([recovery](operations.md#recovery)).

**The log says `molebridge-exit: cannot write /state/applier/result.json:
<reason>`.** The supervisor publishes the status record and couldn't write it
(at most one line a minute). Readers then see the last record go stale after 150
seconds. The usual cause is a `state/applier` mount that the container can't
write; see the state directory entry above.

**NetBird logs `failed to create ipv4 raw socket: operation not permitted`.**
The exit needs `NET_RAW`. Docker grants it by default; Podman does not. The
Compose files add it, so this means a modified Compose file.

### Why the exit stopped itself

A healthy exit does not restart. If the container restarts, the line before it
in the log, `molebridge-exit: stopping (<reason>)`, says why, and the exit status
is 1 for all of these:

- **`stopping (lease lapsed)`.** The worker stopped renewing its lease for
  `GUARD_GRACE` seconds, so the supervisor stopped NetBird and the worker and
  restarted the container ([the lease](architecture.md#the-lease)). The worker
  does not renew while a loop it supervises is late, and says so:
  `molebridge-exit: a supervised loop is late; no lease renewal is sent` (at most
  every 10 seconds). Causes are a stalled host, a host that was suspended for
  longer than `GUARD_GRACE` ([host suspend](operations.md#host-suspend)), a
  container starved of CPU (a quota that throttles it for many seconds), a kernel request that did not
  finish in 10 seconds, or a hang. A refusal on the supervisor's side is
  `molebridge-exit: renewal refused: <reason>`, which a healthy exit never logs.
  If the lease had already expired when a message from the worker arrived, the
  line `molebridge-exit: the lease expired before the worker's message was
  processed` comes first. The supervisor writes a failure record before it
  stops, so the panel and `/readyz` show `failed`, "exit owner stopped
  responding", until the restarted exit publishes again.
- **`stopping (worker exited)`**, after `molebridge-exit: the worker exited
  (status <n>)`. The worker's own last lines say why: a refusal (the settings
  above, the control server, the API key), a crash, or, with gluetun, one of the
  two monitors that end the worker when NetBird's control traffic could go out
  unmarked (see [gluetun backend](#gluetun-backend) below).
- **`stopping (netbird exited)`**, after `molebridge-exit: NetBird could not be
  started: <detail>` or `molebridge-exit: NetBird stopped unexpectedly: <detail>`.
  NetBird's own output, with the prefix `netbird: `, is just above. The detail is one of:

  ```text
  could not start `netbird service run`: <reason>
  could not start `netbird up`: <reason>
  `netbird service run` exited with status <n> before the daemon answered
  the NetBird daemon did not become responsive within 30 seconds
  `netbird up` failed (exit <n>)
  `netbird up` did not finish within 120 seconds
  `netbird service run` exited while `netbird up` ran
  `netbird service run` exited with status <n>
  ```

  A first enrollment with a bad or used setup key fails here: check the key, and that
  the management URL is reachable.
- **`stopping (protocol)`**, after `molebridge-exit: worker protocol violation:
  <what>`. The supervisor and the worker disagree about their messages. That is a
  bug in Molebridge; report it with the line.

If the exit is stopped on purpose (`docker compose stop`), the log shows
`molebridge-exit: received terminated` and then `stopping (requested)`, and the
exit status is 0 when the cleanup completed.

**`molebridge-exit: cannot start the worker: <reason>`, or `cannot create <path>: <reason>`.** The
supervisor could not create its runtime directories under `/run` (the tmpfs the Compose files
mount there), or could not start the worker. The first usually means `/run` is not writable, for
example a Compose override that removed the tmpfs; the container exits with status 1.

**Running the image by hand.** The image's role is its first argument and is never guessed:
`usage: molebridge <role> [arguments]` followed by the list of roles, with exit status 2, or
`molebridge: unknown role "<name>"`. `molebridge exit` takes no arguments of its own;
`molebridge-exit: the only arguments are the internal --worker and --cleanup` and
`molebridge-exit: the worker is started by the supervisor only` mean a role was started by hand
that only the supervisor starts.

### A native sidecar

The refusals of a native sidecar's settings are in the table above. This section
is the rest.

**`molebridge-exit: the sidecar firewall could not be installed; no tunnel was
started`, and the container exits with status 1.** The exit installs its
firewall first, and couldn't. The line before it says why: `nft: install the
sidecar firewall: <cause>`, `nft: open netlink: <cause>`, `nft: install the sidecar
firewall: readback: <what differs>` (the tables were written and the read-back
found something other than what was installed; `<what differs>` is one of the
reasons below). The exit gives each of these 10 seconds. Likely causes are a
kernel without `nf_tables` (or its `inet` family, or the `meta mark` and `ct state`
matches), a container without `NET_ADMIN`, or a netlink socket the engine blocks. No tunnel exists
and the applications, if they are running, stay closed: the previous firewall
and rules, if there are any, stay. Fix the cause and recreate or restart the
exit. `check-config` does not test this; it reads settings only.

**`molebridge-exit: the routing contract could not be installed; no tunnel was
started`.** The line before it, `the routing contract could not be installed:
<cause>`, names the cause: a kernel refusal of a rule, or `the contract does not
verify`. The firewall is already in place. This also needs `NET_ADMIN`, and
policy-routing support in the kernel.

**`molebridge-exit: the sidecar firewall is installed`** is the normal line that
follows a successful install, before `rules installed; the exit table holds its
unreachable fallback`, `bringing the tunnel up` and `tunnel up`.

**`molebridge-exit: warning: net.ipv4.conf.<HOST_IF>.rp_filter is strict (1):
replies arriving on <HOST_IF> are dropped and the tunnel cannot come up; set
rp_filter to 0 or 2 for this namespace (docs/native-sidecar.md)`.** The exit
logs this once, after the firewall is installed, when the larger of
`net.ipv4.conf.all.rp_filter` and `net.ipv4.conf.<HOST_IF>.rp_filter` is 1
(the kernel uses the larger). Under strict filtering the kernel validates a
reply's source with a route lookup from loopback, which the sidecar's `iif lo`
rules send to the tunnel, so replies to the exit's own requests and the
tunnel's UDP arriving on `HOST_IF` are dropped. The exit keeps running, but the
tunnel never comes up. Loose (2) or
off (0) works. Read both values with `cat
/proc/sys/net/ipv4/conf/all/rp_filter` and the same for `HOST_IF`, in the exit
container. A container usually cannot write them itself; in Compose, `sysctls:`
on the exit service can, and elsewhere the node's setting or the network plugin
decides ([prerequisites](native-sidecar.md#prerequisites)). On the k0s cluster
with Cilium this form was tested against, pods had `all=0` and `eth0=2`.

**A Kubernetes pod stays in `Init` and the application never starts, or the exit
is restarted during its startup probe.** The startup probe `molebridge health
--guarded` prints `unhealthy: <reason> (molebridge <version>)` and exits 1 until the worker has
installed the firewall and the routing contract; `no guard heartbeat yet`
means it hasn't yet, and `the guard heartbeat is from another network
namespace` that the file on `/run` is an earlier sandbox's (the new worker
removes it and writes its own once the guards are in). Read the exit's log with `kubectl logs <pod> -c exit` for the install
errors above. A probe with too few failures allowed (the example allows 30 at 2
seconds apart) restarts the exit before it finishes. A usage line,
`usage: molebridge health [--guarded]`, means the probe's command has another
argument.

**`molebridge-exit: the sidecar firewall was not as installed (<reason>);
reinstalled`.** The exit reads the firewall back every 2 seconds and found it
changed, and replaced it. Something in the namespace changed one of the two
tables (`molebridge_sidecar` or `molebridge_sidecar_backstop`), usually a
process with `NET_ADMIN`: your own tooling, or an application that was given the
capability. Find it and take the capability away. Both tables are replaced
together, and the reason names the table, as `<table>: ` before the text below
(the missing-table reason is the exception). The reasons are:

| Reason | Meaning |
|---|---|
| `no table inet molebridge_sidecar`, `no table inet molebridge_sidecar_backstop` | That table is gone |
| `<table>: table flags differ` | The table carries flags |
| `<table>: extra chain <name>` | A chain the table does not have: anything but `output`, `input` and `forward` in the main table, anything but `output` in the backstop |
| `<table>: no chain <name>` | One of its chains is missing |
| `<table>: chain <name>: hook differs`, `priority differs`, `type differs`, `device differs` | The chain's definition differs |
| `<table>: chain <name>: no policy`, `policy accept`, `policy drop`, `policy differs` | The policy is not the one the chain needs (`output` and `forward` drop, `input` accepts). The reason names what the chain has |
| `<table>: chain <name>: rule <n> differs` | The n-th rule is not the one installed, or has a comment |
| `<table>: chain <name>: <n> rules, want <m>` | A rule was added or deleted |

While it differs, `traffic_protection` fails with "Sidecar firewall protection
is incomplete; see docs/operations.md#recovery.", and a switch waits with
"Waiting for the tunnel's routing and firewall; request will retry
automatically." Both clear when the next check finds both tables right.

**`molebridge-exit: the sidecar firewall was not as installed (<reason>) and
could not be replaced: <cause>`, or `molebridge-exit: the sidecar firewall cannot
be read: <cause>`.** The same, but the replacement failed or the read-back
itself did (at most one line a minute for each). The exit stays not operational
and retries every 2 seconds. Look for the cause in the line, as for the install
above.

**`molebridge-exit: not operational: the sidecar firewall is not as installed`**
is the heartbeat withheld for the same reason, and `not operational: the routing
contract is not verified` the same for the contract or a tunnel interface that is
down ([the list above](#startup)).

**"Waiting for the tunnel's routing and firewall; request will retry
automatically."** A server change is held until both the contract and the
firewall verify, as above. If it persists, read the exit's log for the lines
above and for the repairer's.

**"Sidecar firewall protection is incomplete; see docs/operations.md#recovery."**
The firewall (either table) is not as installed, or cannot be read. The exit repairs it by itself
within seconds, so this normally clears on the next check; read the exit's log for
`the sidecar firewall was not as installed`. If it persists, recreate the exit
([recovery](operations.md#recovery)).

**"Routing protection is incomplete; see docs/operations.md#recovery."** For a
native sidecar this is a rule or the fallback route missing or wrong. The
repairer puts them back; look for its lines in the exit's log
([drift and repair](architecture.md#drift-and-repair)). If it keeps being wrong,
something else in the namespace is changing rules, or a `kept IPv4 rule ...` line
says the deletion check refused a repair.

**The application can't reach something on the network.** Anything outside
`SIDECAR_LAN_CIDRS` goes into the tunnel, and anything the tunnel can't carry
fails. A client of the application that sits outside `SIDECAR_LAN_CIDRS`, such as
the engine's gateway for a published port or a node address in Kubernetes, gets
no replies, because the replies go into the tunnel. Add its network to
`SIDECAR_LAN_CIDRS` and recreate the exit.

**PIA registration fails with a tunnel address in `SIDECAR_LAN_CIDRS`.** The exit
refuses an address PIA hands out when it lies inside one of the LAN prefixes or the
namespace's own, because rule 90 would send traffic for it to the host. The panel
shows "Peer update failed; retrying automatically." and the exit tries again on its
backoff ([retries](operations.md#retries)). Narrow `SIDECAR_LAN_CIDRS`.

**`molebridge-exit: applier: port forwarding failed: <reason>`, and `port_forward_error`
"Port forwarding is unavailable; retrying."** PIA's forwarding calls failed, or the
firewall couldn't be given the port. The exit takes the forwarded port out of the
firewall, tries again after a minute and keeps the exit's connected state. The
reason names the step: `PIA refused port forwarding` usually means the selected
region doesn't offer forwarding, and `the provider refused the login` means a
wrong PIA username or password. The reason never includes the login or the token.

**`PIA_PORT_FORWARD_TARGET is for the overlay kind; a sidecar's forwarded port
reaches the namespace itself`.** The exit started with a target set. Unset
`PIA_PORT_FORWARD_TARGET`: a sidecar needs none. It is refused even with
forwarding off. The messages `PIA_PORT_FORWARD needs PIA_PORT_FORWARD_TARGET, an
overlay IPv4 address` and `PIA_PORT_FORWARD_TARGET is set but PIA_PORT_FORWARD is
off` are the overlay's; a sidecar never prints them.

**The forwarded port is bound but the application doesn't get connections.** The
application must listen on `forwarded_port` itself. With qBittorrent, run
[`port-sync`](tools-reference.md#port-sync) and read its log; the messages are in
the tools reference. `no forwarded port yet` is normal until PIA has allotted one.

### NetBird's settings and profile

**NetBird isn't started, and the log (or the exit's only line) says
`NetBird gate: refusing to start NetBird: <reason> (see docs/troubleshooting.md)`.**
The exit refuses settings Molebridge doesn't support on the exit, before it starts
anything, and again before it lets NetBird start. The line still says "NetBird
gate"; there is no gate container any more. If it appears at start, the container
exits with status 1; later, it appears as `molebridge-exit: NetBird is not
started: NetBird gate: ...`, repeated every 30 seconds, and the exit stays
not-ready. [Architecture](architecture.md#netbird-and-its-checks) explains the
requirements. The reasons:

- `<name> is set; Molebridge needs kernel WireGuard and NetBird's kernel
  firewall`, for `NB_FORCE_USERSPACE_FIREWALL`, `NB_FORCE_USERSPACE_ROUTER`,
  `NB_USE_NETSTACK_MODE` or `NB_WG_KERNEL_DISABLED`. Remove the variable from
  your Compose override or `secrets/netbird.env`, then recreate the exit.
  [Configuration](configuration.md#what-compose-fixes-for-netbird) lists the
  values each one is refused with.
- `NB_CONFIG is set; Molebridge supports only NetBird's default profile`, or the
  same for `WT_CONFIG`, `NB_PROFILE` or `WT_PROFILE`. Remove the variable; the
  profile belongs in the `netbird-data` volume at its default path.
- `NB_FOREGROUND_MODE is set; Molebridge supports only NetBird's daemon mode`, or
  the same for `WT_FOREGROUND_MODE`. Remove the variable; the exit runs NetBird
  as a daemon.
- `NB_INTERFACE_NAME is empty`, or `WT_INTERFACE_NAME is set and differs from the
  guarded interface <name>`. Set the interface through `OVERLAY_IF` in `.env`
  only, and remove `WT_INTERFACE_NAME`.
- `the active NetBird profile is not the default profile (<file>)`. Someone
  switched the peer to another NetBird profile. Switch back by removing the
  active-profile record, which makes NetBird use `default` again. Stop the exit,
  then run this as the profile's owner (find the uid and gid as in
  [the blacklist section](operations.md#netbird-interface-blacklist)):

  ```sh
  docker compose stop exit
  docker run --rm --user <owner uid>:<owner gid> -v molebridge_netbird-data:/var/lib/netbird \
    docker.io/library/busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e \
    rm /var/lib/netbird/active_profile.json
  docker compose up -d exit
  ```
- `NB_DISABLE_USERSPACE_ROUTING must be "true" (compose.yaml sets it)`.
  Something overrides the value in `compose.yaml`; remove the override.
- `NB_ENABLE_ROSENPASS is set; Rosenpass cannot work on this exit`, or the same
  for `WT_ENABLE_ROSENPASS`. Remove the variable.
- `Rosenpass is enabled in a stored NetBird profile (RosenpassEnabled)`. The peer
  was once brought up with `--enable-rosenpass`, and its profile in the
  `netbird-data` volume keeps the setting. Turn it off in the profile without
  printing the file, which holds the peer's private key. With the exit stopped, as
  the profile's owner:

  ```sh
  docker run --rm --user <owner uid>:<owner gid> -v molebridge_netbird-data:/var/lib/netbird \
    docker.io/library/busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e \
    sed -i 's/"RosenpassEnabled": true/"RosenpassEnabled": false/' /var/lib/netbird/default.json
  ```

  The exit checks the default profile, `default.json`, and the legacy
  `/etc/netbird/config.json` and `/etc/wiretrustee/config.json` in the
  container if they exist.
- `a stored NetBird profile (<file>) uses a WireGuard interface other than <name>
  (WgIface)`. The peer's profile keeps the interface name it enrolled with (`wt0`
  if it names none), and it no longer matches `OVERLAY_IF`, usually because
  `OVERLAY_IF` changed after enrollment. Either set `OVERLAY_IF` back, or change
  the stored name to match, the same way as for Rosenpass above, for example
  from `wt0` to `mesh0`:

  ```sh
  sed -i 's/"WgIface": "wt0"/"WgIface": "mesh0"/' /var/lib/netbird/default.json
  ```

  NetBird writes the field whenever it loads a profile, so one without it is
  rare; it means `wt0`, so keep `OVERLAY_IF=wt0` for such a profile.
- `cannot read the stored NetBird profile <file>`, `the stored NetBird profile
  <file> is not a valid JSON object`, `the stored NetBird profile <file> repeats
  WgIface or RosenpassEnabled`, `the stored NetBird profile <file> repeats
  IFaceBlackList` or `the stored NetBird profile <file> has a field name outside
  printable ASCII`, and the same for the active profile state (`cannot read the
  active NetBird profile state <file>`, `the active NetBird profile state <file> is
  not a valid JSON object`). NetBird doesn't write files like these; the file was
  edited by hand or damaged. Fix the JSON or the repeated field, keeping one
  `WgIface` and at most one `RosenpassEnabled` set to `false`.
- `the stored NetBird profile <file> does not exclude the tunnel interface <if>
  from NetBird's connection candidates; stop the exit and run fix-blacklist
  (docs/operations.md#netbird-interface-blacklist)`, or `... has an IFaceBlackList
  that is not a list of strings; stop the exit and run fix-blacklist (...)`. The
  peer was enrolled without the tunnel interface in its ICE blacklist. This is the
  one refusal with a tool: [the blacklist section](operations.md#netbird-interface-blacklist)
  has the commands and the two prerequisites.
- `NetBird wrote no stored profile after `netbird up`; its interface blacklist
  cannot be verified`. After `netbird up` the exit read the profile again and found
  none. NetBird failed to enroll or to write its state; see NetBird's output above
  the line. The exit admits no traffic and stops NetBird; the refusal holds until
  the container restarts, so fix the cause and restart the exit. A refusal after
  `netbird up`, this one or the blacklist one above, is also the message of the
  exit's record, which shows `failed` in the panel and in `molebridge status`.
- With gluetun only: `<name> is set; the gluetun backend needs NetBird to mark its
  control traffic`, for `NB_USE_LEGACY_ROUTING`, `NB_SKIP_SOCKET_MARK` or
  `NB_DISABLE_CUSTOM_ROUTING` (remove the variable); `CONTROL_MARK must be
  lowercase hexadecimal like 0x1bd00, low byte zero` or `CONTROL_MARK must fit in
  32 bits`; `NB_FWMARK_BASE must equal CONTROL_MARK (<mark>)` (the Compose file sets
  both from `CONTROL_MARK`); `NB_LOG_FILE must name a log file; the gate reads it`
  (it needs an absolute path); and `FWMARK_GRACE must be 5..30 seconds`.
- `NetBird gate: invalid interface name` and `the tunnel interface name is invalid
  (EXIT_IF)`: `NB_INTERFACE_NAME` or `EXIT_IF` is not a valid interface name.

**On the first start the log says `molebridge-exit: no NetBird identity found in
the state directory or the legacy profile paths; NetBird will enroll a new
peer`.** That is expected on a new install. On an upgrade it means the exit did not
find the old peer's profile: stop and check that the `netbird-data` volume is the
one the 0.7 exit used ([upgrading from 0.7](operations.md#upgrading-from-07x)), or
the exit will enroll a new peer and you will have to recreate its route and group
membership.

**Everything is up, but NetBird is stopped, and the log says `not ready: the
routing contract has not held for <n> seconds: <problems>`.** (After `netbird up`
refused the stored profile, the reason reads `the NetBird profile does not exclude
the tunnel interface; nothing is admitted`; see the blacklist entry above.) The
worker could not restore the contract within `GUARD_GRACE` seconds, so it told the
supervisor to stop NetBird: `molebridge-exit: the worker cannot hold the routing contract: <reason>;
stopping NetBird`. Each problem is a family and a part: `IPv4 rules` (a rule at
Molebridge's priorities differs), `IPv4 exit` (the exit table differs), and with
gluetun `IPv4 host` (the host table differs) or `IPv4 nodefault` (no IPv4 default
route through the host interface). NetBird starts again once the contract
verifies. Look for lines in the log from the repairer, such as `molebridge-exit:
added IPv4 rule 97`, `molebridge-exit: removed IPv4 rule 50: <rule>` and
`molebridge-exit: netlink events were lost; running a full pass` (at most once a minute,
with a count of the losses since the last such line; see
[drift and repair](architecture.md#drift-and-repair)). Something else in the namespace is changing rules or routes faster than
the exit can repair them, or the kernel refuses a change. `ip rule` and `ip route show table
51821` in a [diagnostic shell](verification.md#inside-the-namespace) show what is
there.

### gluetun backend

**The exit stops at start with `molebridge-exit: gluetun's control server is not
listening on 127.0.0.1 port 8000`.** The worker waited 30 seconds for gluetun's
control server on loopback. gluetun isn't running yet or isn't healthy, its role
file was refused (see below), or `GLUETUN_CONTROL_URL` names another port.

**The exit stops at start with `molebridge-exit: gluetun's control server port
8000 has a listener on an address other than loopback; the control server must
listen on 127.0.0.1 only (HTTP_CONTROL_SERVER_ADDRESS)`.** gluetun's control
server is reachable beyond the namespace's loopback. The key it takes is full
gluetun administration. Set `HTTP_CONTROL_SERVER_ADDRESS` to `127.0.0.1:8000` and
don't publish the port. The exit reads `/proc/net/tcp` and `/proc/net/tcp6`; it
cannot judge a port you published at the engine, which is a [host check](operations.md#host-checks).

**The exit logs `molebridge-exit: applier: invalid configuration or unavailable
state` and then `cannot read gluetun API key`, and exits.** The API key file
`secrets/gluetun/api_key` is missing, isn't a regular file (a symlink is refused),
is bigger than a key should be, isn't printable text, or allows a mode beyond
`0600`. Fix it, or write both files again with `gluetun-auth --rotate`
([tools](tools-reference.md#gluetun-auth)), then recreate gluetun and the exit.
Other lines after the same first line name other settings: `invalid gluetun control
URL`, `invalid GLUETUN_UPDATER_PERIOD`.

**gluetun exits with `molebridge: not starting gluetun: ...`.** The wrapper that
starts gluetun, `routing/gluetun-preflight`, refused to hand over. It prints
nothing from the role file, which holds the API key. The reasons:

- `MOLEBRIDGE_KIND must be overlay or sidecar (set by compose.gluetun.yaml and
  compose.sidecar.yaml)`. The Compose file you run sets it on the gluetun service.
- `HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE sets a default role; the role file alone
  decides (...)`. Remove that setting from the gluetun service.
- `the control-server role file /gluetun/auth/config.toml is missing or not a
  regular file (...)`, `... cannot be read`, `... is too large`, `... has NUL or
  carriage-return bytes`, or `... is not the one Molebridge generates (one role,
  apikey, the five routes) (...)`. The role file is missing, edited, or written by
  an older version with fewer routes. Run `gluetun-auth --rotate`
  ([tools](tools-reference.md#gluetun-auth)), then recreate gluetun and the exit
  ([recovery](operations.md#recovery)).
- `a sidecar must not mount the overlay's post-rules (/iptables/post-rules.txt);
  remove that mount from the gluetun service`. A sidecar has no overlay guard behind
  those rules.
- `the post-rules file /iptables/post-rules.txt is missing, empty or not a regular
  file (...)`. An overlay exit needs the file `gluetun-post-rules` writes.

**gluetun stops at start with `the hostname specified is not valid`** (or the
country or city). `GLUETUN_SERVER_*` names a server that isn't in the data gluetun
has when it starts, which on a fresh install is its built-in list. Set only
`GLUETUN_SERVER_COUNTRIES`, to your own country, and choose the server in the panel
once the list has been refreshed.

**On a first start gluetun restarts its VPN several times before it connects.** Its
built-in server list is old, and it picked servers that no longer answer; its health
check restarts the VPN with another one. Setting `GLUETUN_SERVER_COUNTRIES` to your
own country makes a working server likelier. The exit waits for a working tunnel
before asking gluetun to refresh the list.

**The panel lists old servers, or Diagnostics says `server list update failed`.**
The exit asks gluetun to refresh its server list once at start when the data is old,
after gluetun's tunnel has a fresh handshake. A failure means gluetun's updater
couldn't fetch the provider's list through the tunnel; gluetun's log says why
(`molebridge-exit: applier: gluetun's server list update failed`). gluetun tries
again every `GLUETUN_UPDATER_PERIOD`, and recreating the exit starts another
refresh. A role file written before the exit could refresh the list lacks the updater
routes: run `gluetun-auth --rotate`, then recreate gluetun and the exit.

**The panel says "gluetun did not accept the server selection; retrying
automatically."** The exit's request to gluetun's control server failed: gluetun
isn't running, the API key in `secrets/gluetun/api_key` doesn't match the one in
`secrets/gluetun/auth.toml` (run `gluetun-auth --rotate`, then recreate gluetun and
the exit), or gluetun refused the server. The exit tries again after 1, 2, 4 and 8
minutes, then every 15 ([retries](operations.md#retries)).

**The exit stops with status 1 and restarts, and the log says `molebridge-exit:
NetBird gate: stopping NetBird: NetBird logged that it runs without advanced routing,
so its control traffic would be unmarked (see docs/troubleshooting.md)`, or `...
stopping NetBird: wt0 has not carried the control mark 0x1bd00 for 30 seconds (last
reported: <value>) (see docs/troubleshooting.md)`.** The exit's two monitors found
that NetBird's control traffic could have used the provider tunnel. Neither is a
retry: the worker ends, the supervisor runs the stop sequence (`stopping (worker
exited)`) and the restart policy starts the container again. For the first, NetBird's
start-up check of socket marks and `ip rule` support failed: check NetBird's log just
before the line and that the exit still has `NET_ADMIN`. For the second, `absent`
means the overlay interface didn't come up, `off` or another mark means NetBird runs
without its control mark, and `nothing` that it never reported one. The grace is
`FWMARK_GRACE` seconds, counted from NetBird's launch or from the last good
reading.

**The log says `not ready: ... IPv4 nodefault`, or NetBird never starts.** The
namespace lost its host interface or its default route, usually because the engine
restarted `gluetun` into a new namespace and left `exit` in the old one. Recreate
gluetun and the exit together ([recovery](operations.md#recovery)). If it persists
at a first start, `HOST_IF` doesn't name the namespace's interface toward the host
([configuration](configuration.md#gluetun-backend)).

**A sidecar's application carries no traffic after gluetun was recreated or
restarted.** The application stayed in gluetun's old namespace. The exit can't see
that. Run the [attachment procedure](operations.md#checking-that-containers-share-gluetuns-namespace),
then recreate gluetun and the application together.

**A native sidecar's application carries no traffic after the exit was recreated or
restarted under Compose.** The same, with the exit as the owner: the application is
in the exit's old namespace, where the rules and the firewall keep it closed and
no tunnel exists. Run the attachment procedure, then recreate the exit and the
application together ([recovery](native-sidecar.md#recovery)). In a Kubernetes pod
the namespace survives a container restart, and the exit rebuilds the tunnel
in it.

## The panel

Read the panel's log with `docker compose logs switchyard` (on Podman,
`podman logs` with its container name, `molebridge-switchyard` for
`compose.yaml`). Once it is serving, each line starts with a
UTC timestamp, which the quotes below leave out, and each request has a line
such as `2026-01-02T15:04:05Z GET /api/status 200`
([the format](architecture.md#panel-and-access)).

**The panel stops at start with `molebridge panel: refusing to start: <reason>`.**
Its self-check ([configuration](configuration.md#the-panels-isolation-check)) found
that it isn't isolated. The reasons are fixed lines:

- `the panel must run with no capabilities (cap_drop: [ALL]); its effective
  capability set is not empty`. An override gave the panel a capability.
- `the panel cannot read its capability set from /proc/self/status, so it cannot
  show it has none`.
- `the panel must not run as root; set PANEL_USER to the uid:gid that owns
  state/panel (on a rootless engine, PANEL_USER=0:0 with PANEL_ALLOW_ROOT=1)`.
- `an exit's applier state must be mounted read-only into the panel; only its panel
  directory may be writable`, and `the panel cannot tell whether an exit's applier
  state is mounted read-only`. The panel's `state/applier` mount must end `:ro`.

**The panel stops at start with `molebridge panel: <setting> ...`.** Before it checks its
isolation, the panel validates its settings, and the last line of its log names the one it
refused:

- `PROVIDER must be one of: <ids>`: the panel's `PROVIDER` (single-exit panel) is not a
  provider id.
- `EXIT_KIND must be overlay or sidecar`: the single-exit panel's kind. A sidecar may
  use a native provider (a [native sidecar](native-sidecar.md)); 0.8.0 refused that with
  `a sidecar exit needs a gluetun provider (PROVIDER=gluetun-<name>)`.
- `PANEL_EXITS: exit ids are 1-32 of a-z, 0-9 and -, in '<entry>'`,
  `PANEL_EXITS: provider must be one of <ids>, in '<entry>'`,
  `PANEL_EXITS: the kind after / is overlay or sidecar, in '<entry>'`,
  `PANEL_EXITS: labels are at most 40 printable characters, in '<entry>'` and
  `PANEL_EXITS: duplicate exit id '<id>'`. An entry is `id=provider[/kind][:label]`
  ([several exits](switchyard.md#several-exits-in-one-panel)).
- The sign-in messages in [the next section](#sign-in).

`molebridge panel: cannot listen: <reason>` means the panel could not bind its port
(8080 in its container).

**`421 unknown host; publish the panel under PANEL_PUBLIC_HOSTS`.** The request's
`Host` isn't loopback or listed in `PANEL_PUBLIC_HOSTS`; the panel's log has
`rejected request: host is not in PANEL_PUBLIC_HOSTS or loopback`. Add the public hostname. If
your proxy rewrites `Host` when it connects upstream (to `host.docker.internal:8095`,
for example), add that name and port too. Scanners send wrong names too, so the
line is written at most once a minute, and when it skipped some, the next one
it writes ends `(<n> more not logged since the last such line)`. Each request still has its
own access line ending `421`.

**`403 origin is not a published panel host` or `invalid or missing csrf token` when
switching.** The browser's `Origin` must be a listed host, and the CSRF cookie must
reach the panel. Check that the proxy passes cookies and doesn't strip `Origin`, and
that you opened the panel by the name listed in `PANEL_PUBLIC_HOSTS`. The first case
logs `rejected POST: origin is not a published panel host`, at most once a minute like
the line above.

**`500 internal error` when switching.** The panel couldn't write its request,
`desired.json` in the exit's panel directory (`$STATE_DIR/panel`, or
`$STATE_DIR/<id>/panel` with several exits). Its log has `switch failed: cannot write
the request file: <reason>`, where `<reason>` is the file operation, the path and the
system's error, such as `permission denied` or `read-only file system`. That directory
must be mounted writable, and `PANEL_USER` must be the uid and gid that own it
([the `.env` settings](configuration.md#env)).

**"No fresh trusted relay catalogue; selections are unavailable."** The panel can't
read a catalog less than 24 hours old. Either the exit hasn't fetched one yet (give
it a minute after first start), the provider's API is unreachable from the exit, or
the panel can't read `state/applier/`. The last one usually means `PANEL_USER` is
wrong: it must be your host user's `uid:gid` on Docker and `0:0` on rootless Podman.

**The dashboard frame is blank.** Most often your proxy's session for the panel's
hostname has expired: open the panel directly once to sign in. (With the panel's own
[sign-in](#sign-in) the frame shows a "Signed out" page with a link instead.) If that
doesn't help, check that `PANEL_FRAME_ANCESTORS` lists the dashboard's origin, and
that the dashboard and the panel are on the same site, so the browser sends the
proxy's cookie inside the frame.

**The status says "status stale" or "awaiting status".** The panel has no usable
result from the exit: none in the last 150 seconds, or one that is malformed or dated
in the future. Check that the `exit` container is running and healthy, and that the
host's clock is right. After the exit stops on purpose, the last record goes stale
after 150 seconds, as it did in 0.7.

**Other states the panel shows as unknown or failed.** Each is the
[verdict](architecture.md#the-verdict) on the exit's last record:

- **"evidence expired"**: the record is fresh, but a check in it was measured more
  than 150 seconds ago, or passed for another server than the one the record
  reports. An inspection that took very long does this; the next one normally clears
  it. If it persists, look at how long the egress check takes (the exit's log) and at
  the host's clock.
- **"not yet measured"**: a check the exit needs hasn't been measured since the exit
  started or since the server changed. Wait for the next check, about a minute.
- **"request not acknowledged"**: the panel's request is more than 150 seconds old and
  the exit hasn't picked it up. Check that the exit runs, and that it can read
  `state/panel/desired.json` (`PANEL_USER`).
- **"verification failed"**: every check passed, but on another server than the one
  you selected or set in `SERVER`. The exit puts the selection back by itself ("The
  live server is not the selected one; waiting for convergence." below).
- **"kind mismatch"**: the record was written by an exit of the other kind than the
  panel is configured for: an overlay exit where the panel expects a sidecar, or the
  reverse. Make the panel's `EXIT_KIND`, or the `/kind` in that exit's `PANEL_EXITS`
  entry, match the exit's `EXIT_KIND` ([several exits](switchyard.md#several-exits-in-one-panel)).
  A 0.6 record under a sidecar configuration shows this too.
- **"provider mismatch"**: the record names another provider or backend than the
  panel's `PROVIDER` or `PANEL_EXITS` entry. Fix whichever is wrong; a panel pointed at
  another exit's state directory shows this.
- **"unsupported status version"**: the exit is newer than the panel. Upgrade the
  panel ([upgrades](operations.md#upgrades)).
- **"invalid status record"**: the record is missing a check the exit needs, or a check
  is malformed or contradicts itself, such as an egress pass at a tier the provider
  can't have. The exit doesn't write such records: check whether something else writes
  `state/applier/`, and if nothing does, report it as a bug.
- **"switched, egress unverified"**, with "Switched; the egress couldn't be compared
  with this host's address.": a [gluetun sidecar](gluetun-sidecar.md#tunnel-tier-providers)
  with FastestVPN, IVPN, Surfshark or Windscribe. The switch was made; Molebridge has no
  way to verify its egress there. This is expected and doesn't change by itself.

**`A switch is in progress; wait for it to finish.` (409) when switching.** The panel
refuses a new request while the exit is switching, including just after a request the
exit hasn't picked up yet. Wait until switching clears, then choose again. Verification
waits up to 60 seconds after the change (90 with gluetun); making the change and an
inspection under way come on top. A stale status doesn't block a request.

## Sign-in

This applies only when `PANEL_OIDC_ISSUER` is set; see
[panel access](access.md#sign-in-with-openid-connect). The Go panel's sign-in has not been run against a real identity provider; the
Python panel's was, once, with one provider ([testing](testing.md#sign-in-pass-at-62a0170)).
Most of this list comes from the code rather than from failures seen in use.

**The panel stops at start.** The last line of the container's log is
`molebridge panel: ` and the setting it refused, with one of these messages (`<name>`
is the setting):

- `<name> is set but PANEL_OIDC_ISSUER is not; set both or neither`, for
  `PANEL_OIDC_CLIENT_ID`, `PANEL_ACCESS`, `PANEL_ADMIN_GROUPS` or `PANEL_PUBLIC_URL`
- `PANEL_OIDC_ISSUER must be an https URL (http only for a loopback test issuer)`
- `PANEL_OIDC_CLIENT_ID is required with PANEL_OIDC_ISSUER`
- `PANEL_OIDC_CLIENT_SECRET_FILE cannot be read: <reason>` (including `not valid
  UTF-8`) and `PANEL_OIDC_CLIENT_SECRET_FILE is empty`
- `PANEL_PUBLIC_URL must be the https origin people open, such as https://exit.example.net`
- `PANEL_OIDC_SCOPES must include openid`
- `PANEL_ADMIN_GROUPS: '<group>' is not a valid group name`
- `PANEL_ACCESS: entries are group=exit, with no spaces, commas or = in the group, in '<entry>'`
- `PANEL_ACCESS: '<exit>' is not an exit in PANEL_EXITS, in '<entry>'`. A single-exit
  panel has no exits to name, so use `PANEL_ADMIN_GROUPS` there.
- `With PANEL_OIDC_ISSUER set, PANEL_ADMIN_GROUPS or PANEL_ACCESS must name at least one group`
- `PANEL_SESSION_TTL must be a whole number of seconds` and
  `PANEL_SESSION_TTL must be between 300 and 604800 seconds`

**"Sign-in unavailable".** The page says "The identity provider could not be reached.
Try again in a minute." The panel couldn't read the provider's discovery document. The
log has a line `sign-in unavailable: <reason>`, such as `discovery: the issuer could not
be reached (<cause>)`, `discovery: the issuer answered HTTP <code>`, or `discovery: the
issuer in the discovery document does not match PANEL_OIDC_ISSUER`. The `<cause>` is one
of:

- `DNS lookup failed`: the panel container can't resolve the issuer's name.
- `connection refused` or `no route to the issuer`: nothing answers at that address
  from the panel container, or a firewall turns it away.
- `timed out`: no answer within 10 seconds.
- `TLS certificate not trusted`: the certificate isn't valid for the name, or isn't
  signed by an authority the panel image trusts.
- `TLS handshake failed`: the TLS connection failed for another reason, such as plain
  HTTP on that port.
- `connection closed by the issuer`, or `request failed` for anything else.

After a failure the panel waits 30 seconds before asking again, and meanwhile logs
`discovery: the issuer could not be reached recently; retrying shortly`. Check that the
panel container can open an HTTPS connection to the issuer and trusts its certificate,
and that `PANEL_OIDC_ISSUER` is written exactly as the discovery document's `issuer`.

**"Sign-in failed".** The page says "The sign-in could not be completed. Start it again
from the panel." The log has `sign-in failed: <reason>`. Common ones:

- `callback: this browser did not start a sign-in, or it expired`. The browser came back
  without a valid `__Host-molebridge_login` cookie: the sign-in took more than 10
  minutes, the panel restarted meanwhile, the same return link was opened twice, cookies
  are blocked, or the browser began at a different address from `PANEL_PUBLIC_URL`. Start
  again from `PANEL_PUBLIC_URL`.
- `callback: the sign-in state does not match`. The return belongs to a different sign-in
  than the one this browser started last, for example from a second tab. Start again.
- `token: the issuer could not be reached (<cause>)`, with a cause from the list above.
  The provider answered discovery but not the token request, so this shows as "Sign-in
  failed", not "Sign-in unavailable". Check the panel container's route to the issuer.
- `token: the issuer answered HTTP <code>`. The provider refused the code. Check that the
  redirect URL registered there is `PANEL_PUBLIC_URL` plus `/auth/callback`, exactly, and
  that the client is a public client (or that `PANEL_OIDC_CLIENT_SECRET_FILE` holds its
  secret).
- `token: the ID token was issued by another issuer` and `token: the ID token is for
  another client`. `PANEL_OIDC_ISSUER` or `PANEL_OIDC_CLIENT_ID` doesn't match what the
  provider put in the token.
- `token: the issuer sent no groups claim` or `userinfo: the issuer sent no groups claim`
  (with `groups` replaced by `PANEL_OIDC_GROUPS_CLAIM`). The provider isn't sending groups.
  Check that `PANEL_OIDC_SCOPES` includes the scope that adds them and that the client is
  allowed to use it.

**"Not allowed".** The page says "This account is not allowed to use this panel." The log
has `sign-in failed: access: this account is not in a group that may use this panel`: the
person's groups match neither `PANEL_ADMIN_GROUPS` nor `PANEL_ACCESS`. Compare the group
names exactly. The same page appears, with `sign-in failed: access: the identity provider
refused the sign-in`, when the provider itself turned the person away.

**Someone changed groups and still sees the old exits.** A session keeps the groups it was
created with until it ends, at most `PANEL_SESSION_TTL` seconds after sign-in. To apply a
change now, restart the panel, which signs everyone out, or have the person sign out and
in.

**The dashboard shows "Signed out".** The panel session ended, or was never started in this
browser. Choose **Sign in**, which opens in a new tab, then reload the dashboard.

## Switching

The exit's log follows each switch with one line per change of its state, with the
server in quotes:

- `applier: switch to "<server>" admitted (<source>, change <n>); applying`
- `applier: "<server>" is verified`
- `applier: "<server>" is applied but not verified; checked again every 60 seconds`
- `applier: switch to "<server>" waits: <message>`
- `applier: switch to "<server>" rejected: <message>`
- `applier: switch to "<server>" failed: <message> (next try in <n> s)`

`<source>` is what asked for the switch, as in
[requests and switching](architecture.md#requests-and-switching), and `<message>` is the
panel's message, explained below. A check that changes nothing logs nothing.

**"Tunnel handshake is missing or stale; check the account and connectivity."** The
provider isn't answering the tunnel. Possible causes:

- The Mullvad account ran out of time, or the device was removed from the account. Check
  the account page.
- The PIA or NordVPN subscription lapsed.
- Outbound UDP to the provider is blocked. Check the host's firewall and
  [the ports it needs](prerequisites.md#network).
- The selected server is down. If another server works, that's the cause.

**"Peer update failed; retrying automatically."** The exit couldn't apply the server: a
peer change failed, or with PIA the registration failed (a key registration PIA refuses
with a reused login is asked once more with a fresh one first). The exit applies it again
after 1, 2, 4 and 8 minutes, then every 15, and the panel says when ("Retrying at … UTC");
**Retry** does it at once ([retries](operations.md#retries)). If one PIA region keeps
failing while others work, the problem is on PIA's side.

**"PIA refused the login; correct the credentials, or retry."** PIA's login service
answered 401 or 403. Check the files in `secrets/pia/` (one value per file, no extra
whitespace). The exit doesn't try again by itself until `secrets/pia/username` or
`secrets/pia/password` changes; after fixing them, it retries within a few seconds, or
press **Retry**.

**"Switch verification timed out; retrying automatically."** The selected server didn't
become the live one in time: 60 seconds after the change with the native backend, 90
with gluetun. It is applied again on the same backoff. If the selected server did become
live but a check still failed at the timeout, the panel shows that check's own message
instead, such as the handshake or egress message below, and the exit re-checks it every
minute without switching again (with PIA, a handshake stale for 180 seconds registers the
same region again, as below).

**"Routing changed during the switch; retrying after recovery."** A routing rule, the
lease or NetBird's kernel mode went missing while a switch was being verified
([gluetun's reconnection](architecture.md#gluetuns-reconnection-during-a-switch) says what
gluetun may do without causing this). The switch is tried again on the backoff, but only
once the gates pass; until then the panel shows "Waiting for tunnel and overlay routing;
request will retry automatically. If this persists, recreate the exit
(docs/operations.md#recovery)." Recovery is [recreating the exit](operations.md#recovery),
and the exit repairs routing by itself, so look at the exit's log first (`not ready:` and
the repairer's lines).

**"The last switch was interrupted; retrying automatically."** The exit stopped during a
switch, or lost the answer to its change. At start it inspected the tunnel first, found
another server live, and applies the selection again on the backoff. Its log shows
`molebridge-exit: applier: an interrupted switch is inspected before anything else`.

**"The last switch stopped on a file error (<error>); retrying automatically."** A switch
failed on the exit's own files: the error names which, for example a PIA credential file
under `secrets/pia/` that is missing or unreadable, or a state volume that is full. The
log shows the same error after `applier: control cycle failed:`. Fix the file; the switch
is applied again on its backoff without a restart.

**"The live server is not the selected one; waiting for convergence."** The tunnel runs
another server than the one you selected; with `SERVER` set the message is "The configured
SERVER is not the current server; waiting for convergence." Usually gluetun restarted on
the server in its own settings, or someone changed the peer by hand. The exit puts the
selection back by itself, but not within 90 seconds of its last change and not while a
failed attempt waits for its retry; a peer the server list can't name is waited out for 90
seconds first.

**"Expected exactly one tunnel peer."** The tunnel has no peer, or more than one. With PIA
and NordVPN a tunnel the worker brought back has no peer. The exit applies the selection
again at once, but never within 90 seconds of its last change, and after a failed change
only when its retry is due or the worker itself restarted. With gluetun, a reconnecting
tunnel has no peer for a moment, and the exit waits 90 seconds before it acts. The exit's
container stays healthy meanwhile. If it persists, recreate the exit
([recovery](operations.md#recovery)).

All of these but PIA's refused login clear by themselves when a later check finds the
selected server live and passing every check, or a retry succeeds; the refused login waits
for changed credential files or Retry. With PIA, a handshake that has been stale for 180
seconds while the selected region is live makes the exit register the same region again,
on the same backoff, and log `molebridge-exit: applier: the registration lapsed;
registering the same server again`; an egress-check failure alone doesn't.

**`molebridge-exit: applier: repairing the tunnel's address and return-path rules failed:
<reason>`, `applier: installing the ingress guard failed: <reason>`, `applier: clearing a
forwarded port left by an earlier run failed: <reason>` or `applier: removing the forwarded
port from the firewall failed: <reason>`.** PIA only, except the ingress guard, which every
native overlay exit installs. The exit retries the first three on
every pass (every 5 seconds) until they succeed, and the last with the next forwarding
attempt or switch. It logs the first failure, each change of reason, and the same reason
again every 10 minutes while it lasts. A repaired tunnel logs
`applier: the tunnel's address and return-path rules are consistent again`, and the guard
and the cleanup log `applier: the ingress guard is installed` and `applier: the forwarded
port left by an earlier run is cleared`. Port forwarding doesn't start until the ingress
guard and the cleanup have succeeded. The reason names the kernel step that failed. If it
persists, recreate the exit ([recovery](operations.md#recovery)).

**"No PIA region is registered yet; choose one in the panel."** It's a fresh PIA install.
Pick a region.

**"No NordVPN server is selected yet; choose one in the panel."** It's a fresh NordVPN
install, or its tunnel was recreated before any selection. Pick a server.

**"Tunnel egress is not confirmed as NordVPN."** NordVPN's insights check said the traffic
wasn't protected. If the egress address in Diagnostics is the selected server's own
address, NordVPN may be serving an answer it cached before that address was a VPN exit for
you; it caches for up to an hour, and the exit asks again for up to a minute before
reporting this. Try again later, or pick another server. See
[providers](providers.md#how-nordvpn-differs).

**"Tunnel inspection or egress check failed."** The exit couldn't read the tunnel's state,
or the egress check got no usable answer: a timeout, a refused connection, an HTTP error or
a malformed reply. Usually that answer was missing twice, 10 seconds apart, and the log shows
`molebridge-exit: applier: egress check got no answer twice`; a first attempt that took over
15 seconds, or one during a switch, is not asked again (see [egress
tiers](architecture.md#egress-tiers) for when the exit asks once more). An occasional one
usually means the provider's check service, or the path to it through the tunnel, dropped a
connection; the next check a minute later normally passes. The selected server stays in place
meanwhile: the exit re-checks it, it doesn't switch again. If it persists, compare the
handshake age in Diagnostics.

**"Tunnel egress did not pass the tunnel checks."** Only for a provider without its own egress
check, which today means FastestVPN, IVPN, Surfshark and Windscribe through the gluetun
backend: the IP echo services disagreed, or answered with the host's own address or one the
server list doesn't name. See [egress tiers](architecture.md#egress-tiers).

**"Waiting for a fresh trusted relay catalogue; request will retry automatically."** The
selection is saved and will be applied once the exit has a current catalog. If this
persists, the provider's API is unreachable from the exit.

**"Relay refresh failed; retaining the last good catalogue."** The exit couldn't download
or validate the provider's server list. The panel shows this message and the time of the
failed attempt from `state/applier/relay-error.json` (its `message` and `checked_at`; the
file holds an empty object after a refresh succeeds). Switching keeps using the last good
catalog until it is 24 hours old. The exit tries again after one minute and doubles the wait
after each further failure, up to an hour; while the last catalog is less than 24 hours old,
it never waits past the moment the catalog turns 24 hours old, and once there is no such
catalog (none yet, or a stale one) it waits at most five minutes. The exit's log has one line for each new
cause, `molebridge-exit: applier: relay catalogue refresh failed: <reason>`, where the reason
names a step or a file, such as `netx: request timed out` or `duplicate JSON field`, never
the list's content. When a refresh succeeds again it logs `molebridge-exit: applier: relay
catalogue refreshed again`. With the gluetun backend the message is "gluetun's server list is
missing or invalid; retaining the last good catalogue." and the exit reads gluetun's file
again every minute, without this backoff or these log lines.

**"Routing protection is incomplete; see docs/operations.md#recovery."** A routing rule or
fallback route is missing, the lease isn't live, or the local-delivery rule was replaced. The
exit repairs rules itself within milliseconds, so this normally clears on the next check. If
it persists, read the exit's log (`not ready:` and the repairer's lines), and
`docker compose exec exit molebridge status` for `lease: lapsed`; a native exit whose lease isn't held has stopped renewing it
([why the exit stopped itself](#why-the-exit-stopped-itself)). For a native sidecar see [a native sidecar](#a-native-sidecar). For the gluetun forms it can
also mean the exit was left in an old namespace: [recreate](operations.md#recovery) gluetun
and the exit together.

**"NetBird is not running kernel WireGuard with its kernel firewall on the overlay interface;
see the troubleshooting guide."** A selection waits with "Waiting for NetBird to run kernel
WireGuard with its kernel firewall; request will retry automatically." The exit is never
reported as connected in this state. The exit found one of these:

- **The overlay interface isn't a kernel WireGuard link.** NetBird found no usable WireGuard
  kernel module and fell back to userspace WireGuard. In a [diagnostic
  shell](verification.md#inside-the-namespace), `ip -d link show wt0` shows `wireguard` on its
  details line when it's right. Load the module on the host as in
  [requirements](prerequisites.md#rootless-podman), then recreate the exit.
- **NetBird's kernel firewall isn't visible.** `nft list tables` in a diagnostic shell should
  show `table ip netbird` (NetBird's nftables backend) or `table ip filter` holding chains
  named `NETBIRD-…`. The check looks for those names, so a renamed table
  (`NB_NFTABLES_TABLE`) fails it. The image has no iptables, so NetBird uses nftables; the
  kernel needs `nf_tables` ([requirements](prerequisites.md#host)). The live runs saw
  NetBird on that path ([testing](testing.md)).

## Clients

**Clients get no connectivity at all after you restarted or recreated `gluetun` alone.** In the
gluetun forms, `exit` and any application that joins gluetun are still attached to the old
network namespace. The exit reports routing as incomplete or stays not ready. Recreate gluetun
and everything in its namespace together ([recovery](operations.md#recovery)), then run the
[attachment procedure](operations.md#checking-that-containers-share-gluetuns-namespace).

**Everything works, but slowly: clients are relayed.** Run `netbird status -d` inside the exit
container (`docker compose exec exit netbird status -d`) and look at `Connection type`.
`Relayed` has four common causes:

- **A phone with NetBird's "Force relay connection" setting on.** It's on by default on mobile;
  turn it off under Settings → Advanced.
- **The exit interface missing from the peer's ICE blacklist.** The log shows `ICE retries
  exhausted`. The exit refuses to start in that state and names the repair tool; see [the
  blacklist](operations.md#netbird-interface-blacklist).
- **The exit on a private container bridge** with no reachable candidate. This is normal for
  rootless setups; see [exits on a private container
  network](operations.md#exits-on-a-private-container-network).
- **Rootless Podman with pasta, where you published the NetBird WireGuard port.** Remote devices
  are always relayed, while devices on the same LAN still connect directly through
  `--external-ip-map`, which hides the fault. The published port holds the host port, so pasta
  can't bind it for NetBird's outgoing STUN. The passt or pasta log shows `Dropping datagram` for
  port 3478, and the NetBird log shows `wait for gathering timed out` every 5 minutes. Observed on
  Debian with passt 0.0~git20261002 and Podman 5.8.6; Docker is untested. Remove the published
  port and forward it through a pasta network instead, as described in [exits on a private
  container network](operations.md#exits-on-a-private-container-network).

**The exit is healthy, but a device loads nothing on a restrictive network (hotel Wi-Fi).** The
panel and `molebridge status` report the exit as fine. On the exit, the device sits at Connecting
and its handshakes time out. On the device, the relay connection drops every few seconds to
minutes.

The cause is NetBird's relay transport, not Molebridge. The NetBird client prefers QUIC to reach
the relay. Some networks break long-lived UDP flows: QUIC connects, then dies. The client falls
back to WebSocket only when QUIC cannot connect or a datagram is too large. This is NetBird client
behavior and affects any NetBird setup whose relay offers QUIC.

On the device, with a NetBird desktop client 0.79.0 or later, tell the client to prefer WebSocket:

```sh
sudo netbird service reconfigure --service-env NB_RELAY_TRANSPORT=prefer-ws
```

The setting survives restarts and upgrades. To undo it:

```sh
sudo netbird service reconfigure --service-env ""
```

Run `netbird status -d` on the device to confirm. The relay line ends with `via ws` once the client
uses WebSocket. `NB_RELAY_TRANSPORT` accepts `auto` (the default), `quic`, `ws`, `prefer-quic` and
`prefer-ws`. This was confirmed on macOS; other platforms are untested.

**A video call or download stalls after a few seconds, then sometimes recovers.** One possible cause
is path MTU: oversized replies whose ICMP error never reaches the sender. Namespace step 6 in
[verification](verification.md#inside-the-namespace) checks for it; the ICMP source sysctl and rule
94 must both be in place.

**The client shows its real IPv6 address.** Its IPv6 is bypassing the exit. Check that the account has
IPv6 overlay and that the exit has a `::/0` route. NetBird is meant to block IPv6 on a client when it
can't carry it, so if both are missing and the client still leaks, disable IPv6 on that client and
check its NetBird version. See [verification](verification.md#from-a-client).

**Names don't resolve while the exit is selected.** Molebridge doesn't handle DNS. The client keeps its
own resolver. If that resolver is a private address the client can only reach through the exit (for
example, a server on the exit host's LAN), the exit sends it into the tunnel, where it goes nowhere.
Use a resolver the client can reach directly, or NetBird's DNS settings.

**A device can't reach addresses on the exit host's LAN.** That's by design. Forwarded traffic goes
only into the tunnel.
