# Changelog

Molebridge is experimental. Each release lists what was tested; the full
record is in [docs/testing.md](docs/testing.md). Upgrade by following
[operations](docs/operations.md#upgrades).

## 0.9.1 — 2026-10-16

**Experimental.** Three fixes found moving the gluetun forms to Kubernetes. The
release candidate passed its live acceptance on Kubernetes and rootless
Podman ([testing](docs/testing.md#091)).

**gluetun's server-list refresh is decided on gluetun's own list, and says why
it waits.** With the gluetun backend the exit starts one refresh of gluetun's
server list when the data is old. A first pod with gluetun's built-in 2024
NordVPN list never started it in 14 minutes, with nothing in the log or the
record to say why.
- The cause: at start the exit judged the catalogue it had published in an
  earlier run, before it read gluetun's file. Where the exit's state outlived
  gluetun's (a new pod beside kept state, or a recreated gluetun volume), that
  catalogue was fresh, so the refresh was settled as not needed for the life of
  the process. The exit now decides only on a list read from gluetun's file
  since it started. Reproduced live on v0.9.1-rc.1, which still had the fault.
- `server_list_update` in `result.json` now also names what an owed refresh
  waits for: `waiting-for-tunnel` (no single peer with a handshake in the last
  150 seconds), `waiting-for-vpn` (gluetun's VPN status isn't `running`),
  `waiting-for-control-server` (gluetun's control server failed to answer) or
  `waiting-to-retry` (the last run failed or timed out). The panel shows it
  beside the relay list.
- The log says it once per change of reason (`applier: gluetun's server list
  is out of date; its update waits: ...`, with what was seen), and each failed
  try with its cause and count.
- A failed answer of gluetun's control server counts toward the three tries.
  It used to be retried every 5 minutes without end.

**`gluetun-preflight` writes the preflight script from the image**
([tools](docs/tools-reference.md#gluetun-preflight)), for a deployment without a
Molebridge source tree, such as a Kubernetes init container. The gluetun pages
have a Kubernetes section: the preflight, a persistent server list, no user
namespace for a pod that mounts `/dev/net/tun`, and
`WIREGUARD_ALLOWED_IPS=0.0.0.0/0` when the pod has IPv6
([the exit](docs/gluetun-netbird-exit.md#kubernetes),
[the sidecar](docs/gluetun-sidecar.md#kubernetes)).

**Release acceptance**: the policy (version 3) drills a patch release as an
upgrade from the release before it (`upgrade-from-0.9.0`) instead of from 0.8.

**`fix-blacklist --add IFACE` and `--clear-external-ip-map`**, for an enrolled
exit that moved to another runtime: the first adds another interface to the
stored profile's blacklist, the second empties a stored `--external-ip-map`
([operations](docs/operations.md#netbird-interface-blacklist)). Without them the
tool does what it did.

## 0.9.0 — 2026-10-16

**Experimental.** The native sidecar: an exit that other containers share, with
a tunnel Molebridge builds itself, and a routing contract and a firewall of its
own that keep those containers' traffic in the tunnel. It exists so that an
application can use PIA over WireGuard; Molebridge's gluetun forms don't offer
PIA, and gluetun supports PIA over OpenVPN only. It has run live once, with PIA
on Kubernetes (k0s with Cilium) beside qBittorrent; the unit tests, `go vet` and
the namespace drills pass, and Docker Engine, podman-compose and the Compose
file on a live engine are untested ([testing](docs/testing.md#090)). Nothing
changes for the overlay kinds and the gluetun sidecar.

**The native sidecar** ([the page](docs/native-sidecar.md)).
- `EXIT_KIND=sidecar` with `TUNNEL_BACKEND=native` and `PROVIDER` `mullvad`, `pia`
  or `nordvpn`. The exit owns the namespace's tunnel as a native overlay exit
  does; the applications share the namespace (`network_mode: service:exit`, or the
  containers of a Kubernetes pod) and send their own traffic through it. There is
  no NetBird and nothing is forwarded.
- Two layers keep the applications' traffic in the tunnel, both installed before
  the tunnel exists and left in place when the exit stops or restarts: a routing
  contract (rules 88 to 98 and the exit table's fallback, repaired and judged like
  the overlay's) and an nftables firewall, table `inet molebridge_sidecar`, which
  stops what policy routing alone does not, a socket bound to an interface. A
  second table, `inet molebridge_sidecar_backstop`, repeats the output chain, so
  deleting either table leaves the other enforcing it. The output chain admits
  IPv6 on the host link only as ICMPv6 neighbour discovery and MLDv2 reports
  (router solicitation, neighbour solicitation and advertisement, listener
  report), not as blanket `fe80::/10` and `ff02::/16` accepts, so an application
  cannot send multicast or link-local UDP out of the host interface unless
  `SIDECAR_LAN_CIDRS` lists it. Both tables are read back every 2 seconds and
  replaced in one transaction when either differs. A restart of the exit inside a
  kept namespace, as in a Kubernetes pod, leaves the applications closed and the
  exit rebuilds the tunnel.
- New setting `SIDECAR_LAN_CIDRS`: the networks the applications may reach outside
  the tunnel (at most 16 prefixes, no default route). `HOST_IF` and `CONTROL_MARK`
  apply to this form too. Molebridge does not configure the applications' DNS; a
  resolver inside `SIDECAR_LAN_CIDRS` answers outside the tunnel, and one outside
  it is reached through the tunnel ([DNS](docs/native-sidecar.md#dns)).
- New setting `SIDECAR_HOST_RESOLVERS`: up to three resolver addresses for the
  exit's own marked lookups in place of the namespace's, so the applications'
  resolver can be one inside the tunnel (the Kubernetes example points the pod
  at PIA's) while the provider's login, before the tunnel exists, still
  resolves on the host path. Each is asked in turn with its own retries. Set,
  it also makes the firewall drop the applications' DNS (TCP and UDP ports 53
  and 853) to `SIDECAR_LAN_CIDRS`, so their lookups go through the tunnel or
  nowhere.
- The exit's own requests that are not through the tunnel carry the control mark
  and resolve their names over marked sockets, so they take the host path.
- Status: `kind: "sidecar"`, `backend: "native"`; required checks `routing`,
  `traffic_protection` (the contract and the firewall), `peer`, `handshake` and
  `egress`; `app_attachment` stays `not-checked` ([the status
  record](docs/architecture.md#the-status-record)). New messages: "Sidecar firewall
  protection is incomplete; see docs/operations.md#recovery." and "Waiting for the
  tunnel's routing and firewall; request will retry automatically."
  ([troubleshooting](docs/troubleshooting.md#a-native-sidecar)).
- PIA's port forwarding works in a sidecar without a target: the firewall's input
  chain admits the forwarded port, and `forwarded_port` in `result.json` and
  Diagnostics shows it ([port forwarding](docs/native-sidecar.md#port-forwarding)).
- `compose.native-sidecar.yaml`'s example application has `restart: "no"`: after a
  reboot the engine starts restarting containers without waiting for
  `depends_on`, which would let an application run before the guards exist.
  Start the stack at boot with `docker compose up -d --wait`
  ([starting at boot](docs/native-sidecar.md#starting-at-boot)).
- `molebridge health --guarded` (usage: `molebridge health [--guarded]`): passes
  while the native sidecar's guard heartbeat, which the worker renews every 2
  seconds while the firewall reads back as installed and the routing contract
  holds, whether or not the tunnel is up, is at most 15 seconds old and was
  written in the same network namespace as the check runs in (named by the
  kernel's namespace cookie; before 5.14, by its reusable inode number). In a
  Kubernetes pod it is the exit's required startup probe: without one, the
  application containers start as soon as the exit process runs, before the
  firewall and the rules exist ([the startup
  gate](docs/native-sidecar.md#the-startup-gate)).
- The exit logs a warning when the larger of `net.ipv4.conf.all.rp_filter` and
  `net.ipv4.conf.<HOST_IF>.rp_filter` is 1: strict reverse-path filtering drops
  the replies the sidecar's `iif lo` rules send to the tunnel, and the tunnel
  cannot come up ([prerequisites](docs/native-sidecar.md#prerequisites)).
- The deletion check treats the exit's own control-marked traffic as safe out of
  `HOST_IF` or the tunnel interface, and anything else as an escape.
- Known limitation: where a pod's routes carry a smaller MTU than the tunnel's
  encapsulated packets (Cilium on a NetBird overlay sets 1280), the tunnel's
  outer packets are fragmented; it works at some CPU cost
  ([Kubernetes](docs/native-sidecar.md#kubernetes)).
- `compose.native-sidecar.yaml` and `.env.native-sidecar.example`, in the release
  bundle. A Kubernetes pod example is in the page; it is not a packaged or
  supported form.
- Switchyard shows a native sidecar as a tab (`id=pia/sidecar` in `PANEL_EXITS`).

**`molebridge port-sync`.** A new role for a container with no capabilities in the
application's namespace. It keeps qBittorrent's listening port on the port the
exit's record names, through qBittorrent's Web API on loopback, and writes nothing
([tools reference](docs/tools-reference.md#port-sync)). qBittorrent is the only
client.

**Refusals removed.** `EXIT_KIND=sidecar needs TUNNEL_BACKEND=gluetun`, and the
panel's `a sidecar exit needs a gluetun provider` (for `PANEL_EXITS` and for a
single-exit panel), are gone: a sidecar takes a native provider. New refusals
cover the settings above (`SIDECAR_LAN_CIDRS`, `OVERLAY_*` set for a sidecar, and
`PIA_PORT_FORWARD_TARGET` for a sidecar).

**Release acceptance.** The acceptance policy now names the Kubernetes platform and
the native-sidecar kind, and its upgrade drill is from 0.8 (was 0.7)
(`tools/acceptance-policy.json`).

**Upgrade.** Nothing is needed for a 0.8.x install: the Compose files for the overlay
forms and the gluetun sidecar are unchanged except for the image they pin, and state
files and records are read as before. To use the native sidecar, follow [its set-up](docs/native-sidecar.md#set-up).
A 0.8.0 Switchyard refuses a sidecar on a native provider; use the 0.9.0 one for those.

## 0.8.0 — 2026-10-13

**Experimental, and not a 1.0.** A rewrite for adoption: one signed image,
pull and run. The Python and shell are ported to one Go binary; the exit is two
containers instead of four; nothing is built locally and there is no Python on
the host. The routing contract, the status record (schema 2), the verdict, the
admission pipeline, the state files and the panel's wording are unchanged, so
a 0.7.0 Switchyard reads a 0.8.0 exit. Tested live on rootless Podman with
Quadlet units only: eight exits upgraded from 0.7.0 (native Mullvad, PIA and NordVPN, and
NordVPN through gluetun as an overlay exit and as a sidecar), drills from the native
exits' own namespaces, idle CPU 0.15 to 0.5 % of one core per exit (7.9 % at
0.7.0). Docker Engine on Linux, NetBird Cloud and client-held drills were not
tested at 0.8.0 ([testing](docs/testing.md#080)). Upgrade by following
[upgrading from 0.7.x](docs/operations.md#upgrading-from-07x): **Switchyard
first**, then the exits; the state directory and the `netbird-data` volume carry
over, the Compose files do not.

**Install: pull and run.**
- The image `ghcr.io/irashack/molebridge` (amd64 and arm64) is built and published
  by GitHub Actions on a release tag, signed with cosign (keyless), with SLSA
  build provenance and a per-architecture SBOM. A release is promoted from a
  release candidate without rebuilding, and only if a maintainer's acceptance
  run attested that the exact image passed the live drills. The release bundle
  (the Compose files pinned to the image by tag and digest, the `.env` examples
  and `routing/gluetun-preflight`) is signed and attested too. The verification
  order is in [setup](docs/setup.md#1-download-and-verify).
- One role per argument: `exit`, `panel`, `health`, `status`, `check-config`,
  `prepare-config`, `nordvpn-key`, `gluetun-auth`, `gluetun-post-rules` and
  `fix-blacklist`. The setup tools run as throwaway containers
  (`docker run --rm`), as yourself, writing only the paths you mount
  ([tools](docs/tools-reference.md)). The Python 3.10 requirement is gone.
- `doctor` and `recover` are removed. Start-time checks in the exit, `molebridge
  status` and documented host checks replace the first; `docker compose up -d
  --force-recreate` and a documented attachment procedure replace the second
  ([operations](docs/operations.md#recovery)).
- One `compose.yaml` for the native providers, with `PROVIDER` selecting the
  provider (`compose.pia.yaml` and `compose.nordvpn.yaml` are gone), plus
  `compose.gluetun.yaml` and `compose.sidecar.yaml`. `.env.example` has eighteen
  settings, down from thirty-six; the rest are overrides with defaults in the
  code ([configuration](docs/configuration.md)).

**The exit container.**
- `molebridge exit` is PID 1 and a supervisor: it reaps orphans, forks a worker
  that holds the routing contract and runs the provider logic, and starts the
  NetBird client, which is now inside the image (a pinned release, checked against
  a hash committed in the `Dockerfile`). `netbird`, `wireguard`, `applier` and
  `guard` are no longer containers.
- A progress lease replaces the gate in front of NetBird and the owner-record file
  and its `exit-run` volume. The worker may renew every 2 seconds only while the
  mutation owner, the kernel watcher and (gluetun) the mark and log monitors are
  making progress; if the supervisor sees no accepted renewal for `GUARD_GRACE`
  seconds (30 by default, 5 to 30), it stops NetBird, removes the interfaces it
  owns and exits non-zero so the restart policy starts the container again. The stop
  sequence has a 15-second budget; the exit status follows why it stopped
  ([the lease](docs/architecture.md#the-lease)).
- The `owner_record` check keeps its meaning for native exits and carries an
  `expires_at`. The supervisor, not the worker, writes `result.json`, republishes
  that check every 2 seconds, and on a lapsed lease or a dead worker writes a failure
  record ("exit owner stopped responding"), so a 0.7.0 reader sees the failure within
  the lapse time.
- The tunnel is brought up through the kernel's netlink interfaces: no `wg-quick`, no
  `wireguard-tools`, no `bash`, no shell at all. `PostUp` and `PreDown` stay in the
  config the tools write, are checked, and are read as route operations, never run.
- Repair is driven by the kernel's rule, route, link and address notifications, with a
  full pass every `ROUTING_RECONCILE_INTERVAL` seconds as the fallback. The default is
  now 30 (was 2), the range 2 to 60 and any whole number (was an even one); at 0.7 this
  pass was the repair.
- Capabilities: `NET_ADMIN`, `NET_RAW` and `DAC_OVERRIDE` (`DAC_READ_SEARCH` is gone).
- NetBird's settings, stored profile and ICE blacklist are checked before the daemon
  starts and the blacklist again after `netbird up`. A profile without the tunnel
  interface in its blacklist is refused, and the new `fix-blacklist` tool repairs it
  ([operations](docs/operations.md#netbird-interface-blacklist)). When no identity is
  found the exit says it will enroll a new peer.
- gluetun: the 0.7 gate's checks run in the exit: NetBird's fallback from advanced
  routing is read from its log, the overlay interface's mark is sampled every 2 seconds,
  and gluetun's control server must listen on loopback only. `routing/gluetun-preflight`
  stays, with an explicit mode from `MOLEBRIDGE_KIND` on the gluetun service
  (`overlay` requires the post-rules, `sidecar` refuses to start gluetun while they are
  mounted). **The 0.7 standalone form (three containers, no panel or server logic, any
  gluetun WireGuard provider) is gone:** the exit always runs the provider logic and
  accepts only the six registered gluetun providers.
- Switchyard is Go, in its own container. It checks its own isolation at start (no
  capabilities, not uid 0 unless `PANEL_ALLOW_ROOT=1`, the exit's state read-only) and
  refuses to run otherwise.

**Messages that changed.** Refusals now come from the Go binary: for example
`ROUTING_RECONCILE_INTERVAL must be 2..60 seconds`, and the tunnel-config refusal ends
`regenerate it with prepare-config (docs/setup.md)`. The line a NetBird refusal prints
still begins `NetBird gate:`. [Troubleshooting](docs/troubleshooting.md) quotes the
current ones.

**Tested.** Unit, fuzz and namespace-drill suites in CI, and a live pass on one Debian host
with rootless Podman 5.8 and Quadlet units: eight exits upgraded from 0.7.0 and healthy, and
the released image run through the drift, tunnel-loss and frozen-worker drills on the native
exits, from their own namespaces. `v0.8.0-rc.1` failed the PIA tunnel-loss drill (it stayed
fail-closed but did not recover by itself); `v0.8.0-rc.2` fixes that. **Not tested:** Docker
Engine and NetBird Cloud (dropped from acceptance by the maintainer), running the shipped
Compose files at all, live drills on the gluetun exits, and installing from the release bundle
on a clean host. The record, with the full list, is [testing](docs/testing.md#080).

## 0.7.0 (2026-10-11)

One status record, one judgment of it, and one way to change servers; and
an experimental second exit kind, the **gluetun sidecar**. Upgrade
**Switchyard (the panel) first**, then the exits in any order: a 0.6 panel
reads a 0.7 exit's healthy record as "verification failed"
("From 0.6.x to 0.7.0" in `docs/operations.md` at the v0.7.0 tag).

**Status: schema 2 and one verdict.**
- The applier's `state/applier/result.json` now carries `schema: 2`, the exit
  `kind` and `backend`, the `selection` (why the server is what it is, and
  the next automatic action), and **named checks** (`routing`, `netbird`,
  `owner_record`, `peer`, `handshake`, `egress`, `traffic_protection`,
  `app_attachment`), each `pass`, `fail`, `unknown`, `n/a` or `not-checked`,
  with the time it was measured and, for the peer, handshake and egress, the
  server it measured. `routing_ok`, `netbird_native`, `unreachable_fallback`,
  `exit_confirmed`, `egress_tier`, `handshake_age_s` and `mullvad_exit_ip`
  are gone from the record ([architecture](docs/architecture.md#the-status-record)).
- One function, `molebridge/verdict.py` `assess`, judges a record for the
  page, `/api/status`, the exit tabs, the browser, `/readyz`, the switch
  gate, monitoring and the doctor. Only a fresh pass counts as passed. A
  check's evidence expires after 150 s like the record's ("evidence
  expired"), a pass for another server never counts, and the server must be
  the one asked for: a 0.6 panel could show an acknowledged `ok` on another
  server as connected.
- The panel reads 0.6 records too (their checks shown as "not reported
  individually"). Unknown or newer versions ("unsupported status version"),
  and a record whose kind, provider or backend differs from the panel's
  configuration ("kind mismatch", "provider mismatch"), are never connected.
- The container health check is operational only: a fresh completed check
  and an intact namespace (on the overlay the tunnel interface, routing and
  NetBird, but no longer the peer, which the applier puts back itself).
  Whether the exit is verified, including on its `SERVER`, is the verdict's:
  the doctor reports it, with reason codes, and the health check no longer
  fails over it.
- A native tunnel that comes back without its peer gets the selection again
  at once (not within 90 s of the last change); with gluetun, whose own
  reconnects leave it peerless briefly, a missing peer is waited out for
  90 s.
- Gatus receives the verdict, never a switch in progress.

**Admission: one pipeline for every change of server.**
- The panel's request, `SERVER`, gluetun's restore, reconvergence and
  retries all go through the same gates, change and verification, with
  the source recorded in the record's `selection`. Its state is
  `state/applier/attempt.json`, written before any change, so a restart
  resumes it and never replays an interrupted change blindly
  ([the admission pipeline](docs/architecture.md#the-admission-pipeline)).
- **Failures retry on their own**, after 1, 2, 4 and 8 minutes, then every
  15. A switch that is applied but not verified (handshake, egress or the
  check service failing) is **re-checked, not switched again** while the
  live server is the one selected. Re-applying always inspects first, so a
  change whose answer was lost isn't made twice. Drift back to another
  server isn't corrected within 90 s of the last change, nor while a failed
  attempt waits for its retry. "Choose a server again to retry" is gone; a
  new request (Retry) still applies at once and starts the backoff over
  ([retries](docs/operations.md#retries)).
- An unlisted request is refused until the catalogue's server names change,
  and a malformed one until a new request. On gluetun the last verified
  server is still restored meanwhile, and the panel keeps showing the
  refusal.
- **PIA**: a refused login (HTTP 401/403 from PIA's token service) stops
  retries until the credential files change or Retry; a key registration
  refused with a reused token is asked once more with a fresh one. A
  handshake stale for 180 s re-registers the same region on the backoff; an
  egress-check failure alone never does. Port forwarding runs only while the
  verdict is connected.
- **gluetun**: while a switch is verified, gluetun's reconnection (its
  interface gone with rules 90 and 96 detached, an address before its rule
  94, old and new rule 94 together, the tunnel route not back yet) withholds
  readiness instead of aborting; anything else the guard would refuse aborts
  the switch.

**Panel.**
- `POST /select` answers **409** "A switch is in progress; wait for it to
  finish." while the exit is switching, after the CSRF check and the
  configured lock (403). A stale status doesn't block.
- `/api/status` adds `verdict`. `view`, and for a schema-2 record the 0.6
  diagnostic fields in `result` (derived from the verdict, null where
  unknown or not applicable), are deprecated and kept for one release.
- A 0.6 page still open in a browser keeps working until it reloads, within
  limits: its state, label and tier stay right, but a confirmation that
  wasn't measured shows as `false`, and an unmeasured routing check or
  fallback shows blank. "Not applicable", "not checked" and the named checks
  need the reload.
- Diagnostics lists every check by name, says who checks what Molebridge
  doesn't, and when the applier will re-check or retry. The tier and the
  egress address show only for a connected exit.
- `PANEL_EXITS` takes `id=provider/kind[:label]`; a single-exit panel reads
  `EXIT_KIND`. A sidecar on a native provider stops the panel at start.
- The page script has no status rules or wording of its own. Its first
  tests run under Node's own runner (`node --test panel/js-tests/*.test.js`),
  including 0.6.1's script against 0.7 answers.

**The gluetun sidecar (experimental).** `EXIT_KIND=sidecar` and
`compose.sidecar.yaml`: Switchyard and the applier select and verify servers
for an ordinary gluetun that other containers share, with no routing
contract and no NetBird ([gluetun sidecar](docs/gluetun-sidecar.md)). The
applier needs `NET_ADMIN` in gluetun's namespace. Mullvad and NordVPN
through gluetun can be verified; FastestVPN, IVPN, Surfshark and Windscribe
are shown as switched, never connected ("switched, egress unverified"),
because a sidecar can't compare the egress with the host's own address.
Traffic protection is gluetun's firewall and is reported as not checked by
Molebridge. The doctor checks which containers actually share gluetun's
namespace, through the engine, on Docker and rootless Podman, and without
Compose for Quadlet (`doctor --kind sidecar`). `recover` now exits 0 when
recovered and verified, 3 when recovered but not verified, and 1 when it
failed, for both kinds. The host helpers run through podman-compose too
(`--engine podman`), untested on a live host.

**Removed (as announced for 0.7.0):** the `routing/gluetun-rules` link, the
image's `/usr/local/lib/molebridge/gluetun-rules` and
`/custom-cont-init.d/10-exit-routing`, and the `GLUETUN_RULES` setting. Use
`contract-rules` and `CONTRACT_RULES`.

Tested with `pytest -q panel tools`, the Node panel tests and CI's container
and namespace drills, and live on rootless Podman: every exit of the
[0.7.0 pass](docs/testing.md#070-on-rootless-podman-at-d5a234a) (Mullvad,
PIA, NordVPN, gluetun and a gluetun sidecar), with client-held drills on the
NordVPN, Mullvad, PIA and gluetun exits. The pass found two defects, fixed
before release: a native tunnel that came back without its peer waited
90 seconds, and the health check still required a peer.

## 0.6.1 (2026-10-10)

A tunnel config check fix in the routing image and `tools/molebridge.py
check`. Update every native exit; the gluetun backend's guard doesn't read
the tunnel config.

- **The routing image now refuses field names in any spelling but the
  generators'.** `address`, `privatekey`, `allowedIPs` and every other
  spelling that differs from [the table](docs/configuration.md#the-tunnel-config)
  are refused with `unsupported field on line <n>`. `wg-quick` and `wg` read
  field names in any case, and so did the check, but `10-exit-routing` reads
  only `Address`: a lowercase `address` passed the check, then the rule
  installer missed it, and Mullvad and NordVPN exits stopped with
  `10-exit-routing: tunnel configuration needs an IPv4 Address`. With PIA,
  the rule installer run on its own and `tools/molebridge.py check` took
  such a file as an addressless config, leaving rules 94 and 98 to the
  applier, while `wg-quick` would still have assigned the address (the
  image's own check refused it there, as `Address on line <n> is not
  supported for PIA`). `10-exit-routing` now refuses an `Address` in
  another case (`10-exit-routing: tunnel configuration spells Address
  another way; write it as Address`), and `tools/molebridge.py check`
  refuses a PIA config with an address or peer in any case. Configs the
  generators wrote are unaffected.

Tested with `pytest -q panel tools` on macOS and `tools/check-exit-image.sh`
on OrbStack (Docker Engine 29.4.0). On the rootless Podman host in
[testing](docs/testing.md#the-routing-image-on-rootless-podman-at-0086fac),
the new check accepted all six live native configs (four Mullvad, one PIA,
one NordVPN); no live exit has run this release.

## 0.6.0 (2026-10-10)

- Add optional `SERVER`: a server hostname, or a PIA region id. When set,
  configuration wins over `desired.json` for native Mullvad, PIA, NordVPN
  and the gluetun backend, including gluetun restart restoration. Invalid
  or unknown names report a quoted failure rather than using a panel choice.
- Switchyard shows configured exits read-only, refuses selection posts and
  exposes the setting through `/api/status`, using the applier's existing
  status snapshot. Empty `SERVER` keeps panel selection unchanged.
- **Molebridge's own routing image.** The `wireguard` container is built
  from a digest-pinned Alpine 3.24.2 with `bash`, `iproute2`,
  `wireguard-tools` and `tini`, instead of LinuxServer's WireGuard image. Its
  entrypoint checks the settings and the tunnel config before anything
  changes, installs the routing contract before the tunnel exists (a failed
  install now stops the container instead of letting the tunnel come up),
  brings the tunnel up under supervision, retrying after 2 seconds and
  doubling to 60 while the container stays up and not ready, and stops
  within about 7 seconds, leaving the rules in place. Only `<EXIT_IF>.conf`
  is used. See "Start, supervision and stop" in `docs/architecture.md` at the v0.6.0 tag.
- **The tunnel config is checked against what the generators write.**
  `DNS`, `PreUp`, `PostDown`, `SaveConfig`, `FwMark`, a `Table` other than
  `off` and any other field are refused with a message that names the line
  (and the field, when it is one Molebridge accepts) and never prints the
  file. `molebridge-exit --check-config`
  (`docker compose run --rm --no-deps wireguard --check-config`) checks
  without changing anything. `tools/prepare-tunnel-config.py` now refuses
  more than one address per family and prefixes other than `/32` and
  `/128`. See [the tunnel config](docs/configuration.md#the-tunnel-config).
- **Native exits now repair drift.** Every `ROUTING_RECONCILE_INTERVAL`
  seconds (2 by default, even, 2 to 60) the exit puts back a deleted rule,
  fallback or tunnel route and removes an inserted rule at priorities 0–98
  or a foreign route in the exit table; a lost tunnel interface is brought
  back. Single deletions are contained by the remaining protections
  meanwhile; nothing is promised about traffic before an insertion is
  removed. See [drift and repair](docs/architecture.md#drift-and-repair).
- **New native rule 98**, `from <tunnel address> ipproto icmp unreachable`
  (`ipv6-icmp` for IPv6), backs up rule 94. With PIA the applier owns rules
  94 and 98: it adds both before changing the address, removes the old pair
  last, and repairs them on every pass.
- **Owner record.** The exit writes `/run/molebridge/exit-owner` on a new
  `exit-run` volume every 2 seconds. NetBird's gate and the applier count it
  as live only from the same boot and network namespace and at most 6
  seconds old; without it the applier reports `routing_ok` false and its
  health check fails. See "The owner record" in `docs/architecture.md` at the v0.6.0 tag; 0.8.0 replaced the file (below).
- **NetBird's gate stays in front of NetBird on native exits too.** It waits
  for the owner record and the whole contract, runs NetBird as its child in
  its own process group, and stops it as soon as the owner record isn't live
  or the guards have been incomplete for `GUARD_GRACE` seconds (30 by
  default, 5 to 30). Recovery is still `tools/molebridge.py recover`.
- **Compose.** `wireguard`: `cap_drop: [ALL]` with `NET_ADMIN` and
  `DAC_READ_SEARCH` (which lets rootful Docker read your mode-0600 tunnel
  config), `no-new-privileges`, read-only root, a tmpfs on `/run`, the
  `exit-run` volume, 15 seconds to stop. `netbird`: `init: true`, 15 seconds
  to stop, the routing settings, and `routing/contract-rules` and `exit-run`
  mounted read-only. `applier`: `exit-run` read-only. `PUID` and `PGID` are
  no longer read. NetBird 0.80.0.
- `routing/gluetun-rules` is now `routing/contract-rules`; the old name stays
  as a link until 0.7.0. The gluetun backend's `guard` runs the image's own
  entrypoint; `/custom-cont-init.d/10-exit-routing` stays in the image as a
  link until 0.7.0.

Upgrading from 0.5.3: build the routing image and check your tunnel config
with it before you recover; see [operations](docs/operations.md#upgrades).

Tested live on rootless Podman only, at `0086fac` (this release's code):
- six native exits (Mullvad, PIA, NordVPN) and a gluetun exit were upgraded
  in place;
- on the NordVPN exit: drift repair, tunnel loss, a stale owner record and
  `SERVER`.
No client traffic ran during the drills. Docker has no live pass with the
routing image: CI builds it and runs its start, repair, bring-up failure
and stop cases (`tools/check-exit-image.sh`) and the namespace drills under
busybox sh. See [the routing image on rootless Podman](docs/testing.md#the-routing-image-on-rootless-podman-at-0086fac).

## 0.5.3 (2026-10-09)

Applier only, like 0.5.2. Update every exit; a Switchyard panel on 0.5.1 or
0.5.2 works with 0.5.3 exits.

- **A failed switch no longer outlives a request that has been met.** A
  failed switch kept its message ("Peer update failed; choose a server again
  to retry.", "Switch verification timed out; …", "Routing changed during the
  switch; …") until someone chose a server again, even when the requested
  server was live and passing every check. With PIA this left an exit
  `failed` indefinitely: when a tunnel's handshake went stale, the applier
  re-registered the region on its own; if PIA's API refused that while the
  tunnel recovered on its existing registration, the handshake stayed fresh,
  so no later re-registration ran and the message stayed. Now, once a check
  has published the failure, the first later check that finds the requested
  server live and passing every check reports `ok` and logs that it cleared
  the failure. A failure while another server is live, or while any check
  fails, stays until a new request, as before; nothing is applied again
  automatically. See [architecture](docs/architecture.md) and
  [troubleshooting](docs/troubleshooting.md).

Tested: unit tests for clearing a met failure, publishing it first, and
keeping it while another server is live, a check fails, a request is
pending or none is set, including PIA's refused re-registration followed by
a recovered tunnel. The PIA case was seen live and cleared there by
selecting the same region again; the fix itself was not run on a live exit
before release.

## 0.5.2 (2026-10-09)

Applier only: the panel, routing, NetBird gate and Compose files are
unchanged from 0.5.1 apart from the panel's version string. Update every
exit; a Switchyard panel on 0.5.1 works with 0.5.2 exits.

- **One unanswered egress check no longer fails an exit.** Each health check
  asks the provider's egress check (Mullvad's `am.i.mullvad.net`, PIA's
  status call, NordVPN's insights, or the IP echo services at the `tunnel`
  tier) through the tunnel, with a 10-second limit and, until now, no second
  try. One connection that timed out made a healthy exit report `failed`
  until the next check a minute later, and turned Switchyard's `/readyz`,
  which needs every exit verified, red with it. Live exits saw this up to a
  few times an hour, each time one connection that timed out while the next,
  seconds later, succeeded. Now a check that gets no usable answer asks once
  more after 10 seconds. An answer that does not confirm the egress still
  fails at once, and now ends the check before any further request, so a
  later timeout can't turn it into a retry. Routing protection, NetBird's
  mode, the peer count and a missing or stale handshake fail without a second
  try, as before. A switch still verifies through its own loop and never
  reports `ok` before a check passes. No retry follows a first attempt that
  took over 15 seconds, and the second attempt starts no request after 30
  seconds, so a check stays well inside the 150 seconds after which a result
  counts as unknown. The applier logs each retry. See
  [status reporting](docs/architecture.md#status-reporting).
- Mullvad's check stops at the first family Mullvad says is not its exit,
  and the `tunnel` tier at the first family that fails, with echo answers
  that disagree, or that the catalogue doesn't list as the server's exit,
  failing before the host's own address is measured.
- With the gluetun backend, measuring the host's own address now ends within
  its 10 seconds in all: before, each of up to four addresses, the TLS
  handshake and each read had 10 seconds of their own.
- At the `tunnel` tier, a failed measurement of the host's own address is no
  answer: it is asked once more and then reports "Tunnel inspection or egress
  check failed." instead of "Tunnel egress did not pass the tunnel checks.",
  which now means the answers failed the checks.

Tested: unit tests for the retry, for each case that must not retry
(including a negative answer followed by a request that times out), and for
the time bounds (including NordVPN's cache retry inside a second attempt),
with Mullvad, PIA, NordVPN, the `tunnel` tier and each egress check through
gluetun. Not run on a live exit before release.

## 0.5.1 (2026-10-08)

Switchyard and documentation only: the applier, routing, NetBird gate and
Compose files are unchanged from 0.5.0.

- **gluetun exits look like gluetun.** In the provider style, an exit on the
  gluetun backend takes gluetun's dark slate, with the provider behind it as
  the accent: Mullvad's yellow, NordVPN's blue, Surfshark's teal, and a
  color each for FastestVPN, IVPN and Windscribe. Before, a Mullvad or
  NordVPN exit through gluetun looked like the native one, and the other four
  providers had no colors at all, so their pages lost their card
  backgrounds.
- **Switchyard finishes a switch in place.** The page no longer reloads when
  a switch completes or fails, or when another tab switches the exit: the
  current exit crossfades to the new server where the browser supports view
  transitions. A failed switch now shows the server the exit is actually
  on, which the pin and latency follow; before, the page could keep showing
  the server that failed.
- **Switchyard shows how fresh the status is** ("checked 20 s ago", live),
  and offers **Copy** for a verified egress address.
- **Smoother panel.** Latency values no longer resize chips and rows when
  they arrive; their signal bars grow in. The first measurement shows
  placeholder rows, and Retest keeps the previous answers dimmed instead of
  collapsing the list. Countries unfold when opened (where the browser
  supports animating `<details>`), the exit tabs' points swing over, and
  pressing a switch or filter gives feedback. All of it stops when the
  system asks for reduced motion.
- **Panel fixes.** Searching after a country's "Fastest" line appeared
  could throw and stop filtering. A status poll no longer replaces a
  button that has keyboard focus. Saved and Fastest show NordVPN's and
  gluetun's short server names. Choosing the current PIA region works with
  JavaScript too, as the docs said. While switching, the page names the
  applier's real limit (90 seconds with gluetun, not "about a minute").
  Arming a region on a phone no longer adds a line. Servers from gluetun's
  list show their country's flag. Sign-in and error pages in the provider
  style now have their colors.
- **Documentation review.** Corrections across the guides after a review
  against the code: recreating gluetun's namespace with `recover` after
  rotating its key or changing its post-rules, which verification steps
  apply to the gluetun backend, the gate's real timing, the switch
  timeouts, backups with gluetun, and stale testing claims. New diagrams in
  [architecture](docs/architecture.md), new screenshots, and testing
  records for NordVPN and the gluetun backend on rootless Podman.
- `tools/preview-panel.py --exits` adds a NordVPN exit and two gluetun exits
  (Mullvad and Surfshark) to the preview.

Tested: unit tests, and the panel in the local preview
(`tools/preview-panel.py`) on desktop and phone widths, light and dark,
both styles, with switches that succeed and fail. Not yet on a live exit.

Upgrading from 0.5.0: pull, then recover; nothing in `.env` changes. Only
the panel behaves differently, so a Switchyard can move to 0.5.1 while its
exits stay on 0.5.0.

## 0.5.0 (2026-10-08)

- **Provider registry.** Everything Molebridge knows per VPN provider is now
  one entry in `molebridge/providers.py`, which the applier, the panel and
  the doctor read. Nothing changes for Mullvad or PIA exits.
- **Egress tiers.** `result.json` gains `egress_tier`: `provider` when the
  provider's own endpoint confirmed the egress (`exit_confirmed`, unchanged),
  `tunnel` when only Molebridge's tunnel checks did, for a provider without
  its own check, or null. The panel labels a tunnel-verified exit "tunnel
  checks only", and `/readyz` passes for both. No native provider uses the `tunnel` tier;
  FastestVPN, IVPN, Surfshark and Windscribe through the gluetun backend do.
  It is covered by unit tests only. See
  [status reporting](docs/architecture.md#status-reporting).
- **NordVPN, experimental.** `PROVIDER=nordvpn` with
  `EXIT_IF=nordvpn` and `COMPOSE_FILE=compose.yaml:compose.nordvpn.yaml`.
  `tools/nordvpn-key.py` fetches the account's NordLynx key once, from an
  access token read from a mode-0600 file or standard input, and writes the
  tunnel config; the exit stores no token. One key and the address
  `10.5.0.2/32` work on every server; IPv4 only, so forwarded IPv6 hits the
  unreachable fallback, as with PIA. The panel lists servers by country and
  city, and labels NordVPN's virtual locations. The applier identifies the
  current server by the live peer's endpoint, because NordVPN shares server
  keys within a location, and confirms egress with NordVPN's insights check,
  asking again for up to a minute when a cached answer looks stale. See
  [providers](docs/providers.md#how-nordvpn-differs).
- The applier's `/tmp` grows from 16 MB to 48 MB, room for NordVPN's server
  list download (up to 32 MiB). It uses memory only while a download is
  there.
- **Bounded latency probing in the panel.** Opening a country times every
  server in it up to 128, and a larger country (NordVPN has some) on a fixed
  sample of 128; one request names at most 256 servers. The panel runs one
  latency request per exit and four in all, answering 429 with `Retry-After`
  beyond that, and a page sends one request at a time. See
  [Switchyard](docs/switchyard.md). Covered by unit tests; not run live.

Tested: unit tests for the registry, both tiers and NordVPN, including the
NordVPN parsers against fixtures with documentation addresses, and one live
NordVPN pass at `036e1cc` on macOS with OrbStack: key setup, the server list,
switches, NordVPN-confirmed egress from a client, IPv6 blocked
([testing](docs/testing.md#nordvpn-pass-at-036e1cc)). Not run live: the
insights cache retry, the `tunnel` tier, the panel with NordVPN's list,
rootless Podman, and the fail-closed drills.

- **Experimental gluetun backend.** With `compose.gluetun.yaml`, gluetun
  owns the tunnel and brings its WireGuard providers; the panel can select
  servers for FastestVPN, IVPN, Mullvad, NordVPN, Surfshark and Windscribe
  through gluetun, shown with the provider's name and "via gluetun". Live
  passes with NordVPN on Docker; other providers and rootless Podman are
  untested. What it consists of:
  - Molebridge's routing image runs beside gluetun as a guard sidecar. It
    installs the same fail-closed rules plus rules 88/89 and a host table for
    NetBird's control traffic, and rules 91/92 so that what the exit itself
    sends to the overlay, such as the ICMP errors path MTU discovery needs,
    uses NetBird's overlay route and never gluetun's tunnel, and rules
    102-104 so that what the exit itself sends leaves only through gluetun's
    tunnel (gluetun's WireGuard socket excepted), even while gluetun
    reconnects. It puts
    everything back every few seconds as gluetun recreates its interface.
  - NetBird's gate refuses settings that turn off NetBird's control mark,
    waits for the whole guard (checked with the guard's own definitions),
    and stops NetBird, exiting non-zero, if it runs without the mark or the
    guard stays broken. Its deadlines run on the kernel's boot clock.
  - The applier reads gluetun's own server list (read-only, never
    downloaded), selects servers through gluetun's control server, and
    verifies the peer, the handshake, the guard and egress: Mullvad's and
    NordVPN's own checks, the tunnel checks for the others. It puts the last
    verified server back after gluetun restarts, and asks gluetun to
    refresh its server list once at start when that list is old.
  - `python3 tools/molebridge.py gluetun-auth` writes gluetun's role file
    and the applier's API key, which is full gluetun administration;
    `gluetun-post-rules` writes gluetun's firewall post-rules, in forms
    gluetun's own rule parser accepts. Neither calls the container engine,
    so both work with Docker and podman-compose; `gluetun-post-rules` reads
    `.env`. `doctor` and `recover`
    support the gluetun file.

  See [providers](docs/providers.md#the-gluetun-backend),
  [architecture](docs/architecture.md#gluetun-backend) and
  [configuration](docs/configuration.md#gluetun-backend). The default
  backend is unchanged.
- **A standalone guide** to [gluetun as a NetBird exit
  node](docs/gluetun-netbird-exit.md), with only Molebridge's routing guard
  and NetBird gate beside gluetun, no panel or applier: the rules, the gate,
  gluetun's settings and post-rules, choosing servers through gluetun's
  control server, and drills that need no applier.
- `recover` waits up to 180 seconds for the applier to verify the exit
  before it runs the doctor, and names the step that failed.

Tested, for the gluetun backend: unit tests for the guard and gate against a
stand-in for iproute2, the validator, the post-rules and the applier against
fakes of the kernel and gluetun's control server, and namespace drills with
gluetun's and NetBird's rules simulated, forwarded packets carrying marks 0,
0x1bd00, 0x1bd21 and 51820, and the exit's ICMP errors to clients; gluetun's
behavior was read in the v3.41.3 source. Live passes with NordVPN on Docker at
`a3bb14f` ([testing](docs/testing.md#gluetun-backend-pass-at-a3bb14f)), and at
`4933360` for the standalone form
([testing](docs/testing.md#gluetun-backend-at-4933360-and-the-standalone-form)).

Documentation fixes:

- **Rootless Podman direct path.** Publishing NetBird's WireGuard port keeps
  remote devices relayed under rootless Podman with pasta;
  [operations](docs/operations.md#exits-on-a-private-container-network) now
  gives `wireguard` its own pasta network that forwards the port. Tested as
  a Quadlet unit on one Debian host with a LAN client; a remote client, the
  podman-compose form and Docker are untested.
- **Restrictive Wi-Fi.** [Troubleshooting](docs/troubleshooting.md#clients)
  covers a healthy exit with a device that loads nothing on a network that
  breaks NetBird's QUIC relay connection, and how to make the NetBird
  client prefer WebSocket. Confirmed on macOS only.
- **DNS.** [Operations](docs/operations.md#dns) corrects what a DNS leak
  test shows through a Mullvad exit, from one observation (PIA untested),
  and says that a NetBird nameserver group served by the exit gets no
  answers.

Upgrading from 0.4.1: pull, then recover. Existing Mullvad and PIA exits
need no `.env` changes. NordVPN and the gluetun backend are new opt-in
paths: see [providers](docs/providers.md#how-nordvpn-differs) and
[the gluetun backend](docs/providers.md#the-gluetun-backend).

## 0.4.1 (2026-10-08)

A security release: overlay traffic is never delivered to the exit itself,
and NetBird must run in the configuration Molebridge supports. See the
[security advisory](https://github.com/irashack/molebridge/security/advisories/GHSA-7642-v6p6-wjfj)
for this release.

- **Overlay traffic is never delivered to the exit itself.** Routing
  initialization replaces the kernel's priority-0 `lookup local` rule with
  `not iif wt0 lookup local` at priority 1, in both address families. Packets
  arriving over NetBird are routed into the tunnel like any other forwarded
  traffic, or dropped; loopback and the host's other interfaces keep local
  delivery. NetBird's entrypoint gate and the applier's routing check require
  the new rule. See [architecture](docs/architecture.md#routing-contract).
- **NetBird must run with kernel WireGuard and its kernel firewall.**
  Molebridge supports only NetBird's daemon mode, the default profile and the
  settings in [configuration](docs/configuration.md#env). `compose.yaml` sets
  `NB_DISABLE_USERSPACE_ROUTING=true`. NetBird's entrypoint gate refuses to
  start it when that is missing, when userspace or netstack mode is forced,
  when a NetBird profile other than the default one could be used
  (`NB_CONFIG`, `NB_PROFILE`, foreground mode, or an active profile other
  than `default`), when Rosenpass is enabled in the environment or the stored
  profile, or when the stored profile names a WireGuard interface other than
  `OVERLAY_IF`. The applier's health check and the doctor fail unless the
  overlay interface is a kernel WireGuard link and NetBird's kernel firewall
  is in place; `result.json` gains `netbird_native`. See "NetBird requirements" in `docs/architecture.md` at the v0.6.0 tag.
- **Rosenpass, NetBird SSH, DNS nameservers and domain routes are not
  supported on the exit peer.** Leave them off for it; Rosenpass stops NetBird
  from starting. See [requirements](docs/prerequisites.md#netbird).
- The exit no longer answers pings to its own overlay address. NetBird 0.79.0
  doesn't use them.

Upgrading from 0.4.0: NetBird refuses to start after the upgrade if your
setup uses a setting 0.4.1 no longer supports, so check these first. The
fixes are in [troubleshooting](docs/troubleshooting.md#startup).

- Your Compose override and `secrets/netbird.env` set none of the NetBird
  variables the gate refuses ([configuration](docs/configuration.md#env)),
  such as `NB_FORCE_USERSPACE_FIREWALL`, `NB_USE_NETSTACK_MODE`,
  `NB_CONFIG`, `NB_PROFILE` or `NB_FOREGROUND_MODE`.
- Rosenpass is off. If you ever brought the peer up with
  `--enable-rosenpass`, turn it off in the stored profile.
- The peer uses NetBird's default profile, and that profile names the same
  interface as `OVERLAY_IF`. If you changed `OVERLAY_IF` after the peer
  enrolled, change one of them back.
- NetBird SSH, DNS nameservers, domain routes and Rosenpass are off for the
  exit peer in your NetBird dashboard
  ([requirements](docs/prerequisites.md#netbird)).

Then pull and recover, which rebuilds the routing image and recreates
NetBird with `NB_DISABLE_USERSPACE_ROUTING=true`, which `compose.yaml` now
sets. No `.env` changes are needed. The doctor checks the NetBird settings
and the stored profile afterwards.

Tested: unit tests for the routing validator, the gate and the health check,
and the isolated namespace drills in `tools/check-routing.sh`, which cover
local delivery from the overlay in both address families. A live PIA test
exit with Docker ran the routing and NetBird checks at `0f9511a`; see
[testing](docs/testing.md#routing-and-netbird-checks-at-0f9511a). The gate's
other refusals on a running peer, a Mullvad exit and rootless Podman with
these checks are untested; the NetBird settings were checked against the
0.79.0 source.

## 0.4.0 (2026-10-07)

- **Optional sign-in for the panel** with OpenID Connect. Set
  `PANEL_OIDC_ISSUER` and the panel signs people in through your identity
  provider, and each person sees only the exits their groups grant
  (`PANEL_ADMIN_GROUPS`, `PANEL_ACCESS`). A sign-in lasts `PANEL_SESSION_TTL`
  seconds (one hour by default). See
  [panel access](docs/access.md#sign-in-with-openid-connect) and
  [per-person exits](docs/switchyard.md#per-person-exits).
- **The panel now makes HTTPS requests to the identity provider** when sign-in
  is on, and the panel container needs a route to it. The ID token's signature
  is not checked; the panel relies on the verified TLS connection to the token
  endpoint instead, as OpenID Connect Core 1.0 section 3.1.3.7 allows. See
  [architecture](docs/architecture.md#sign-in) for what that trusts.
- **A PIA exit registers on its own after PIA's API comes back.** When a
  recreated tunnel's first registration failed (for example while PIA's
  login API was down), the applier never retried, because the tunnel had no
  address yet and the retry waited for one. It now retries the requested
  region every five minutes until it registers, as it already did for a
  stale handshake.

Without `PANEL_OIDC_ISSUER` the panel behaves as in 0.3.0, with no login. The
new settings are in [configuration](docs/configuration.md#panel-sign-in).
Upgrading from 0.3.0: pull, then recover. No `.env` changes are needed.

Tested: unit and integration tests against a fake issuer, and a live pass with
Pocket ID v2.16.0 as a public client: an admin sign-in, a switch verified by
the applier, and the signed-out behavior through a proxy. Sign-in by someone
granted only some exits has not been observed live; see
[testing](docs/testing.md#sign-in-pass-at-62a0170). The PIA retry: unit
tests, and a live exit that registered by itself once PIA's login API
recovered; see [testing](docs/testing.md#pia-registration-retry-at-8587542).

## 0.3.0 (2026-09-27)

- **PIA as a second provider** (`PROVIDER=pia`). You pick a region, not a
  server. The applier holds the PIA login and registers the tunnel key on
  each switch. IPv4 only. Optional port forwarding to one overlay device is
  off by default. See [providers](docs/providers.md).
- **Switchyard, one panel for several exits** (`PANEL_EXITS`). There is one
  tab per exit, each showing its state and where it exits. See
  [the panel guide](docs/switchyard.md).
- **Provider styling.** Each exit is drawn in its provider's colors and
  layout: Mullvad's country → city → server tree, and PIA's flat region list.
  `PANEL_STYLE=dashboard` keeps the previous neutral look.
- The panel's default title is now **Switchyard**. Set `PANEL_TITLE` to keep
  the old one.
- The panel shows latency as signal bars, and an empty state when a search
  matches nothing.
- `tools/preview-panel.py` serves the panel against fake exits, for working on
  its look.

Upgrading from 0.2.0: pull, then recover. The applier image must be rebuilt
because it gained nftables. Existing Mullvad deployments need no `.env`
changes.

Tested: PIA on the rootless Podman host (first start, recreation, a client
held on the exit through a tunnel-down drill, IPv6 and LAN isolation, region
switches); Switchyard serving a Mullvad and a PIA exit on that host. Not
tested live: PIA port forwarding (it is covered by the isolated drills only).

## 0.2.0 (2026-09-25)

A panel release. Routing, the tunnel configuration, Compose networking and
the NetBird container are unchanged.

- Saved servers: pin with the star, and recent servers are listed too. They
  are stored in each browser, never on the exit.
- A "Fastest" row in each fully measured country.
- Switch progress, a Retry button for failed switches, and protection against
  re-requesting a switch that is already running.
- Hosting filters (Mullvad-owned, RAM-only), shown only when they would narrow
  the list.
- Light and dark themes (`PANEL_THEME`).
- Screen-reader announcements, Escape to cancel, visible focus and
  reduced-motion support.

## 0.1.0 (2026-09-24)

First public release: a Mullvad exit for a NetBird mesh, run as one Compose
project.

- Forwarded client traffic can leave only through the WireGuard tunnel.
  Unreachable fallback routes for each address family and a terminal routing
  rule keep it closed if the tunnel, its route or its lookup rule disappears.
- A privileged applier checks each request against its own relay catalogue.
  The panel has no capabilities and only writes the desired server.
- Freshness-aware status (`/readyz`), host-side `doctor` and `recover`, and
  optional Gatus pushes.
- Docker Engine with Compose, or rootless Podman with podman-compose.
