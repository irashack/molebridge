# Testing

This page records tests on real hosts and the gaps that remain. Unit tests
and isolated Linux namespace drills in CI do not establish that a whole
NetBird deployment works with any provider or backend.

Published hashes below map to identical trees from before the metadata-only
history rewrite: `ae95c33` → `1390860`, `984a703` → `336d904`, and
`afa8594` → `4739352`; their quoted CI runs used the old hashes. The panel
switcher revisions were replaced by a rebase merge, also with identical trees:
`07c7b41` → `56ac2cc` and `0d518e4` → `40c461c`.

Sections below the 0.9.0 and 0.8.0 ones record what ran at earlier revisions, and use the
container and tool names of those releases (`wireguard`, `netbird`, `applier`,
`control-panel`, `tools/molebridge.py doctor`). They are the history of what was
tested, not instructions; the current commands are in the other pages.

## 0.9.1

0.9.1 changes the gluetun backend's server-list refresh (it reports why it
waits, and a control-server failure counts as a try), adds the
`gluetun-preflight` tool and `fix-blacklist`'s `--add` and
`--clear-external-ip-map`. Run so far: `go test ./...`, `go vet ./...` and
`gofmt -l` pass on the 0.9.1 branch with Go 1.27.2, with a test for each
waiting path and each new option. Not run: the namespace drills (nothing in
routing, the tunnel or the mutation owner changed), a live exit on any
platform, and the new tool in a Kubernetes init container. The 0.9.0 and 0.8.0
records below still hold for everything else.

**v0.9.1-rc.1, live on Kubernetes (k0s with Cilium), 2026-10-16.** Molebridge's
CI, the namespace drills included, passed on the candidate's commit. Every exit
of one deployment ran the candidate: native Mullvad, PIA and NordVPN overlay
exits, a gluetun overlay exit and a gluetun sidecar with NordVPN, and a PIA
native sidecar beside qBittorrent. All reported `ok` after the upgrade. Both
gluetun pods took their preflight from an init container running
`gluetun-preflight`, and gluetun started through it. The fault the release was
for was then reproduced on purpose: the gluetun sidecar's server list was moved
aside, so its new pod started from gluetun's built-in list (data from
2024-03-21) beside the exit's kept state. In 25 minutes the exit asked for no
refresh and `server_list_update` stayed null: it had judged its own earlier,
fresh catalogue. rc.2 fixes that.

## 0.9.0

0.9.0 adds the [native sidecar](native-sidecar.md) (`EXIT_KIND=sidecar` with
`TUNNEL_BACKEND=native`, `compose.native-sidecar.yaml`) and the `port-sync` role.
The live acceptance of the first candidate is recorded below, under Live
acceptance. Nothing changes for the overlay exits and the gluetun sidecar, and
the 0.8.0 record below is still the record for them.

### Run so far

| What | How | Where and what |
|---|---|---|
| Unit tests and `go vet` | `go test ./...`, `go vet ./...` | Pass on the 0.9.0 branch, Go 1.27.2 |
| Namespace drills | `go test -tags drill ./internal/...` | Passed in a privileged rootful Podman 5.8.6 container on Debian forky/sid, kernel 7.2.8 (amd64), including the drills new for the native sidecar, below. All 33 test packages, drills included, passed in one run at revision `fb381b2` of the 0.9.0 branch, and the two packages changed after it (`internal/netx`, `internal/exit`) again at `3e60c23` |

The new drills, for the native sidecar:

- The contract installs exactly, both from a clean namespace and from one that
  kept a previous run's rules.
- Every rule deleted, and a `lookup main` rule inserted at priority 50, is
  repaired within the 250 ms bound.
- With the tunnel route absent, an unmarked send fails, and a LAN send and a
  control-marked send leave by the host interface.
- The firewall (two tables, `inet molebridge_sidecar` and
  `inet molebridge_sidecar_backstop`) installs, is replaced atomically with a new
  port, and a deleted rule or a flipped policy is detected.
- At packet level: an unmarked socket bound to the host interface is dropped;
  LAN and control-marked sends pass; the tunnel passes; inbound on the tunnel to a
  port other than the forwarded one is dropped.
- With the DNS rules (`SIDECAR_HOST_RESOLVERS` set): an unmarked UDP send to a LAN
  address on port 53 or 853 is refused and never arrives, one to port 54
  arrives, a control-marked send to port 53 arrives, and a send into the tunnel
  on port 53 leaves. A firewall installed without the rules reads back as
  different.
- IPv6 on the host link, with the firewall's ICMPv6 rule (neighbour discovery
  only; see [the firewall](native-sidecar.md#the-firewall)), on the same kernel
  and container as the drills above:
  - A capability-free UDP sender (every capability dropped, `no_new_privs`)
    bound to the host interface and sending to `ff02::1`, and another sending to
    `fe80::1`, are dropped: zero packets reach a counter on the outside. With
    the same destination listed in `SIDECAR_LAN_CIDRS`, the same sender does
    reach the outside.
  - Neighbour discovery works without static entries: with the neighbour caches
    flushed on both sides, a ping to a LAN-listed IPv6 address succeeds and the
    neighbour entry is a discovered one, not `PERMANENT`.
  - A capability-free sender bound to the host interface sends continuously
    while the main table is deleted and repaired, and again while the backstop
    table is: zero packets reach the outside in either case. The control, with
    both tables deleted (two faults, outside the guarantee), does reach it.
- The end-to-end drill (`internal/exit/drill_native_sidecar_test.go`), on the
  same Debian forky/sid, kernel 7.2.8, Podman 5.8.6 privileged container as the
  other drills: the real `molebridge` binary runs as a native sidecar in a
  namespace, with a tunnel config whose peer does not exist, and counts what
  reaches a destination outside by the host path. It checks that:
  - `molebridge health --guarded` passes once the guards are in;
  - unbound and `eth0`-bound pings to a destination outside the LAN prefix
    never arrive outside, and the LAN gateway answers;
  - with `SIDECAR_HOST_RESOLVERS` naming the LAN gateway, an application's UDP
    to it on port 53 or 853 is refused and nothing arrives on 853, while the
    exit's own lookups reach it on 53 by the host path, whatever the
    namespace's `/etc/resolv.conf` names;
  - the tunnel's handshake leaves by the host path, through its fwmark;
  - a deleted firewall table is reinstalled and the reinstall is logged, and
    the namespace has both tables (`inet molebridge_sidecar` and
    `inet molebridge_sidecar_backstop`) again afterwards;
  - after a killed worker the tunnel link is gone, the rules and both firewall
    tables stay, the failure record marks the five required checks `unknown`, and
    nothing leaks;
  - a second run in the same namespace ends with one copy of each firewall
    table and of each rule;
  - a requested stop exits 0 and leaves the guards in place.

The drill run did not use a live provider, a container engine's networking or a
cluster: it is a kernel in a disposable namespace, and the end-to-end drill's
peer never answers. It does not show that a real
tunnel comes up, that PIA's registration and port forwarding work against PIA, or
how an engine's DNS and published ports behave.

### Live acceptance

The acceptance policy for 0.9.0 (`tools/acceptance-policy.json`) names a
Kubernetes platform and a native-sidecar kind, with an upgrade from 0.8 as one of
its drills.

#### v0.9.0-rc.2, 2026-10-16

The candidate `ghcr.io/irashack/molebridge:v0.9.0-rc.2`, index digest
`sha256:812801af2fae2df9f185475ad84197ebcd914ddf9a1826f5851eae142e610048`
(commit `bf8c5fc`: rc.1 and the `port-sync` login fix below), signature
verified with cosign, on the same host, replacing rc.1 on every project with
no setting changed. Every project came back healthy with its required checks
passing.

- **port-sync**, live against qBittorrent 5.2.4: on a fresh start it logged
  `no forwarded port yet`, then `qBittorrent listens on 37336; set to 51583`
  once PIA forwarded a port; a TCP connection from the host's own uplink to
  PIA's exit address and that port reached qBittorrent.
- **Drift** on the native overlay exits (Mullvad, PIA, NordVPN), as at rc.1:
  repaired in 10 to 13 ms.
- **Tunnel loss** on the same three: the exit table held only its unreachable
  fallback until the tunnel was back (0.8 to 1.4 s); a fresh verified egress
  1.3 to 8.2 s after the deletion.
- **Lease lapse** on NordVPN: NetBird stopped 32.3 s after the worker froze,
  the exit stopped with exit 1 and the guards in place, and it reported a
  verified egress 104.8 s after the freeze.
- **The native sidecar in its pod**: IPv4 rules 97, 96 and 88 and IPv6 rule
  97 deleted one at a time were back in 7 to 9 ms; the firewall's main table
  deleted was back in 0.9 s and its backstop in 2.0 s (one 2-second check),
  the other table enforcing meanwhile; nothing in the pod restarted.
- **A recreated pod sandbox**, between rc.1 and rc.2 (a CNI change on the
  node restarted the pod): the new network namespace had only `eth0`, `lo`
  and the tunnel, `molebridge health --guarded` passed before qBittorrent
  started, and the exit reported `ok`.

#### v0.9.0-rc.1, 2026-10-16

The candidate `ghcr.io/irashack/molebridge:v0.9.0-rc.1`, index digest
`sha256:850c1ddde82155e164b24af89f691de859c1c0805126ec2b70fcac0dfea561ed`
(commit `ab031d7`, signature verified with cosign against the release
workflow), pulled from the registry on the maintainer's home server (Debian, kernel
7.2.8, amd64).

**Upgrade from 0.8.** Every 0.8.0 project there moved to the candidate with no
setting changed: the native Mullvad, PIA and NordVPN exits, the gluetun
overlay exit, the gluetun sidecar, three more native exits and Switchyard, as
rootless Podman Quadlet units. Each came back healthy with its required checks
passing.

**Drills on the native overlay exits** (Mullvad, PIA, NordVPN), from the exit's
namespace:

- Drift: IPv4 rules 97, 95 and 1 and IPv6 rule 97 deleted one at a time, and a
  foreign `lookup main` rule added at 96: each repaired in 13 to 17 ms
  (polling included).
- Tunnel loss: the tunnel interface deleted. The exit table held only its
  unreachable fallback until the tunnel was back (0.2 to 1.2 s), and each exit
  reported a fresh verified egress 4.8 to 8.0 s after the deletion.
- Lease lapse on NordVPN: the worker frozen with SIGSTOP. NetBird stopped 31.8 s
  later, the exit removed the interfaces it owns ("the routing guards stay in
  place") and stopped with exit 1; the unit restarted it and it reported a
  verified egress 104.7 s after the freeze.

**The native sidecar on Kubernetes**: k0s with Cilium (pod MTU 1280, a /32 on
`eth0`), one pod: the exit as an init container with `restartPolicy: Always`
and `molebridge health --guarded` as its startup probe, the official
qBittorrent 5.2.4 image (libtorrent 1.2) as uid 1000 with no capabilities,
and `port-sync`. PIA, `ca_ontario`, port forwarding on;
`SIDECAR_LAN_CIDRS` the pod range only, `SIDECAR_HOST_RESOLVERS` the cluster's
DNS service, the pod's resolvers PIA's (`dnsPolicy: None`). From inside the
pod's namespace, as uid 1000 with no capabilities:

- the exit's record: `ok`, routing, traffic protection, peer, handshake and
  egress passing, a forwarded port;
- an unbound request leaves with PIA's address, not the host's; one bound to
  `eth0` gets nothing;
- DNS to PIA's resolver through the tunnel answers; DNS to the cluster's DNS
  service and directly to a cluster DNS pod is dropped; the pod range answers;
- the policy rules are the native sidecar's (88, 89, 90, 93, 94, 96, 97, 98);
- the application's clients (other pods, the cluster's gateway, a host-network
  forwarder) reach it, and nothing restarted.

**Failed: `port-sync` against qBittorrent 5.2.** qBittorrent 5.2 answers a good
login with HTTP 204 and no body; rc.1 accepted only 200 `Ok.`, so it logged
`qBittorrent answered the login with HTTP 204` every interval and never set
the listening port. Fixed after rc.1 (204 is a good login, 401 a refused one).

Not drilled live at rc.1: the native sidecar's own drift, tunnel-loss and
lease-lapse drills (the namespace drills above cover them), a sandbox
recreation, and Mullvad or NordVPN as native sidecars.

### Not tested at 0.9.0

- The native sidecar under Docker or Podman Compose on a live host; its live
  run so far is the Kubernetes one above.
- Docker Engine and podman-compose. `compose.native-sidecar.yaml` has not been run
  on any engine; it has been through `docker compose config` (above).
- Mullvad and NordVPN as native sidecars, live. PIA is the reason for the form.
- `port-sync` setting the port live: rc.1's failed against qBittorrent 5.2
  (above); PIA's port forwarding itself worked as a native sidecar (the record
  held a forwarded port). The PIA overlay exit's port forwarding has not been
  tested against PIA at any version.
- DNS on a live engine: which resolvers an application's namespace uses under
  Docker, and what a leak test shows on either platform until the acceptance
  records it. `SIDECAR_HOST_RESOLVERS`'s resolver override has unit tests
  (several resolvers, a truncated answer retried over TCP) and the drills above.
- shellcheck on the 0.9.0 scripts (CI runs it). staticcheck, govulncheck, the
  panel's script tests and `tools/check-compose.sh` (with the standalone Docker
  Compose 2.39.4) ran locally on the 0.9.0 branch and passed.
- Everything in the [0.8.0 list](#not-tested-at-080) that applies to the other
  forms.

## 0.8.0

0.8.0 was tested live on one host: a Debian host with rootless Podman 5.8 and
Quadlet units. Eight exits were upgraded there from 0.7.0 (six native: one
NordVPN, four Mullvad and one PIA; a gluetun overlay exit and a gluetun sidecar,
both with NordVPN), and the fail-closed drills ran from inside the exits' own namespaces
on the native Mullvad, PIA and NordVPN exits. The released image was then
checked against the same exits ([release acceptance](#release-acceptance-at-v080)).

Not tested at 0.8.0, in short: **Docker Engine on Linux and NetBird Cloud**; the
**shipped Compose files, which were validated with `docker compose config` only
and never run**; the drills with a client device held on an exit (they ran from
the exit's namespace instead); and any live drill on the gluetun exits, whose
rules only the namespace drills in CI cover. The full list is
[at the end of this section](#not-tested-at-080).

### Run so far

| What | How | Where and when |
|---|---|---|
| Unit tests, table-driven, ported from the 0.7 Python suite | `go test -count=1 ./...` | CI (ubuntu-24.04, amd64) and macOS arm64, Go 1.27.2, at `e27f5ae`, 2026-10-13 |
| Status records and verdicts compared with the Python code's | `internal/applier` golden tests, `internal/verdict`, `internal/egress` | Same runs. The goldens were generated from 0.7.0's Python at `d553f25`. 24 failure records the Go supervisor writes were also read by the unchanged 0.7.0 Python verdict in an independent review, with the expected results |
| Fuzz targets | 25 targets, run over their seed corpora | Same runs. No fuzzing campaign has been run |
| The panel script | `node --test panel/js-tests/*.test.js` against the Go panel | Same runs |
| Namespace drills | `go test -tags drill` in a privileged container (`internal/nstest/drill.sh`) and as root on the CI runner | Passed at `e27f5ae` (CI and an arm64 Linux VM). Every single-fault row of the drift table in both families with the 250 ms assertion, tunnel loss, the PIA address transaction and its partial failures, event loss by flood, the gluetun rules including 91/92 at packet level, PIA port forwarding and its ingress guard at packet level, the temporary guard, a frozen and a wedged worker, a crashed worker with the namespace held, a NetBird that dies, a profile without the tunnel exclusion, and the stop budget |
| Image checks | `tools/check-image.sh`, `tools/check-exit-image.sh` | CI, both architectures (the exit-image check on amd64). The exit-image check starts the image with a throwaway config in a namespace with no network: refusals, start order, the rules after a stop |
| Release tooling | Bundle, notes, acceptance policy and predicate, notices, reproducible binary | CI |
| Independent review | Static review rounds with probes, by a second model | Routing core: seven rounds; exit process: three rounds plus a fix checked by the maintainer's agent. The remaining residuals are listed in [architecture](architecture.md#the-deletion-check-and-what-it-assumes) |

### Live pass on rootless Podman with Quadlet

On 2026-10-12 and 13. Host: Debian testing (amd64), rootless Podman 5.8 with Quadlet units, a root-only user-namespace
remap (container root is an unprivileged host uid), pasta networking. The image
was built on the host from the pinned commit with the repository's Dockerfile.
NetBird: the 0.80.0 client in the image against a self-hosted NetBird server.

| Exit | Provider or kind | Revision | Result |
|---|---|---|---|
| Canary, upgraded from 0.7.0 first | NordVPN, native | `60ac63c`, then `404ca80`, `f7da3d2`, `2d9af6d` | Healthy; provider-confirmed egress; the stored NetBird peer and the selection carried over |
| Five more native exits upgraded from 0.7.0 | Mullvad (four), PIA | `2d9af6d` | Healthy, connected, verified egress; peers, selections and PIA's registration carried over |
| gluetun overlay exit, upgraded | gluetun with NordVPN | `2d9af6d` | Healthy, connected |
| gluetun sidecar, upgraded | gluetun with NordVPN | `2d9af6d` | Healthy |
| Switchyard and two per-exit panels | `panel` role | `2d9af6d` | `/readyz` ready with eight exits; sign-in not exercised |

An external health bridge that reads `state/applier/result.json` with 0.7.0's
rules reported every exit healthy, so the state-file contract held across the
upgrade.

Drills on the live NordVPN exit at `f7da3d2`, made from the host in the exit's
namespace with the host's `ip` (no client device):

- Deleting IPv4 rules 97, 95 and 1, IPv6 rule 97, and the exit table's tunnel
  route, one at a time: each was back in 13 to 23 ms. A foreign rule inserted at
  priority 96 was gone in 17 ms.
- `SIGSTOP` to the worker: NetBird's daemon was gone 32 s later (GUARD_GRACE 30
  plus one renewal interval); the supervisor logged "stopping (lease lapsed)",
  removed its interfaces, left the rules and exited 1 about 6 s after the lapse;
  the unit restarted it and it was connected and verified again 65 s later.
- Deleting the tunnel interface: the exit table held only its unreachable
  fallback until the tunnel was back, 0.86 s later; the selected peer was put
  back and the exit verified again within 20 s.
- NetBird runs its firewall on the nftables path in the image (`table ip
  netbird` and `table ip6 netbird` present; the image has no iptables).

Not done: a client held on an exit through these drills, phones, a reboot of
the host, PIA port forwarding against PIA, the Go panel's sign-in against a real
identity provider, `fix-blacklist` against a real enrolled peer.

### Release acceptance at v0.8.0

The released image is the one tested: `ghcr.io/irashack/molebridge:v0.8.0`,
index digest `sha256:aa882618115e602c554901a9b5e7d504068499da6da0ff921bf40cd39767e52a`,
source commit `ea43d5d`, promoted from `v0.8.0-rc.2` without a rebuild. The
live-acceptance attestation on that digest names the coverage below; the
verification in [setup](setup.md#1-download-and-verify) was run against the
published release from a clean directory on 2026-10-13 and every step passed.

Every exit of the live pass above was moved to the candidate digest (the
`v0.8.0-rc.2` one, which became `v0.8.0`), pulled from the registry, and these
drills were run on it from the exit's namespace. They ran on the native exits
only; the gluetun exits were not drilled live:

- Drift on the Mullvad, PIA and NordVPN exits (IPv4 rules 97, 95 and 1, IPv6
  rule 97, a foreign rule at 96): each repaired in 8 to 13 ms.
- Tunnel loss on the same three: the exit table held only its unreachable
  fallback until the tunnel was back (0.2 to 1.5 s), and each exit recovered by
  itself to a verified egress.
- A frozen worker on the NordVPN exit: NetBird stopped 33 s later, the
  interfaces were removed, the rules stayed, and the exit recovered.

The first candidate, `v0.8.0-rc.1`, failed the PIA tunnel-loss drill: the
recreated tunnel has no address until PIA's registration is applied again, and
the exit kept removing and re-adding the old address's return-path rules
instead of re-registering. It stayed fail-closed but did not recover by itself.
`v0.8.0-rc.2` fixes it (the provider's retirement of an address it no longer
holds is final for the routing owner) and passed the same drill.

### Resources at 0.8.0 on rootless Podman

By the 0.7.0 method ([below](#resources-at-070-on-rootless-podman)): each
container's cgroup `cpu.stat` over 120 seconds and `memory.current` at the end,
on exits with no client traffic, at `2d9af6d`, 2026-10-13. NetBird is inside the
exit container, so each figure is the whole exit.

| Exit | CPU, % of one core | memory.current | of which anonymous |
|---|---|---|---|
| Mullvad, native | 0.32 | 67 MB | 57 MB |
| Mullvad, native (second) | 0.31 | 78 MB | 68 MB |
| PIA, native | 0.50 | 77 MB | 68 MB |
| NordVPN, native | 0.29 | 189 MB | 136 MB |
| gluetun overlay exit (the Molebridge container only) | 0.28 | 123 MB | 114 MB |
| gluetun sidecar (the Molebridge container only) | 0.15 | 78 MB | 74 MB |
| Switchyard (eight exits) | 0.01 | 27 MB | 13 MB |

At 0.7.0 a native exit idled at about 7.9 % of one core in four containers. The
0.8.0 target of 0.5 % or less holds for every exit measured. The 70 MB target
holds only for the first Mullvad exit (67 MB); the second Mullvad exit, PIA and the
sidecar are at 77 to 78 MB, and the gluetun overlay exit (123 MB) and the NordVPN exit
(189 MB) parse large server catalogs, whose heap is not all returned. The image is 61 MB
unpacked (target 80 MB).

### Not tested at 0.8.0

- Docker Engine on Linux and NetBird Cloud (dropped from 0.8.0's acceptance by the
  maintainer).
- Running any of the shipped Compose files (`compose.yaml`, `compose.gluetun.yaml`,
  `compose.sidecar.yaml`), with Docker or podman-compose. They are validated with
  `docker compose config` only. The live exits ran as Quadlet units.
- A client device held on an exit through the fail-closed drills.
- Live drills on the gluetun overlay exit and the sidecar, and any gluetun provider
  other than NordVPN. The gluetun rules, including 91 and 92 at packet level, are
  covered only by the namespace drills in CI.
- The gluetun backend at any version: IPv6 (NordVPN is IPv4 only), the `SERVER_CATEGORIES`
  override, podman-compose, and Docker Engine on Linux. For FastestVPN,
  IVPN, Surfshark and Windscribe the gluetun egress check (the tunnel's address against
  this host's, on a socket that carries NetBird's control mark) has unit tests only.
- podman-compose last ran in September 2026, at v0.1.0 (the
  [rootless Podman pass](#rootless-podman-pass)).
- Installing from the release bundle on a clean host. The signature and attestation
  verification of the published release ran from a clean directory (above), but no
  exit was installed from the bundle.
- The smallest capability set: `DAC_OVERRIDE` is what the Compose files grant.
- The Go panel's sign-in against a real identity provider; `fix-blacklist` against a
  real enrolled peer; PIA port forwarding against PIA; phones during failure drills.

## macOS / OrbStack pass

Apple silicon, self-hosted NetBird 0.78, simulated client routing plus one real
phone. Steady-state fail-closed behavior held in every drill for both
families. The pass found six defects, all fixed in `1390860` through
`336d904`: a single-family tunnel-route loss reported healthy; the applier
stayed healthy in an orphaned namespace; `OVERLAY_IF` was not passed to
NetBird; a transient start-up failure consumed the saved selection; NetBird
preceded the routing guards only by timing; and the exit's ICMP errors for
oversized tunnel replies left over the host's route, so UDP (QUIC) through the
exit stalled.

## Rootless Podman pass

Revision `336d904` on Debian 13 / rootless Podman 5.4.2 / podman-compose 1.6.0
on amd64, NetBird client 0.79 against a self-hosted 0.79 management server,
through a Compose file carrying the same services and settings as
`compose.yaml`. Checked live, inside the namespace and from one iPhone client:

- Rules 90/94/95/96/97 present for both families with the `ipproto` qualifier
  on 94 and ahead of NetBird's own rules; `default dev mullvad` plus the
  unreachable fallback in the exit table for both families.
- ICMP from the tunnel address resolves to the tunnel interface for both
  families, while UDP from the same address takes the host path (the point of
  narrowing rule 94).
- Applier `--doctor`: recent check, routing protection, fresh catalogue and
  verified Mullvad egress all PASS; per-family egress probes succeed.
- Real client: mullvad.net/check clean, exit follows a server switch,
  direct (P2P) path once the peer carried the interface blacklist, a
  published UDP port and an external address mapping (see
  [operations](operations.md#exits-on-a-private-container-network)); without
  them every client was relayed.
- Recreation: a forced recreation of all four containers preserved the peer
  identity and rejoined the shared namespace.
- CI green at `336d904` (run on its pre-publication hash).

Found and fixed while adding Podman support: Docker-only Compose settings, the
missing `NET_RAW` capability, the panel user under uid remapping, the missing
kernel module autoload, and the interface blacklist as a requirement rather
than a tip (`4739352` through `336d904`).

## Live client and reboot pass at `5a6e0b5`

2026-09-24, the same Debian 13 / rootless Podman 5.4.2 / podman-compose 1.6.0
host, NetBird 0.79.0 client and self-hosted server. The client was a separate
NetBird 0.79.0 Linux peer (a container on another machine) with the exit
selected, probing IPv4 and IPv6 egress against `am.i.mullvad.net` about every
two seconds, 781 probes in all. Each family's probe used a pinned address, so a
failed family could not take the other's name resolution down with it.

**Fail-closed with the client on the exit.** All six drills from
[verification](verification.md#fail-closed-drills):

| Drill | Client during the drill | Status | After restore |
| :--- | :--- | :--- | :--- |
| Tunnel down | both families failed | — | Mullvad egress on both |
| IPv4 route deleted | IPv4 failed, IPv6 on Mullvad | `/readyz` 503 within 60 s, applier `failed` | Mullvad egress on both |
| IPv6 route deleted | IPv6 failed, IPv4 on Mullvad | `/readyz` 503 within 25 s | Mullvad egress on both |
| IPv4 lookup rule deleted | IPv4 failed, IPv6 on Mullvad | `/readyz` 503 within 45 s | recovered by recreating all four |
| IPv6 lookup rule deleted | IPv6 failed, IPv4 on Mullvad | `/readyz` 503 within 40 s | recovered by recreating all four |
| `wireguard` stopped | both families failed | — | recovered by recreating all four |

No probe returned a non-Mullvad address during any drill, and the exit host's
own traffic kept its ordinary path throughout.

**Reboot.** The host was rebooted with the client still selected. The
lingering boot unit brought the project up without intervention: all four
containers healthy 76 seconds after boot, one shared namespace, doctor 4×
PASS, the same peer identity, and `mullvad` still in the ICE blacklist. The
client failed closed for the whole outage (the NetBird client kept the exit
selected while the peer was offline) and regained Mullvad egress on its own.
A tunnel-down drill after the reboot failed closed.

**LAN isolation.** Through the exit, the client could not reach the exit
host's router (ICMP, TCP 80), the host itself (TCP 22), or the gateway of the
exit's container network. The host reached the same router and port directly,
so the targets were live.

**Oversized replies.** IPv6 replies larger than the overlay MTU made the exit
send ICMPv6 Packet Too Big (MTU 1280) out of the tunnel interface, sourced from
the tunnel address; a capture on the host-side interface saw no ICMP error
leave there. The public servers used ignore Packet Too Big for echo replies,
so that flow did not recover end to end. HTTP/3 (QUIC) requests through the
exit completed on both families to three large sites, but none of them sent
a datagram above 1280 bytes, so no live UDP flow exceeded the overlay MTU.

**Client fallback.** Deselecting the exit on the client sent its IPv4 traffic
out of the client's own connection at once. That is the documented boundary
in the README: server routing is not a device-wide kill switch.

## Clean install from the published files

2026-09-24, a fresh clone of `5a6e0b5` from GitHub on the same host, with the
bundled `compose.yaml` unchanged and only `.env` edited (project name, overlay
ranges, `PUID`/`PGID`, `PANEL_USER=0:0`, panel port, `NB_HOSTNAME`,
`NB_MANAGEMENT_URL`). A new peer enrolled with a fresh setup key; the tunnel
config came from an existing device while that device's other exit was
stopped. Following [setup](setup.md) with the
[rootless Podman commands](operations.md#rootless-podman):

- Build and start: all containers healthy, routing log `rules installed`, the
  three namespace users identical. podman-compose puts the project in its
  default pod; that works, no `x-podman` setting is needed.
- `NB_EXTRA_IFACE_BLACKLIST` put `mullvad` in the ICE blacklist at the first
  enrollment.
- [Namespace checks](verification.md#inside-the-namespace) 1 to 4 and 6 pass;
  doctor 4× PASS. The panel serves `/` and `/readyz`.
- The documented upgrade sequence (pull, build, recreate all four) left all
  four healthy in one namespace with the same peer identity, doctor passing.

This instance carried no client route and had no boot unit; the client and
reboot results above come from the long-running deployment.

**Fixed after the pass.** The panel did not exit on `SIGTERM`: as the
container's PID 1 without a handler it ignored the signal, so every stop waited
for the engine's 10-second timeout and then killed it. The panel now handles
`SIGTERM` and exits cleanly; this is a panel-only change, with routing, the
applier and Compose unchanged from `5a6e0b5`.

## Panel switcher pass at `56ac2cc` and `40c461c`

2026-09-25, the same Debian 13 / rootless Podman host, with each revision
deployed by pinning it in the owner's deployment tooling. That tooling
recreates all four containers on every pin change. Routing, the tunnel
configuration and Compose networking are unchanged from `b4cf640`.

At `56ac2cc`:

- Doctor 4× PASS before and after the deployment. All four containers were
  healthy, and the applier shared the WireGuard namespace.
- The live relay catalogue carried `owned`, `stboot` and `provider` with the
  expected types on every active relay: 536 relays, 113 Mullvad-owned, and
  all reported RAM-only at the time. Inactive relays were excluded as before.
- Panel in Chromium through an SSH forward:
  - Saved stayed hidden until a server was pinned.
  - The Mullvad-owned filter narrowed the list.
  - An opened country showed its Fastest row.
  - Escape canceled an armed switch.
  - Both themes rendered correctly at desktop width and at 390 px.
- One switch to another server in the same city showed switch progress and
  reached connected about 2.4 s after the confirming click.

**Fixed after the pass**, in `40c461c`:

- a RAM-only filter that hid nothing, because every relay was RAM-only;
- a Switch button offered for the server a switch was already moving to;
- the current-exit line wrapping after its separator on a phone;
- the Diagnostics arrow spacing;
- browsers requesting a missing `/favicon.ico`.

At `40c461c`: doctor 4× PASS before and after, the exit returned on the same
server, and the catalogue refreshed. The page offered only the Mullvad-owned
filter, declared its icon, and made no `/favicon.ico` request. It showed no
console errors and kept the address together when the line wrapped, in both
themes.

Not tested live:

- the Switch-button fix, which needs a switch in progress;
- Retry, since no switch failed;
- fixed `PANEL_THEME=light` and `dark`, since only `auto` was used;
- screen readers beyond the announcement text;
- phone clients.

## PIA pass at `0165147`

2026-09-27, the same Debian 13 / rootless Podman 5.4 / podman-compose 1.6 /
amd64 host, NetBird 0.79 self-hosted, as a second deployment beside the Mullvad
exit with `PROVIDER=pia`, its own peer and port forwarding off. The tunnel key
came from `tools/prepare-tunnel-config.py --pia`; the PIA login had two-factor
authentication on.

- First start: the applier minted a token, registered the key in the seeded
  region, and reported healthy with PIA confirming the egress. Doctor 4× PASS.
  The applier logged nothing; the login and token appear in no state file.
- Namespace, observed 2026-09-27 on this exit: IPv4 holds rules 90, 94, 95,
  96 and 97, with rule 94 naming the PIA-assigned address. IPv6 holds rules
  90, 95, 96 and 97, with no rule 94. Table 51821 holds the tunnel default
  for IPv4 and only the unreachable fallback for IPv6. The tunnel has one
  IPv4 address and no global IPv6 address; `inet molebridge_guard` sits beside
  NetBird's own iptables tables. The host has the `nf_tables` and `wireguard`
  modules loaded.
- A full recreation of the four containers registered the saved region again
  with no intervention.
- A temporary Linux NetBird client selected the exit (`0.0.0.0/0` and `::/0`):
  PIA answered `connected: true` for its traffic, from an address other than
  the host's; IPv6 went to the exit and got no reply; the home LAN router and
  the host's LAN address did not answer.
- With the client holding the exit, `wg-quick down` in the WireGuard container
  left it with no response at all, never the host's address. After `wg-quick
  up`, the applier found no peer, registered the saved region again, and the
  client's traffic returned within ten seconds.
- Switching region and back through `desired.json` reached healthy each time
  on a new server with a new tunnel address, leaving exactly one address and
  one priority-94 rule.

Not tested live: port forwarding against PIA (the isolated drill covers the
nftables DNAT and the ingress guard); a PIA server forgetting the key mid-run;
a stale-catalogue period; phone clients.

## Switchyard pass at `4eda8ff`

2026-09-27, the same host, with one extra panel container serving the Mullvad
and PIA exits above (`PANEL_EXITS=mullvad=mullvad:Mullvad,pia=pia:PIA`),
published through an authenticating proxy and embedded in a dashboard. Both
exits stayed on their own revision, `b2a0a02`.

- `/api/exits` listed both exits connected, with their places. `/readyz`
  answered 200. `/` redirected to `/?exit=<id>`, each exit rendered in its
  provider's layout (Mullvad's tree, PIA's region list), and the embed carried
  the configured `frame-ancestors`.
- A selection posted through the proxy for each exit (its current location
  again) was written to that exit's `desired.json`, acknowledged by its
  applier, and verified connected within a minute. The other exit was
  untouched.
- Headless Chrome screenshots of the full page, a phone width and the embed,
  in both styles and both themes, including the armed and failed states, using
  `tools/preview-panel.py`. Stopping the panel under an open page turned every
  exit tab to "status unavailable" on the next poll.

Not tested live: a switch to a different location through Switchyard; phone
home-screen installation of the multi-exit page.

## Sign-in pass at `62a0170`

2026-10-01, the same host, one Switchyard serving four Mullvad and PIA exits
behind NetBird's reverse proxy (which also answers plain http), signing in
with a self-hosted Pocket ID v2.16.0 whose public name is fronted by
Cloudflare. Public client with PKCE, `PANEL_ADMIN_GROUPS` and a
`PANEL_ACCESS` group per exit.

- Signed out, through the proxy: `/readyz` answered 200 with no login; `/`
  over https and over plain http both answered 303 to the https `/login`;
  `/login` answered 303 to the provider's authorization endpoint with an S256
  challenge; `/api/status`, `/api/latency` and `POST /select` answered 401;
  `/readyz?exit=` gave the same 404 for every id, configured or not; `/embed`
  showed the sign-in link that opens a new tab.
- An admin signed in with a passkey in a browser and saw every exit. A switch
  on one exit was logged (`switch: user=… sub=… exit=… server=…`),
  acknowledged by that exit's applier under the same request ID, and verified
  connected one second after the request.
- Found and fixed during the pass: Cloudflare answered 403 to the panel's
  discovery request, because it refuses urllib's default `Python-urllib`
  agent (fixed in `a8fa497`); with four exits the tabs broke labels mid-word
  (fixed in `62a0170`, checked in headless Chrome at four widths and in the
  embed).

Not tested live: a sign-in by someone granted only some exits (the per-exit
refusals are covered by `panel/test_oidc.py`, 287 tests in all), a dashboard
frame after sign-in, and a phone.

## PIA registration retry at `8587542`

2026-10-07, the same host, the PIA exit. The host restarted while PIA's login
API answered 502 to every request, so the recreated tunnel's first
registration failed and the tunnel had no address. Before this change the
applier waited for an address that never came. Running `8587542` (the same
change as in 0.4.0), it retried the requested region, and the exit registered
and connected by itself after PIA's API recovered. The retry without an
address is covered by `tools/test_pia.py`.

## Routing and NetBird checks at `0f9511a`

2026-10-08, a PIA test exit on macOS with OrbStack (a Linux 7.0 kernel VM)
and Docker, a self-hosted NetBird server and the 0.79.0 client, with a Linux
NetBird client routed through it. First at `d00b52d`, then again at `0f9511a`.
0.4.1 changes only wording on top of `0f9511a`.

- Initialization installed the native rules, 1, 90 and 94 to 97 (no rule 94
  in IPv6, where PIA's tunnel has no address), and no rule 0; `recover` reinstalled them after recreating the containers, and
  `doctor` passed, including the NetBird settings, stored profile and kernel
  mode checks.
- The client's traffic left through PIA. TCP, UDP and ping from the client to
  the exit's own overlay address got no answer, while the same TCP connection
  made from inside the exit's namespace reached the listener.
- With the tunnel interface down, the client had no egress and a capture on
  the host interface showed no client packets.
- In the NetBird container itself (busybox), the startup checks accepted the
  enrolled default profile and refused it when `NB_INTERFACE_NAME` named a
  different interface than its stored one.

## NordVPN pass at `036e1cc`

2026-10-08, a test exit built from `036e1cc`: macOS, OrbStack, Docker, a
self-hosted NetBird server and the NetBird 0.79.0 client, `PROVIDER=nordvpn` with a NordVPN
account.

- `tools/nordvpn-key.py` exchanged a real access token for the account's
  NordLynx key and wrote the tunnel config with mode 0600.
- The applier's catalogue held 5,291 servers; `relays.json` was about
  1.48 MB.
- A selected server in one US city came up `ok` with `egress_tier`
  `provider`: NordVPN's insights check answered `protected: true` and named
  the city.
- A NetBird client routed through the exit egressed from that server.
- A switch to another server in the same city, which shares the location's
  key, was identified correctly by its endpoint.
- A switch to a server in Germany worked and was confirmed by NordVPN.
- Forwarded IPv6 had no egress: the exit table's IPv6 side held only the
  unreachable default.
- A TCP connection from the client to the exit's own overlay address was
  refused.

Not tested live: the insights cache-retry path, the `tunnel` egress tier, the
panel with the NordVPN catalogue, rootless Podman, and the fail-closed drills
in [verification](verification.md) on this provider. The later fixes on this
branch (the unverified IPv6 measurement in the tunnel tier, the snapshot size
limit and the bounded latency probing) are covered by unit tests, not by this
pass.

## gluetun backend pass at `a3bb14f`

2026-10-08, a test exit: Docker on OrbStack (a Linux 7.0 kernel VM on a
macOS host), gluetun v3.41.3 with NordVPN, a self-hosted NetBird server and
the NetBird 0.79.0 client, `compose.gluetun.yaml`. The final pass ran at
`a3bb14f`; earlier revisions of the same pass found these, each fixed
before it:

- the routing image's rule directory was not searchable without
  `DAC_OVERRIDE`, so the guard couldn't start;
- gluetun's built-in server list was stale, and the catalogue offered
  NordVPN's dedicated-IP servers, which an ordinary account can't use;
- a post-rule with a mark match broke gluetun's own iptables parser, so
  its old accepts piled up on every reconnect;
- gluetun's own established DNS-over-TLS connections left by the host
  interface when its tunnel went down (now rules 102–104);
- the kill switch blocked the kernel's check of the gateway route gluetun
  adds at start (now rule 103, added before 104).

Verified at `a3bb14f`:

- A NetBird client on a direct (P2P) connection routed through the exit,
  with provider-confirmed egress (NordVPN's insights check).
- A server switch through the panel's API.
- Traffic from the overlay to the exit's own addresses was not delivered.
- With the tunnel interface down, the client had no egress, and the host
  interface carried no client traffic and none of gluetun's own flows;
  only the kernel's ICMP port-unreachable replies to inbound UDP.
- NetBird's control traffic appeared only on the host interface.
- `tools/molebridge.py recover` recreated the stack, the applier put the
  last verified server back by itself, and `doctor` passed.

Not tested live: other providers through gluetun, rootless Podman, IPv6
through gluetun, gluetun restarting into a new namespace outside a drill,
and long-running stability. The fixes after `a3bb14f` (gluetun's role-file
check before it starts, and identifying the server by any of its addresses)
are covered by unit tests and drills, not by this pass.

## gluetun backend at `4933360`, and the standalone form

2026-10-08, the same test exit, rebuilt at `4933360`:

- gluetun started through the role-file check, every container became
  healthy, and `recover` and `doctor` passed. With `apikey` misspelled in the
  role file, gluetun refused to start with the check's fixed message, and the
  key appeared nowhere in gluetun's log; with the file restored, `recover`
  brought the exit back.
- With the applier and the panel stopped, as in
  [gluetun as a NetBird exit](gluetun-netbird-exit.md): the guide's checks 1 to
  4; deleting the exit-table route and deleting lookup rule 95 (guard stopped),
  restarting NetBird, and recreating gluetun, guard and NetBird, each with the
  client's probe failing during the break and nothing to or from the probe
  addresses on the host interface; local delivery refused; a server switch
  through gluetun's control server with the guide's `curl` commands.
- Observed: gluetun did not bring back a tunnel interface set down by hand
  within several minutes; recreating the containers did. NetBird in the
  namespace resolves names through gluetun's DNS, through the tunnel.

Not tested: rootless Podman, other providers, IPv6 through gluetun.

## NordVPN on rootless Podman at v0.5.0

2026-10-08, the same long-running Debian host with rootless Podman 5.8.6, a
native NordVPN exit (`compose.nordvpn.yaml`) at the release `v0.5.0`, run
as Quadlet units rather than through podman-compose.

- The after-deploy checks: every container healthy, the doctor's five
  `PASS` lines, NordVPN-confirmed egress.
- Namespace checks with no exit route enabled: forwarded IPv4 left only
  through the tunnel; forwarded IPv6, the exit's own overlay address and the
  LAN were never delivered or routed outside it; with the exit-table route
  deleted, forwarded traffic was unreachable.
- Then, with the route enabled, a phone used the exit on cellular over a
  direct (P2P) path for about 1 GB of traffic.

Not done on this host: the client-held fail-closed drills, and a DNS or IPv6
leak test from the phone.

## gluetun backend on rootless Podman at v0.5.0

2026-10-08, the same host, gluetun v3.41.3 with NordVPN, a self-hosted NetBird server, the release `v0.5.0`.
The four containers of `compose.gluetun.yaml` ran as Quadlet units rather
than through podman-compose, with the container's root remapped to another
host ID, on their own pasta network as in
[operations](operations.md#exits-on-a-private-container-network).

- gluetun, the guard, NetBird and the applier all became healthy.
- The applier verified the exit with NordVPN-confirmed egress.
- The exit peer enrolled and its exit routes were created.
- Found: with the container's root remapped, `secrets/gluetun/api_key` must
  belong to the container's root with mode `0600`; the applier refuses a
  group-readable copy. [Operations](operations.md#rootless-podman) now says
  so.

Not done on this host: traffic from a client through the exit, a switch
from the panel, the fail-closed drills, and podman-compose.

## The routing image on rootless Podman at `0086fac`

2026-10-10. The same long-running host: Debian testing, kernel 7.2, amd64,
rootless Podman 5.8.6 running Quadlet units, a self-hosted NetBird server
and NetBird 0.80.0 in the exits. The revision is `0086fac`, v0.6.0's code;
the release commit adds only this record and the panel's version string.

Every exit was upgraded in place from v0.5.3:
- four Mullvad, one PIA and one NordVPN native exits;
- a gluetun v3.41.3 exit with NordVPN;
- the Switchyard panel serving all of them.

On each exit:
- The container's root is remapped to another host ID.
- The tunnel config is the host user's, mode `0640`, readable through an ACL.
- The `wireguard` container ran with only `NET_ADMIN`. The `DAC_READ_SEARCH`
  in `compose.yaml` was left out because the ACL already grants the read.

The NordVPN exit was the canary and went first. The rest followed only after
it passed.

- Before the upgrade, `--check-config` with the new image accepted every
  live tunnel config: Mullvad's with an IPv4 and an IPv6 address, PIA's with
  none, and NordVPN's with an IPv4 address. Each was read through its ACL.
- After the upgrade, every container was healthy and the applier's health
  check passed on every exit. On each exit the `wireguard` process's
  effective capabilities were `NET_ADMIN` alone.
- Rules 1, 90 and 94–98 were in place for IPv4, and 1, 90 and 95–97 for
  IPv6 on the IPv4-only NordVPN exit. On the PIA exit, rules 94 and 98 for
  the registered address were installed by the applier, and the owner record
  read `applier`.
- The gluetun exit's `guard` ran the image's own entrypoint under tini and
  reported every rule in place.

The drills ran on the NordVPN exit, one at a time, with no client on the
exit:

- **Rule deletions.** IPv4 rules 97, 94, 98, 1 and 95 and IPv6 rules 97 and
  1 were each deleted. Each was back within 1–2 seconds; the reconcile
  interval is 2 seconds. The applier stayed healthy and NetBird kept
  running.
- **Tunnel loss.** The tunnel interface was deleted. Readiness was
  withdrawn, and the interface came back in about 2 seconds. The applier
  restored its peer, and its health check passed again with NordVPN-confirmed
  egress 3 seconds later. NetBird was not restarted.
- **Stale owner record.** The entrypoint was frozen with `SIGSTOP`, so the
  owner record stopped updating. The gate stopped NetBird 10 seconds after
  the freeze; it logged that the record was written 7 seconds ago. The
  applier's health check failed while the record was stale. The entrypoint
  was resumed after 12 seconds. All three containers were healthy again 90
  seconds later, most of it the NetBird unit's 60-second restart delay.
- **`SERVER`.** `SERVER` was set on the NordVPN exit to a server other than
  the panel's choice. The applier switched to it with NordVPN-confirmed
  egress. The panel then reported the exit with `selection_mode`
  `configuration` and no panel choice. This was read by running the panel's
  own status code in its container, not a signed-in browser. The panel's
  refusal condition for selection posts held. Removing `SERVER` brought the
  panel's choice back.

Not done:
- client traffic through any exit during these drills, or a phone on the
  exit;
- the drills on the Mullvad, PIA or gluetun exits;
- a PIA region switch, which is where the applier moves rules 94 and 98 to
  the new address; the namespace drill covers three address changes;
- `SERVER` on any exit other than NordVPN, and the read-only panel in a
  browser;
- the routing image on Docker. Docker relies on CI's container drill
  (`tools/check-exit-image.sh`: start, repair, tunnel loss, bring-up
  failures and every stop case) and the namespace drills under busybox sh.

## 0.7.0 on rootless Podman at `d5a234a`

2026-10-11, the same host as [the routing image pass](#the-routing-image-on-rootless-podman-at-0086fac):
Debian testing, kernel 7.2, rootless Podman 5.8.6 with Quadlet units, a
self-hosted NetBird server and NetBird 0.80.0 in the exits. The exits ran
0.6.0's code before.

The upgrade followed [the order](operations.md#upgrades): Switchyard first,
then the NordVPN exit as the canary at `25a8bcd`, then every exit. With the
0.7.0 panel and the exits still on 0.6.0, every 0.6 record read as connected
through the new verdict. After the upgrade:
- every exit wrote schema-2 records, and every verdict was `ok`: four
  Mullvad, one PIA and one NordVPN native exit, the gluetun exit with
  NordVPN, and a new gluetun sidecar with NordVPN;
- the homelab's own health bridge, reading the new record, reported every
  exit healthy;
- a fresh upgrade without `attempt.json` re-applied each exit's saved
  request once after its container restarted, and changed nothing else.

A temporary Linux NetBird client (a container on another machine, in the
exit-users group) held the NordVPN, PIA and gluetun exits and one Mullvad
exit in turn (not the three other Mullvad exits, see below) and probed its
public address once a second through every drill below. It never left from the host's own
address except where noted.

**NordVPN exit (the canary).**
- The client's egress was NordVPN's, confirmed by NordVPN's own check, and
  its IPv6 stayed blocked before, during and after every drill.
- **Rule and route deletions** (rules 94, 95 in both families, 97, the IPv4
  tunnel route, both families' fallbacks) were each back at the next
  repair pass. The client lost at most a few probes.
- **Inserted bypass** (`ip rule add lookup main priority 50`): the client
  left from the host's own address for one probe before the next repair
  pass removed the rule. This is what the drill table says; nothing is
  promised before that pass.
- **Tunnel loss** found two defects at `25a8bcd`, both fixed in `b85f3d7`.
  The tunnel came back from its config without a peer. The applier waited
  90 seconds to apply it again, as it waits out gluetun's own reconnects.
  Meanwhile its container health check, which still required a peer, had the
  homelab kill it. At `b85f3d7` the client lost about 5 seconds of probes.
- **Stale owner record** (the entrypoint frozen): the client lost egress 9
  seconds after the freeze, as NetBird's gate stopped NetBird. The applier
  reported routing, NetBird and the owner record failed, and the verdict
  and the health bridge agreed. It was resumed after 80 seconds, and the
  client's egress was back 20 seconds later.
- **The egress check unreachable** (the applier's own HTTPS through the
  tunnel dropped for 4 minutes): each check reported `failed`, egress
  "unanswered", as `applied-unverified` with `recheck`. Nothing was applied
  again, and all of the client's 222 probes left through NordVPN. The
  health bridge kept its five-minute grace. The first check after the drop
  was removed verified, still on the same attempt.

**Mullvad.** Egress was Mullvad's in both families, by Mullvad's own check.
After tunnel loss the tunnel came back with its config's own peer: the
client left through that Mullvad server for 2 seconds until the applier
reconverged. The route and rule drills behaved as on NordVPN.

**PIA.**
- Egress was confirmed by PIA, and IPv6 stayed blocked throughout.
- After tunnel loss PIA registered again within 3 seconds.
- An interrupted registration's leftovers were removed at the next pass: a
  second address with its rules 94 and 98. The registered address kept its
  pair.
- **Live region switch** to another region and back: the client's egress
  moved without a failed probe. The record read `source: panel`,
  `outcome: verified`.

**gluetun exit.**
- **Live switch:** the client lost one probe while gluetun reconnected. The
  switch verified on its first attempt.
- **gluetun restarted:** gluetun came back on its environment's server, and
  the client left from that NordVPN server meanwhile. The pipeline put the
  selected server back once the 90-second guard had passed since the last
  change (`source: reconverge`, verified). The client was never on the
  host's address.

**gluetun sidecar** (Quadlet: gluetun, the applier and a test app sharing
gluetun's network and user namespaces; no NetBird):
- A selection verified, confirmed by NordVPN's own check, with traffic
  protection and app attachment reported as not checked.
- The [Compose-less doctor](gluetun-sidecar.md) passed.
- gluetun's control server listened on loopback only and was not published.
  It refused a request without the key, and routes outside the role even
  with it. The preflight refused a malformed role file without printing the
  key it held.
- **gluetun restarted outside systemd** (`podman restart`): the applier and
  the app were stopped with it rather than left in the old namespace, and
  the doctor failed until systemd started them again. The pipeline then
  restored the selection, and the doctor passed.
- The panel's own code, run against the live state, rendered the sidecar's
  wording.

Not done:
- the 409 from a signed-in panel, live. It is tested in `panel/test_status.py`
  and was seen once in a local preview;
- the drills with a client on the three friend exits, which only their
  owners' devices receive;
- a PIA registration lapsing on its own (D15) or a refused PIA login. The
  unit tests cover both;
- a tunnel-tier sidecar provider, Docker, and podman-compose. CI runs the
  doctor's identity probe and recovery on Docker with a stand-in owner;
- an app left in gluetun's old namespace, live. On Podman a restart took
  the dependents with it; CI's Docker drill covers the case.

## Resources at 0.7.0 on rootless Podman

2026-10-12, the host of [the 0.7.0 pass](#070-on-rootless-podman-at-d5a234a),
24 cores, every exit at `d5a234a` and idle. Read from each container's
cgroup v2 `cpu.stat` and `memory.current`: a 120-second window sampled every
5 seconds, and the totals since the containers started 34 hours earlier.
Where two CPU figures are given, the window is the lower and since start the
higher; `memory.peak` is since start. Percentages are of one core.

| Container | CPU, % of one core | Memory, average | Memory, peak |
| :--- | :--- | :--- | :--- |
| Routing container (`wireguard`), six native exits | 2.5 to 3.6, 70 % of it system time | 1.6 to 2.0 MB | 12 to 15 MB |
| gluetun backend's `guard` | 4.7 to 6.5 | 3 MB | 16 MB |
| `netbird` | 1.3 to 3.6 | 49 to 56 MB | 81 to 91 MB |
| `applier`, Mullvad and PIA | 1.2 to 1.8 | 17 to 22 MB | 53 to 60 MB |
| `applier`, NordVPN | 1.5 to 1.6 | 103 MB | 155 MB |
| `applier`, gluetun backend and sidecar | 1.8 to 2.0 | 59 to 64 MB | 108 to 109 MB |
| `control-panel`, one exit | 0.7 to 0.8 | 20 to 22 MB | 46 to 48 MB |
| Switchyard, eight exits | 0.7 to 0.8 | 68 MB | 94 MB |
| `gluetun` | 0.1 | 91 to 100 MB | 149 to 157 MB |

Per stack: a Mullvad or PIA exit with its own panel, 6 to 8 % and 93 to
99 MB; a native exit without a panel, 5.1 to 7.2 % and 68 to 77 MB (NordVPN
158 MB); the gluetun exit, 9.4 to 12.2 % and 216 MB; the gluetun sidecar,
1.9 % and 155 MB. Images, from `podman system df -v`: the routing image
14.0 MB, the applier 145.4 MB (124 MB of it the `python:3.14.7-slim` base,
shared with the panel), NetBird 0.80.0 102.3 MB, gluetun v3.41.3 67.9 MB.

## Not yet tested (as of 0.7.0)

- The NetBird gate's other refusals (forced userspace modes, Rosenpass,
  foreground mode, other profiles and config paths) on a running peer. Unit
  tests and `tools/check-routing.sh` cover them; the NetBird settings were
  checked against the 0.79.0 source and re-checked unchanged in 0.80.0. On
  rootless Podman the gate accepted the live configuration of Mullvad, PIA
  and NordVPN exits at `0086fac`; its refusals have not run on a live peer.
- The [gluetun backend](architecture.md#gluetun-backend) beyond the passes
  [on Docker](#gluetun-backend-pass-at-a3bb14f) and
  [on rootless Podman](#gluetun-backend-on-rootless-podman-at-v050): other
  providers than NordVPN, the repair drills with a client on rootless Podman
  (the [0.7.0 pass](#070-on-rootless-podman-at-d5a234a) held a client through a switch and a gluetun
  restart), podman-compose, IPv6 through gluetun, and gluetun restarting into a new
  namespace outside a drill. `tools/check-routing.sh`
  exercises the guard and gate in isolated namespaces with gluetun's rules
  98–101 and NetBird's 105/110 simulated; unit tests cover the scripts
  against a stand-in for iproute2 and the applier against fakes of the
  kernel and gluetun. The applier's request to gluetun clearing every other
  server filter was checked against gluetun's source, not a running gluetun.
  gluetun v3.41.3 and NetBird 0.79.0 behaviors the passes above did not
  exercise were read in their source.
- A live UDP flow whose datagrams exceed the overlay MTU, and an IPv4
  fragmentation-needed error on a live flow. The isolated CI drill covers both
  return paths; the live pass above shows the IPv6 error leaving through the
  tunnel.
- Fail-closed drills with a phone client. The drills above used a Linux
  client; a phone's NetBird client may fall back to its own connection
  differently while the exit peer is offline.
- Docker Engine on Linux, Docker Desktop, and NetBird Cloud, end to end. The
  routing image has no live Docker pass; see
  [above](#the-routing-image-on-rootless-podman-at-0086fac) for what CI covers.
- NordVPN beyond the passes [at `036e1cc`](#nordvpn-pass-at-036e1cc) and
  [on rootless Podman](#nordvpn-on-rootless-podman-at-v050): the insights
  cache retry (covered by `tools/test_nordvpn_applier.py`) and the panel with
  NordVPN's catalogue. The client-held drills ran in the [0.7.0 pass](#070-on-rootless-podman-at-d5a234a).
- The egress check's one retry (0.5.2) on a live exit before its release.
  `tools/test_runtime.py`, `tools/test_egress.py` and the PIA, NordVPN and
  gluetun applier tests cover it.
- Clearing a failed switch whose server is live and verified (0.5.3) on a
  live exit before its release. `tools/test_runtime.py` and
  `tools/test_pia.py` cover it.
- The `tunnel` egress tier, live: FastestVPN, IVPN, Surfshark and Windscribe
  through gluetun use it, and none of them has had a live pass.
  `tools/test_egress.py` and the gluetun tests cover it.
- The gluetun sidecar beyond the [0.7.0 pass](#070-on-rootless-podman-at-d5a234a): Docker, podman-compose,
  Mullvad, the four `tunnel`-tier providers (FastestVPN, IVPN, Surfshark and
  Windscribe), and an application left in
  gluetun's old namespace. `tools/check-sidecar-doctor.py` covers the doctor
  and recovery on Docker in CI.
- A PIA registration lapsing on its own, and a refused PIA login, live.
  `tools/test_pia.py` covers both.
- The panel's [OpenID Connect sign-in](access.md#sign-in-with-openid-connect)
  for someone granted only some exits (`PANEL_ACCESS`), live; any provider but
  Pocket ID; a confidential client; the userinfo fallback against a real
  provider; a phone's home-screen app signing in.

## Validating a new revision

Follow [backups](operations.md#backups) and [upgrades](operations.md#upgrades),
then run [verification](verification.md) on your host. Record:

- Date, revision, OS, architecture, container runtime and Compose versions.
- Provider, NetBird server and client versions, and client device types.
- Checks run, address families tested, pass/fail results, recovery timings and
  checks you skipped. Separate isolated namespace results from live client
  results.

Keep real hostnames, addresses, peer IDs, account numbers and keys out of the
record.
