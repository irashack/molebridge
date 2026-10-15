# The native sidecar

Experimental, new in 0.9.0. Use this when your application needs a tunnel
that Molebridge builds itself, in a network namespace the application shares.
The exit owns the namespace and the WireGuard tunnel, as a native overlay exit
does, and keeps the application's traffic in that tunnel with a routing
contract and an nftables firewall of its own. There is no NetBird peer and
nothing is forwarded for other devices: that is the NetBird exit, the
`overlay` kind ([setup](setup.md)). The native sidecar is the `sidecar` kind
with the native backend: `EXIT_KIND=sidecar` and `TUNNEL_BACKEND=native`,
`compose.native-sidecar.yaml` and `.env.native-sidecar.example`.

The word "sidecar" has two meanings on this page. The *sidecar kind* is
Molebridge's name for an exit that other containers share. A *sidecar
container* is a Kubernetes feature: an init container with
`restartPolicy: Always`, which the [Kubernetes example](#kubernetes) uses for
the exit.

**What has been tested.** At 0.9.0 the unit tests and `go vet` pass, and the
namespace drills passed in a privileged rootful Podman container on Debian
forky/sid, kernel 7.2.8 (amd64), including the drills for this form. No native
sidecar has run live: the live acceptance on Kubernetes has not been recorded
yet. Docker Engine, podman-compose, the Compose form, Mullvad and NordVPN as
native sidecars, and PIA's port forwarding against PIA are untested, and
`compose.native-sidecar.yaml` has not been through `docker compose config`
yet. Exactly what ran, and what did not, is in [testing](testing.md#090).

## When to use it

| | Native sidecar (`compose.native-sidecar.yaml`) | [gluetun sidecar](gluetun-sidecar.md) (`compose.sidecar.yaml`) |
|---|---|---|
| Who owns the tunnel | The exit container, with Molebridge's own WireGuard code | gluetun |
| Providers | Mullvad, PIA, NordVPN | Whatever gluetun drives over WireGuard with Molebridge: FastestVPN, IVPN, Mullvad, NordVPN, Surfshark, Windscribe |
| What keeps the applications' traffic in the tunnel | Molebridge: the routing contract and the firewall below, checked by the exit | gluetun's firewall, not checked by Molebridge |
| Stays closed while the exit is down | Yes: the rules and the firewall stay when the exit stops or restarts | Depends on gluetun's firewall |
| PIA port forwarding | Yes, to the namespace itself | No |
| Live record | None yet | A NordVPN pass at 0.8.0 |

Choose the native sidecar for PIA over WireGuard. gluetun supports PIA over
OpenVPN only, and Molebridge's gluetun forms don't offer PIA. Choose the
gluetun sidecar when you need one of gluetun's other providers, or want
gluetun's own firewall and features. Mullvad and NordVPN work in both; only
the gluetun sidecar has had a live pass.

## What is checked, and by whom

| Property | Checked by | How |
|---|---|---|
| The routing contract: its rules and the exit table's fallback, in both address families | the exit | Read back from the kernel on every change and on a full pass every `ROUTING_RECONCILE_INTERVAL` seconds, repaired when it differs. The `routing` check |
| The firewall: table `inet molebridge_sidecar` is exactly what the exit installed | the exit | Read back every 2 seconds, replaced in one transaction when it differs. Part of the `traffic_protection` check, which also needs `routing` to pass |
| The peer, the handshake and egress through the tunnel | the exit | The peer and handshake through WireGuard's netlink interface, against the provider's server list; egress through the provider's own check, as with a native overlay exit |
| An application's traffic really stays in the tunnel, including during a reconnect | the contract and the firewall | The exit checks that they are in place; it sends no test traffic from the applications' side. The drills in [verification](verification.md#a-native-sidecar) do |
| DNS | nothing | Not tunnelled and not checked; see [DNS](#dns) |
| Your applications are in the exit's current namespace | you, with the attachment procedure | `app_attachment` stays `not-checked`; see [operations](operations.md#checking-that-containers-share-gluetuns-namespace) |
| The application listens on the forwarded port | `molebridge port-sync` for qBittorrent, otherwise you | [Port forwarding](#port-forwarding) |

Five checks are required for the exit to count as connected: `routing`,
`traffic_protection`, `peer`, `handshake` and `egress`. `netbird` and
`owner_record` are `n/a` and `app_attachment` is `not-checked`
([the status record](architecture.md#the-status-record)). A failed firewall
shows as `traffic_protection` failed with `from: "firewall"` and the message
"Sidecar firewall protection is incomplete; see docs/operations.md#recovery."
A failed contract shows as `routing` and `traffic_protection` both failed,
with "Routing protection is incomplete; see docs/operations.md#recovery."

## How it keeps traffic in the tunnel

The exit installs two layers before the tunnel exists, the firewall first.
Both stay when the exit stops or restarts; only the tunnel link is removed.
The design is in [architecture](architecture.md#the-native-sidecar).

### The routing contract

Policy routing sends everything the namespace sends to the exit table, whose
only routes are the tunnel's default route and an `unreachable` fallback. The
rules are for IPv4 and IPv6 alike. `iif lo` selects locally generated packets;
nothing is forwarded in a sidecar. With the defaults (`EXIT_TABLE=51821`, which
is `0xca6d`, and `CONTROL_MARK=0x1bd00`) `ip rule` shows:

| Priority | Rule | Purpose |
|---|---|---|
| 88 | `fwmark 0x1bd00 iif lo lookup main` | The exit's own host-path traffic: the provider's login and server list, PIA's registration with the server's public address, and their name lookups ([below](#the-exits-own-traffic)) |
| 89 | `fwmark 0x1bd00 iif lo unreachable` | Backstop behind 88 |
| 90 | `to <prefix> iif lo lookup main`, one per `SIDECAR_LAN_CIDRS` prefix of the family | The applications' LAN, outside the tunnel |
| 93 | `fwmark 0xca6d iif lo lookup main` | WireGuard's own encapsulated UDP, which the tunnel device marks with `EXIT_TABLE` |
| 94 | `from <tunnel address> ipproto icmp lookup 51821` | ICMP errors the namespace generates for tunnel traffic return through the tunnel, as on a native overlay exit. IPv6 uses `ipproto ipv6-icmp` |
| 96 | `iif lo lookup 51821` | Everything else the namespace sends: the tunnel |
| 97 | `iif lo unreachable` | Terminal guard if rule 96 or the exit table is gone |
| 98 | `from <tunnel address> ipproto icmp unreachable` | Backstop behind 94 |
| — | `unreachable default metric 4096 table 51821` | Fallback when the tunnel route is absent |

Rules 94 and 98 follow the native overlay logic exactly, including PIA's
change of address ([providers](providers.md#how-pia-differs)). Molebridge owns
priorities 1 to 98 in the namespace. The kernel's priority-0 `lookup local`
rule is left alone, and anything else in 1 to 98 is removed by the repairer
like any other drift ([drift and repair](architecture.md#drift-and-repair)).
There is no local-delivery guard and no temporary priority-80 rule: the
firewall, installed first, already drops what is not tunnel, LAN, loopback or
marked. The install order is 97, 96, 98, 89, 88, 90, 93 and 94, so the terminal
guard and the tunnel lookup stand before any exception, also in a namespace
that kept a previous run's rules.

The deletion check judges every rule or route the repairer would delete
([the deletion check](architecture.md#the-deletion-check-and-what-it-assumes)).
For a native sidecar a packet to loopback or a local address may end anywhere;
a control-marked packet may leave only by `HOST_IF` or the tunnel, or be
refused; a WireGuard-marked packet or one to a `SIDECAR_LAN_CIDRS` prefix may
end anywhere; and any other packet may leave only by the tunnel interface or be
refused. A route out of the host interface for such a packet is an escape, and
a deletion that would allow it is kept.

No sysctl is needed. A native overlay exit sets
`net.ipv4.icmp_errors_use_inbound_ifaddr` for the errors it generates on
forwarded traffic; a sidecar forwards nothing, and its routing status never
depends on that setting.

### The firewall

The exit installs one table, `inet molebridge_sidecar`. This is what
`nft list table inet molebridge_sidecar` prints for the defaults, with
`SIDECAR_LAN_CIDRS=198.51.100.0/24,2001:db8::/32`, `EXIT_IF=pia` and a forwarded
port of 43210 (the counters differ on a live exit; the input chain has no port
rules when no port is forwarded):

```text
table inet molebridge_sidecar {
	chain output {
		type filter hook output priority filter; policy drop;
		oifname "lo" accept
		oifname "pia" accept
		meta mark 0x0000ca6d accept
		meta mark 0x0001bd00 accept
		ip daddr 198.51.100.0/24 accept
		ip6 daddr 2001:db8::/32 accept
		ip6 daddr fe80::/10 accept
		ip6 daddr ff02::/16 accept
		counter packets 0 bytes 0 drop
	}

	chain input {
		type filter hook input priority filter; policy accept;
		iifname "pia" ct state established,related accept
		iifname "pia" tcp dport 43210 accept
		iifname "pia" udp dport 43210 accept
		iifname "pia" counter packets 0 bytes 0 drop
	}

	chain forward {
		type filter hook forward priority filter; policy drop;
	}
}
```

The output chain admits loopback, the tunnel interface, the two marks, your
LAN prefixes (IPv4 first, then IPv6, in the order you wrote them) and IPv6
link-local and link-scope multicast for neighbour discovery. Everything else
is counted and dropped. The input chain accepts replies on the tunnel and, when
PIA forwards a port, new TCP and UDP connections to that port, and drops the
rest of what arrives on the tunnel; traffic arriving on other interfaces is
accepted. The forward chain drops everything.

The exit installs the table in one transaction that deletes an earlier one and
adds the new, so there is never a moment without it, and it reads the table
back after every install. It compares chains, hooks, priorities, policies and
rules in order, not counters. An extra rule, a comment, a changed policy or a
missing chain is a difference.

Marks are matched exactly. Only a process with `CAP_NET_ADMIN` can set a socket
mark, and the applications get no capabilities.

### Why both

A routing rule decides where a route lookup goes. A socket that an application
binds to an interface (`SO_BINDTODEVICE`, which any process may do since
Linux 5.7) is not looked up the same way: when the lookup fails, the kernel
assumes the destination is on-link and sends the packet out of the bound
device (`ip_route_output_key_hash_rcu`). With the tunnel down and the fallback
route in place, an application could bind to the host interface and reach the
network outside the tunnel. The firewall's output policy drops that packet. The
contract, for its part, routes ordinary traffic into the tunnel and turns it
into an error when the tunnel route disappears; the firewall alone would not
route anything. The namespace drills check both, in [testing](testing.md#090).

### The exit's own traffic

The exit's own requests must not depend on the tunnel they set up, so in a
native sidecar every request that is not bound to the tunnel interface carries
the control mark, `CONTROL_MARK`. Rule 88 sends it to the main table, the
firewall admits it, and it leaves by the host interface. That covers the
provider's login and server-list downloads, PIA's token and its registration
with the server's public address, and the Gatus push. The exit resolves those
requests' host names with Go's own resolver over sockets that carry the same
mark, so the lookups take the host path too.

Requests bound to the tunnel interface, the egress checks and PIA's
port-forwarding calls, carry no mark and follow rule 96 into the exit table.
The applications get no capability, so they cannot mark a socket and cannot use
the host path.

### What stays when the exit stops

The stop sequence removes the tunnel link and nothing else
([the stop sequence](architecture.md#the-stop-sequence)). The rules, the
fallback and the firewall stay, so the applications in the namespace have no
route out except to your LAN prefixes and no tunnel to use. When the exit
starts again in the same namespace it replaces the firewall in one transaction,
repairs the rules, and builds the tunnel. This is what lets a Kubernetes pod
keep its namespace across a container restart. Under Docker, restarting or
recreating the exit gives it a new namespace instead; see
[recovery](#recovery).

## Settings

Compose sets `EXIT_KIND=sidecar` and `TUNNEL_BACKEND=native` itself. All
settings are [configuration](configuration.md#native-sidecar) too; the refusals
below are printed as `molebridge-exit: <message>`, and `check-config` shows
them without starting anything.

| Setting | Default | Meaning |
|---|---|---|
| `EXIT_KIND` | `overlay` | `sidecar` selects this kind with the native backend |
| `TUNNEL_BACKEND` | `native` | Must be `native`. `wireguard` is read as `native` |
| `PROVIDER` | `mullvad` (`pia` in the Compose file) | `mullvad`, `pia` or `nordvpn` |
| `EXIT_IF` | `mullvad` (`pia` in the Compose file) | The tunnel interface, and the tunnel config's file name under `tunnel/wg_confs/`: up to 15 characters, letters, digits and underscore first, then also `.` and `-` |
| `EXIT_TABLE` | `51821` | The exit table, and the tunnel device's firewall mark. A whole number from 256 to 2147483647 with no leading zero. Tables 51820 and 7120 are not reserved here: no gluetun and no NetBird runs |
| `HOST_IF` | `eth0` | The namespace's interface toward the host. Docker and Kubernetes name it `eth0`; rootless Podman with pasta copies the host's interface name. The deletion check judges the control-marked path against it and the watcher follows it; the firewall doesn't use it. Not `lo`, not `EXIT_IF` |
| `CONTROL_MARK` | `0x1bd00` | The mark on the exit's own host-path sockets: lowercase hexadecimal with a leading `0x`, no leading zero, low byte zero. Must differ from `EXIT_TABLE` |
| `SIDECAR_LAN_CIDRS` | empty | The networks your applications may reach outside the tunnel, below |
| `PIA_PORT_FORWARD` | `off` | `on` forwards one PIA port to the namespace itself; see [port forwarding](#port-forwarding) |

`SIDECAR_LAN_CIDRS` is a comma-separated list of IPv4 and IPv6 prefixes. Put
in it the networks the applications must reach without the tunnel: in
Compose, the engine's network, which published ports and their replies use;
in Kubernetes, the pod and Service ranges and anything that connects to the
application. Each entry must be a network prefix written with its network
address (`198.51.100.0/24`, not `198.51.100.5/24`). Spaces around an entry are
dropped. There can be at most 16 entries, IPv4 and IPv6 together. The exit
refuses:

| Message | Cause |
|---|---|
| `SIDECAR_LAN_CIDRS must have at most 16 entries` | More than 16 |
| `SIDECAR_LAN_CIDRS: empty entry is not a network prefix` | An empty entry, such as a trailing comma |
| `SIDECAR_LAN_CIDRS: <entry> is not a network prefix` | Not a prefix (no `/`, a bad address or length), or an IPv4-mapped IPv6 address |
| `SIDECAR_LAN_CIDRS: <entry> is a default route` | A `/0` prefix |
| `SIDECAR_LAN_CIDRS: <entry> must use the network address` | Host bits set |
| `SIDECAR_LAN_CIDRS: <entry> is duplicated` | The same prefix twice |

Beyond that the exit checks nothing about breadth: a `/1` prefix is accepted
and sends half the address space outside the tunnel. Anything in the namespace
can reach a LAN prefix without the tunnel, so list your own networks, not
broad ranges such as `10.0.0.0/8` unless you mean them. When PIA assigns a
tunnel address inside one of these prefixes or one of the namespace's own, the
exit refuses to use it and the registration is retried on the usual backoff
([retries](operations.md#retries)); a prefix that covers the addresses PIA
hands out keeps that registration from succeeding.

These are refused as well:

| Message | Cause |
|---|---|
| `EXIT_KIND must be overlay or sidecar`, `TUNNEL_BACKEND must be native or gluetun` | A value outside the two |
| `PROVIDER must be mullvad, pia or nordvpn` | Any other provider, a `gluetun-*` id included |
| `OVERLAY_CIDR is for the overlay kind; a sidecar has no overlay`, and the same for `OVERLAY6_CIDR` and `OVERLAY_IF` | One of the three is set |
| `invalid interface name`, `invalid HOST_IF` | `EXIT_IF` or `HOST_IF` is not a valid interface name |
| `HOST_IF must name the namespace's host interface, not lo, the overlay or the tunnel` | `HOST_IF` is `lo` or the same as `EXIT_IF` |
| `EXIT_TABLE must be numeric`, `EXIT_TABLE must be canonical decimal`, `EXIT_TABLE must be 256..2147483647` | The table number |
| `CONTROL_MARK must be lowercase hexadecimal like 0x1bd00`, with `, low byte zero` appended when the low byte is set | The mark |
| `CONTROL_MARK and EXIT_TABLE must differ` | Both are the same number |
| `PIA_PORT_FORWARD_TARGET is for the overlay kind; a sidecar's forwarded port reaches the namespace itself` | The target is set; it is refused whatever `PIA_PORT_FORWARD` says |

`NB_*` and `WT_*` settings are ignored: no NetBird runs. The tunnel config, the
PIA login, `SERVER`, the panel and the Gatus settings mean what they mean in a
native overlay exit ([configuration](configuration.md)).

## DNS

Molebridge doesn't tunnel or configure DNS. The applications use the
namespace's `/etc/resolv.conf`, which your engine writes, and what its
resolvers are depends on the engine; the exit does not look at it. The routing
decides the path of a lookup like any other packet:

- A resolver inside `SIDECAR_LAN_CIDRS` answers outside the tunnel. Your
  applications' lookups reach it, and whatever it forwards upstream leaves
  from its own network, not through the tunnel. In Kubernetes the cluster's DNS
  service is in the Service range you must list, so the names your application
  looks up go to the cluster's resolver.
- A resolver outside `SIDECAR_LAN_CIDRS` is reached through the tunnel. If the
  provider's network does not let it answer, lookups fail.
- The exit's own lookups are marked and go to the host, whatever the
  resolvers are ([above](#the-exits-own-traffic)).

To keep lookups inside the tunnel, point the namespace at a resolver that the
tunnel can reach and leave its network out of `SIDECAR_LAN_CIDRS`, with the
engine's DNS settings: `dns:` on the exit service in Compose, `dnsPolicy` and
`dnsConfig` in a pod. Run the DNS check in [verification](verification.md#a-native-sidecar)
afterwards. None of this has been tested.

## Port forwarding

With PIA, `PIA_PORT_FORWARD=on` forwards one port to the namespace itself. It
needs no target. After each healthy switch the exit asks PIA for a port through
the tunnel and binds it again every ten minutes (PIA drops a port that isn't
bound for 15), as on an overlay exit, and lists only regions that offer
forwarding ([providers](providers.md#port-forwarding)). A sidecar has no DNAT
table (`ip molebridge_forward`) and no ingress guard (`inet molebridge_guard`):
the firewall's input chain admits the port instead. Each time the port changes
or goes away, the exit installs the firewall again with the new port, or with
none.

The port is published in `result.json` as `forwarded_port`, with `port_forward`
and `port_forward_error`, and Switchyard shows it under Diagnostics. PIA picks
the number and it can change after a switch, a re-registration or a restart.
Your application has to listen on that port itself; there is no port
translation. This opens a port to the Internet: anyone can connect to it, and
the connection reaches your application.

For qBittorrent the `port-sync` role keeps the listening port in step
([tools reference](tools-reference.md#port-sync)). It runs as its own container
in the same namespace, with no capabilities, reads the exit's record from a
read-only mount and calls qBittorrent's Web API on loopback. In Compose it is
the `port-sync` service, started by the profile of that name. Any other
application needs its own way to follow `forwarded_port`.

## Set up

You need Docker with Compose 2.24 or later, a kernel where the `wireguard`
module is loaded or loadable, and an account with Mullvad, PIA or NordVPN.
Rootless Podman with podman-compose is untested for this form. No Python is
needed.

1. From the verified, extracted bundle ([setup](setup.md#1-download-and-verify)):

   ```sh
   cp .env.native-sidecar.example .env
   mkdir -p state/panel state/applier secrets/pia tunnel/wg_confs
   chmod 700 secrets secrets/pia tunnel/wg_confs
   IMAGE=$(grep -o 'ghcr.io/irashack/molebridge[^ "]*' compose.native-sidecar.yaml | head -1)
   ```

   `secrets/pia` must exist for every provider; Compose refuses to start when it
   is missing. Set `PANEL_USER` to the uid:gid that owns `state/` (`0:0` and
   `PANEL_ALLOW_ROOT=1` under rootless Podman), as in
   [configuration](configuration.md#overrides).

2. Edit `.env`. Set `PROVIDER` and `EXIT_IF` to match (`pia` and `pia`, or
   `mullvad` and `mullvad`, or `nordvpn` and `nordvpn`). Set
   `SIDECAR_LAN_CIDRS` to the networks your applications must reach outside
   the tunnel, including the engine's network if you publish a port (the subnet that
   `docker network inspect` shows for your project's network): a published
   port's replies are dropped if it isn't listed. The example file's
   `198.51.100.0/24` is a documentation range; replace it. Set `SERVER` to a
   server or PIA region id if you want the exit to converge to it without the
   panel.

3. Create the tunnel config and, for PIA, store the login, as in
   [setup](setup.md#3-create-the-tunnel-config). For PIA that is:

   ```sh
   docker run --rm --user "$(id -u):$(id -g)" \
     -v "$PWD/tunnel/wg_confs:/out" \
     "$IMAGE" prepare-config --pia /out/pia.conf

   (umask 077; printf '%s' 'p1234567' > secrets/pia/username)
   (umask 077; read -rs pia_password && printf '%s' "$pia_password" > secrets/pia/password)
   ```

4. Add your applications in a Compose file of your own, for example
   `compose.apps.yaml`:

   ```yaml
   services:
     downloader:
       image: <your image, pinned>
       network_mode: service:exit
       cap_drop: [ALL]
       depends_on:
         exit:
           condition: service_healthy
           restart: true
   ```

   Then, in `.env`, set `COMPOSE_FILE=compose.native-sidecar.yaml:compose.apps.yaml`
   and remove `COMPOSE_PROFILES=example` once yours are in; until then the
   example application, a busybox that only sleeps, stands in. Give the
   applications no capabilities: without `NET_ADMIN` they can neither change
   the rules nor mark a socket past the firewall. To reach an application from
   the host, publish its port on the `exit` service (the comment in the Compose
   file shows where) and list the engine's network in `SIDECAR_LAN_CIDRS`.

5. For qBittorrent with PIA's forwarded port, set `PIA_PORT_FORWARD=on`, put
   qBittorrent's Web UI login in `secrets/port-sync/username` and
   `secrets/port-sync/password` (mode 0600, one value per file), and add the
   `port-sync` profile: `COMPOSE_PROFILES=example,port-sync`. Turn on
   qBittorrent's Web UI and have it listen on `PORT_SYNC_URL`, `127.0.0.1:8080`
   by default.

6. Start and check:

   ```sh
   docker compose config --quiet
   docker compose run --rm --no-deps exit check-config
   docker compose up -d exit switchyard
   docker compose logs exit
   ```

   `check-config` prints `molebridge-exit: configuration accepted
   (/config/wg_confs/pia.conf: no address (the exit sets it))` or the one line
   naming what it refused ([troubleshooting](troubleshooting.md#a-native-sidecar)).
   The log should show, in order, `molebridge-exit: the sidecar firewall is installed`,
   `molebridge-exit: rules installed; the exit table holds its unreachable fallback`,
   `molebridge-exit: bringing the tunnel up` and `molebridge-exit: tunnel up`.

7. Open `http://127.0.0.1:8095` (or your `PANEL_PORT`). With PIA or NordVPN,
   choose a region or server now unless you set `SERVER`: until then the
   exit has no tunnel address, stays unhealthy, and the applications, which
   wait for it, don't start. Then start the rest and read the status:

   ```sh
   docker compose up -d
   docker compose exec exit molebridge status
   ```

   The applications' connections may drop during a switch.

8. Run the checks in [verification](verification.md#a-native-sidecar) before you
   rely on it, and the attachment procedure
   ([operations](operations.md#checking-that-containers-share-gluetuns-namespace))
   after every start, recreation or reboot.

## Kubernetes

The example runs the exit as a Kubernetes sidecar container beside an
application, and `port-sync` as a further container. This is the form the live
acceptance on Kubernetes uses, but it is not a packaged or supported form:
Molebridge ships no manifests, and nothing in it has run live yet
([testing](testing.md#090)). Adapt it, and check it with the
[verification](verification.md#a-native-sidecar) drills in your own cluster.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: downloader
spec:
  initContainers:
    - name: exit
      image: ghcr.io/irashack/molebridge:<tag>@sha256:<digest>   # the verified reference
      args: ["exit"]
      restartPolicy: Always            # a sidecar container: it keeps running
      env:
        - {name: EXIT_KIND, value: sidecar}
        - {name: TUNNEL_BACKEND, value: native}
        - {name: PROVIDER, value: pia}
        - {name: EXIT_IF, value: pia}
        - {name: HOST_IF, value: eth0}
        - {name: SIDECAR_LAN_CIDRS, value: "198.51.100.0/24,203.0.113.0/24"}  # pod and Service ranges
        - {name: SERVER, value: "<a PIA region id>"}
        - {name: PIA_PORT_FORWARD, value: "on"}
        - {name: STATE_DIR, value: /state}
        - {name: PIA_SECRETS_DIR, value: /secrets/pia}
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: [ALL]
          add: [NET_ADMIN, NET_RAW]    # add DAC_OVERRIDE only if the files are not owned by the exit's user
      startupProbe:                    # the application starts when this passes
        exec:
          command: ["/usr/local/bin/molebridge", "health"]
        periodSeconds: 5
        failureThreshold: 60
      volumeMounts:
        - {name: run, mountPath: /run}
        - {name: state, mountPath: /state/applier}
        - {name: tunnel, mountPath: /config/wg_confs/pia.conf, subPath: pia.conf, readOnly: true}
        - {name: pia, mountPath: /secrets/pia/username, subPath: username, readOnly: true}
        - {name: pia, mountPath: /secrets/pia/password, subPath: password, readOnly: true}
  containers:
    - name: app
      image: <your application, pinned>
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: [ALL]
    - name: port-sync
      image: ghcr.io/irashack/molebridge:<tag>@sha256:<digest>
      args: ["port-sync"]
      env:
        - {name: STATE_DIR, value: /state}
        - {name: PORT_SYNC_CLIENT, value: qbittorrent}
        - {name: PORT_SYNC_URL, value: "http://127.0.0.1:8080"}
        - {name: PORT_SYNC_USERNAME_FILE, value: /secrets/port-sync/username}
        - {name: PORT_SYNC_PASSWORD_FILE, value: /secrets/port-sync/password}
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: [ALL]
      volumeMounts:
        - {name: state, mountPath: /state/applier, readOnly: true}
        - {name: port-sync, mountPath: /secrets/port-sync, readOnly: true}
  volumes:
    - name: run
      emptyDir: {medium: Memory, sizeLimit: 4Mi}
    - name: state
      emptyDir: {}
    - name: tunnel
      secret: {secretName: molebridge-tunnel, defaultMode: 0600}    # holds pia.conf
    - name: pia
      secret: {secretName: molebridge-pia, defaultMode: 0600}       # holds username and password
    - name: port-sync
      secret: {secretName: molebridge-port-sync, defaultMode: 0600} # holds username and password
```

Create the secrets from files you wrote as in [setup](setup.md#3-create-the-tunnel-config),
never from values on a command line. The notes that go with it:

- **A container restart keeps the pod's namespace**, and the exit is built for
  that: it replaces the firewall in one transaction and repairs the rules, then
  rebuilds the tunnel. While it is down the applications have no route out
  ([what stays when the exit stops](#what-stays-when-the-exit-stops)).
- **`SIDECAR_LAN_CIDRS` must name the pod and Service ranges**, and anything
  that connects to the application: node addresses for a NodePort or host
  port, and where the kubelet's probes come from. Replies to a client outside
  these prefixes go into the tunnel and are lost. Cluster DNS answers outside
  the tunnel if its service is in these ranges ([DNS](#dns)).
- **The Kubernetes version.** The exit is an init container with
  `restartPolicy: Always`, which needs Kubernetes 1.29 or later. The kubelet
  starts the application when the exit's startup probe passes.
- **The startup probe is `molebridge health`.** It passes when the exit is
  operational: the tunnel interface is up, the contract and the firewall are
  verified and a completed check is less than 150 seconds old. That is not the
  same as verified egress, which is what `molebridge status` reports
  ([health](operations.md#health)). The exit becomes healthy about a minute
  after it starts. With PIA and no `SERVER` it stays unhealthy until a region is
  chosen, and there is no panel in this pod, so set `SERVER`.
- **No sysctl is needed**, so the pod needs no unsafe-sysctl allowance.
- **`wireguard` must be loadable on the node.** A container can't load kernel
  modules; check with `modprobe wireguard` on the node
  ([requirements](prerequisites.md#rootless-podman)).
- **Mount each secret file with `subPath`.** The exit refuses a symbolic link
  for the tunnel config, and reads the PIA login without following one. A
  Kubernetes secret volume presents its files as symbolic links, so a plain
  mount of the secret fails; `subPath` mounts the file itself. The
  `port-sync` role does follow links, so it can mount its secret as a directory.
- **State.** `emptyDir` is enough: the exit registers its region again when the
  pod is recreated. A persistent volume keeps `state/applier` across pods
  ([the files](configuration.md#state-files)). The exit runs as root in its
  container and writes it, so a volume owned by another user needs
  `DAC_OVERRIDE`.
- **The application has no capabilities** and, with the firewall in the same
  namespace, no way to use the host path. Keep `port-sync` as a separate
  container too, so the exit never holds the application's credentials.

Read the exit's log with `kubectl logs downloader -c exit` and its verdict with
`kubectl exec downloader -c exit -- molebridge status`.

## Recovery

When the exit restarts but its namespace is kept, as in a Kubernetes pod, there
is nothing to do: the firewall and the rules stayed, the applications stayed
closed, and the exit rebuilds the tunnel.

Under Compose the namespace is the exit's own. If the exit is recreated, or
restarted in a way that gives it a new namespace, the applications stay in the
old one, where the rules and the firewall still keep them closed, but no
tunnel exists. Recreate them together with the exit, the exit first:

```sh
docker compose up -d --force-recreate
```

recreates every service in the project, including the applications in
`compose.apps.yaml` when that file is in `COMPOSE_FILE`. Applications you run
elsewhere need their own recreate command, after the exit. Then run the
attachment procedure
([operations](operations.md#checking-that-containers-share-gluetuns-namespace))
and read `docker compose exec exit molebridge status`: operational recovery
and verified egress are two different things.

If the exit stops with `molebridge-exit: the sidecar firewall could not be
installed; no tunnel was started`, no tunnel exists and the applications stay
closed; the line before it says why
([troubleshooting](troubleshooting.md#a-native-sidecar)).

Nothing here deletes a volume.

## Removing

`docker compose down` stops and removes the containers; the namespace goes with
the exit. Add `-v` to also delete any volumes. Delete `secrets/`, `state/`,
`tunnel/` and `.env`, or keep them if you might reinstall. On Kubernetes, delete
the pod and the secrets you created for it.
