# Verification

Run these on your own host before relying on the exit, and again after
changing routing, the tunnel config, Compose networking or the image.
[Testing](testing.md) records which checks have run and on which platforms; at
0.8.0 none of the live ones have yet.

Keep an independent host access path. Do not share raw addresses or peer
information from diagnostics. Never run `wg showconf`, `wg show ... dump` or
`wg show ... private-key` for a report: they disclose the live key.

Commands use the defaults: the exit container `molebridge-exit`, tunnel
interface `mullvad`, exit table `51821`, and overlay interface `wt0`. For PIA,
substitute `pia` for `mullvad` in interface names and config paths, and
`nordvpn` for NordVPN; the table stays `51821`. NordVPN is experimental. If you
changed `COMPOSE_PROJECT_NAME`, `EXIT_IF`, `EXIT_TABLE` or `OVERLAY_IF`, use
your values. For rootless Podman, use `podman` where this page says `docker`
(the [Podman notes](operations.md#rootless-podman)).

**The gluetun backend** has other rules, so the namespace checks and drills on
this page don't carry over by renaming. Use the ones in
[gluetun as a NetBird exit](gluetun-netbird-exit.md#verification), then
`docker compose exec exit molebridge status`. The [client checks](#from-a-client)
below apply as written. One difference matters when you read results: in
gluetun's namespace, unmarked traffic the exit sends goes into gluetun's tunnel,
and only NetBird's marked control traffic uses the host's connection, so check 4
below doesn't apply.

## Inside the namespace

The exit container is an Alpine image with busybox, not a toolbox: it has no
`curl`, `nft`, `wg`, `tcpdump` or iproute2's `ip` (busybox's `ip` has no `-d`
and no `route get`, and it knows none of the rule selectors the contract uses, such
as `not`, `ipproto` and `suppress_prefixlength`). For the checks below, join a
throwaway container to the exit's network namespace and install the tools in it.
It uses the same pinned Alpine as the image, and downloads its packages through
the namespace's ordinary route (the host's), so it needs the Internet:

```sh
docker run --rm -it --network container:molebridge-exit \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  docker.io/library/alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 \
  sh -c 'apk add --no-cache iproute2 nftables curl wireguard-tools tcpdump >/dev/null && exec sh'
```

Commands below that say "in the shell" run there. This container has `NET_ADMIN`
in the exit's namespace, so it can change what the exit protects: that is how the
drills break things, and it is why you start it only to look or to drill and leave
it again. Nothing from the exit's own container is exposed to it except the
network.

What the exit container itself can answer without that shell:

```sh
docker compose exec exit molebridge status             # the verdict, the lease and the heartbeat
docker compose exec exit ps                             # molebridge exit, molebridge exit --worker, netbird service run
docker inspect -f '{{.HostConfig.CapAdd}} {{.HostConfig.CapDrop}}' molebridge-exit
docker exec molebridge-switchyard grep CapEff /proc/self/status    # 0000000000000000: the panel holds nothing
```

On PIA, select a region before completing checks 1–3, 6 and 8: registration
supplies the tunnel address, peer and IPv4 rules 94 and 98. Select a region
before the fail-closed drills and client or port-forwarding checks too. IPv6
stays blocked; PIA has no global IPv6 tunnel address or IPv6 rules 94 and
98.

On NordVPN, select a server before checks 3 and 8 and the drills: the config
has no peer until you do. Its IPv4 address (`10.5.0.2`) and rules 94 and 98
come from the config, as with Mullvad; IPv6 stays blocked as on PIA.

1. Check the rules. In the shell, `ip rule` shows priority 1 (`not from all iif
   wt0 lookup local`) and no priority-0 `from all lookup local` rule, then
   priority 90 (`iif mullvad`, overlay destination → `main`), 94 (`from` the
   tunnel's IPv4 address, `ipproto icmp` → table 51821), 95 (`iif wt0` → table
   51821), 96 (`oif mullvad` → table 51821), 97 (`iif wt0 unreachable`), and 98
   (`from` the tunnel's IPv4 address, `ipproto icmp unreachable`), and nothing
   else up to priority 98. No temporary priority-80 guard should remain. IPv6
   (`ip -6 rule`) has 1/95/96/97 in all cases, 90 when `OVERLAY6_CIDR` is set, and
   94 and 98 with `ipproto ipv6-icmp` when the tunnel has an IPv6 address. Rules 94
   and 98 must carry the protocol qualifier: without it every protocol sourced from
   the tunnel address is forced into the tunnel, or dropped, and the exit's `routing`
   check fails. `ip` may print the protocol as `1` or `58`.
2. Check the exit table. `ip route show table 51821` shows `default dev mullvad`
   and `unreachable default ... metric 4096`. The same holds for `ip -6 route show
   table 51821` with an IPv6 tunnel config; an IPv4-only config still has the IPv6
   unreachable fallback. PIA and NordVPN must have only that fallback for IPv6, with
   no tunnel default.
3. Check provider egress with the commands below. For a dual-stack Mullvad
   tunnel, both families must succeed. On PIA, IPv4 must report `"connected":
   true`, and on NordVPN `protected` must be `true`; on both, IPv6 through the
   exit must fail on the unreachable fallback.
4. Check unbound traffic with the IPv4 probe for your provider, omitting
   `--interface`. It should report your host's normal public IP. This is the
   path for the provider handshake and NetBird control connections.
5. Check the trust boundary. The panel can read `state/applier/relays.json` but
   cannot write the applier mount (`docker exec molebridge-switchyard touch
   /state/applier/x` must fail with a read-only filesystem). The old panel-owned
   catalogue is ignored. A malformed desired file and a valid request for an
   unlisted name must report failure without changing the peer. A valid request has
   `server`, `requested_at` (current UTC `YYYY-MM-DDTHH:MM:SSZ`) and an optional
   32-character lowercase hexadecimal `request_id`. Use a fictitious unlisted name
   such as `xx-xxx-wg-999`, then restore the desired state by selecting a valid
   server or region in the panel. In the shell, `wg show mullvad peers` exposes only
   public peer keys.
6. Check that the exit's ICMP errors return through the tunnel. In the shell, `cat
   /proc/sys/net/ipv4/icmp_errors_use_inbound_ifaddr` prints `1`, and `ip route get
   198.51.100.1 from <tunnel IPv4 address> ipproto icmp` shows `dev mullvad`; with an
   IPv6 tunnel address, `ip -6 route get 2001:db8::1 from <tunnel IPv6 address>
   ipproto ipv6-icmp` does too. On PIA and NordVPN, run only the IPv4 return-path
   check. With an IPv6 tunnel, replies larger than the overlay MTU should increase
   `Icmp6OutPktTooBigs` in `/proc/net/snmp6`. Capture on both the tunnel and host-side
   interfaces (`tcpdump -ni mullvad 'icmp6 and ip6[40] == 2'`, and the same on `eth0`):
   the errors should leave through the tunnel and not the host-side interface. Do not
   rely on `Ip6OutNoRoutes`: on a container network without IPv6 it also counts the
   exit's own IPv6 attempts. Without this return path, oversized replies are dropped
   with no error to the origin, which can stall UDP flows such as QUIC through the exit.
7. Check that NetBird runs kernel WireGuard with its kernel firewall. In the shell,
   `ip -d link show wt0` shows `wireguard` on its details line, and `nft list tables`
   shows `table ip netbird` or a `table ip filter` whose chains include `NETBIRD-`
   ones (`nft list chains`). The exit's `netbird` check requires both.
8. `docker compose exec exit molebridge status` should print `state: ok (connected)`.
   It checks routing, NetBird's mode, status freshness and, last, the verdict on the
   exit's record. Its `lease:` line should say `held`, and `heartbeat:` `fresh`.

Run these egress probes in the shell:

| Provider | Command | Expected |
|---|---|---|
| Mullvad, IPv4 | `curl -4 -fsS --interface mullvad https://ipv4.am.i.mullvad.net/json` | `"mullvad_exit_ip": true` |
| Mullvad, IPv6 tunnel | `curl -6 -fsS --interface mullvad https://ipv6.am.i.mullvad.net/json` | `"mullvad_exit_ip": true` |
| PIA, IPv4 | `curl -4 -fsS --interface pia https://www.privateinternetaccess.com/api/client/status` | `"connected": true` |
| PIA, IPv6 | `curl -6 -fsS --max-time 10 --interface pia https://ipv6.am.i.mullvad.net/json` | Connection fails; IPv6 is blocked |
| NordVPN, IPv4 | `curl -4 -fsS --interface nordvpn https://api.nordvpn.com/v1/helpers/ips/insights` | `protected` is `true` |
| NordVPN, IPv6 | `curl -6 -fsS --max-time 10 --interface nordvpn https://ipv6.am.i.mullvad.net/json` | Connection fails; IPv6 is blocked |

The PIA and NordVPN IPv6 probes check blocking. Use the explicit IPv6 hostname above;
`am.i.mullvad.net` itself has no AAAA record. A DNS failure alone does not
prove routing blocked the request.

## Fail-closed drills

Run these on every exit you rely on, each provider and backend, with a client
holding the exit. For each drill, keep that client on the selected exit probing
the provider's status endpoint above or pinging a public IP. During the drill,
the affected path must fail without using your host's own public IP. Test IPv4
and IPv6 explicitly; a browser check may exercise only one family. Where the exit
carries both families, drill both. Where it carries only IPv4 (PIA, NordVPN, an
IPv4-only Mullvad config), check that IPv6 is blocked before, during and after
each drill.

Also record any client fallback to its own connection: server routing cannot
enforce a device-wide kill switch after NetBird disconnects or deselects the exit.

**The repair is fast, so hold it off to see the containment.** The exit repairs a
deleted rule or route as soon as the kernel announces the change, normally within
a few milliseconds and by design within 250 ms. A client probe will usually not
notice a deletion at all. That is the repair working, and what you check in that
case is the log line and the absence of any host-interface traffic (the
[capture](#a-capture-on-the-host-interface) below). To watch a path fail, freeze
the worker, which holds the repairer, make the break in the shell, watch the probe
fail, and let the worker continue within the lease (`GUARD_GRACE`, 30 seconds by
default; 15 is a safe window):

```sh
docker exec molebridge-exit pkill -STOP -f 'exit --work[e]r'
# ... break something in the shell, watch the client's probe fail ...
docker exec molebridge-exit pkill -CONT -f 'exit --work[e]r'
```

(The bracket keeps `pkill` from matching its own command line.) A worker frozen
longer than the lease is itself a drill, the last-but-one row below. Follow the
exit's log while you run them: `docker compose logs -f exit`.

| Drill | Break (in the shell) | Expect |
|---|---|---|
| Tunnel down | `ip link del mullvad` | The probe fails until the exit brings the tunnel back by itself: `molebridge-exit: bringing the tunnel up`, then `molebridge-exit: tunnel up`. |
| IPv4 route deleted | `ip route del default dev mullvad table 51821` | The probe fails on the unreachable fallback until the repair logs `molebridge-exit: molebridge: IPv4 tunnel route through mullvad restored`. |
| IPv6 route deleted (dual-stack Mullvad only) | `ip -6 route del default dev mullvad table 51821` | The same for IPv6: `molebridge-exit: molebridge: IPv6 tunnel route through mullvad restored`. |
| IPv4 lookup rule deleted | `ip rule del priority 95` | The probe fails on rule 97 until `molebridge-exit: molebridge: added IPv4 rule 95`. |
| IPv6 lookup rule deleted | `ip -6 rule del priority 95` | The same for IPv6: `molebridge-exit: molebridge: added IPv6 rule 95`. |
| Terminal rule deleted | `ip rule del priority 97` | The probe keeps working through rule 95 and the tunnel; then `molebridge-exit: molebridge: added IPv4 rule 97`. |
| Fallback deleted | `ip route del unreachable default metric 4096 table 51821` | The probe keeps working through the tunnel route; then `molebridge-exit: molebridge: IPv4 unreachable fallback in table 51821 restored`. |
| Return path deleted (Mullvad, NordVPN) | `ip rule del priority 94` | Until `molebridge-exit: molebridge: added IPv4 rule 94`, `ip route get 198.51.100.1 from <tunnel IPv4 address> ipproto icmp` in the shell fails as unreachable (rule 98) instead of naming the host's interface. |
| Inserted bypass | `ip rule add lookup main priority 50` | Removed by the repair: `molebridge-exit: molebridge: removed IPv4 rule 50: from all lookup main`. Nothing is promised about traffic before that. |
| Wrong action at a protected priority | `ip rule del priority 97; ip rule add iif wt0 lookup main priority 97` | The rule is corrected and the change logged. Until then, forwarded traffic is held by rule 95 and the exit table, not by 97. |
| Worker hung | `docker exec molebridge-exit pkill -STOP -f 'exit --work[e]r'`, and leave it | The tunnel and NetBird keep forwarding while the lease lasts. After `GUARD_GRACE` seconds `molebridge-exit: stopping (lease lapsed)` appears, NetBird is stopped (TERM at once, KILL at 6 seconds), the tunnel and overlay interfaces are removed, the container exits with status 1 and its restart policy starts it again. The panel shows the exit as failed, "exit owner stopped responding", within the lapse time, and `/readyz` returns 503. |
| NetBird killed | `docker exec molebridge-exit pkill -KILL -x netbird` | The supervisor notices (`molebridge-exit: NetBird stopped unexpectedly: ...`), runs the stop sequence and exits with status 1; the restart policy starts a clean container. |
| Container stopped | `docker compose stop exit` | The probe fails, the exit's log has `molebridge-exit: stopping (requested)` and ends `molebridge-exit: stopped (requested, exit 0); the routing guards stay in place`. Restore with `docker compose up -d exit`. |

On PIA, rules 94 and 98 belong to the PIA transaction, which puts a deleted one back
within one pass of the exit's loop (normally 5 seconds, longer during a switch or
periodic check), without a log line. After each drill, confirm provider egress returns
on the supported families. After the tunnel-down drill, the exit reapplies the saved
server or region when the interface returns. A failed switch is retried by itself on
its backoff, and clears at a later check when its server is live and verified
([retries](operations.md#retries)). These drills follow from the code and the
isolated drills below; [testing](testing.md) records which have run on a live exit.

Confirm the exit host's own unbound traffic stays on its ordinary path while the
client path is blocked.

### A capture on the host interface

To see that nothing a client sends leaves by the host's route, capture on the
namespace's host-side interface in the shell for the duration of a drill, filtered on
the address your probe targets (`<probe-ip>`):

```sh
tcpdump -ni eth0 'host <probe-ip>'
```

It must print nothing for the whole drill. A packet there means a client's traffic left
the namespace by the host's route. `eth0` is Docker's name; under rootless Podman with
pasta it is the host's own interface name. Without a filter you should see NetBird's
WireGuard port, STUN and its TCP control connections, and the provider's endpoint;
anything else needs an explanation.

### What the isolated drills cover

The namespace drills in `internal/drill` run the same cases against a real kernel,
inside disposable namespaces in a privileged container (CI, and
`internal/nstest/drill.sh` locally; [CONTRIBUTING](../CONTRIBUTING.md#checks)). They delete
all exit-table routes together to exercise the terminal guard; check that an oversized
tunnel reply produces an ICMP error back over the tunnel, that a missing return-path rule
is detected, and that with the tunnel route gone no error reaches the tunnel side; count
ICMP errors that reach the host side (none escape with rule 94 missing or with the exit
table empty, and removing rules 94 and 98 together shows the counter can see them); send
TCP and UDP from the overlay side to the exit's overlay and host-side addresses, in both
families, and check that no listener in the exit's namespace receives them, also after an
nftables DNAT to a local port; assert that a single deletion or insertion is repaired within
250 ms of the event; try rules with the wrong action or an extra selector; flood the event
socket until the kernel drops events; and check continuously, with packets, that nothing
forwarded leaves while a repair runs. A hung worker and a crashed one, with the namespace kept
alive by another container, are checked the same way: nothing forwarded leaves off-tunnel, and
overlay forwarding has stopped once the cleanup has run. What they cover and don't is in
[testing](testing.md#080).

A blocked client path must not appear healthy. The exit checks about once a minute, so a
short break can fall between two checks, and a repair can land inside the window; the
hung-worker drill lasts as long as you leave the worker frozen. During it, confirm the
status record reports `failed` with "exit owner stopped responding", `/readyz` returns 503,
and any monitoring push reports failure. During a
route deletion on a dual-stack Mullvad tunnel, the other family should still work. On PIA,
deleting the IPv4 default must leave both families blocked.

Check that nothing arriving over NetBird reaches the exit itself. In the shell, `ip route get <exit
overlay address> from <client overlay address> iif wt0` must show `dev mullvad table 51821`, not
`local`; with an IPv6 overlay, `ip -6 route get` the same way. `docker compose exec exit netbird
status -d` lists both addresses. From a client on the exit, ping the exit's overlay address: there must
be no reply, although the access policy allows ICMP, because the ping is routed into the tunnel instead
of reaching the exit. Repeat the ping with the tunnel down. The local-delivery refusal was checked on live
PIA, NordVPN and gluetun exits at 0.7.0; [testing](testing.md) says which protocols and families each
covered.

## Status and recovery

### Reading the status

Read the exit's record on the host. Every check is listed with its state; only `pass` counts:

```sh
jq '{schema, kind, status, message, selection, tier: .checks.egress.tier, checks: (.checks | map_values(.state))}' state/applier/result.json
```

A connected overlay exit shows `schema 2`, `ok`, every required check `pass` ([which are
required](architecture.md#the-status-record)), `app_attachment` `n/a`, and `egress tier provider` (or
`tunnel` for a provider with only the tunnel checks). A native exit's `owner_record` check carries an
`expires_at`.

The page, the API, `/readyz`, `molebridge status` and any Gatus push must agree, because they all judge
the record with the same function. Compare them at the same moment:

```sh
curl -fsS http://127.0.0.1:8095/api/status | jq '.verdict | {state, label, reasons, tier}'
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8095/readyz
docker compose exec exit molebridge status | head -n 2
```

Add `?exit=<id>` on a panel serving several exits. `ok` / `connected` goes with `/readyz` 200 and `state: ok
(connected)`; anything else goes with 503 and `state:` followed by the same label and reason codes.

### Status drills

Stop the exit (`docker compose stop exit`). Within 150 seconds plus one browser poll, the panel must show
stale/unknown and `/readyz` must return 503; `/healthz` remains 200. Start it again and confirm fresh status
returns. Disconnect an open browser from the panel and confirm its next failed poll clears connected status.
Test a failed switch followed by **Retry**, which applies at once, and confirm the panel shows when the exit
would have retried by itself ("Retrying at … UTC").

Start a switch and, before it finishes, choose another server from a second tab: the panel must answer 409,
"A switch is in progress; wait for it to finish.", and the first switch must complete. Then choose again.

Fail the egress check briefly while the client holds the exit. Drop the exit's own HTTPS through the tunnel,
which only the exit's egress check uses, and leave it for one or two checks. In the shell:

```sh
nft add table inet molebridge_drill
nft add chain inet molebridge_drill out '{ type filter hook output priority 0; }'
nft add rule inet molebridge_drill out oifname mullvad tcp dport 443 drop
nft delete table inet molebridge_drill
```

Until you delete the table, the panel shows the exit failed with "Tunnel inspection or egress check failed.",
the record's `selection.outcome` is `applied-unverified` with `next_action` `recheck`, the live server stays the
same (no "Applying the requested server."), and the client's traffic continues. After you delete the table, the
next check, within about a minute, shows it connected again. This drill follows from the code; whether it has run
live is in [testing](testing.md). Finally, verify that recreating the exit and a host reboot preserve the NetBird peer
identity. With the gluetun forms, recreate gluetun alone outside Compose and confirm the
[attachment procedure](operations.md#checking-that-containers-share-gluetuns-namespace) fails for the exit, then
recover. Repeat with a non-default `OVERLAY_IF` and confirm NetBird creates that interface.

Start with a saved desired selection, an expired catalogue and an unavailable relay API. Confirm no peer change
occurs and the result says the request will retry. Restore the API and confirm the same request is applied
automatically. An unlisted request is not retried until the server list's names change or you select again, and a
malformed one until you select again; a failed peer update is retried on its backoff.

## From a client

With the exit selected on a device in `exit-users`:

- For Mullvad, <https://mullvad.net/check> reports Mullvad egress in the chosen server's city. For PIA,
  <https://www.privateinternetaccess.com/api/client/status> reports `"connected": true`.
- Addresses on the host's own LAN, such as its router, are unreachable.
- With IPv6 overlay and a `::/0` route, an IPv6 egress check shows a Mullvad address for a dual-stack Mullvad
  tunnel. On PIA it must fail: forwarded IPv6 hits the unreachable fallback. Without an IPv6 overlay and exit
  route, check that IPv6 fails or is unused; a native IPv6 address means that traffic bypasses the exit.
- Try a video call or an HTTP/3 (QUIC) download. A stall followed by recovery can be a symptom of a missing ICMP
  return path when a browser falls back to TCP. Check the return path with namespace step 6 before drawing that
  conclusion; a completed download alone does not test oversized UDP replies.
- On the host, use `docker compose exec exit netbird status -d` to check whether the client's path is `P2P` or
  `Relayed`. If it is relayed, see [direct connections](operations.md#direct-connections). The exit refuses to start
  NetBird unless the exit interface is in the peer's ICE blacklist
  ([the blacklist](operations.md#netbird-interface-blacklist)).
- Choose another Mullvad server or PIA region in the panel. Confirm the panel reports the new location and the
  client's egress follows without reselecting the exit.
- Molebridge does not change DNS; see [operations](operations.md#dns). Run a DNS leak check and confirm the resolvers
  shown are acceptable to you. If it flags a resolver, see
  [when a leak test flags DNS](operations.md#when-a-leak-test-flags-dns).

## Optional PIA port forwarding

These are acceptance checks for [port forwarding](providers.md#port-forwarding). Live forwarding against PIA remains
untested in the [test record](testing.md). Enable it, select a region that offers forwarding, and wait for an allocated
port in the panel or `forwarded_port` in `/api/status`.

- Have the target service listen on that allocated port for TCP and UDP. DNAT changes the destination address and keeps
  the port.
- Confirm the NetBird policy allows the exit peer to reach the target on that port for both protocols. Forwarded
  connections use the exit peer's overlay address.
- From outside your NetBird network, connect to the PIA egress address and allocated port over TCP and UDP. Confirm both
  reach the target service.
- Set `PIA_PORT_FORWARD=off` and clear `PIA_PORT_FORWARD_TARGET`, then recreate the exit so it reads the new settings.
  Check that `nft list table ip molebridge_forward` in the shell reports the table absent after startup; the exit
  retries removal if it fails. `nft list table inet molebridge_guard` must still show the ingress guard. Use new
  connections for the check: existing conntrack mappings can outlive the forwarding rules.
