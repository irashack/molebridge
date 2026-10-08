#!/usr/bin/env sh
# Disposable Linux network namespaces; no accounts, real endpoints or Docker.
set -eu
[ "$(uname -s)" = Linux ] && [ "$(id -u)" -eq 0 ] || {
    echo "Run on Linux as root (sudo sh tools/check-routing.sh)." >&2
    exit 1
}
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
work=$(mktemp -d)
created=''
gate_pid=''
listeners=''
cleanup() {
    if [ -n "$gate_pid" ]; then kill "$gate_pid" 2>/dev/null || true; wait "$gate_pid" 2>/dev/null || true; fi
    for pid in $listeners; do kill "$pid" 2>/dev/null || true; done
    for ns in $created; do ip netns del "$ns" 2>/dev/null || true; done
    rm -f "$work/ready" "$work/rules.json" "$work/routes.json" "$work/gate-started" "$work/mullvad.conf" "$work/pia.conf" "$work/ping" "$work/forward.nft" "$work/guard.nft"
    rm -f "$work/gate.err" "$work/delivered" "$work/listening" "$work/nbstate/default.json"
    rm -f "$work/nbstate/active_profile.json" "$work/legacy.json" "$work/gate-legacy"
    rm -rf "$work/awk-gawk" "$work/awk-mawk" "$work/awk-busybox"
    rmdir "$work/nbstate" 2>/dev/null || true
    rmdir "$work"
}
trap cleanup EXIT HUP INT TERM
client=mb-client-$$
exitns=mb-exit-$$
outside=mb-outside-$$
tunnel=mb-tunnel-$$
overlay_if=${TEST_OVERLAY_IF:-wt0}
# Fictitious tunnel addresses; the fake config mirrors a real one's Address line.
tunnel4=203.0.113.1
tunnel6=2001:db8:3::1
for ns in "$client" "$exitns" "$outside" "$tunnel"; do
    ip netns add "$ns"
    created="$created $ns"
    ip -n "$ns" link set lo up
    ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.default.accept_dad=0
done
ip -n "$exitns" link add "$overlay_if" type veth peer name client0 netns "$client"
ip -n "$exitns" link add eth0 type veth peer name outside0 netns "$outside"
ip -n "$exitns" link add mullvad type veth peer name tunnel0 netns "$tunnel"
# Fixed, locally administered MACs for the synthetic overlay; see the
# permanent neighbor entries below.
ip -n "$exitns" link set "$overlay_if" address 02:00:00:00:01:01
ip -n "$client" link set client0 address 02:00:00:00:01:02

configure() {
    ip -n "$1" addr add "$3" dev "$2"
    ip -n "$1" -6 addr add "$4" dev "$2" nodad
    ip -n "$1" link set "$2" up
}
configure "$exitns" "$overlay_if" 192.0.2.1/24 2001:db8:1::1/64
configure "$client" client0 192.0.2.2/24 2001:db8:1::2/64
configure "$exitns" eth0 198.51.100.1/24 2001:db8:2::1/64
configure "$outside" outside0 198.51.100.2/24 2001:db8:2::2/64
configure "$exitns" mullvad "$tunnel4/24" "$tunnel6/64"
configure "$tunnel" tunnel0 203.0.113.2/24 2001:db8:3::2/64
# The overlay link is narrower than the tunnel, as with a real WireGuard pair
# (1280 inside NetBird, 1420 inside Mullvad), so tunnel replies can need
# fragmentation and the exit must send ICMP errors back through the tunnel.
ip -n "$exitns" link set "$overlay_if" mtu 1280
ip -n "$client" link set client0 mtu 1280
ip -n "$exitns" link set mullvad mtu 1420
ip -n "$tunnel" link set tunnel0 mtu 1420
# The fake tunnel is Ethernet; real WireGuard needs no neighbor discovery.
# Use a fixed, locally administered MAC for the synthetic destination below.
ip -n "$tunnel" link set tunnel0 address 02:00:00:00:03:02
ip netns exec "$exitns" sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
# compose.yaml sets this on the wireguard service; the applier requires it.
ip netns exec "$exitns" sysctl -qw net.ipv4.icmp_errors_use_inbound_ifaddr=1
ip -n "$client" route add default via 192.0.2.1
ip -n "$client" -6 route add default via 2001:db8:1::1
ip -n "$exitns" route add default via 198.51.100.2
ip -n "$exitns" -6 route add default via 2001:db8:2::2
ip -n "$outside" route add 192.0.2.0/24 via 198.51.100.1
ip -n "$outside" -6 route add 2001:db8:1::/64 via 2001:db8:2::1
ip -n "$tunnel" route add 192.0.2.0/24 via "$tunnel4"
ip -n "$tunnel" -6 route add 2001:db8:1::/64 via "$tunnel6"
# Real WireGuard has no neighbor discovery; this veth stand-in does. The
# local-delivery guard (rule 1) keeps everything arriving on the overlay away
# from the exit's own stack, including ARP requests for its address (the
# kernel answers only when the route lookup says local) and IPv6 neighbor
# discovery. Fixed entries in both directions keep the fixture working; the
# production guard is unchanged.
for address in 192.0.2.1 2001:db8:1::1; do
    ip -n "$client" neigh replace "$address" lladdr 02:00:00:00:01:01 nud permanent dev client0
done
for address in 192.0.2.2 2001:db8:1::2; do
    ip -n "$exitns" neigh replace "$address" lladdr 02:00:00:00:01:02 nud permanent dev "$overlay_if"
done
# The same fictitious destination is reachable over both paths. A broken
# guard would therefore turn an expected failed client probe into a success.
ip -n "$outside" addr add 198.51.100.100/32 dev outside0
ip -n "$outside" -6 addr add 2001:db8:2::100/128 dev outside0 nodad
ip -n "$tunnel" addr add 198.51.100.100/32 dev tunnel0
ip -n "$tunnel" -6 addr add 2001:db8:2::100/128 dev tunnel0 nodad

# Only the Address line matters to the routing script; the key is a zero placeholder.
cat > "$work/mullvad.conf" <<EOF
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = $tunnel4/32, $tunnel6/128
Table = off
EOF
# A PIA config has no Address: the applier assigns one per server.
cat > "$work/pia.conf" <<EOF
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Table = off
EOF
install_rules() {
    ip netns exec "$exitns" env OVERLAY_CIDR=192.0.2.0/24 OVERLAY6_CIDR=2001:db8:1::/64 \
        OVERLAY_IF="$overlay_if" EXIT_IF=mullvad EXIT_TABLE=51821 ROUTING_READY_FILE="$work/ready" \
        PROVIDER="${1:-mullvad}" TUNNEL_CONF="$work/${1:-mullvad}.conf" sh "$root/routing/10-exit-routing"
}
restore_routes() {
    for family in -4 -6; do
        ip -n "$exitns" "$family" route replace unreachable default metric 4096 table 51821
        ip -n "$exitns" "$family" route replace default dev mullvad table 51821
    done
    # Model a point-to-point tunnel without off-subnet ARP/NDP dependencies.
    ip -n "$exitns" -4 neigh replace 198.51.100.100 lladdr 02:00:00:00:03:02 nud permanent dev mullvad
    ip -n "$exitns" -6 neigh replace 2001:db8:2::100 lladdr 02:00:00:00:03:02 nud permanent dev mullvad
}
probe() {
    address=198.51.100.100
    [ "$2" = -4 ] || address=2001:db8:2::100
    ip netns exec "$1" ping "$2" -c 1 -W 1 "$address" >/dev/null 2>&1
}
blocked() {
    for family in -4 -6; do
        if probe "$client" "$family"; then
            echo "FAIL client escaped during $1 ($family)" >&2
            exit 1
        fi
        # Prove the normal path is still available to locally originated traffic.
        probe "$exitns" "$family"
    done
    echo "PASS $1 (IPv4 and IPv6 blocked; normal host path still reachable)"
}
connected() {
    for family in -4 -6; do
        if ! probe "$client" "$family"; then
            echo "FAIL expected tunnel forwarding ($family)" >&2
            # These namespaces contain only the documentation addresses above.
            # Include enough context to distinguish fixture and routing errors.
            for ns in "$client" "$exitns" "$tunnel"; do
                ip -n "$ns" "$family" addr show
                ip -n "$ns" "$family" rule show
                ip -n "$ns" "$family" route show table all
                ip -n "$ns" "$family" neigh show
            done
            exit 1
        fi
    done
}
# A tunnel-side sender with an oversized, don't-fragment packet must get the
# exit's ICMP error back over the tunnel path; only iputils reports it. The
# sender uses the off-subnet address that the main table would route out
# eth0, as a real Internet origin is; only the return-path rule brings the
# error back over the tunnel.
too_big_reported() {
    address=192.0.2.2
    source=198.51.100.100
    pattern='Frag needed'
    if [ "$1" = -6 ]; then
        address=2001:db8:1::2
        source=2001:db8:2::100
        pattern='Packet too big'
    fi
    # The sender caches the path MTU from a previous answer; a probe served
    # from that cache would say nothing about the exit's return path.
    ip -n "$tunnel" "$1" route flush cache
    # 1300 bytes of payload fits the 1420 tunnel link but not the 1280 overlay link.
    ip netns exec "$tunnel" ping "$1" -I "$source" -c 1 -W 1 -M 'do' -s 1300 "$address" > "$work/ping" 2>&1 || true
    if grep -q 'local error' "$work/ping"; then
        echo "FAIL probe was answered from the sender's own path MTU cache ($1)" >&2
        exit 1
    fi
    grep -q "$pattern" "$work/ping"
}
# Check the exact iproute2 JSON emitted by a real kernel, not just fixtures.
validate_family() {
    ip -n "$exitns" -j "-$1" rule show > "$work/rules.json"
    ip -n "$exitns" -j "-$1" route show table 51821 > "$work/routes.json"
    address=$tunnel4
    [ "$1" = 4 ] || address=$tunnel6
    # A third argument overrides the family's tunnel address; "none" means the
    # tunnel does not carry that family.
    [ -z "${3:-}" ] || address=$3
    python3 - "$work/rules.json" "$work/routes.json" "$1" "$2" "$overlay_if" "$address" <<'PY'
import json, sys
from molebridge.routing import RoutingConfig, family_status
with open(sys.argv[1]) as f:
    rules = json.load(f)
with open(sys.argv[2]) as f:
    routes = json.load(f)
config = RoutingConfig('192.0.2.0/24', '2001:db8:1::/64', overlay_if=sys.argv[5])
address = None if sys.argv[6] == 'none' else sys.argv[6]
result = family_status(rules, routes, config, int(sys.argv[3]), tunnel_address=address)
assert result == (sys.argv[4] == 'healthy', True), f'IPv{sys.argv[3]} validation={result}; rules={rules!r}; routes={routes!r}'
PY
}

# The gate refuses unsupported NetBird settings before it looks at routing. No NetBird state exists here, so point it at an empty one.
gate() {
    ip netns exec "$exitns" env NB_INTERFACE_NAME="$overlay_if" NB_DISABLE_USERSPACE_ROUTING=true \
        NB_STATE_DIR="$work/nbstate" "$@"
}
# Bounded: a gate that failed to refuse would wait here for routing guards.
gate_refuses() {
    if gate "$@" timeout 5 sh "$root/routing/wait-for-guards" true 2>"$work/gate.err" ||
            ! grep -q 'refusing to start NetBird' "$work/gate.err"; then
        echo "FAIL NetBird gate did not refuse: ${*:-a stored profile}" >&2
        exit 1
    fi
}
gate_refuses NB_FORCE_USERSPACE_FIREWALL=true
gate_refuses NB_ENABLE_ROSENPASS=1
gate_refuses NB_DISABLE_USERSPACE_ROUTING=false
gate_refuses NB_CONFIG=/var/lib/netbird/peer.json
gate_refuses NB_FOREGROUND_MODE=true
gate_refuses WT_FOREGROUND_MODE=1
gate_refuses WT_INTERFACE_NAME=other0
mkdir "$work/nbstate"
for profile in '{\n    "WgIface": "%s",\n    "RosenpassEnabled": true\n}' '{"WgIface": "%s", "RosenpassEnabled":\n  true}' \
        '{\n    "Name": "%s",\n    "WgIface": "other0"\n}' '{"WgIface": "%s", "Rosenpass\\u0045nabled": true}'; do
    # Deliberately a format string: %s is the guarded interface.
    # shellcheck disable=SC2059
    printf "$profile\n" "$overlay_if" > "$work/nbstate/default.json"
    gate_refuses
done
printf '{\n    "WgIface": "%s",\n    "RosenpassEnabled": false\n}\n' "$overlay_if" > "$work/nbstate/default.json"
if ! gate sh "$root/routing/wait-for-guards" --check-config >/dev/null; then
    echo 'FAIL NetBird gate refused a profile for the guarded interface without Rosenpass' >&2
    exit 1
fi
rm "$work/nbstate/default.json"
echo 'PASS NetBird gate refuses unsupported settings, other profile locations, Rosenpass and other interfaces in stored profiles'

gate_script=''
# The gate's JSON reader under every awk available here, and under busybox
# sh and awk as in the NetBird image. Configuration checks only; no routing.
awk_dirs=''
for impl in gawk mawk busybox; do
    command -v "$impl" >/dev/null 2>&1 || continue
    mkdir "$work/awk-$impl"
    if [ "$impl" = busybox ]; then
        for applet in sh awk tr wc; do ln -s "$(command -v busybox)" "$work/awk-$impl/$applet"; done
    else
        ln -s "$(command -v "$impl")" "$work/awk-$impl/awk"
    fi
    awk_dirs="$awk_dirs $work/awk-$impl"
done
# json_case accept|refuse <description> <default.json contents> [active_profile.json contents]
json_case() {
    printf '%s\n' "$3" > "$work/nbstate/default.json"
    rm -f "$work/nbstate/active_profile.json"
    [ -z "${4:-}" ] || printf '%s\n' "$4" > "$work/nbstate/active_profile.json"
    for dir in $awk_dirs; do
        shell='sh'
        [ ! -e "$dir/sh" ] || shell=$dir/sh
        if env PATH="$dir:$PATH" NB_INTERFACE_NAME=mesh0 NB_DISABLE_USERSPACE_ROUTING=true \
                NB_STATE_DIR="$work/nbstate" "$shell" "${gate_script:-$root/routing/wait-for-guards}" \
                --check-config >/dev/null 2>&1; then
            got=accept
        else
            got=refuse
        fi
        if [ "$got" != "$1" ]; then
            echo "FAIL JSON reader with $(basename "$dir"): expected $1 for $2" >&2
            exit 1
        fi
    done
}
if [ -z "$awk_dirs" ]; then
    echo 'SKIP JSON reader under gawk, mawk and busybox (none installed)'
else
    json_case accept 'a plain profile' '{"WgIface": "mesh0", "RosenpassEnabled": false}'
    json_case accept 'escapes, Unicode and nesting in other fields' \
        '{"Name": "R&D é 😀 \"q\" \\ \/", "WgIface": "mesh0",
          "Nested": {"WgIface": "wt0", "RosenpassEnabled": true}, "List": [0, -2.5e3, true, null, {}, []]}'
    json_case refuse 'Rosenpass across lines' '{"WgIface": "mesh0", "RosenpassEnabled":
        true}'
    json_case refuse 'an escaped Rosenpass field name' '{"WgIface": "mesh0", "RosenpassEnabled": true}'
    json_case refuse 'Rosenpass null' '{"WgIface": "mesh0", "RosenpassEnabled": null}'
    json_case refuse 'a field repeated in another case' '{"WgIface": "mesh0", "wgiface": "mesh0"}'
    json_case refuse 'a nested WgIface only' '{"Extra": {"WgIface": "mesh0"}}'
    json_case refuse 'a "Wg Iface" field only' '{"Wg Iface": "mesh0"}'
    json_case refuse 'a field name escaped outside ASCII' '{"WgIface": "mesh0", "Key": 1}'
    json_case refuse 'a field name with a non-ASCII byte' "$(printf '{"WgIface": "mesh0", "R\303\266senpassEnabled": true}')"
    json_case refuse 'a top-level array' '["WgIface", "mesh0"]'
    json_case refuse 'trailing data' '{"WgIface": "mesh0"} {}'
    json_case refuse 'a bad number' '{"WgIface": "mesh0", "Port": 01}'
    json_case refuse 'a bad escape' '{"WgIface": "mesh0", "Name": "a\qb"}'
    json_case refuse 'another active profile' '{"WgIface": "mesh0"}' '{"name": "alternate", "username": ""}'
    json_case accept 'the default active profile' '{"WgIface": "mesh0"}' '{"name": "default", "username": ""}'
    # The legacy paths are absolute; a copy of the gate names a file here instead.
    sed "s#/etc/netbird/config.json#$work/legacy.json#" "$root/routing/wait-for-guards" > "$work/gate-legacy"
    printf '%s\n' '{"WgIface": "mesh0", "RosenpassEnabled": true}' > "$work/legacy.json"
    gate_script="$work/gate-legacy"
    json_case refuse 'Rosenpass in the legacy profile' '{"WgIface": "mesh0"}'
    gate_script=''
    rm -f "$work/nbstate/default.json" "$work/nbstate/active_profile.json" "$work/legacy.json"
    echo "PASS the gate's JSON reader agrees across$(for dir in $awk_dirs; do printf ' %s' "${dir##*/awk-}"; done)"
fi

# Start NetBird's gate before initialization, just as a runtime restart can.
gate sh "$root/routing/wait-for-guards" sh -c 'touch "$1"' gate "$work/gate-started" &
gate_pid=$!
sleep 2
test ! -f "$work/gate-started"
ip -n "$exitns" -4 rule add iif "$overlay_if" unreachable priority 97
sleep 2
test ! -f "$work/gate-started"
# Both terminal rules and the local-delivery rule, but the kernel's rule 0
# still delivers overlay packets locally: the gate must keep waiting.
ip -n "$exitns" -6 rule add iif "$overlay_if" unreachable priority 97
for family in -4 -6; do
    ip -n "$exitns" "$family" rule add not iif "$overlay_if" lookup local priority 1
done
sleep 2
test ! -f "$work/gate-started"
install_rules
# Bound the wait so a gate regression fails CI rather than hanging it.
attempt=0
while [ "$attempt" -lt 5 ] && [ ! -f "$work/gate-started" ]; do
    sleep 1
    attempt=$((attempt + 1))
done
test -f "$work/gate-started"
wait "$gate_pid"
gate_pid=''
echo 'PASS overlay startup waits for both routing guards and the local-delivery guard'
restore_routes
connected
for family in 4 6; do validate_family "$family" healthy; done

for family in -4 -6; do
    if ! too_big_reported "$family"; then
        echo "FAIL oversized tunnel reply produced no ICMP error over the tunnel ($family)" >&2
        cat "$work/ping" >&2
        exit 1
    fi
done
echo 'PASS oversized tunnel replies get ICMP errors back through the tunnel (IPv4 and IPv6)'
for family in 4 6; do
    ip -n "$exitns" "-$family" rule del priority 94
    if too_big_reported "-$family"; then
        echo "FAIL ICMP error reached the tunnel without the return-path rule (IPv$family)" >&2
        exit 1
    fi
    validate_family "$family" failed
    echo "PASS missing IPv$family return-path rule is detected and leaks nothing over the tunnel"
done
install_rules
restore_routes
connected
for family in -4 -6; do
    too_big_reported "$family" || { echo "FAIL ICMP return path not restored by reinstallation ($family)" >&2; exit 1; }
done
for family in -4 -6; do ip -n "$exitns" "$family" route del default dev mullvad table 51821; done
for family in -4 -6; do
    if too_big_reported "$family"; then
        echo "FAIL ICMP error escaped with the tunnel route gone ($family)" >&2
        exit 1
    fi
done
echo 'PASS return-path rule fails closed without the tunnel route'
restore_routes
connected

for family in 4 6; do
    surviving=4
    [ "$family" = 4 ] && surviving=6
    ip -n "$exitns" "-$family" route del default dev mullvad table 51821
    if probe "$client" "-$family"; then
        echo "FAIL client escaped after IPv$family route deletion" >&2
        exit 1
    fi
    probe "$client" "-$surviving"
    probe "$exitns" "-$family"
    validate_family "$family" failed
    validate_family "$surviving" healthy
    echo "PASS IPv$family route loss detected (other family and host path still reachable)"
    restore_routes
    connected
done
for family in -4 -6; do ip -n "$exitns" "$family" route del default dev mullvad table 51821; done
blocked 'tunnel route deleted'
restore_routes
connected
for family in -4 -6; do ip -n "$exitns" "$family" rule del priority 95; done
blocked 'exit lookup rule deleted'
install_rules
connected
for family in -4 -6; do ip -n "$exitns" "$family" route flush table 51821; done
blocked 'all exit-table routes deleted'
restore_routes
connected
ip -n "$exitns" link set mullvad down
blocked 'tunnel interface down'
ip -n "$exitns" link set mullvad up
# Linux removes this manually assigned IPv6 address on link-down. Real
# recovery runs wg-quick, which restores the configured interface addresses.
ip -n "$exitns" -6 addr replace "$tunnel6/64" dev mullvad nodad
restore_routes
connected
install_rules
connected
for family in 4 6; do validate_family "$family" healthy; done
for family in -4 -6; do
    counts=$(ip -n "$exitns" "$family" rule show | awk '$1 == "0:" { zero++ } $1 == "1:" { one++ } END { print zero + 0, one + 0 }')
    if [ "$counts" != '0 1' ]; then
        echo "FAIL reinstallation left local-delivery rules 0/1 at counts $counts ($family)" >&2
        exit 1
    fi
done
echo 'PASS routing reinstallation and recovery (one local-delivery rule, no rule 0)'

# Exercise local-delivery regression coverage: local delivery from the overlay
# is refused. With rule 1, nothing arriving on the overlay reaches a local
# socket, even after a DNAT to a local port. Such packets take rule 95 into
# the tunnel side, where this fixture drops them.
exit_addresses='192.0.2.1 198.51.100.1 2001:db8:1::1 2001:db8:2::1'
ip netns exec "$exitns" python3 -c '
import selectors, socket, sys
watch = selectors.DefaultSelector()
for family, host in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
    for port in (53, 5053):
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            s = socket.socket(family, kind)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            s.bind((host, port))
            if kind == socket.SOCK_STREAM:
                s.listen(8)
            watch.register(s, selectors.EVENT_READ)
open(sys.argv[2], "w").close()
while True:
    for key, _ in watch.select():
        s = key.fileobj
        if s.type == socket.SOCK_STREAM:
            c, peer = s.accept()
            c.close()
        else:
            _, peer = s.recvfrom(512)
        with open(sys.argv[1], "a") as f:
            f.write("%s %d\n" % (peer[0], s.getsockname()[1]))
' "$work/delivered" "$work/listening" &
listeners="$listeners $!"
attempt=0
while [ "$attempt" -lt 10 ] && [ ! -f "$work/listening" ]; do
    sleep 1
    attempt=$((attempt + 1))
done
test -f "$work/listening"
# Three UDP datagrams and one TCP connection attempt to port 53; true when
# the listener in the exit namespace saw any of them.
delivered_from() {
    : > "$work/delivered"
    ip netns exec "$1" python3 -c '
import socket, sys
address = sys.argv[1]
family = socket.AF_INET6 if ":" in address else socket.AF_INET
with socket.socket(family, socket.SOCK_DGRAM) as u:
    for _ in range(3):
        try:
            u.sendto(bytes(12), (address, 53))
        except OSError:
            pass
with socket.socket(family, socket.SOCK_STREAM) as t:
    t.settimeout(1)
    try:
        t.connect((address, 53))
    except OSError:
        pass
' "$2"
    sleep 1
    [ -s "$work/delivered" ]
}
for address in $exit_addresses; do
    if delivered_from "$client" "$address"; then
        echo "FAIL overlay traffic to $address port 53 reached a local socket" >&2
        exit 1
    fi
done
echo "PASS TCP and UDP port 53 from the overlay to the exit's own addresses never reach a local socket (IPv4 and IPv6)"
for address in 198.51.100.1 2001:db8:2::1; do
    delivered_from "$outside" "$address" || { echo "FAIL the host interface lost local delivery ($address)" >&2; exit 1; }
done
for address in 127.0.0.1 ::1; do
    delivered_from "$exitns" "$address" || { echo "FAIL loopback lost local delivery ($address)" >&2; exit 1; }
done
echo 'PASS the host interface and loopback keep local delivery'
# With the kernel's rule 0 back, the validator objects and the same probes
# arrive: the drill can see local delivery.
for family in -4 -6; do ip -n "$exitns" "$family" rule add lookup local priority 0; done
for family in 4 6; do validate_family "$family" failed; done
for address in $exit_addresses; do
    delivered_from "$client" "$address" || { echo "FAIL drill cannot see local delivery ($address)" >&2; exit 1; }
done
for family in -4 -6; do ip -n "$exitns" "$family" rule del priority 0; done
for family in 4 6; do validate_family "$family" healthy; done
echo 'PASS a restored kernel rule 0 is detected and reopens local delivery (drill confirmed sensitive)'

if command -v nft >/dev/null 2>&1; then
    # A prerouting DNAT that keeps the local address and changes the port.
    # DNAT happens before the routing decision, so rule 1 still applies.
    ip netns exec "$exitns" nft -f - <<NFT
table inet mb_local_dnat {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    iifname "$overlay_if" ip daddr 192.0.2.1 udp dport 53 counter dnat ip to 192.0.2.1:5053
    iifname "$overlay_if" ip daddr 192.0.2.1 tcp dport 53 counter dnat ip to 192.0.2.1:5053
    iifname "$overlay_if" ip daddr 198.51.100.1 udp dport 53 counter dnat ip to 198.51.100.1:5053
    iifname "$overlay_if" ip daddr 198.51.100.1 tcp dport 53 counter dnat ip to 198.51.100.1:5053
    iifname "$overlay_if" ip6 daddr 2001:db8:1::1 udp dport 53 counter dnat ip6 to [2001:db8:1::1]:5053
    iifname "$overlay_if" ip6 daddr 2001:db8:1::1 tcp dport 53 counter dnat ip6 to [2001:db8:1::1]:5053
    iifname "$overlay_if" ip6 daddr 2001:db8:2::1 udp dport 53 counter dnat ip6 to [2001:db8:2::1]:5053
    iifname "$overlay_if" ip6 daddr 2001:db8:2::1 tcp dport 53 counter dnat ip6 to [2001:db8:2::1]:5053
  }
}
NFT
    for address in $exit_addresses; do
        if delivered_from "$client" "$address"; then
            echo "FAIL overlay traffic to $address port 53 reached a local socket after DNAT" >&2
            exit 1
        fi
    done
    matched=$(ip netns exec "$exitns" nft list table inet mb_local_dnat | grep -c 'packets [1-9]')
    [ "$matched" -eq 8 ] || { echo "FAIL only $matched of 8 DNAT rules saw traffic" >&2; exit 1; }
    echo 'PASS overlay traffic DNATed to a local port never reaches a local socket (IPv4 and IPv6, TCP and UDP)'
    for family in -4 -6; do ip -n "$exitns" "$family" rule add lookup local priority 0; done
    for address in $exit_addresses; do
        delivered_from "$client" "$address" && grep -q ' 5053$' "$work/delivered" ||
            { echo "FAIL drill cannot see local delivery after DNAT ($address)" >&2; exit 1; }
    done
    for family in -4 -6; do ip -n "$exitns" "$family" rule del priority 0; done
    ip netns exec "$exitns" nft delete table inet mb_local_dnat
    echo 'PASS without rule 1 the DNATed traffic is delivered (drill confirmed sensitive)'
else
    echo 'SKIP DNAT local-delivery drill (nft not installed)'
fi

# PIA: no Address in the config, so initialization installs every guard but no
# return-path rule. A switch then assigns a per-server IPv4 address and rule
# 94, as the applier does, and the tunnel carries no IPv6.
install_rules pia
for family in -4 -6; do
    if [ -n "$(ip -n "$exitns" "$family" rule show priority 94)" ]; then
        echo "FAIL address-less PIA initialization installed a return-path rule ($family)" >&2
        exit 1
    fi
done
ip -n "$exitns" -6 route del default dev mullvad table 51821
for family in 4 6; do validate_family "$family" healthy none; done
if probe "$client" -6; then
    echo 'FAIL IPv6 escaped through an IPv4-only PIA tunnel' >&2
    exit 1
fi
echo 'PASS PIA initialization without an address keeps every guard and blocks IPv6'
pia4=203.0.113.5
# The applier's order: new address first, then the old one goes, then the
# tunnel default is re-asserted. Removing the last address first would delete
# every route through the interface. The applier assigns /32 addresses; a
# second address inside the old prefix would be a secondary, removed with it.
ip -n "$exitns" -4 addr replace "$pia4/32" dev mullvad
ip -n "$exitns" -4 addr del "$tunnel4/24" dev mullvad
ip -n "$exitns" -4 route replace default dev mullvad table 51821
ip -n "$exitns" -4 neigh replace 198.51.100.100 lladdr 02:00:00:00:03:02 nud permanent dev mullvad
ip -n "$tunnel" route replace 192.0.2.0/24 via "$pia4"
ip -n "$exitns" -4 rule add from "$pia4" ipproto icmp lookup 51821 priority 94
probe "$client" -4 || { echo 'FAIL IPv4 did not forward after the PIA address change' >&2; exit 1; }
validate_family 4 healthy "$pia4"
validate_family 4 failed "$tunnel4"
validate_family 6 healthy none
too_big_reported -4 || { echo 'FAIL ICMP return path broken after the PIA address change' >&2; exit 1; }
if probe "$client" -6; then
    echo 'FAIL IPv6 escaped after the PIA address change' >&2
    exit 1
fi
echo 'PASS PIA address change keeps IPv4 forwarding, its ICMP return path and the IPv6 block'
ip -n "$exitns" -4 route del default dev mullvad table 51821
blocked 'PIA tunnel route deleted'

# PIA port forwarding, with the applier's own nftables text: a connection from
# the Internet side to the forwarded port reaches the overlay target, and the
# ingress guard stops it leaving any other way when the overlay route is gone.
if ! command -v nft >/dev/null 2>&1; then
    echo 'SKIP PIA port-forwarding drill (nft not installed)'
    exit 0
fi
restore_routes
python3 - "$work" "$overlay_if" <<'PY'
import sys, tempfile
from pathlib import Path
from applier.pia import PiaApplier
from molebridge.routing import RoutingConfig
work = Path(sys.argv[1])
captured = []
config = RoutingConfig('192.0.2.0/24', '2001:db8:1::/64', overlay_if=sys.argv[2])
applier = PiaApplier(Path(tempfile.mkdtemp()), config, port_forward=True, forward_target='192.0.2.2',
                     run=lambda args, **kw: captured.append(Path(args[2]).read_text()) or '')
applier.install_guard()
(work / 'guard.nft').write_text(captured[-1])
(work / 'forward.nft').write_text(applier.forward_rules(40000))
PY
listen() {
    ip netns exec "$1" python3 -c '
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], 40000)); s.listen(8)
while True:
    c, _ = s.accept(); c.sendall(sys.argv[2].encode()); c.close()
' "$2" "$3" &
    listeners="$listeners $!"
}
# The overlay target answers; a counter in the outside namespace, behind the
# exit's ordinary default route, detects any forwarded packet that leaks there.
listen "$client" 192.0.2.2 target
ip netns exec "$outside" nft -f - <<'NFT'
table inet leak {
  chain input {
    type filter hook prerouting priority raw; policy accept;
    ip daddr 192.0.2.2 tcp dport 40000 counter name seen
  }
  counter seen {}
}
NFT
sleep 1
inbound() {
    ip netns exec "$tunnel" python3 -c '
import socket, sys
s = socket.create_connection(("203.0.113.5", 40000), timeout=2, source_address=("198.51.100.100", 0))
print(s.recv(16).decode())
' 2>/dev/null || true
}
leaked() {
    ip netns exec "$outside" nft reset counter inet leak seen >/dev/null
    inbound >/dev/null
    ip netns exec "$outside" nft list counter inet leak seen | grep -q 'packets [1-9]'
}
ip netns exec "$exitns" nft -f "$work/guard.nft"
ip netns exec "$exitns" nft -f "$work/forward.nft"
[ "$(inbound)" = target ] || { echo 'FAIL forwarded port did not reach the overlay target' >&2; exit 1; }
echo 'PASS PIA forwarded port reaches the overlay target and replies return through the tunnel'
ip -n "$exitns" route del 192.0.2.0/24 dev "$overlay_if"
if leaked; then echo 'FAIL forwarded connection left through the ordinary route' >&2; exit 1; fi
ip netns exec "$exitns" nft delete table inet molebridge_guard
leaked || { echo 'FAIL leak detector did not see the unguarded path' >&2; exit 1; }
ip netns exec "$exitns" nft -f "$work/guard.nft"
if leaked; then echo 'FAIL guard reinstall did not stop the leak' >&2; exit 1; fi
echo 'PASS ingress guard stops forwarded connections leaving other than over the overlay (drill confirmed sensitive)'
