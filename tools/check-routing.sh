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
    rm -f "$work/auth-ok.toml" "$work/auth-bad.toml" "$work/preflight-started" "$work/preflight.out"
    rmdir "$work/nbstate" 2>/dev/null || true
    rm -rf "$work/gl"
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

# gluetun's role-file check under the same shells and awks, busybox as in
# gluetun's Alpine image: the generated file starts gluetun, a misspelled key
# field does not, and nothing from the file is printed.
if [ -n "$awk_dirs" ]; then
    preflight_key=Zx9-_kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk
    printf '%s\n' '[[roles]]' 'name = "molebridge"' 'auth = "apikey"' "apikey = \"$preflight_key\"" \
        'routes = ["PUT /v1/vpn/settings", "GET /v1/vpn/status", "GET /v1/publicip/ip", "GET /v1/updater/status", "PUT /v1/updater/status"]' \
        > "$work/auth-ok.toml"
    sed 's/^apikey = /api_key = /' "$work/auth-ok.toml" > "$work/auth-bad.toml"
    for dir in $awk_dirs; do
        for case in ok bad; do
            rm -f "$work/preflight-started"
            # gluetun's image sets HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE="{}".
            PATH="$dir:$PATH" HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH="$work/auth-$case.toml" \
                HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE='{}' \
                sh "$root/routing/gluetun-preflight" touch "$work/preflight-started" > "$work/preflight.out" 2>&1 || :
            if grep -q "$preflight_key" "$work/preflight.out"; then
                echo "FAIL gluetun's role-file check printed the key (${dir##*/awk-})" >&2
                exit 1
            fi
            if [ "$case" = ok ] && [ ! -f "$work/preflight-started" ]; then
                echo "FAIL gluetun's role-file check refused the generated file (${dir##*/awk-})" >&2
                exit 1
            fi
            if [ "$case" = bad ] && [ -f "$work/preflight-started" ]; then
                echo "FAIL gluetun's role-file check accepted a misspelled key field (${dir##*/awk-})" >&2
                exit 1
            fi
        done
    done
    for dir in $awk_dirs; do
        rm -f "$work/preflight-started"
        PATH="$dir:$PATH" HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH="$work/auth-ok.toml" \
            HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE='{"auth":"none"}' \
            sh "$root/routing/gluetun-preflight" touch "$work/preflight-started" > /dev/null 2>&1 || :
        if [ -f "$work/preflight-started" ]; then
            echo "FAIL gluetun's role-file check accepted a public default role (${dir##*/awk-})" >&2
            exit 1
        fi
    done
    rm -f "$work/auth-ok.toml" "$work/auth-bad.toml" "$work/preflight-started" "$work/preflight.out"
    echo "PASS gluetun's role-file check accepts only the generated file with gluetun's own empty default role, refuses a public one, and prints nothing from the file, across$(for dir in $awk_dirs; do printf ' %s' "${dir##*/awk-}"; done)"
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

# gluetun backend. Separate namespaces stand in for gluetun's: its rules 98
# (local subnet), 100 (inbound) and 101 (`not fwmark 51820 lookup 51820`)
# with table 51820 through the tunnel interface, and NetBird's 105 and 110.
# The guard then runs in gluetun mode. Forwarded packets carry marks set in
# the exit's prerouting; locally generated ones come from a socket with
# SO_MARK, like NetBird's dialers. Counters on the far side of the host link
# and of the tunnel show where each packet went.
gl_client=mb-gc-$$
gl_exit=mb-ge-$$
gl_outside=mb-go-$$
gl_tunnel=mb-gt-$$
gl=$work/gl
gl_target4=198.51.100.100
gl_target6=2001:db8:4::100
gl_env() {
    env TUNNEL_BACKEND=gluetun OVERLAY_CIDR=192.0.2.0/24 OVERLAY6_CIDR=2001:db8:1::/64 \
        OVERLAY_IF="$overlay_if" EXIT_IF=wg0 EXIT_TABLE=51821 HOST_IF=eth0 HOST_TABLE=51822 \
        CONTROL_MARK=0x1bd00 ROUTING_READY_FILE="$gl/ready" GUARD_STATUS_FILE="$gl/status" \
        GLUETUN_RULES="$root/routing/gluetun-rules" "$@"
}
gl_guard() {
    gl_env ip netns exec "$gl_exit" sh "$root/routing/10-exit-routing" "$@" > "$gl/guard.log" 2>&1 || {
        cat "$gl/guard.log" >&2
        return 1
    }
}
# gluetun's tunnel interface (a veth here) with its addresses, gluetun's own
# table 51820, and the far end holding the same destination as the host side.
gl_tunnel_up() {
    ip -n "$gl_exit" link add wg0 type veth peer name tunnel0 netns "$gl_tunnel"
    ip -n "$gl_tunnel" link set tunnel0 address 02:00:00:00:13:02
    ip -n "$gl_exit" addr add "$1/28" dev wg0
    ip -n "$gl_exit" -6 addr add 2001:db8:3::1/64 dev wg0 nodad
    ip -n "$gl_tunnel" addr add 203.0.113.2/28 dev tunnel0
    ip -n "$gl_tunnel" -6 addr add 2001:db8:3::2/64 dev tunnel0 nodad
    ip -n "$gl_tunnel" addr add "$gl_target4/32" dev tunnel0
    ip -n "$gl_tunnel" -6 addr add "$gl_target6/128" dev tunnel0 nodad
    ip -n "$gl_exit" link set wg0 up
    ip -n "$gl_tunnel" link set tunnel0 up
    ip -n "$gl_tunnel" route replace 192.0.2.0/24 via "$1"
    ip -n "$gl_tunnel" -6 route replace 2001:db8:1::/64 via 2001:db8:3::1
    for family in -4 -6; do ip -n "$gl_exit" "$family" route replace default dev wg0 table 51820; done
    ip -n "$gl_exit" -4 neigh replace "$gl_target4" lladdr 02:00:00:00:13:02 nud permanent dev wg0
    ip -n "$gl_exit" -6 neigh replace "$gl_target6" lladdr 02:00:00:00:13:02 nud permanent dev wg0
    # Real WireGuard sends whatever its route gives it; this veth stand-in
    # would first ask for the next hop and get no answer. The client's
    # overlay addresses are reachable on wg0 only when something sends
    # overlay traffic into the tunnel by mistake, which the rule 91/92 drill
    # must be able to see.
    ip -n "$gl_exit" -4 neigh replace 192.0.2.2 lladdr 02:00:00:00:13:02 nud permanent dev wg0
    ip -n "$gl_exit" -6 neigh replace 2001:db8:1::2 lladdr 02:00:00:00:13:02 nud permanent dev wg0
}
gl_validate() {
    ip -n "$gl_exit" -j "-$1" rule show > "$gl/rules.json"
    ip -n "$gl_exit" -j "-$1" route show table 51821 > "$gl/routes.json"
    ip -n "$gl_exit" -j "-$1" route show table 51822 > "$gl/host.json"
    ip -n "$gl_exit" -j "-$1" route show table main > "$gl/main.json"
    python3 - "$gl" "$1" "$2" "$3" "$overlay_if" <<'PY'
import json, sys
from molebridge.routing import RoutingConfig, family_status, host_table_status
work, family, expected, address, overlay_if = sys.argv[1:]
family = int(family)
config = RoutingConfig.from_env({'TUNNEL_BACKEND': 'gluetun', 'OVERLAY_CIDR': '192.0.2.0/24',
                                 'OVERLAY6_CIDR': '2001:db8:1::/64', 'OVERLAY_IF': overlay_if, 'EXIT_IF': 'wg0'})
data = {}
for name in ('rules', 'routes', 'host', 'main'):
    with open(f'{work}/{name}.json') as f:
        data[name] = json.load(f)
rules = family_status(data['rules'], data['routes'], config, family, tunnel_address=address)
host = host_table_status(data['host'], config, family, main=data['main'])
result = rules[0] and host
assert result == (expected == 'healthy'), f'IPv{family} gluetun validation rules={rules} host={host}; {data!r}'
PY
}
# A counter in each far namespace: "client" counts overlay-sourced packets,
# "local" anything else sent to the shared destination.
gl_counters() {
    ip netns exec "$1" nft -f - <<NFT
table inet gl {
  counter client {}
  counter local {}
  chain pre {
    type filter hook prerouting priority raw; policy accept;
    ip saddr 192.0.2.0/24 counter name client
    ip6 saddr 2001:db8:1::/64 counter name client
    ip daddr $gl_target4 ip saddr != 192.0.2.0/24 counter name local
    ip6 daddr $gl_target6 ip6 saddr != 2001:db8:1::/64 counter name local
  }
}
NFT
}
gl_reset() {
    for ns in "$gl_outside" "$gl_tunnel"; do
        for name in client local; do ip netns exec "$ns" nft reset counter inet gl "$name" >/dev/null; done
    done
}
gl_count() {
    ip netns exec "$1" nft list counter inet gl "$2" | awk '{ for (i = 1; i < NF; i++) if ($i == "packets") print $(i + 1) }'
}
gl_mark_forwarded() {
    ip netns exec "$gl_exit" nft delete table inet glmark 2>/dev/null || :
    [ "$1" != 0 ] || return 0
    ip netns exec "$gl_exit" nft -f - <<NFT
table inet glmark {
  chain pre {
    type filter hook prerouting priority mangle; policy accept;
    iifname "$overlay_if" meta mark set $1
  }
}
NFT
}
gl_forward() {
    gl_dst=$gl_target4
    [ "$1" = -4 ] || gl_dst=$gl_target6
    ip netns exec "$gl_client" ping "$1" -c 1 -W 1 "$gl_dst" >/dev/null 2>&1
}
# Three UDP datagrams from an unbound socket in the exit namespace, with the
# given mark (0 for none). Prints "unreachable" when routing refuses them.
gl_send() {
    gl_dst=$gl_target4
    [ "$1" = -4 ] || gl_dst=$gl_target6
    [ -z "${3:-}" ] || gl_dst=$3
    ip netns exec "$gl_exit" python3 -c '
import socket, sys
family = socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET
s = socket.socket(family, socket.SOCK_DGRAM)
mark = int(sys.argv[2], 0)
if mark:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
try:
    for _ in range(3):
        s.sendto(b"x", (sys.argv[1], 9))
    print("sent")
except OSError:
    print("unreachable")
' "$gl_dst" "$2"
}
gl_fail() {
    echo "FAIL $1" >&2
    # Only the documentation addresses above.
    for family in -4 -6; do
        ip -n "$gl_exit" "$family" rule show
        ip -n "$gl_exit" "$family" route show table all
    done
    exit 1
}
# Forwarded packets with each mark reach the tunnel ("tunnel") or nothing
# ("blocked"); none may reach the host side.
gl_forwarding() {
    for mark in 0 0x1bd00 0x1bd21 51820; do
        gl_mark_forwarded "$mark"
        for family in -4 -6; do
            gl_reset
            if gl_forward "$family"; then gl_outcome=tunnel; else gl_outcome=blocked; fi
            [ "$(gl_count "$gl_outside" client)" = 0 ] ||
                gl_fail "forwarded packet with mark $mark left through the host interface ($family, $2)"
            [ "$gl_outcome" = "$1" ] || gl_fail "forwarded packet with mark $mark: expected $1, got $gl_outcome ($family, $2)"
            if [ "$1" = tunnel ] && [ "$(gl_count "$gl_tunnel" client)" = 0 ]; then
                gl_fail "forwarded packet with mark $mark was answered without crossing the tunnel ($family)"
            fi
        done
    done
    gl_mark_forwarded 0
}
# Where a locally generated datagram with this mark goes: host, tunnel or none.
gl_local_path() {
    gl_reset
    gl_sent=$(gl_send "$1" "$2")
    sleep 1
    gl_in_host=$(gl_count "$gl_outside" local)
    gl_in_tunnel=$(gl_count "$gl_tunnel" local)
    if [ "$gl_in_host" != 0 ] && [ "$gl_in_tunnel" = 0 ]; then echo host
    elif [ "$gl_in_tunnel" != 0 ] && [ "$gl_in_host" = 0 ]; then echo tunnel
    elif [ "$gl_in_host$gl_in_tunnel" = 00 ] && [ "$gl_sent" = unreachable ]; then echo none
    else echo "mixed:$gl_sent:$gl_in_host:$gl_in_tunnel"
    fi
}
# Rules 91/92: what the exit itself sends to the overlay. A counter in the
# client namespace sees the probe datagrams arrive over the overlay; one in
# the tunnel's far end sees them leak into the tunnel. Both count UDP to
# port 9 only, so the client's own ICMP answers, which take rule 95 into the
# tunnel like any client packet, are not mistaken for a leak.
gl_overlay_counters() {
    ip netns exec "$gl_client" nft -f - <<NFT
table inet glo {
  counter arrived {}
  chain pre {
    type filter hook prerouting priority raw; policy accept;
    ip daddr 192.0.2.2 udp dport 9 counter name arrived
    ip6 daddr 2001:db8:1::2 udp dport 9 counter name arrived
  }
}
NFT
    ip netns exec "$gl_tunnel" nft -f - <<NFT
table inet glo {
  counter leaked {}
  chain pre {
    type filter hook prerouting priority raw; policy accept;
    ip daddr 192.0.2.0/24 udp dport 9 counter name leaked
    ip6 daddr 2001:db8:1::/64 udp dport 9 counter name leaked
  }
}
NFT
}
gl_overlay_count() {
    ip netns exec "$1" nft list counter inet glo "$2" | awk '{ for (i = 1; i < NF; i++) if ($i == "packets") print $(i + 1) }'
}
# Where an unmarked datagram from the exit to a client's overlay address
# goes: overlay, tunnel or none.
gl_overlay_path() {
    ip netns exec "$gl_client" nft reset counter inet glo arrived >/dev/null
    ip netns exec "$gl_tunnel" nft reset counter inet glo leaked >/dev/null
    gl_client_address=192.0.2.2
    [ "$1" = -4 ] || gl_client_address=2001:db8:1::2
    gl_sent=$(gl_send "$1" 0 "$gl_client_address")
    sleep 1
    gl_arrived=$(gl_overlay_count "$gl_client" arrived)
    gl_leaked=$(gl_overlay_count "$gl_tunnel" leaked)
    if [ "$gl_arrived" != 0 ] && [ "$gl_leaked" = 0 ]; then echo overlay
    elif [ "$gl_leaked" != 0 ] && [ "$gl_arrived" = 0 ]; then echo tunnel
    elif [ "$gl_arrived$gl_leaked" = 00 ] && [ "$gl_sent" = unreachable ]; then echo none
    else echo "mixed:$gl_sent:$gl_arrived:$gl_leaked"
    fi
}
# A client's oversized, don't-fragment packet toward the tunnel must bring
# the exit's ICMP error (fragmentation needed, packet too big) back to it.
gl_too_big_reported() {
    gl_dst=$gl_target4
    gl_pattern='Frag needed'
    if [ "$1" = -6 ]; then
        gl_dst=$gl_target6
        gl_pattern='Packet too big'
    fi
    # A path MTU the client cached from an earlier answer would hide the exit's.
    ip -n "$gl_client" "$1" route flush cache
    # ICMP errors are rate limited per destination.
    sleep 1
    ip netns exec "$gl_client" ping "$1" -c 1 -W 1 -M 'do' -s 1300 "$gl_dst" > "$gl/ping" 2>&1 || :
    if grep -q 'local error' "$gl/ping"; then
        gl_fail "the client answered from its own path MTU cache ($1)"
    fi
    grep -q "$gl_pattern" "$gl/ping"
}
gl_overlay_route() {
    if [ "$1" = del ]; then
        ip -n "$gl_exit" -4 route del 192.0.2.0/24 dev "$overlay_if"
        ip -n "$gl_exit" -6 route del 2001:db8:1::/64 dev "$overlay_if"
    else
        ip -n "$gl_exit" -4 route add 192.0.2.0/24 dev "$overlay_if" proto kernel scope link src 192.0.2.1
        ip -n "$gl_exit" -6 route add 2001:db8:1::/64 dev "$overlay_if" proto kernel metric 256
    fi
}
# Rules 102-104: the exit's own unmarked traffic leaves only through
# gluetun's tunnel. gl_tunnel_table empty|fill empties or refills gluetun's
# table 51820, as gluetun's reconnect does.
gl_tunnel_table() {
    for family in -4 -6; do
        if [ "$1" = empty ]; then
            ip -n "$gl_exit" "$family" route flush table 51820
        else
            ip -n "$gl_exit" "$family" route replace default dev wg0 table 51820
        fi
    done
}
# An established TCP flow from the exit to the shared destination, opened
# through the tunnel; then gluetun's tunnel table is emptied and the flow
# keeps sending. Prints how many packets of it the host side saw. The
# background processes write nowhere: the caller reads this one's output.
gl_established() {
    gl_dst=$gl_target4
    [ "$1" = -4 ] || gl_dst=$gl_target6
    rm -f "$gl/flow-listening" "$gl/flow-connected" "$gl/flow-go" "$gl/flow-done"
    ip netns exec "$gl_tunnel" python3 -c '
import socket, sys
family = socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET
s = socket.socket(family, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], 7001)); s.listen(1)
open(sys.argv[2], "w").close()
s.settimeout(30)
c, _ = s.accept()
c.settimeout(30)
while c.recv(4096):
    pass
' "$gl_dst" "$gl/flow-listening" >/dev/null 2>&1 &
    listeners="$listeners $!"
    gl_wait "$gl/flow-listening"
    ip netns exec "$gl_exit" python3 -c '
import os, socket, sys, time
family = socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET
s = socket.socket(family, socket.SOCK_STREAM)
s.settimeout(5)
s.connect((sys.argv[1], 7001))
s.sendall(b"a")
open(sys.argv[2], "w").close()
for _ in range(100):
    if os.path.exists(sys.argv[3]):
        break
    time.sleep(0.1)
for _ in range(5):
    try:
        s.send(b"b" * 512)
    except OSError:
        pass
    time.sleep(0.4)
open(sys.argv[4], "w").close()
' "$gl_dst" "$gl/flow-connected" "$gl/flow-go" "$gl/flow-done" >/dev/null 2>&1 &
    listeners="$listeners $!"
    gl_wait "$gl/flow-connected"
    gl_tunnel_table empty
    gl_reset
    touch "$gl/flow-go"
    gl_wait "$gl/flow-done"
    sleep 1
    gl_count "$gl_outside" local
}
gl_wait() {
    gl_waited=0
    while [ ! -f "$1" ] && [ "$gl_waited" -lt 50 ]; do sleep 0.2; gl_waited=$((gl_waited + 1)); done
    [ -f "$1" ] || gl_fail "fixture: $1 did not appear"
}
# A new TCP connection attempt from the exit to the shared destination.
gl_new_tcp() {
    gl_dst=$gl_target4
    [ "$1" = -4 ] || gl_dst=$gl_target6
    gl_reset
    ip netns exec "$gl_exit" python3 -c '
import socket, sys
family = socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET
s = socket.socket(family, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect((sys.argv[1], 7002))
except OSError:
    pass
' "$gl_dst"
    sleep 1
    gl_count "$gl_outside" local
}
gl_gate() {
    ip netns exec "$gl_exit" env TUNNEL_BACKEND=gluetun NB_INTERFACE_NAME="$overlay_if" \
        NB_DISABLE_USERSPACE_ROUTING=true NB_STATE_DIR="$gl/nbstate" NB_LOG_FILE="console,$gl/client.log" \
        GUARD_STATUS_FILE="$gl/status" CONTROL_MARK=0x1bd00 NB_FWMARK_BASE=0x1bd00 HOST_IF=eth0 \
        HOST_TABLE=51822 OVERLAY_CIDR=192.0.2.0/24 OVERLAY6_CIDR=2001:db8:1::/64 EXIT_IF=wg0 EXIT_TABLE=51821 \
        GLUETUN_RULES="$root/routing/gluetun-rules" "$@"
}
# A fwmark record as the guard writes it: boot id, boot-clock seconds, value.
gl_record() {
    read -r gl_up _ < /proc/uptime
    echo "$(cat /proc/sys/kernel/random/boot_id) ${gl_up%%.*} $1" > "$gl/status"
}
# True when the gate, given a few seconds, would start NetBird.
gl_gate_starts() {
    rm -f "$gl/started"
    gl_gate timeout 5 sh "$root/routing/wait-for-guards" sh -c 'touch "$1"' gate "$gl/started" 2>/dev/null || :
    [ -f "$gl/started" ]
}

gluetun_drills() {
    mkdir "$gl" "$gl/nbstate"
    for ns in "$gl_client" "$gl_exit" "$gl_outside" "$gl_tunnel"; do
        ip netns add "$ns"
        created="$created $ns"
        ip -n "$ns" link set lo up
        ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
        ip netns exec "$ns" sysctl -qw net.ipv6.conf.default.accept_dad=0
    done
    # The provider's side ends traffic, it doesn't route it on. A new
    # namespace inherits IPv4 forwarding from the host (on wherever Docker
    # runs), and a forwarding tunnel end would send overlay traffic leaked
    # into the tunnel straight back to the exit and on to the client, hiding
    # the leak the rule 91/92 drill looks for.
    ip netns exec "$gl_tunnel" sysctl -qw net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0
    ip -n "$gl_exit" link add "$overlay_if" type veth peer name client0 netns "$gl_client"
    ip -n "$gl_exit" link add eth0 type veth peer name outside0 netns "$gl_outside"
    ip -n "$gl_exit" link set "$overlay_if" address 02:00:00:00:11:01
    ip -n "$gl_client" link set client0 address 02:00:00:00:11:02
    configure "$gl_exit" "$overlay_if" 192.0.2.1/24 2001:db8:1::1/64
    configure "$gl_client" client0 192.0.2.2/24 2001:db8:1::2/64
    configure "$gl_exit" eth0 198.51.100.1/28 2001:db8:2::1/64
    configure "$gl_outside" outside0 198.51.100.2/28 2001:db8:2::2/64
    ip -n "$gl_outside" addr add "$gl_target4/32" dev outside0
    ip -n "$gl_outside" -6 addr add "$gl_target6/128" dev outside0 nodad
    ip netns exec "$gl_exit" sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
    ip netns exec "$gl_exit" sysctl -qw net.ipv4.icmp_errors_use_inbound_ifaddr=1
    ip -n "$gl_client" route add default via 192.0.2.1
    ip -n "$gl_client" -6 route add default via 2001:db8:1::1
    ip -n "$gl_exit" route add default via 198.51.100.2
    ip -n "$gl_exit" -6 route add default via 2001:db8:2::2
    for address in 192.0.2.1 2001:db8:1::1; do
        ip -n "$gl_client" neigh replace "$address" lladdr 02:00:00:00:11:01 nud permanent dev client0
    done
    for address in 192.0.2.2 2001:db8:1::2; do
        ip -n "$gl_exit" neigh replace "$address" lladdr 02:00:00:00:11:02 nud permanent dev "$overlay_if"
    done
    gl_tunnel_up 203.0.113.1
    # gluetun's rules and NetBird's, as they stand when the guard starts.
    ip -n "$gl_exit" -4 rule add to 198.51.100.0/28 lookup main priority 98
    ip -n "$gl_exit" -6 rule add to 2001:db8:2::/64 lookup main priority 98
    ip -n "$gl_exit" -4 rule add from 198.51.100.1 lookup 200 priority 100
    ip -n "$gl_exit" -6 rule add from 2001:db8:2::1 lookup 200 priority 100
    ip -n "$gl_exit" -4 route add default via 198.51.100.2 dev eth0 table 200
    ip -n "$gl_exit" -6 route add default via 2001:db8:2::2 dev eth0 table 200
    for family in -4 -6; do
        ip -n "$gl_exit" "$family" rule add not fwmark 51820 lookup 51820 priority 101
        ip -n "$gl_exit" "$family" rule add lookup main suppress_prefixlength 0 priority 105
        ip -n "$gl_exit" "$family" rule add not fwmark 0x1bd00 lookup 7120 priority 110
    done
    gl_counters "$gl_outside"
    gl_counters "$gl_tunnel"

    # Before the guard, gluetun's rule 101 already takes unmarked traffic into
    # the tunnel, and NetBird's marked traffic too: the reason for 88/89.
    [ "$(gl_local_path -4 0x1bd00)" = tunnel ] ||
        gl_fail 'fixture: without the guard, marked traffic should reach the tunnel through rule 101'

    gl_guard --once || gl_fail 'gluetun guard installation'
    test -f "$gl/ready"
    [ "$(cut -d' ' -f3 "$gl/status")" = absent ] || gl_fail 'status file should report no WireGuard overlay'
    [ "$(cut -d' ' -f1 "$gl/status")" = "$(cat /proc/sys/kernel/random/boot_id)" ] ||
        gl_fail 'status record should carry the boot id'
    for family in 4 6; do
        address=203.0.113.1
        [ "$family" = 4 ] || address=2001:db8:3::1
        gl_validate "$family" healthy "$address"
    done
    echo 'PASS gluetun guard installs rules 1/88/89/90/91/92/94/95/96/97/102/103/104, the exit table and the host table (IPv4 and IPv6)'

    gl_forwarding tunnel 'tunnel up'
    echo 'PASS forwarded packets marked 0, 0x1bd00, 0x1bd21 and 51820 go only into the tunnel (IPv4 and IPv6)'
    for family in -4 -6; do
        [ "$(gl_local_path "$family" 0x1bd00)" = host ] ||
            gl_fail "control-marked local traffic did not leave through the host interface ($family)"
        [ "$(gl_local_path "$family" 0)" = tunnel ] ||
            gl_fail "unmarked local traffic did not take gluetun's rule 101 into the tunnel ($family)"
        [ "$(gl_local_path "$family" 0x1bd21)" = tunnel ] ||
            gl_fail "a data-plane mark matched the control-plane rules ($family)"
    done
    echo "PASS local traffic: control mark via the host interface, unmarked and other marks through gluetun's tunnel"

    for family in -4 -6; do ip -n "$gl_exit" "$family" route flush table 51822; done
    for family in -4 -6; do
        [ "$(gl_local_path "$family" 0x1bd00)" = none ] ||
            gl_fail "control traffic without a host route was not unreachable ($family)"
    done
    for family in 4 6; do
        address=203.0.113.1
        [ "$family" = 4 ] || address=2001:db8:3::1
        gl_validate "$family" failed "$address"
    done
    echo 'PASS with the host table empty, control traffic is unreachable, never the tunnel (IPv4 and IPv6)'
    for family in -4 -6; do ip -n "$gl_exit" "$family" rule del priority 89; done
    for family in -4 -6; do
        [ "$(gl_local_path "$family" 0x1bd00)" = tunnel ] ||
            gl_fail "drill cannot see control traffic reaching the tunnel without rule 89 ($family)"
    done
    gl_guard --reconcile || gl_fail 'reconcile after host-table loss'
    for family in -4 -6; do
        [ "$(gl_local_path "$family" 0x1bd00)" = host ] || gl_fail "reconcile did not restore the host route ($family)"
    done
    echo 'PASS without rule 89 the drill sees control traffic in the tunnel; one reconcile pass restores both (drill confirmed sensitive)'

    ip -n "$gl_exit" link del wg0
    gl_forwarding blocked 'tunnel interface deleted'
    gl_tunnel_up 203.0.113.9
    # gluetun brought its interface back with a new address; until the guard
    # reconciles, the exit table has only its unreachable fallback.
    gl_forwarding blocked 'tunnel recreated, not reconciled'
    gl_guard --reconcile || gl_fail 'reconcile after tunnel recreation'
    gl_forwarding tunnel 'tunnel recreated and reconciled'
    gl_validate 4 healthy 203.0.113.9
    gl_validate 4 failed 203.0.113.1
    gl_validate 6 healthy 2001:db8:3::1
    echo 'PASS after gluetun recreates its interface, forwarding is blocked until one reconcile pass restores it, with rule 94 for the new address'

    # Sensitivity: without 95 and 97, a forwarded packet marked 51820 skips
    # gluetun's rule 101 and NetBird's 105, and leaves by the main table.
    for family in -4 -6; do
        ip -n "$gl_exit" "$family" rule del priority 95
        ip -n "$gl_exit" "$family" rule del priority 97
    done
    gl_mark_forwarded 51820
    for family in -4 -6; do
        gl_reset
        gl_forward "$family" || :
        [ "$(gl_count "$gl_outside" client)" != 0 ] ||
            gl_fail "drill cannot see a forwarded leak without rules 95 and 97 ($family)"
    done
    gl_guard --reconcile || gl_fail 'reconcile after rule loss'
    gl_forwarding tunnel 'rules 95 and 97 restored'
    echo 'PASS without rules 95 and 97 a forwarded packet marked 51820 leaks to the host side; reconcile restores them (drill confirmed sensitive)'

    # Sensitivity: rule 88 without `iif lo` would hand forwarded packets that
    # carry the control mark to the host table.
    for family in -4 -6; do
        ip -n "$gl_exit" "$family" rule del priority 88
        ip -n "$gl_exit" "$family" rule add fwmark 0x1bd00/0xffffffff lookup 51822 priority 88
    done
    gl_mark_forwarded 0x1bd00
    for family in -4 -6; do
        gl_reset
        gl_forward "$family" || :
        [ "$(gl_count "$gl_outside" client)" != 0 ] ||
            gl_fail "drill cannot see forwarded control-marked packets leak through rule 88 without iif lo ($family)"
    done
    gl_guard --reconcile || gl_fail 'reconcile after a wrong rule 88'
    gl_forwarding tunnel 'rule 88 corrected'
    for family in 4 6; do
        address=203.0.113.9
        [ "$family" = 4 ] || address=2001:db8:3::1
        gl_validate "$family" healthy "$address"
    done
    echo 'PASS rule 88 without iif lo leaks forwarded control-marked packets; reconcile replaces it (drill confirmed sensitive)'

    # The exit's own traffic to the overlay (rules 91 and 92). gluetun's rule
    # 101 would otherwise take it into the tunnel: the ICMP errors the exit
    # returns to clients, such as packet too big, would never reach them.
    gl_overlay_counters
    # Narrower than the client's link, so a full-size client packet needs
    # the exit's ICMP error.
    ip -n "$gl_exit" link set wg0 mtu 1280
    ip -n "$gl_tunnel" link set tunnel0 mtu 1280
    for family in -4 -6; do
        [ "$(gl_overlay_path "$family")" = overlay ] ||
            gl_fail "unmarked local traffic to the overlay did not leave over the overlay ($family)"
        gl_too_big_reported "$family" || gl_fail "the client got no ICMP error for an oversized packet ($family)"
    done
    gl_overlay_route del
    for family in -4 -6; do
        [ "$(gl_overlay_path "$family")" = none ] ||
            gl_fail "local traffic to the overlay was not unreachable without the overlay route ($family)"
    done
    for family in 4 6; do
        address=203.0.113.9
        [ "$family" = 4 ] || address=2001:db8:3::1
        gl_validate "$family" healthy "$address"
    done
    echo 'PASS the exit reaches clients only over the overlay: their ICMP errors arrive, and with no overlay route the traffic is unreachable, never the tunnel (IPv4 and IPv6)'
    # Sensitivity: without rule 92 and with no overlay route, the traffic
    # takes gluetun's rule 101 into the tunnel.
    for family in -4 -6; do ip -n "$gl_exit" "$family" rule del priority 92; done
    for family in -4 -6; do
        [ "$(gl_overlay_path "$family")" = tunnel ] ||
            gl_fail "drill cannot see local overlay traffic reach the tunnel without rule 92 ($family)"
    done
    gl_overlay_route add
    # Without rule 91 as well, the client's ICMP errors go into the tunnel.
    for family in -4 -6; do ip -n "$gl_exit" "$family" rule del priority 91; done
    for family in -4 -6; do
        [ "$(gl_overlay_path "$family")" = tunnel ] ||
            gl_fail "drill cannot see local overlay traffic reach the tunnel without rules 91/92 ($family)"
        ! gl_too_big_reported "$family" ||
            gl_fail "drill cannot see the client's ICMP error lost without rules 91/92 ($family)"
    done
    gl_guard --reconcile || gl_fail 'reconcile after rules 91/92 loss'
    for family in -4 -6; do
        [ "$(gl_overlay_path "$family")" = overlay ] || gl_fail "reconcile did not restore rules 91/92 ($family)"
        gl_too_big_reported "$family" || gl_fail "reconcile did not restore the client's ICMP errors ($family)"
    done
    ip -n "$gl_exit" link set wg0 mtu 1500
    ip -n "$gl_tunnel" link set tunnel0 mtu 1500
    echo 'PASS without rules 91/92 the exit sends client-bound traffic and ICMP errors into the tunnel; reconcile restores them (drill confirmed sensitive)'

    # The exit's own traffic with gluetun's tunnel table empty, as during a
    # reconnect: unmarked new and established flows are unreachable (rule
    # 104), never the host side; gluetun's WireGuard socket (mark 51820)
    # still leaves by the host (rule 102).
    for family in -4 -6; do
        [ "$(gl_local_path "$family" 0)" = tunnel ] || gl_fail "unmarked local traffic did not take the tunnel ($family)"
        [ "$(gl_local_path "$family" 51820)" = host ] ||
            gl_fail "gluetun's WireGuard mark did not leave by the host interface ($family)"
        [ "$(gl_established "$family")" = 0 ] ||
            gl_fail "an established local flow left by the host interface once the tunnel table emptied ($family)"
        [ "$(gl_local_path "$family" 0)" = none ] ||
            gl_fail "unmarked local UDP was not unreachable with the tunnel table empty ($family)"
        [ "$(gl_new_tcp "$family")" = 0 ] ||
            gl_fail "a new local TCP connection left by the host interface with the tunnel table empty ($family)"
        [ "$(gl_local_path "$family" 51820)" = host ] ||
            gl_fail "gluetun's WireGuard mark did not leave by the host interface with the tunnel table empty ($family)"
        [ "$(gl_local_path "$family" 0x1bd00)" = host ] ||
            gl_fail "NetBird's control traffic did not leave by the host interface with the tunnel table empty ($family)"
        gl_tunnel_table fill
    done
    for family in 4 6; do
        address=203.0.113.9
        [ "$family" = 4 ] || address=2001:db8:3::1
        gl_validate "$family" healthy "$address"
    done
    echo "PASS with gluetun's tunnel table empty, the exit's own unmarked traffic (UDP, new and established TCP) is unreachable, never the host side; gluetun's WireGuard socket and NetBird's control traffic still leave by the host (IPv4 and IPv6)"
    # Sensitivity: without rule 104 the same traffic leaves by the host side;
    # without 102 gluetun's WireGuard socket can't reach its server.
    gl_tunnel_table empty
    for family in -4 -6; do
        ip -n "$gl_exit" "$family" rule del priority 104
        [ "$(gl_local_path "$family" 0)" = host ] ||
            gl_fail "drill cannot see unmarked local traffic leave by the host without rule 104 ($family)"
        ip -n "$gl_exit" "$family" rule add iif lo unreachable priority 104
        ip -n "$gl_exit" "$family" rule del priority 102
        [ "$(gl_local_path "$family" 51820)" = none ] ||
            gl_fail "drill cannot see gluetun's WireGuard socket cut off without rule 102 ($family)"
    done
    gl_guard --reconcile || gl_fail 'reconcile after rules 102/104 loss'
    for family in -4 -6; do
        [ "$(gl_local_path "$family" 0)" = none ] || gl_fail "reconcile did not restore rule 104 ($family)"
        [ "$(gl_local_path "$family" 51820)" = host ] || gl_fail "reconcile did not restore rule 102 ($family)"
    done
    gl_tunnel_table fill
    echo "PASS without rule 104 the exit's own traffic leaves by the host, without 102 gluetun's WireGuard socket is cut off; reconcile restores both (drill confirmed sensitive)"

    # gluetun's start-up, with the whole guard already in place, as on a
    # recreated stack: it adds `default via <gateway> dev <host if> table 200`
    # before its own rule 98 for local subnets exists. The kernel checks the
    # gateway with a lookup through the policy rules as local traffic; rule
    # 103 (the host table's on-link routes) must answer it before 104 does.
    gl_route200() {
        gl_gw=198.51.100.2
        [ "$1" = -4 ] || gl_gw=2001:db8:2::2
        ip -n "$gl_exit" "$1" route replace default via "$gl_gw" dev eth0 table 200 2> "$gl/route200.err"
    }
    for family in -4 -6; do
        ip -n "$gl_exit" "$family" rule del priority 98
        ip -n "$gl_exit" "$family" route flush table 200
        gl_route200 "$family" ||
            gl_fail "gluetun's table-200 default route was refused with the guard in place ($family): $(cat "$gl/route200.err")"
    done
    echo "PASS with the whole guard in place and gluetun's rule 98 not yet there, gluetun's table-200 default route via the host gateway is accepted (IPv4 and IPv6)"
    # Sensitivity: without rule 103 the gateway check reaches 104 and the
    # route is refused, as on the live exit (IPv4; IPv6 is reported only).
    for family in -4 -6; do
        ip -n "$gl_exit" "$family" route flush table 200
        ip -n "$gl_exit" "$family" rule del priority 103
    done
    # The refusal reads differently by tool: gluetun's netlink call got
    # "network is unreachable", iproute2 says "Nexthop has invalid gateway".
    # Either way the same command that succeeds with rule 103 fails.
    ! gl_route200 -4 || gl_fail 'drill cannot see the IPv4 gateway check fail without rule 103'
    if gl_route200 -6; then
        echo 'INFO without rule 103 the IPv6 gateway check still passed (a global gateway on this kernel)'
    else
        echo 'INFO without rule 103 the IPv6 gateway check failed too'
    fi
    gl_guard --reconcile || gl_fail 'reconcile after rule 103 loss'
    for family in -4 -6; do
        ip -n "$gl_exit" "$family" route flush table 200
        gl_route200 "$family" || gl_fail "reconcile did not restore rule 103 ($family): $(cat "$gl/route200.err")"
    done
    ip -n "$gl_exit" -4 rule add to 198.51.100.0/28 lookup main priority 98
    ip -n "$gl_exit" -6 rule add to 2001:db8:2::/64 lookup main priority 98
    echo "PASS without rule 103 gluetun's IPv4 table-200 gateway route is refused; reconcile restores it (drill confirmed sensitive)"

    # The NetBird gate in gluetun mode.
    for setting in NB_USE_LEGACY_ROUTING=true NB_SKIP_SOCKET_MARK=1 NB_DISABLE_CUSTOM_ROUTING=true \
            NB_FWMARK_BASE=0x2bd00; do
        if gl_gate "$setting" timeout 5 sh "$root/routing/wait-for-guards" true 2>"$gl/gate.err" ||
                ! grep -q 'refusing to start NetBird' "$gl/gate.err"; then
            gl_fail "gluetun gate did not refuse $setting"
        fi
    done
    # The gate judges the namespace with the guard's own definitions: every
    # rule at 0-97, the exit table and the host table. Each break below must
    # keep NetBird from starting until the guard repairs it.
    gl_gate_starts || gl_fail 'gluetun gate did not start NetBird with the whole guard in place'
    for priority in 88 89 90 94 95 96; do
        ip -n "$gl_exit" -6 rule del priority "$priority"
        ! gl_gate_starts || gl_fail "gluetun gate started NetBird without IPv6 rule $priority"
        gl_guard --reconcile || gl_fail "reconcile after IPv6 rule $priority loss"
    done
    ip -n "$gl_exit" -4 rule add iif "$overlay_if" lookup main priority 50
    ! gl_gate_starts || gl_fail 'gluetun gate started NetBird with an early main-table rule for the overlay'
    gl_guard --reconcile || gl_fail 'reconcile after an early main-table rule'
    ip -n "$gl_exit" -4 route add 198.51.100.0/28 via 198.51.100.2 dev eth0 table 51821
    ! gl_gate_starts || gl_fail 'gluetun gate started NetBird with a host route in the exit table'
    gl_guard --reconcile || gl_fail 'reconcile after a host route in the exit table'
    gl_gate_starts || gl_fail 'gluetun gate did not start NetBird after the guard repaired everything'
    echo 'PASS gluetun gate refuses to start NetBird on a missing rule 88/89/90/94/95/96, an early main-table rule or a host route in the exit table (IPv4 and IPv6)'
    : > "$gl/client.log"
    gl_record 0x1bd00
    gl_gate timeout 30 sh "$root/routing/wait-for-guards" sh -c \
        'touch "$1"; sleep 3; echo "WARN client/net/env_linux.go:66: system doesn'"'"'t support required routing features, falling back to legacy routing" >> "$2"; exec sleep 60' \
        gate "$gl/started" "$gl/client.log" 2>"$gl/gate.err" && gl_fail 'gluetun gate exited zero after a legacy-routing line'
    [ -f "$gl/started" ] && grep -q 'stopping NetBird: NetBird logged that it runs without advanced routing' "$gl/gate.err" ||
        gl_fail 'gluetun gate did not stop NetBird on the legacy-routing line'
    rm -f "$gl/started"
    gl_record absent
    gl_gate FWMARK_GRACE=5 timeout 30 sh "$root/routing/wait-for-guards" sh -c 'touch "$1"; exec sleep 60' \
        gate "$gl/started" 2>"$gl/gate.err" && gl_fail 'gluetun gate exited zero without the control mark'
    [ -f "$gl/started" ] && grep -q 'has not carried the control mark 0x1bd00' "$gl/gate.err" ||
        gl_fail 'gluetun gate did not stop NetBird without the control mark'
    echo 'PASS gluetun gate refuses unmarked-routing settings, waits for rules 88/89, and stops NetBird (non-zero exit) on a legacy-routing line or a missing fwmark'
}

if command -v nft >/dev/null 2>&1; then
    gluetun_drills
else
    echo 'SKIP gluetun backend drills (nft not installed)'
fi

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
