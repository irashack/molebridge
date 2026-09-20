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
cleanup() {
    if [ -n "$gate_pid" ]; then kill "$gate_pid" 2>/dev/null || true; wait "$gate_pid" 2>/dev/null || true; fi
    for ns in $created; do ip netns del "$ns" 2>/dev/null || true; done
    rm -f "$work/ready" "$work/rules.json" "$work/routes.json" "$work/gate-started"
    rmdir "$work"
}
trap cleanup EXIT HUP INT TERM
client=mb-client-$$
exitns=mb-exit-$$
outside=mb-outside-$$
tunnel=mb-tunnel-$$
overlay_if=${TEST_OVERLAY_IF:-wt0}
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

configure() {
    ip -n "$1" addr add "$3" dev "$2"
    ip -n "$1" -6 addr add "$4" dev "$2" nodad
    ip -n "$1" link set "$2" up
}
configure "$exitns" "$overlay_if" 192.0.2.1/24 2001:db8:1::1/64
configure "$client" client0 192.0.2.2/24 2001:db8:1::2/64
configure "$exitns" eth0 198.51.100.1/24 2001:db8:2::1/64
configure "$outside" outside0 198.51.100.2/24 2001:db8:2::2/64
configure "$exitns" mullvad 203.0.113.1/24 2001:db8:3::1/64
configure "$tunnel" tunnel0 203.0.113.2/24 2001:db8:3::2/64
# The fake tunnel is Ethernet; real WireGuard needs no neighbor discovery.
# Use a fixed, locally administered MAC for the synthetic destination below.
ip -n "$tunnel" link set tunnel0 address 02:00:00:00:03:02
ip netns exec "$exitns" sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
ip -n "$client" route add default via 192.0.2.1
ip -n "$client" -6 route add default via 2001:db8:1::1
ip -n "$exitns" route add default via 198.51.100.2
ip -n "$exitns" -6 route add default via 2001:db8:2::2
ip -n "$outside" route add 192.0.2.0/24 via 198.51.100.1
ip -n "$outside" -6 route add 2001:db8:1::/64 via 2001:db8:2::1
ip -n "$tunnel" route add 192.0.2.0/24 via 203.0.113.1
ip -n "$tunnel" -6 route add 2001:db8:1::/64 via 2001:db8:3::1
# The same fictitious destination is reachable over both paths. A broken
# guard would therefore turn an expected failed client probe into a success.
ip -n "$outside" addr add 198.51.100.100/32 dev outside0
ip -n "$outside" -6 addr add 2001:db8:2::100/128 dev outside0 nodad
ip -n "$tunnel" addr add 198.51.100.100/32 dev tunnel0
ip -n "$tunnel" -6 addr add 2001:db8:2::100/128 dev tunnel0 nodad

install_rules() {
    ip netns exec "$exitns" env OVERLAY_CIDR=192.0.2.0/24 OVERLAY6_CIDR=2001:db8:1::/64 \
        OVERLAY_IF="$overlay_if" EXIT_IF=mullvad EXIT_TABLE=51821 ROUTING_READY_FILE="$work/ready" \
        sh "$root/routing/10-exit-routing"
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
# Check the exact iproute2 JSON emitted by a real kernel, not just fixtures.
validate_family() {
    ip -n "$exitns" -j "-$1" rule show > "$work/rules.json"
    ip -n "$exitns" -j "-$1" route show table 51821 > "$work/routes.json"
    python3 - "$work/rules.json" "$work/routes.json" "$1" "$2" "$overlay_if" <<'PY'
import json, sys
from molebridge.routing import RoutingConfig, family_status
with open(sys.argv[1]) as f:
    rules = json.load(f)
with open(sys.argv[2]) as f:
    routes = json.load(f)
config = RoutingConfig('192.0.2.0/24', '2001:db8:1::/64', overlay_if=sys.argv[5])
result = family_status(rules, routes, config, int(sys.argv[3]))
assert result == (sys.argv[4] == 'healthy', True), f'IPv{sys.argv[3]} validation={result}; rules={rules!r}; routes={routes!r}'
PY
}

# Start NetBird's gate before initialization, just as a runtime restart can.
ip netns exec "$exitns" env NB_INTERFACE_NAME="$overlay_if" \
    sh "$root/routing/wait-for-guards" sh -c 'touch "$1"' gate "$work/gate-started" &
gate_pid=$!
sleep 2
test ! -f "$work/gate-started"
ip -n "$exitns" -4 rule add iif "$overlay_if" unreachable priority 97
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
echo 'PASS overlay startup waits for both routing guards'
restore_routes
connected
for family in 4 6; do validate_family "$family" healthy; done

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
ip -n "$exitns" -6 addr replace 2001:db8:3::1/64 dev mullvad nodad
restore_routes
connected
install_rules
connected
echo 'PASS routing reinstallation and recovery'
