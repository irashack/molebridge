#!/usr/bin/env sh
# Runs the routing image (routing/Dockerfile) the way compose.yaml does, with a
# throwaway tunnel config whose peer is a documentation address (no handshake
# is needed for the interface to come up), and checks its life cycle: what the
# image holds, reading the config under the capabilities compose.yaml grants,
# start, repair, tunnel loss, a bring-up that fails or hangs, every stop, and
# the guard mode. The routing contract's traffic properties are drilled in
# tools/check-routing.sh; this checks the container around it.
#
# Needs Docker on Linux with kernel WireGuard. No accounts, real endpoints or
# keys: keys are generated per run and discarded.
#   sh tools/check-exit-image.sh <image>
set -eu
image=${1:?usage: sh tools/check-exit-image.sh <image>}
work=$(mktemp -d)
run=mbx$$
names=''
volumes=''
cleanup() {
    for name in $names; do docker rm -f "$name" >/dev/null 2>&1 || :; done
    for volume in $volumes; do docker volume rm -f "$volume" >/dev/null 2>&1 || :; done
    rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM
fail() {
    echo "FAIL $1" >&2
    if [ -n "${2:-}" ]; then docker logs "$2" 2>&1 | tail -40 >&2 || :; fi
    exit 1
}
pass() { echo "PASS $1"; }
# Seconds, for timing; /proc/uptime on Linux, perl where there is none (a
# macOS host driving a Docker VM).
uptime_now() {
    if [ -r /proc/uptime ]; then awk '{ print $1 }' /proc/uptime; else perl -MTime::HiRes=time -e 'printf "%.2f\n", time'; fi
}
elapsed() { awk -v a="$1" -v b="$(uptime_now)" 'BEGIN { printf "%.1f", b - a }'; }

# --- What the image holds.
docker run --rm --network none --entrypoint sh "$image" -c '
    set -e
    for tool in bash wg wg-quick ip tini setsid timeout stat; do command -v "$tool" >/dev/null; done
    ip -Version >/dev/null
    test "$(stat -c %u:%a /usr/local/bin/molebridge-exit)" = 0:755
    test "$(stat -c %u:%a /usr/local/lib/molebridge/10-exit-routing)" = 0:755
    test "$(stat -c %u:%a /usr/local/lib/molebridge/contract-rules)" = 0:644
    test "$(stat -c %u:%a /usr/local/lib/molebridge)" = 0:755
    test "$(readlink -f /custom-cont-init.d/10-exit-routing)" = /usr/local/lib/molebridge/10-exit-routing
    test "$(readlink -f /usr/local/lib/molebridge/gluetun-rules)" = /usr/local/lib/molebridge/contract-rules
    sleep 0.1
    apk info -v 2>/dev/null | grep -E "^(alpine-baselayout|bash|busybox|iproute2|tini|wireguard-tools)-[0-9]" | sort
' > "$work/versions" || fail 'the image is missing a tool or a script has the wrong owner or mode'
echo "Installed: $(tr '\n' ' ' < "$work/versions")"
pass 'image tools, script ownership and the compatibility links'

# A Mullvad-shaped config (dual stack) in a fresh volume, owned by $2:$3.
make_conf() {
    volume=$run-$1
    volumes="$volumes $volume"
    docker volume create "$volume" >/dev/null
    private=$(docker run --rm --network none --entrypoint wg "$image" genkey)
    public=$(docker run --rm --network none --entrypoint wg "$image" genkey | docker run --rm -i --network none --entrypoint wg "$image" pubkey)
    case "$1" in
        pia*)
            printf '%s\n' '[Interface]' "PrivateKey = $private" 'MTU = 1420' 'Table = off' \
                'PostUp = ip route replace default dev %i table 51821' 'PreDown = ip route del default dev %i table 51821' > "$work/conf" ;;
        *)
            printf '%s\n' '[Interface]' "PrivateKey = $private" 'Address = 203.0.113.2/32, 2001:db8:3::2/128' \
                'MTU = 1420' 'Table = off' \
                'PostUp = ip route replace default dev %i table 51821; ip -6 route replace default dev %i table 51821' \
                'PreDown = ip route del default dev %i table 51821; ip -6 route del default dev %i table 51821' '' \
                '[Peer]' "PublicKey = $public" 'Endpoint = 192.0.2.10:51820' 'AllowedIPs = 0.0.0.0/0, ::/0' \
                'PersistentKeepalive = 25' > "$work/conf" ;;
    esac
    exit_if=mullvad
    case "$1" in pia*) exit_if=pia ;; esac
    docker run --rm -i --network none -v "$volume:/c" --entrypoint sh "$image" \
        -c "cat > /c/$exit_if.conf && chown $2:$3 /c/$exit_if.conf && chmod 600 /c/$exit_if.conf" < "$work/conf"
}

# The exit as compose.yaml runs it; extra docker arguments follow the name.
start_exit() {
    name=$run-$1
    volume=$run-$2
    shift 2
    names="$names $name"
    docker run -d --name "$name" --cap-drop ALL --cap-add NET_ADMIN --cap-add DAC_READ_SEARCH \
        --security-opt no-new-privileges:true --read-only --tmpfs /run:size=1m,mode=0755,noexec,nosuid,nodev \
        --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.forwarding=1 \
        --sysctl net.ipv4.icmp_errors_use_inbound_ifaddr=1 --sysctl net.ipv6.conf.all.disable_ipv6=0 \
        --sysctl net.ipv6.conf.default.disable_ipv6=0 --stop-timeout 15 \
        -e OVERLAY_CIDR=192.0.2.0/24 -e OVERLAY6_CIDR=2001:db8:1::/64 -e EXIT_IF="${EXIT_IF:-mullvad}" \
        -e PROVIDER="${PROVIDER:-mullvad}" -v "$volume:/config/wg_confs:ro" "$@" "$image" >/dev/null
}
in_exit() { docker exec "$name" sh -c "$1"; }
wait_for() {
    # $1 seconds for the command in $2 to succeed in the container.
    deadline=$(awk -v n="$(uptime_now)" -v s="$1" 'BEGIN { printf "%.2f", n + s }')
    while ! in_exit "$2" >/dev/null 2>&1; do
        awk -v n="$(uptime_now)" -v d="$deadline" 'BEGIN { exit !(n > d) }' && return 1
        sleep 0.5
    done
}
ready() { wait_for "${1:-20}" 'test -f /run/molebridge-routing-ready'; }
running() { [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" = true ]; }
stop_exit() {
    started=$(uptime_now)
    docker stop -t 15 "$name" >/dev/null
    took=$(elapsed "$started")
    code=$(docker inspect -f '{{.State.ExitCode}}' "$name")
}
expected_rules() {
    # $1 family, $2 address or empty: the native contract as `ip rule show` prints it.
    {
        echo "1: not from all iif wt0 lookup local"
        if [ "$1" = -4 ]; then echo "90: from all to 192.0.2.0/24 iif mullvad lookup main"; else echo "90: from all to 2001:db8:1::/64 iif mullvad lookup main"; fi
        icmp=icmp
        [ "$1" = -4 ] || icmp=ipv6-icmp
        [ -z "$2" ] || echo "94: from $2 ipproto $icmp lookup 51821"
        echo "95: from all iif wt0 lookup 51821"
        echo "96: from all oif mullvad lookup 51821"
        echo "97: from all iif wt0 unreachable"
        [ -z "$2" ] || echo "98: from $2 ipproto $icmp unreachable"
    } | sort
}
actual_rules() {
    in_exit "ip $1 rule show" | sed 's/\t/ /; s/ \[detached\]//g; s/ipproto 1 /ipproto icmp /; s/ipproto 58 /ipproto ipv6-icmp /' |
        awk -F: '$1 <= 98' | sort
}

# --- Reading the config: a host user's 0600 file needs DAC_READ_SEARCH.
make_conf user 1000 1000
names="$names $run-nodac"
docker run -d --name "$run-nodac" --cap-drop ALL --cap-add NET_ADMIN --read-only --tmpfs /run \
    -e OVERLAY_CIDR=192.0.2.0/24 -v "$run-user:/config/wg_confs:ro" "$image" >/dev/null
docker wait "$run-nodac" >/dev/null
[ "$(docker inspect -f '{{.State.ExitCode}}' "$run-nodac")" = 1 ] || fail 'started without DAC_READ_SEARCH' "$run-nodac"
docker logs "$run-nodac" 2>&1 | grep -q "can't be read" || fail 'no message about reading the config' "$run-nodac"
docker logs "$run-nodac" 2>&1 | grep -q 'bringing the tunnel up' && fail 'touched the network before reading the config' "$run-nodac"
start_exit main user
ready || fail 'not ready with DAC_READ_SEARCH' "$name"
pass "a host user's mode-0600 config: refused without DAC_READ_SEARCH, read with it"

# --- The running exit: owner record, rules, readiness.
in_exit 'test -f /run/molebridge/exit-owner' || fail 'no owner record' "$name"
in_exit 'read -r a b c d e f g h i j k < /run/molebridge/exit-owner; [ "$a $b $g $h $i" = "molebridge-exit 1 203.0.113.2 2001:db8:3::2 conf" ]' ||
    fail 'the owner record is not the expected shape' "$name"
for family in -4 -6; do
    address=203.0.113.2
    [ "$family" = -4 ] || address=2001:db8:3::2
    [ "$(actual_rules "$family")" = "$(expected_rules "$family" "$address")" ] || {
        actual_rules "$family" >&2
        fail "IPv${family#-} rules differ from the native contract" "$name"
    }
done
in_exit 'ip route show table 51821 | grep -q "^default dev mullvad" && ip route show table 51821 | grep -q "^unreachable default metric 4096"' ||
    fail 'IPv4 exit table' "$name"
in_exit 'ip -6 route show table 51821 | grep -q "^default dev mullvad" && ip -6 route show table 51821 | grep -q "^unreachable default"' ||
    fail 'IPv6 exit table' "$name"
pass 'running: owner record, the native rules 1/90/94/95/96/97/98 in both families, the exit table'

# --- Single deletions, insertions and tunnel loss: repaired and logged.
for change in 'ip rule del priority 97' 'ip -6 rule del priority 94' 'ip rule del priority 98' \
        'ip route del unreachable default metric 4096 table 51821' 'ip -6 rule del priority 1' \
        'ip rule add lookup main priority 50' 'ip -6 rule add lookup local priority 0' \
        'ip route add 203.0.113.99 dev eth0 table 51821'; do
    in_exit "$change"
    wait_for 6 "[ \"\$(ip rule show | awk -F: '\$1 <= 98' | wc -l)\" = 7 ] && [ \"\$(ip -6 rule show | awk -F: '\$1 <= 98' | wc -l)\" = 7 ] && [ \"\$(ip route show table 51821 | wc -l)\" = 2 ]" ||
        fail "not repaired within 6 s: $change" "$name"
done
for family in -4 -6; do
    address=203.0.113.2
    [ "$family" = -4 ] || address=2001:db8:3::2
    [ "$(actual_rules "$family")" = "$(expected_rules "$family" "$address")" ] || fail "IPv${family#-} rules after repair" "$name"
done
docker logs "$name" 2>&1 | grep -q '10-exit-routing: added IPv4 rule 97' || fail 'the repair of rule 97 is not logged' "$name"
docker logs "$name" 2>&1 | grep -q '10-exit-routing: removed IPv4 rule 50' || fail 'the removal of rule 50 is not logged' "$name"
in_exit 'read -r a b c d e f g h i j k < /run/molebridge/exit-owner; [ "$j" -gt 0 ] && [ "$k" != - ]' || fail 'repairs are not counted in the owner record' "$name"
pass 'deletions (97, 94, 98, the fallback, 1) and insertions (lookup main at 50, lookup local at 0, a foreign route) repaired within 6 s and logged'
ups=$(docker logs "$name" 2>&1 | grep -c 'molebridge-exit: tunnel up')
in_exit 'ip link del mullvad'
deadline=$(awk -v n="$(uptime_now)" 'BEGIN { printf "%.2f", n + 15 }')
until [ "$(docker logs "$name" 2>&1 | grep -c 'molebridge-exit: tunnel up')" -gt "$ups" ]; do
    awk -v n="$(uptime_now)" -v d="$deadline" 'BEGIN { exit !(n > d) }' && fail 'the tunnel did not come back' "$name"
    sleep 0.5
done
docker logs "$name" 2>&1 | grep -q 'molebridge-exit: not ready' || fail 'readiness was not withdrawn while the tunnel was gone' "$name"
ready 5 || fail 'not ready after the tunnel came back' "$name"
pass 'tunnel interface deleted: readiness withdrawn, tunnel recreated, ready again'

# --- A slow reconcile interval keeps the heartbeat at 2 s.
start_exit slow user -e ROUTING_RECONCILE_INTERVAL=60
ready || fail 'not ready with a 60 s interval' "$name"
sleep 5
in_exit 'read -r a b c s rest < /run/molebridge/exit-owner; read -r up _ < /proc/uptime; [ $(( ${up%%.*} - s )) -le 3 ]' ||
    fail 'the owner record went stale with a 60 s reconcile interval' "$name"
pass 'heartbeat every 2 s whatever the reconcile interval'
docker rm -f "$name" >/dev/null

# --- Stopping, with the tunnel up.
name=$run-main
stop_exit
[ "$code" = 0 ] || fail "exit code $code after a stop" "$name"
awk -v t="$took" 'BEGIN { exit !(t <= 8) }' || fail "stop took ${took}s" "$name"
docker logs "$name" 2>&1 | grep -q 'stopped; the routing guards stay in place' || fail 'no stop message' "$name"
pass "stop with the tunnel up: exit 0 in ${took}s"

# --- A root-owned config, and PIA's addressless one.
make_conf root 0 0
start_exit root root
ready || fail 'not ready with a root-owned config' "$name"
pass 'a root-owned config'
docker rm -f "$name" >/dev/null
make_conf pia 0 0
# Assignments before a function call outlive it in some shells: set and reset.
EXIT_IF=pia
PROVIDER=pia
start_exit pia pia
EXIT_IF=mullvad
PROVIDER=mullvad
ready || fail 'PIA: not ready before registration' "$name"
in_exit 'ip rule show | grep -Eq "^9[48]:"' && fail 'PIA: the loop installed 94 or 98' "$name"
in_exit 'ip rule add from 203.0.113.7 ipproto icmp lookup 51821 priority 94 && ip rule add from 203.0.113.7 ipproto icmp unreachable priority 98 && ip addr add 203.0.113.7/32 dev pia'
sleep 5
[ "$(in_exit 'ip rule show | grep -cE "^9[48]:"')" = 2 ] || fail "PIA: the loop changed the applier's rules" "$name"
in_exit 'test -f /run/molebridge-routing-ready' || fail 'PIA: not ready with the applier-owned rules' "$name"
pass "PIA: ready without an address; rules 94/98 left to the applier"
docker rm -f "$name" >/dev/null

# --- Settings and configs refused before anything changes.
names="$names $run-bad"
docker run -d --name "$run-bad" --cap-drop ALL --cap-add NET_ADMIN --cap-add DAC_READ_SEARCH --read-only --tmpfs /run \
    -e OVERLAY_CIDR=192.0.2.1/24 -v "$run-root:/config/wg_confs:ro" "$image" >/dev/null
docker wait "$run-bad" >/dev/null
[ "$(docker inspect -f '{{.State.ExitCode}}' "$run-bad")" = 1 ] || fail 'an invalid OVERLAY_CIDR did not stop the exit' "$run-bad"
docker logs "$run-bad" 2>&1 | grep -Eq 'installed|bringing the tunnel' && fail 'routing or the tunnel changed with invalid settings' "$run-bad"
pass 'invalid settings: exit 1 before any routing or tunnel change'

# --- wg-quick that fails, hangs, or leaves the interface behind: a stand-in
# ahead of it in PATH, and one for `ip link del`.
cat > "$work/wg-quick" <<'EOF'
#!/bin/sh
case "${FAKE_WGQ:-}:$1" in
    fail:up) exit 1 ;;
    hang:up) sleep 300 & exec sleep 301 ;;
    hangdown:down) sleep 300 & exec sleep 301 ;;
    failpredown:down) ip route del default dev "$EXIT_IF" table 51821 2>/dev/null || : ;;
esac
exec /usr/bin/wg-quick "$@"
EOF
cat > "$work/ip" <<'EOF'
#!/bin/sh
case "${FAKE_IP:-}:$*" in
    nodel:link\ del*) exit 2 ;;
esac
exec /sbin/ip "$@"
EOF
chmod 755 "$work/wg-quick" "$work/ip"
fakes="-v $work/wg-quick:/usr/local/sbin/wg-quick:ro -v $work/ip:/usr/local/sbin/ip:ro"

# shellcheck disable=SC2086 # $fakes is two docker arguments each
start_exit fail root $fakes -e FAKE_WGQ=fail
wait_for 10 'test -f /run/molebridge/exit-owner' || fail 'no owner record during failing bring-ups' "$name"
sleep 6
running || fail 'a failing bring-up stopped the container' "$name"
in_exit 'test ! -f /run/molebridge-routing-ready' || fail 'ready without a tunnel' "$name"
in_exit 'read -r a b c s rest < /run/molebridge/exit-owner; read -r up _ < /proc/uptime; [ $(( ${up%%.*} - s )) -le 3 ]' ||
    fail 'the heartbeat stopped during failing bring-ups' "$name"
[ "$(docker logs "$name" 2>&1 | grep -c 'tunnel bring-up failed')" -ge 2 ] || fail 'bring-up is not retried' "$name"
stop_exit
[ "$code" = 0 ] || fail "exit code $code stopping during backoff" "$name"
pass "bring-up failing: alive, not ready, heartbeat fresh, retried with backoff; stop during backoff exits 0 in ${took}s"

# shellcheck disable=SC2086
start_exit hang root $fakes -e FAKE_WGQ=hang
wait_for 10 'pgrep -f "sleep 301" >/dev/null' || fail 'the hanging bring-up did not start' "$name"
# At its 20-second deadline the bring-up's whole group goes, its child too,
# before the retry 2 seconds later.
deadline=$(awk -v n="$(uptime_now)" 'BEGIN { printf "%.2f", n + 30 }')
until docker logs "$name" 2>&1 | grep -q 'tunnel bring-up failed'; do
    awk -v n="$(uptime_now)" -v d="$deadline" 'BEGIN { exit !(n > d) }' && fail 'the hanging bring-up was not ended at its deadline' "$name"
    sleep 0.5
done
in_exit '! pgrep -f "sleep 30[01]" >/dev/null' || fail "part of the hung bring-up's group survived its deadline" "$name"
wait_for 10 'pgrep -f "sleep 301" >/dev/null' || fail 'the bring-up was not retried after its deadline' "$name"
in_exit 'read -r a b c s rest < /run/molebridge/exit-owner; read -r up _ < /proc/uptime; [ $(( ${up%%.*} - s )) -le 3 ]' ||
    fail 'the heartbeat stopped during a hanging bring-up' "$name"
# The stop's cancellation, not the engine's KILL, must end the hung worker
# and its child: the entrypoint logs nothing about a survivor, and the stop
# finishes well inside the engine's timeout.
stop_exit
[ "$code" = 0 ] || fail "exit code $code stopping during a hanging bring-up" "$name"
docker logs "$name" 2>&1 | grep -q 'cleanup incomplete' && fail 'a hung bring-up worker survived its cancellation' "$name"
awk -v t="$took" 'BEGIN { exit !(t <= 8) }' || fail "stop during a hanging bring-up took ${took}s" "$name"
pass "stop during a hanging bring-up (with a child): its group cancelled, exit 0 in ${took}s"

for mode in failpredown hangdown; do
    # shellcheck disable=SC2086
    start_exit "$mode" root $fakes -e FAKE_WGQ="$mode"
    ready || fail "$mode: not ready" "$name"
    stop_exit
    [ "$code" = 0 ] || fail "$mode: exit code $code" "$name"
    awk -v t="$took" 'BEGIN { exit !(t <= 8) }' || fail "$mode: stop took ${took}s" "$name"
    pass "stop with a $mode PreDown: the interface removed directly, exit 0 in ${took}s"
done

# shellcheck disable=SC2086
start_exit nodel root $fakes -e FAKE_WGQ=hangdown -e FAKE_IP=nodel
ready || fail 'nodel: not ready' "$name"
stop_exit
[ "$code" = 1 ] || fail "cleanup failure reported as exit $code" "$name"
docker logs "$name" 2>&1 | grep -q 'cleanup incomplete' || fail 'no cleanup-incomplete message' "$name"
pass "the interface can't be removed: exit 1 and 'cleanup incomplete', in ${took}s"

# --- The guard mode starts under busybox sh and waits for gluetun's tunnel.
names="$names $run-guard"
docker run -d --name "$run-guard" --cap-drop ALL --cap-add NET_ADMIN --read-only --tmpfs /tmp --tmpfs /run \
    -e TUNNEL_BACKEND=gluetun -e OVERLAY_CIDR=192.0.2.0/24 -e EXIT_IF=wg0 \
    -e ROUTING_READY_FILE=/run/routing-ready "$image" >/dev/null
sleep 5
[ "$(docker inspect -f '{{.State.Running}}' "$run-guard")" = true ] || fail 'the guard mode exited' "$run-guard"
docker logs "$run-guard" 2>&1 | grep -q '10-exit-routing:' || fail 'the guard mode logged nothing' "$run-guard"
pass 'guard mode (TUNNEL_BACKEND=gluetun) runs and waits for the tunnel'
echo 'All routing image checks passed.'
