#!/usr/bin/env sh
# Runs the Molebridge image's `exit` role the way compose.yaml does, with a
# throwaway tunnel config whose peer is a documentation address (no handshake
# is needed for the interface to come up), and checks the container around the
# exit: the refusal of each invalid setting with its exact message, the start
# (the routing contract first, then the tunnel, readiness, and only then
# NetBird), the health check failing while the exit cannot be healthy, and a
# stop that exits 0 inside the 15 second budget and leaves the routing rules in
# place. The routing contract's traffic properties are drilled in Go
# (internal/drill, internal/exit); this checks the image and the container.
#
# The exit runs in a network namespace that a busybox container owns and keeps
# alive, as a recreated exit does behind gluetun. That container has no
# network, so nothing here reaches a provider, a NetBird server or the
# Internet. A second busybox container joins the namespace to look at the
# rules and links the exit leaves. The sysctls compose.yaml sets on the exit
# are set on the namespace's owner, because a container that joins a namespace
# cannot set them.
#
# NetBird gets no setup key and no management server, so it cannot enroll. What
# is checked of it: the exit says plainly that it would enroll a new peer, it
# starts NetBird only after the rules are installed, the tunnel is up and the
# exit is ready, the daemon runs, and the interface blacklist reaches its
# profile. NetBird's own firewall table and the overlay interface exist only
# after an enrollment, so `nft list tables` from the diagnostic container is
# not part of this script (the stripped image's nftables path is covered by
# internal/nft's drill and docs/verification.md). For the same reason the
# health check stays failing: it passes only when NetBird runs.
#
# Needs Docker on Linux with kernel WireGuard. No accounts, real endpoints or
# keys: keys are generated per run and discarded.
#   sh tools/check-exit-image.sh <image>
set -eu
image=${1:?usage: sh tools/check-exit-image.sh <image>}
busybox=docker.io/library/busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e
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
note() { echo "NOTE $1"; }

new_volume() {
    volumes="$volumes $run-$1"
    docker volume create "$run-$1" >/dev/null
}

# --- Throwaway tunnel configs, made with the image's own prepare-config.
# A Mullvad-shaped download (dual stack, documentation addresses, random keys:
# any 32 random bytes are a valid WireGuard key) and a PIA config with a key
# the tool generates itself.
key() { head -c 32 /dev/urandom | base64; }
umask 077
printf '%s\n' '[Interface]' "PrivateKey = $(key)" 'Address = 203.0.113.2/32, 2001:db8:3::2/128' \
    'DNS = 192.0.2.53' '' '[Peer]' "PublicKey = $(key)" 'AllowedIPs = 0.0.0.0/0, ::/0' \
    'Endpoint = 192.0.2.10:51820' > "$work/download.conf"
umask 022
new_volume mullvad
docker run --rm --network none -v "$run-mullvad:/out" -v "$work/download.conf:/in.conf:ro" \
    "$image" prepare-config /in.conf /out/mullvad.conf >/dev/null || fail 'prepare-config refused the throwaway Mullvad download'
new_volume pia
docker run --rm --network none -v "$run-pia:/out" "$image" prepare-config --pia /out/pia.conf >/dev/null ||
    fail 'prepare-config --pia could not create a config'
# The same Mullvad config owned by a host user (uid 1000), mode 0600: container
# root reads it only with DAC_OVERRIDE.
new_volume user
docker run --rm --network none -v "$run-mullvad:/a:ro" -v "$run-user:/b" "$busybox" \
    sh -c 'cat /a/mullvad.conf > /b/mullvad.conf && chown 1000:1000 /b/mullvad.conf && chmod 600 /b/mullvad.conf' ||
    fail 'could not copy the throwaway config'
pass 'throwaway tunnel configs made with prepare-config (Mullvad download, PIA key)'

new_volume state
new_volume nbdata
new_volume nbdata-pia
new_volume stale
# A stored NetBird profile that does not exclude the tunnel interface.
docker run --rm --network none -v "$run-stale:/n" "$busybox" \
    sh -c 'printf "{\"WgIface\":\"wt0\",\"IFaceBlackList\":[\"docker0\"]}" > /n/default.json' ||
    fail 'could not write the throwaway NetBird profile'

# The exit's environment, as compose.yaml sets it for a native Mullvad exit,
# one option per line. Later -e options override earlier ones.
env_args() {
    printf '%s\n' -e TUNNEL_BACKEND=native -e EXIT_KIND=overlay -e PROVIDER=mullvad -e EXIT_IF=mullvad \
        -e EXIT_TABLE=51821 -e OVERLAY_IF=wt0 -e OVERLAY_CIDR=192.0.2.0/24 -e OVERLAY6_CIDR=2001:db8:1::/64 \
        -e STATE_DIR=/state -e NB_INTERFACE_NAME=wt0 -e NB_DISABLE_USERSPACE_ROUTING=true \
        -e NB_MANAGEMENT_URL=https://netbird.example.test:33073 -e NB_EXTRA_IFACE_BLACKLIST=mullvad
}

# --- Refusals: one line, exit 1, before anything changes. The container is
# one-shot with no network; $1 is the whole line expected, the rest are extra
# docker options.
refuse_case() {
    want=$1
    shift
    rc=0
    # shellcheck disable=SC2046 # env_args prints one option per line
    docker run --rm --network none --cap-drop ALL --cap-add NET_ADMIN --cap-add DAC_OVERRIDE --read-only \
        $(env_args) -v "$run-mullvad:/config/wg_confs:ro" -v "$run-state:/state" "$@" \
        "$image" exit > "$work/refusal" 2>&1 || rc=$?
    [ "$rc" = 1 ] || { cat "$work/refusal" >&2; fail "exit status $rc, want 1, for: $want"; }
    printf '%s\n' "$want" > "$work/refusal.want"
    cmp -s "$work/refusal" "$work/refusal.want" || {
        echo "want: $want" >&2
        echo 'got:' >&2
        cat "$work/refusal" >&2
        fail 'the refusal is not the expected line'
    }
}
refuse_case 'molebridge-exit: TUNNEL_BACKEND must be native or gluetun' -e TUNNEL_BACKEND=docker
refuse_case 'molebridge-exit: EXIT_KIND must be overlay or sidecar' -e EXIT_KIND=edge
refuse_case 'molebridge-exit: PROVIDER must be mullvad, pia or nordvpn' -e PROVIDER=acme
refuse_case 'molebridge-exit: OVERLAY_CIDR must be an IPv4 CIDR' -e OVERLAY_CIDR=
refuse_case 'molebridge-exit: OVERLAY_CIDR must use the network address' -e OVERLAY_CIDR=192.0.2.1/24
refuse_case 'molebridge-exit: overlay and exit interfaces must differ' -e EXIT_IF=wt0
refuse_case 'molebridge-exit: ROUTING_RECONCILE_INTERVAL must be 2..60 seconds' -e ROUTING_RECONCILE_INTERVAL=1
refuse_case 'molebridge-exit: GUARD_GRACE must be 5..30 seconds' -e GUARD_GRACE=4
refuse_case 'molebridge-exit: the tunnel config /config/wg_confs/other.conf is missing; regenerate it with prepare-config (docs/setup.md)' -e EXIT_IF=other
refuse_case 'molebridge-exit: NB_INTERFACE_NAME (nb0) must equal OVERLAY_IF (wt0), the interface the routing contract guards' -e NB_INTERFACE_NAME=nb0
refuse_case 'NetBird gate: refusing to start NetBird: NB_DISABLE_USERSPACE_ROUTING must be "true" (compose.yaml sets it) (see docs/troubleshooting.md)' -e NB_DISABLE_USERSPACE_ROUTING=false
refuse_case 'NetBird gate: refusing to start NetBird: NB_ENABLE_ROSENPASS is set; Rosenpass cannot work on this exit (see docs/troubleshooting.md)' -e NB_ENABLE_ROSENPASS=true
refuse_case "NetBird gate: refusing to start NetBird: NB_FOREGROUND_MODE is set; Molebridge supports only NetBird's daemon mode (see docs/troubleshooting.md)" -e NB_FOREGROUND_MODE=true
refuse_case "NetBird gate: refusing to start NetBird: the stored NetBird profile /var/lib/netbird/default.json does not exclude the tunnel interface mullvad from NetBird's connection candidates; stop the exit and run fix-blacklist (docs/operations.md#netbird-interface-blacklist) (see docs/troubleshooting.md)" \
    -v "$run-stale:/var/lib/netbird"
pass 'invalid settings: each refused with its exact message and exit 1 (backend, kind, provider, overlay range, interface names, intervals, NetBird settings, a stored profile)'

# Refusals that need a different container shape than refuse_case gives.
refuse_shape() {
    # $1 the whole line expected, $2 what the case is, the rest docker options
    # (without the image); the environment is the Mullvad exit's.
    want=$1
    what=$2
    shift 2
    rc=0
    # shellcheck disable=SC2046
    docker run --rm --network none --cap-drop ALL --cap-add NET_ADMIN --read-only $(env_args) "$@" \
        "$image" exit > "$work/refusal" 2>&1 || rc=$?
    [ "$rc" = 1 ] || { cat "$work/refusal" >&2; fail "$what: exit status $rc, want 1"; }
    printf '%s\n' "$want" > "$work/refusal.want"
    cmp -s "$work/refusal" "$work/refusal.want" || { cat "$work/refusal" >&2; fail "$what: not refused with its exact message"; }
}
# A state directory that does not exist and cannot be created (read-only root).
refuse_shape "molebridge-exit: the state directory /state/applier is missing and can't be created (on Docker the container needs DAC_OVERRIDE; see docs/setup.md)" \
    'a missing state directory' --cap-add DAC_OVERRIDE -v "$run-mullvad:/config/wg_confs:ro"
pass 'a missing state directory: refused with its exact message'
# A host user's mode-0600 config: container root reads it only with
# DAC_OVERRIDE, which compose.yaml grants.
refuse_shape "molebridge-exit: the tunnel config /config/wg_confs/mullvad.conf can't be read (on Docker the exit container needs DAC_OVERRIDE to read a mode-0600 tunnel config, and the Compose files grant it; see docs/setup.md)" \
    "a host user's config without DAC_OVERRIDE" -v "$run-user:/config/wg_confs:ro" -v "$run-state:/state"
pass "a host user's mode-0600 config: refused without DAC_OVERRIDE (the message names DAC_OVERRIDE)"

# --- The namespace's owner, and the exit joined to it.
# $1 name. A namespace keeps the rules of the exit that left them, so each
# provider's exit gets a namespace of its own.
new_owner() {
    owner=$run-$1
    names="$names $owner"
    docker run -d --name "$owner" --network none --cap-drop ALL \
        --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.forwarding=1 \
        --sysctl net.ipv4.icmp_errors_use_inbound_ifaddr=1 --sysctl net.ipv6.conf.all.disable_ipv6=0 \
        --sysctl net.ipv6.conf.default.disable_ipv6=0 "$busybox" sleep 3600 >/dev/null ||
        fail 'could not start the namespace owner'
}
new_owner owner

nbvolume=$run-nbdata
# $1 name, $2 config volume, the rest extra docker options.
start_exit() {
    name=$run-$1
    confvolume=$2
    shift 2
    names="$names $name"
    # shellcheck disable=SC2046
    docker run -d --name "$name" --network "container:$owner" --cap-drop ALL \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add DAC_OVERRIDE \
        --security-opt no-new-privileges:true --read-only \
        --tmpfs /run:size=4m,mode=0755,noexec,nosuid,nodev \
        --tmpfs /var/log/netbird:size=16m,mode=0755,noexec,nosuid,nodev \
        --stop-timeout 15 $(env_args) \
        -v "$confvolume:/config/wg_confs:ro" -v "$run-state:/state" -v "$nbvolume:/var/lib/netbird" \
        "$@" "$image" exit >/dev/null
}
# Seconds since the epoch; the timings here are coarse.
now() { date +%s; }
wait_log() {
    # $1 container, $2 text, $3 seconds
    waited=0
    while [ "$waited" -lt "$3" ]; do
        if docker logs "$1" 2>&1 | grep -qF -- "$2"; then return 0; fi
        [ "$(docker inspect -f '{{.State.Running}}' "$1")" = true ] || return 1
        sleep 1
        waited=$((waited + 1))
    done
    return 1
}
line_of() { docker logs "$1" 2>&1 | grep -nF -- "$2" | head -n 1 | cut -d: -f1; }
# What the joined diagnostic container sees of the namespace.
diag() {
    docker run --rm --network "container:$owner" --cap-drop ALL --cap-add NET_ADMIN "$busybox" sh -c "$1"
}
rules_in_place() {
    # $1 container whose logs to print on failure, $2 where we are
    diag 'ip rule; echo ---; ip -6 rule' > "$work/rules" || fail 'could not list the rules' "$1"
    sed '/^---$/q' "$work/rules" > "$work/rules4"
    sed '1,/^---$/d' "$work/rules" > "$work/rules6"
    for family in 4 6; do
        for priority in 1 90 94 95 96 97 98; do
            grep -q "^$priority:" "$work/rules$family" || fail "IPv$family rule $priority is not in place$2" "$1"
        done
    done
    grep -q '^95:.*iif wt0 lookup 51821' "$work/rules4" || fail "rule 95 does not send the overlay into the exit table$2" "$1"
    grep -q '^97:.*iif wt0.*unreachable' "$work/rules4" || fail "rule 97 is not the overlay fallback$2" "$1"
}

# --- Start: contract first, tunnel, readiness, then NetBird.
start_exit main "$run-mullvad"
# The health check cannot pass before the exit has run a healthy tick.
rc=0
docker exec "$name" /usr/local/bin/molebridge health > "$work/health" 2>&1 || rc=$?
[ "$rc" = 1 ] || fail "health exited $rc right after the start, want 1" "$name"
grep -q '^unhealthy: ' "$work/health" || fail 'health did not say why it failed' "$name"
pass 'molebridge health fails before the exit is ready'
wait_log "$name" 'molebridge-exit: ready' 40 || fail 'the exit did not become ready' "$name"
wait_log "$name" 'molebridge-exit: starting NetBird' 10 || fail 'the exit did not start NetBird' "$name"
notice='molebridge-exit: no NetBird identity found in the state directory or the legacy profile paths; NetBird will enroll a new peer'
installed=$(line_of "$name" 'molebridge-exit: rules installed')
tunnel=$(line_of "$name" 'molebridge-exit: tunnel up')
ready=$(line_of "$name" 'molebridge-exit: ready')
starting=$(line_of "$name" 'molebridge-exit: starting NetBird')
told=$(line_of "$name" "$notice")
[ -n "$installed" ] && [ -n "$tunnel" ] && [ -n "$ready" ] && [ -n "$starting" ] || fail 'the start log lacks a step' "$name"
{ [ "$installed" -lt "$tunnel" ] && [ "$tunnel" -lt "$ready" ] && [ "$ready" -lt "$starting" ]; } ||
    fail 'the start order is not rules, tunnel, ready, NetBird' "$name"
pass 'start order: rules installed, tunnel up, ready, and only then NetBird'
[ -n "$told" ] && [ "$told" -lt "$starting" ] || fail 'the exit did not say plainly, before starting NetBird, that it would enroll a new peer' "$name"
pass 'with no NetBird identity the exit says it will enroll a new peer, before NetBird starts'
wait_log "$name" 'started daemon server' 30 || fail 'the NetBird daemon did not start' "$name"
pass 'NetBird daemon started (no setup key: it cannot enroll)'
# NB_EXTRA_IFACE_BLACKLIST reaches the stored profile on the first `netbird up`;
# a recreated exit would refuse to start without it.
waited=0
until docker exec "$name" grep -q mullvad /var/lib/netbird/default.json 2>/dev/null; do
    waited=$((waited + 1))
    [ "$waited" -le 30 ] || fail "the tunnel interface did not reach NetBird's interface blacklist" "$name"
    sleep 1
done
pass "NB_EXTRA_IFACE_BLACKLIST reached NetBird's stored profile"
rules_in_place "$name" ' while running'
diag 'ip link show mullvad' >/dev/null || fail 'the tunnel interface is missing' "$name"
pass 'running: the tunnel interface and the contract rules 1/90/94/95/96/97/98 in both families'
if diag 'ip link show wt0' >/dev/null 2>&1; then
    note 'NetBird created wt0 without enrolling; its firewall table is not checked here'
else
    note "no overlay interface or NetBird firewall table: NetBird cannot enroll without a setup key (see this script's header)"
fi
rc=0
docker exec "$name" /usr/local/bin/molebridge health > "$work/health" 2>&1 || rc=$?
[ "$rc" = 1 ] || fail "health exited $rc while NetBird cannot enroll, want 1" "$name"
pass 'molebridge health keeps failing while NetBird is not running'

# --- Stop: exit 0 inside the 15 second budget, the rules stay.
started=$(now)
docker stop -t 15 "$name" >/dev/null
took=$(($(now) - started))
code=$(docker inspect -f '{{.State.ExitCode}}' "$name")
[ "$code" = 0 ] || fail "exit code $code after a stop (137 would mean the engine had to kill it)" "$name"
[ "$took" -le 15 ] || fail "stop took ${took}s, over the 15 s budget" "$name"
docker logs "$name" 2>&1 | grep -qF 'stopped (requested, exit 0); the routing guards stay in place' || fail 'no stop message' "$name"
if docker logs "$name" 2>&1 | grep -qF 'cleanup incomplete'; then fail 'the stop left something behind' "$name"; fi
pass "docker stop: exit 0 in ${took}s (budget 15 s)"
rules_in_place "$name" ' after the stop'
if diag 'ip link show mullvad' >/dev/null 2>&1; then fail 'the tunnel interface survived the stop' "$name"; fi
pass 'after the stop the contract rules are still in place in both families and the tunnel interface is gone'

# --- A recreated exit finds the guards in place and repairs onto them.
docker rm -f "$name" >/dev/null
start_exit again "$run-mullvad"
wait_log "$name" 'molebridge-exit: ready' 40 || fail 'a recreated exit did not become ready in the kept namespace' "$name"
started=$(now)
docker stop -t 15 "$name" >/dev/null
took=$(($(now) - started))
[ "$(docker inspect -f '{{.State.ExitCode}}' "$name")" = 0 ] || fail 'a recreated exit did not stop with exit 0' "$name"
pass "a recreated exit in the kept namespace becomes ready and stops with exit 0 in ${took}s"
docker rm -f "$name" >/dev/null

# --- PIA: a config with no address; rules 94 and 98 are left to the pipeline.
nbvolume=$run-nbdata-pia
new_owner owner-pia
start_exit pia "$run-pia" -e PROVIDER=pia -e EXIT_IF=pia -e NB_EXTRA_IFACE_BLACKLIST=pia
wait_log "$name" 'molebridge-exit: ready' 40 || fail 'PIA: the exit did not become ready' "$name"
diag 'ip link show pia' >/dev/null || fail 'PIA: the tunnel interface is missing' "$name"
diag 'ip rule; echo ---; ip -6 rule' > "$work/rules" || fail 'could not list the rules' "$name"
if grep -Eq '^9[48]:' "$work/rules"; then fail 'PIA: the exit installed rule 94 or 98 for a config with no address' "$name"; fi
grep -q '^95:' "$work/rules" || fail 'PIA: rule 95 is missing' "$name"
pass 'PIA: ready without an address; rules 94 and 98 left to the pipeline'
docker stop -t 15 "$name" >/dev/null
[ "$(docker inspect -f '{{.State.ExitCode}}' "$name")" = 0 ] || fail 'PIA: the stop did not exit 0' "$name"
pass 'PIA: stop exits 0'

echo 'All exit image checks passed.'
