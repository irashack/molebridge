#!/usr/bin/env sh
# Static checks of the single Molebridge image (Dockerfile): what it holds, what
# it must not hold, ownership and modes, license notices, the pinned NetBird
# client, and the unpacked size limit (80 MB, D10). Nothing is started that
# needs privileges or a network. Runs for the image's own architecture or, with
# QEMU, a foreign one.
#   sh tools/check-image.sh <image> [linux/amd64|linux/arm64]
set -eu
image=${1:?usage: sh tools/check-image.sh <image> [platform]}
platform=${2:-}
netbird_version=${NETBIRD_VERSION:-0.80.0}
# 80 MB unpacked, as `du -sk` counts it (1 MB = 1000 * 1000 bytes).
limit_kib=78125
fail() { echo "FAIL $1" >&2; exit 1; }
pass() { echo "PASS $1"; }
if [ -n "$platform" ]; then set -- --platform "$platform"; else set --; fi
run() { docker run --rm --network none "$@"; }

entry=$(docker image inspect "$image" --format '{{json .Config.Entrypoint}}')
[ "$entry" = '["/usr/local/bin/molebridge"]' ] || fail "entrypoint is $entry"
cmd=$(docker image inspect "$image" --format '{{json .Config.Cmd}}')
[ "$cmd" = 'null' ] || [ "$cmd" = '[]' ] || fail "image sets a default command: $cmd"
pass "entrypoint is the molebridge binary, no default command"

rc=0
run "$@" "$image" >/dev/null 2>"${TMPDIR:-/tmp}/check-image.$$" || rc=$?
usage=$(cat "${TMPDIR:-/tmp}/check-image.$$"); rm -f "${TMPDIR:-/tmp}/check-image.$$"
[ "$rc" -eq 2 ] || fail "running with no role exited $rc, want 2"
echo "$usage" | grep -q 'usage: molebridge <role>' || fail "no usage text without a role"
pass "no role: usage, exit 2"

run "$@" --entrypoint /usr/local/bin/netbird "$image" version | grep -qx "$netbird_version" ||
    fail "netbird is not version $netbird_version"
pass "NetBird client $netbird_version"

# Nothing the old images carried: Python, bash, wireguard-tools, a second
# init. busybox stays for `docker exec` diagnostics.
for tool in python3 python bash wg wg-quick tini; do
    if run "$@" --entrypoint sh "$image" -c "command -v $tool" >/dev/null 2>&1; then
        fail "$tool is in the image"
    fi
done
pass "no python, bash, wireguard-tools or tini"

for f in /usr/share/licenses/molebridge/LICENSE /usr/share/licenses/molebridge/THIRD_PARTY.md \
    /usr/share/licenses/molebridge/PIA-CA-LICENSE.txt /usr/share/licenses/molebridge/JetBrainsMono-OFL.txt \
    /usr/share/licenses/netbird/LICENSE /usr/share/licenses/netbird/LICENSES/BSD-3-Clause.txt; do
    run "$@" --entrypoint sh "$image" -c "test -s $f" || fail "license file missing or empty: $f"
done
pass "license notices present"

# Root-owned, not writable by others: binaries and notices.
bad=$(run "$@" --entrypoint sh "$image" -c \
    'find /usr/local/bin /usr/share/licenses \( -perm -002 -o -perm -020 -o ! -user 0 -o ! -group 0 \) -print')
[ -z "$bad" ] || fail "writable or non-root-owned: $bad"
mode=$(run "$@" --entrypoint sh "$image" -c "stat -c '%a' /usr/local/bin/molebridge /usr/local/bin/netbird" | tr '\n' ' ')
[ "$mode" = "755 755 " ] || fail "binary modes are '$mode'"
pass "ownership and modes"

size=$(run "$@" --entrypoint sh "$image" -c 'du -sxk / 2>/dev/null | cut -f1')
[ "$size" -le "$limit_kib" ] || fail "unpacked size is $size KiB, over the limit of $limit_kib KiB"
echo "PASS unpacked size $size KiB (limit $limit_kib KiB)"
