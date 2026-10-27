#!/usr/bin/env sh
# Static checks of the single Molebridge image (Dockerfile): what it holds, what
# it must not hold, ownership and modes, license notices, the pinned NetBird
# client, the binary's version, the OCI labels, and the unpacked size limit
# (80 MB, D10). Nothing is started that needs privileges or a network. Runs for
# the image's own architecture or, with QEMU, a foreign one. With VERSION set,
# the version role must print exactly `molebridge $VERSION`.
#   [VERSION=v0.10.0-rc.1] sh tools/check-image.sh <image> [linux/amd64|linux/arm64]
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

# The labels the Dockerfile sets. The release workflow adds the version and
# revision labels at publish time; a local build has none.
for label in org.opencontainers.image.title org.opencontainers.image.description \
    org.opencontainers.image.source org.opencontainers.image.licenses; do
    value=$(docker image inspect "$image" --format "{{index .Config.Labels \"$label\"}}")
    [ -n "$value" ] && [ "$value" != '<no value>' ] || fail "label $label is missing"
done
source=$(docker image inspect "$image" --format '{{index .Config.Labels "org.opencontainers.image.source"}}')
[ "$source" = 'https://github.com/irashack/molebridge' ] || fail "org.opencontainers.image.source is '$source'"
pass "OCI labels: title, description, source, licenses"

rc=0
run "$@" "$image" >/dev/null 2>"${TMPDIR:-/tmp}/check-image.$$" || rc=$?
usage=$(cat "${TMPDIR:-/tmp}/check-image.$$"); rm -f "${TMPDIR:-/tmp}/check-image.$$"
[ "$rc" -eq 2 ] || fail "running with no role exited $rc, want 2"
echo "$usage" | grep -q 'usage: molebridge <role>' || fail "no usage text without a role"
pass "no role: usage, exit 2"

reported=$(run "$@" "$image" version) || fail "the version role failed"
if [ -n "${VERSION:-}" ]; then
    [ "$reported" = "molebridge $VERSION" ] || fail "the version role says '$reported', want 'molebridge $VERSION'"
else
    printf '%s\n' "$reported" | grep -Eqx 'molebridge [0-9A-Za-z.+-]+' || fail "the version role says '$reported'"
fi
pass "version role: $reported"

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

# The panel's Compose health check runs `wget`: busybox's applet.
wget=$(run "$@" --entrypoint sh "$image" -c 'readlink -f "$(command -v wget)"') || fail "wget is not in the image"
[ "$wget" = /bin/busybox ] || fail "wget is $wget, not busybox's"
pass "busybox wget (the panel's health check)"

# Nothing setuid or setgid anywhere on the image's file system.
special=$(run "$@" --entrypoint sh "$image" -c 'find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -print')
[ -z "$special" ] || fail "setuid or setgid files: $special"
pass "no setuid or setgid files"

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
