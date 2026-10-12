#!/usr/bin/env sh
# Tests routing/gluetun-preflight, the entrypoint wrapper that runs inside
# gluetun's container: the kind of exit (MOLEBRIDGE_KIND), the post-rules rule
# that follows from it, the control-server role file, and that a refusal prints
# nothing from the file. Ports the role-file cases of tools/check-routing.sh.
#
# POSIX sh, no root and no network. gluetun's image is Alpine, so run it under
# busybox as well as the host's shell:
#   sh tools/test-gluetun-preflight.sh
#   docker run --rm -v "$PWD:/repo:ro" -w /repo \
#     docker.io/library/busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e \
#     sh tools/test-gluetun-preflight.sh
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
preflight=$here/../routing/gluetun-preflight
[ -f "$preflight" ] || { echo "FAIL no $preflight" >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
fail() { echo "FAIL $1" >&2; exit 1; }
pass() { echo "PASS $1"; }

key=Zx9-_kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk
routes='routes = ["PUT /v1/vpn/settings", "GET /v1/vpn/status", "GET /v1/publicip/ip", "GET /v1/updater/status", "PUT /v1/updater/status"]'
good=$work/auth-good.toml
printf '%s\n' '[[roles]]' 'name = "molebridge"' 'auth = "apikey"' "apikey = \"$key\"" "$routes" > "$good"
rules=$work/post-rules.txt
printf '%s\n' 'iptables -A OUTPUT -o eth0 -j ACCEPT' > "$rules"
absent=$work/absent-rules.txt

# Runs the wrapper in a clean environment with the given settings, handing
# over to `touch started`. Sets $status, leaves the output in $work/out, and
# checks that the output never carries the API key.
run() {
    rm -f "$work/started"
    status=0
    env -i PATH="$PATH" "$@" sh "$preflight" touch "$work/started" > "$work/out" 2>&1 || status=$?
    if grep -q "$key" "$work/out"; then fail "$name: the output carries the API key"; fi
}
# starts <name> <setting>...: gluetun's entrypoint is reached, with its arguments.
starts() {
    name=$1; shift
    run "$@"
    [ "$status" = 0 ] && [ -f "$work/started" ] || { cat "$work/out" >&2; fail "$name: refused"; }
    pass "$name"
}
# refuses <name> <text> <setting>...: exit 1 with <text> in the message, and gluetun never started.
refuses() {
    name=$1; text=$2; shift 2
    run "$@"
    [ "$status" = 1 ] || fail "$name: exit status $status, not 1"
    [ ! -f "$work/started" ] || fail "$name: gluetun was started"
    grep -qF "$text" "$work/out" || { cat "$work/out" >&2; fail "$name: no message containing: $text"; }
    grep -q '^molebridge: not starting gluetun: ' "$work/out" || fail "$name: not the fixed prefix"
    pass "$name"
}
auth() { echo "HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH=$1"; }

# The mode is explicit and never guessed.
for kind in '' overlay_ Overlay SIDECAR 'overlay ' 'overlay,sidecar' both; do
    refuses "kind '$kind' is refused" 'MOLEBRIDGE_KIND must be overlay or sidecar' \
        "MOLEBRIDGE_KIND=$kind" "$(auth "$good")" "MOLEBRIDGE_POST_RULES_FILE=$rules"
done
refuses 'no kind is refused' 'MOLEBRIDGE_KIND must be overlay or sidecar' \
    "$(auth "$good")" "MOLEBRIDGE_POST_RULES_FILE=$rules"

# Overlay: the post-rules file is required.
starts 'overlay starts with its post-rules' MOLEBRIDGE_KIND=overlay "$(auth "$good")" "MOLEBRIDGE_POST_RULES_FILE=$rules"
refuses 'overlay without post-rules' 'gluetun-post-rules writes it' \
    MOLEBRIDGE_KIND=overlay "$(auth "$good")" "MOLEBRIDGE_POST_RULES_FILE=$absent"
: > "$work/empty-rules.txt"
refuses 'overlay with empty post-rules' 'missing, empty or not a regular file' \
    MOLEBRIDGE_KIND=overlay "$(auth "$good")" "MOLEBRIDGE_POST_RULES_FILE=$work/empty-rules.txt"
mkdir "$work/rules-dir"
refuses 'overlay with a directory for post-rules' 'missing, empty or not a regular file' \
    MOLEBRIDGE_KIND=overlay "$(auth "$good")" "MOLEBRIDGE_POST_RULES_FILE=$work/rules-dir"
ln -s "$rules" "$work/rules-link"
refuses 'overlay with a symlink for post-rules' 'missing, empty or not a regular file' \
    MOLEBRIDGE_KIND=overlay "$(auth "$good")" "MOLEBRIDGE_POST_RULES_FILE=$work/rules-link"

# Sidecar: the post-rules file must not be there, in any form.
starts 'sidecar starts without post-rules' MOLEBRIDGE_KIND=sidecar "$(auth "$good")" "MOLEBRIDGE_POST_RULES_FILE=$absent"
refuses 'sidecar with post-rules' "a sidecar must not mount the overlay's post-rules" \
    MOLEBRIDGE_KIND=sidecar "$(auth "$good")" "MOLEBRIDGE_POST_RULES_FILE=$rules"
refuses 'sidecar with empty post-rules' "a sidecar must not mount the overlay's post-rules" \
    MOLEBRIDGE_KIND=sidecar "$(auth "$good")" "MOLEBRIDGE_POST_RULES_FILE=$work/empty-rules.txt"
refuses 'sidecar with a directory for post-rules' "a sidecar must not mount the overlay's post-rules" \
    MOLEBRIDGE_KIND=sidecar "$(auth "$good")" "MOLEBRIDGE_POST_RULES_FILE=$work/rules-dir"
refuses 'sidecar with a symlink for post-rules' "a sidecar must not mount the overlay's post-rules" \
    MOLEBRIDGE_KIND=sidecar "$(auth "$good")" "MOLEBRIDGE_POST_RULES_FILE=$work/rules-link"
ln -s "$absent" "$work/rules-dangling"
refuses 'sidecar with a dangling symlink for post-rules' "a sidecar must not mount the overlay's post-rules" \
    MOLEBRIDGE_KIND=sidecar "$(auth "$good")" "MOLEBRIDGE_POST_RULES_FILE=$work/rules-dangling"

# With the default path (gluetun's /iptables/post-rules.txt) and no override,
# a host without that file behaves as a sidecar's gluetun does.
if [ ! -e /iptables/post-rules.txt ]; then
    starts 'default post-rules path, sidecar' MOLEBRIDGE_KIND=sidecar "$(auth "$good")"
    refuses 'default post-rules path, overlay' '/iptables/post-rules.txt' MOLEBRIDGE_KIND=overlay "$(auth "$good")"
fi

# The role file, in both kinds. A role file problem is refused before the
# post-rules rule is looked at, with the repair tool named and no file content.
for kind in overlay sidecar; do
    if [ "$kind" = overlay ]; then pr=$rules; else pr=$absent; fi
    base="MOLEBRIDGE_KIND=$kind MOLEBRIDGE_POST_RULES_FILE=$pr"
    # shellcheck disable=SC2086
    set -- $base
    starts "$kind: the generated role file, with gluetun's own empty default role" "$@" "$(auth "$good")" 'HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE={}'
    starts "$kind: an empty default role" "$@" "$(auth "$good")" 'HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE= {} '
    refuses "$kind: a public default role" 'sets a default role' "$@" "$(auth "$good")" 'HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE={"auth":"none"}'
    refuses "$kind: a missing role file" 'is missing or not a regular file' "$@" "$(auth "$work/missing.toml")"
    refuses "$kind: the repair tool is named" 'gluetun-auth --rotate writes a valid one' "$@" "$(auth "$work/missing.toml")"
    sed 's/^apikey = /api_key = /' "$good" > "$work/auth-misspelled.toml"
    refuses "$kind: a misspelled key field" 'is not the one Molebridge generates' "$@" "$(auth "$work/auth-misspelled.toml")"
    sed 's/^auth = "apikey"/auth = "none"/' "$good" > "$work/auth-none.toml"
    refuses "$kind: auth none" 'is not the one Molebridge generates' "$@" "$(auth "$work/auth-none.toml")"
    { cat "$good"; printf '%s\n' '[[roles]]' 'name = "extra"' 'auth = "none"'; } > "$work/auth-two.toml"
    refuses "$kind: a second role" 'is not the one Molebridge generates' "$@" "$(auth "$work/auth-two.toml")"
    sed 's/, "PUT \/v1\/updater\/status"//' "$good" > "$work/auth-routes.toml"
    refuses "$kind: a route left out" 'is not the one Molebridge generates' "$@" "$(auth "$work/auth-routes.toml")"
    sed "s/^apikey = .*/apikey = \"short\"/" "$good" > "$work/auth-short.toml"
    refuses "$kind: a short key" 'is not the one Molebridge generates' "$@" "$(auth "$work/auth-short.toml")"
    { cat "$good"; printf '# %0700d\n' 0 | tr 0 x; } > "$work/auth-comment.toml"
    refuses "$kind: trailing content" 'is not the one Molebridge generates' "$@" "$(auth "$work/auth-comment.toml")"
    { cat "$good"; head -c 5000 /dev/zero | tr '\0' x; printf '\n'; } > "$work/auth-big.toml"
    refuses "$kind: a file over 4096 bytes" 'is too large' "$@" "$(auth "$work/auth-big.toml")"
    sed 's/$/\r/' "$good" > "$work/auth-crlf.toml"
    refuses "$kind: carriage returns" 'has NUL or carriage-return bytes' "$@" "$(auth "$work/auth-crlf.toml")"
    { cat "$good"; printf 'x\000y\n'; } > "$work/auth-nul.toml"
    refuses "$kind: a NUL byte" 'has NUL or carriage-return bytes' "$@" "$(auth "$work/auth-nul.toml")"
    ln -s "$good" "$work/auth-link.toml"
    refuses "$kind: a symlinked role file" 'is missing or not a regular file' "$@" "$(auth "$work/auth-link.toml")"
    mkdir -p "$work/auth-dir.toml"
    refuses "$kind: a directory for the role file" 'is missing or not a regular file' "$@" "$(auth "$work/auth-dir.toml")"
    rm -rf "$work/auth-dir.toml" "$work/auth-link.toml"
done

# The diagnostics name the container tools and none of the old Python helper.
for text in 'tools/molebridge.py' 'python3'; do
    if grep -qF "$text" "$preflight"; then fail "the preflight still mentions $text"; fi
done
grep -qF 'ghcr.io/irashack/molebridge:<tag> gluetun-post-rules' "$preflight" || fail "no gluetun-post-rules diagnostic"
grep -qF 'ghcr.io/irashack/molebridge:<tag> gluetun-auth' "$preflight" || fail "no gluetun-auth diagnostic"
pass "diagnostics name the container tools"

# gluetun's arguments reach its entrypoint unchanged.
printf '#!/bin/sh\nprintf "%%s|" "$@" > "%s/args"\n' "$work" > "$work/entry"
chmod 0755 "$work/entry"
env -i PATH="$PATH" MOLEBRIDGE_KIND=sidecar MOLEBRIDGE_POST_RULES_FILE="$absent" "HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH=$good" \
    sh "$preflight" "$work/entry" 'a b' '' --flag > /dev/null 2>&1 || fail "entrypoint not reached"
[ "$(cat "$work/args")" = 'a b||--flag|' ] || fail "arguments changed: $(cat "$work/args")"
pass "arguments pass through"
echo "all gluetun-preflight tests passed"
