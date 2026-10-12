#!/usr/bin/env sh
# Installs from an extracted bundle with no repository checkout: unpacks
# molebridge-<tag>.tar.gz into a fresh directory, and from there checks that
# the three Compose forms (native, gluetun, sidecar) validate with their
# example environment files, that every Molebridge image they reference is the
# exact pinned tag@digest reference the bundle was built with, that the
# relative file the gluetun forms bind-mount (routing/gluetun-preflight) is in
# the bundle and executable by sh, and that this preflight refuses a missing
# control-server role file and accepts the one the tools write. Needs Docker
# Compose and jq; starts no container.
#   sh tools/check-bundle.sh <bundle.tar.gz> <tag@sha256:digest reference>
set -eu
bundle=${1:?usage: sh tools/check-bundle.sh <bundle.tar.gz> <image-reference>}
ref=${2:?usage: sh tools/check-bundle.sh <bundle.tar.gz> <image-reference>}
case "$bundle" in /*) ;; *) bundle=$(pwd)/$bundle ;; esac
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
fail() { echo "FAIL $1" >&2; exit 1; }
pass() { echo "PASS $1"; }

# The directory is outside any checkout, so nothing else can satisfy a path.
cd "$work"
tar -xzf "$bundle"
top=$(ls)
[ "$(echo "$top" | wc -l | tr -d ' ')" = 1 ] || fail "bundle has more than one top-level entry"
cd "$work/$top"
for f in compose.yaml compose.gluetun.yaml compose.sidecar.yaml .env.example .env.sidecar.example routing/gluetun-preflight LICENSE THIRD_PARTY.md; do
    [ -f "$f" ] || fail "bundle lacks $f"
done
[ ! -d .git ] || fail "bundle carries a .git directory"
pass "bundle layout"

cp .env.example .env
docker compose config --quiet || fail "compose.yaml does not validate"
docker compose -f compose.gluetun.yaml config --quiet || fail "compose.gluetun.yaml does not validate"
docker compose --env-file .env.sidecar.example -f compose.sidecar.yaml config --quiet || fail "compose.sidecar.yaml does not validate"
pass "all three Compose forms validate"

for form in "compose.yaml:.env" "compose.gluetun.yaml:.env" "compose.sidecar.yaml:.env.sidecar.example"; do
    file=${form%%:*}
    envfile=${form#*:}
    images=$(docker compose --env-file "$envfile" -f "$file" config --format json | jq -r '.services[].image // empty')
    mine=$(echo "$images" | grep '^ghcr\.io/irashack/molebridge' || true)
    [ -n "$mine" ] || fail "$file references no Molebridge image"
    echo "$mine" | grep -vxF "$ref" && fail "$file references a Molebridge image other than $ref"
done
pass "every Molebridge image is the pinned reference"

[ -x routing/gluetun-preflight ] || fail "gluetun-preflight is not executable"
grep -q 'routing/gluetun-preflight' compose.gluetun.yaml compose.sidecar.yaml || fail "no Compose file mounts routing/gluetun-preflight"
auth=$work/auth.toml
if HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH=$work/missing.toml sh routing/gluetun-preflight true >/dev/null 2>&1; then
    fail "preflight accepted a missing role file"
fi
key=$(printf 'k%.0s' $(seq 1 40))
cat > "$auth" <<EOM
[[roles]]
name = "molebridge"
auth = "apikey"
apikey = "$key"
routes = ["PUT /v1/vpn/settings", "GET /v1/vpn/status", "GET /v1/publicip/ip", "GET /v1/updater/status", "PUT /v1/updater/status"]
EOM
HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH=$auth sh routing/gluetun-preflight true || fail "preflight refused the role file the tools write"
printf 'bad\n' > "$auth"
if HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH=$auth sh routing/gluetun-preflight true >/dev/null 2>&1; then
    fail "preflight accepted a malformed role file"
fi
pass "preflight refuses a missing or malformed role file and accepts a valid one"
