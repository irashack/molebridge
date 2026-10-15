#!/usr/bin/env sh
# Installs from an extracted bundle with no repository checkout: unpacks
# molebridge-<tag>.tar.gz into a fresh directory, and from there checks that
# the four Compose forms (native, gluetun, sidecar, native sidecar) validate
# with their example environment files, that each runs the services it should
# (the exit and Switchyard, plus gluetun for the gluetun forms, and the example
# application and port-sync, in their profiles, for the native sidecar), that
# every Molebridge image they reference, port-sync's included, is the exact
# pinned tag@digest reference the bundle was built with, that the native
# sidecar's exit is the native sidecar kind and the panel is the sidecar
# kind, that the relative file the gluetun forms bind-mount
# (routing/gluetun-preflight) is in the bundle and executable by sh, that each
# gluetun form tells it its kind, and that this preflight refuses a missing
# control-server role file, an unset kind and the wrong post-rules for its kind,
# and accepts the role file the tools write. Needs Docker Compose and jq;
# starts no container.
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
for f in compose.yaml compose.gluetun.yaml compose.sidecar.yaml compose.native-sidecar.yaml .env.example .env.gluetun.example .env.sidecar.example .env.native-sidecar.example routing/gluetun-preflight LICENSE THIRD_PARTY.md; do
    [ -f "$f" ] || fail "bundle lacks $f"
done
[ ! -d .git ] || fail "bundle carries a .git directory"
pass "bundle layout"

cp .env.example .env
docker compose config --quiet || fail "compose.yaml does not validate"
docker compose --env-file .env.gluetun.example -f compose.gluetun.yaml config --quiet || fail "compose.gluetun.yaml does not validate"
docker compose --env-file .env.sidecar.example -f compose.sidecar.yaml config --quiet || fail "compose.sidecar.yaml does not validate"
docker compose --env-file .env.native-sidecar.example -f compose.native-sidecar.yaml config --quiet || fail "compose.native-sidecar.yaml does not validate"
pass "all four Compose forms validate"

# resolved <compose file> <env file>: Compose's resolved model. The native
# sidecar's port-sync runs only in its profile, so every profile is on for it.
resolved() {
    if [ "$1" = compose.native-sidecar.yaml ]; then
        COMPOSE_PROFILES=example,port-sync docker compose --env-file "$2" -f "$1" config --format json
    else
        docker compose --env-file "$2" -f "$1" config --format json
    fi
}
for form in "compose.yaml:.env" "compose.gluetun.yaml:.env.gluetun.example" "compose.sidecar.yaml:.env.sidecar.example" "compose.native-sidecar.yaml:.env.native-sidecar.example"; do
    file=${form%%:*}
    envfile=${form#*:}
    images=$(resolved "$file" "$envfile" | jq -r '.services[].image // empty')
    mine=$(echo "$images" | grep '^ghcr\.io/irashack/molebridge' || true)
    [ -n "$mine" ] || fail "$file references no Molebridge image"
    echo "$mine" | grep -vxF "$ref" && fail "$file references a Molebridge image other than $ref"
done
pass "every Molebridge image is the pinned reference"

# Services, and the kind each gluetun form tells its preflight.
services() { resolved "$1" "$2" | jq -r '.services | keys | join(" ")'; }
[ "$(services compose.yaml .env)" = "exit switchyard" ] || fail "compose.yaml does not run exactly exit and switchyard"
[ "$(services compose.gluetun.yaml .env.gluetun.example)" = "exit gluetun switchyard" ] || fail "compose.gluetun.yaml does not run exactly exit, gluetun and switchyard"
sidecar_services=$(services compose.sidecar.yaml .env.sidecar.example)
for svc in exit gluetun switchyard; do
    case " $sidecar_services " in *" $svc "*) ;; *) fail "compose.sidecar.yaml lacks the $svc service" ;; esac
done
[ "$(services compose.native-sidecar.yaml .env.native-sidecar.example)" = "example-app exit port-sync switchyard" ] ||
    fail "compose.native-sidecar.yaml does not run exactly exit, switchyard, example-app and port-sync"
# The native sidecar has no gluetun: its exit is the native sidecar kind and its panel the sidecar kind.
nsc_kinds=$(resolved compose.native-sidecar.yaml .env.native-sidecar.example |
    jq -r '[.services.exit.environment.EXIT_KIND, .services.exit.environment.TUNNEL_BACKEND, .services.switchyard.environment.EXIT_KIND] | join(" ")')
[ "$nsc_kinds" = "sidecar native sidecar" ] || fail "compose.native-sidecar.yaml is not the native sidecar kind (exit and Switchyard report: $nsc_kinds)"
kind_of() { resolved "$1" "$2" | jq -r '.services.gluetun.environment.MOLEBRIDGE_KIND // empty'; }
[ "$(kind_of compose.gluetun.yaml .env.gluetun.example)" = overlay ] || fail "compose.gluetun.yaml does not set MOLEBRIDGE_KIND=overlay"
[ "$(kind_of compose.sidecar.yaml .env.sidecar.example)" = sidecar ] || fail "compose.sidecar.yaml does not set MOLEBRIDGE_KIND=sidecar"
pass "each form runs the right services, and tells its preflight its kind"

[ -x routing/gluetun-preflight ] || fail "gluetun-preflight is not executable"
grep -q 'routing/gluetun-preflight' compose.gluetun.yaml compose.sidecar.yaml || fail "no Compose file mounts routing/gluetun-preflight"
auth=$work/auth.toml
rules=$work/post-rules.txt
none=$work/no-post-rules.txt
echo 'iptables -A OUTPUT -o eth0 -j ACCEPT' > "$rules"
# preflight <kind> <role file> <post-rules file>: succeeds if gluetun would start.
preflight() {
    env MOLEBRIDGE_KIND="$1" HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH="$2" MOLEBRIDGE_POST_RULES_FILE="$3" \
        sh routing/gluetun-preflight true >/dev/null 2>&1
}
if preflight sidecar "$work/missing.toml" "$none"; then
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
preflight sidecar "$auth" "$none" || fail "preflight refused the role file the tools write"
preflight overlay "$auth" "$rules" || fail "preflight refused an overlay with its post-rules"
if preflight overlay "$auth" "$none"; then fail "preflight accepted an overlay without post-rules"; fi
if preflight sidecar "$auth" "$rules"; then fail "preflight accepted a sidecar with post-rules"; fi
if env HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH="$auth" MOLEBRIDGE_POST_RULES_FILE="$none" sh routing/gluetun-preflight true >/dev/null 2>&1; then
    fail "preflight accepted a start with no kind"
fi
printf 'bad\n' > "$auth"
if preflight sidecar "$auth" "$none"; then
    fail "preflight accepted a malformed role file"
fi
pass "preflight refuses a missing or malformed role file, an unset kind and the wrong post-rules, and accepts a valid start"
