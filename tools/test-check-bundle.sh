#!/usr/bin/env sh
# Tests tools/check-bundle.sh with a minimal fake source tree: a good bundle
# passes; a bundle with an unpinned Molebridge image, a missing preflight or
# an invalid Compose file is refused. Needs GNU tar (tar, or gtar on a Mac),
# Docker Compose and jq; skips when one is missing.
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH='' cd -- "$here/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
fail() { echo "FAIL $1" >&2; exit 1; }
pass() { echo "PASS $1"; }
for t in gtar tar; do
    if command -v "$t" >/dev/null 2>&1 && "$t" --version 2>/dev/null | grep -q 'GNU tar'; then have=1; break; fi
done
[ -n "${have:-}" ] || { echo "SKIP check-bundle tests: GNU tar not found"; exit 0; }
docker compose version >/dev/null 2>&1 && command -v jq >/dev/null 2>&1 || { echo "SKIP check-bundle tests: docker compose or jq not found"; exit 0; }

digest=sha256:$(printf '0%.0s' $(seq 1 64))
ref=ghcr.io/irashack/molebridge:v0.8.0-rc.1@$digest
src=$work/src
mkdir -p "$src/routing"
cp "$root/routing/gluetun-preflight" "$src/routing/gluetun-preflight"
cat > "$src/compose.yaml" <<'EOM'
services:
  exit:
    image: ghcr.io/irashack/molebridge:0.8
    environment:
      PROVIDER: ${PROVIDER:-mullvad}
  switchyard:
    image: ghcr.io/irashack/molebridge:0.8
EOM
cat > "$src/compose.gluetun.yaml" <<'EOM'
services:
  gluetun:
    image: docker.io/example/gluetun:1
    environment:
      MOLEBRIDGE_KIND: overlay
    volumes:
      - ./routing/gluetun-preflight:/usr/local/bin/molebridge-gluetun-preflight:ro
  exit:
    image: ghcr.io/irashack/molebridge:0.8
  switchyard:
    image: ghcr.io/irashack/molebridge:0.8
EOM
cat > "$src/compose.sidecar.yaml" <<'EOM'
services:
  gluetun:
    image: docker.io/example/gluetun:1
    environment:
      MOLEBRIDGE_KIND: sidecar
    volumes:
      - ./routing/gluetun-preflight:/usr/local/bin/molebridge-gluetun-preflight:ro
  exit:
    image: ghcr.io/irashack/molebridge:0.8
  switchyard:
    image: ghcr.io/irashack/molebridge:0.8
EOM
cat > "$src/compose.native-sidecar.yaml" <<'EOM'
services:
  exit:
    image: ghcr.io/irashack/molebridge:0.8
    environment:
      EXIT_KIND: sidecar
      TUNNEL_BACKEND: native
  switchyard:
    image: ghcr.io/irashack/molebridge:0.8
    environment:
      EXIT_KIND: sidecar
  example-app:
    profiles: [example]
    image: docker.io/example/app:1
    network_mode: service:exit
  port-sync:
    profiles: [port-sync]
    image: ghcr.io/irashack/molebridge:0.8
    network_mode: service:exit
EOM
echo 'PROVIDER=mullvad' > "$src/.env.example"
echo 'GLUETUN_PROVIDER=nordvpn' > "$src/.env.gluetun.example"
echo 'X=1' > "$src/.env.sidecar.example"
printf 'COMPOSE_PROFILES=example\n' > "$src/.env.native-sidecar.example"
echo MIT > "$src/LICENSE"; echo notices > "$src/THIRD_PARTY.md"

make() { BUNDLE_SOURCE=$src sh "$here/make-bundle.sh" v0.8.0-rc.1 "$digest" "$1" >/dev/null; }
mkdir -p "$work/good"
make "$work/good"
sh "$here/check-bundle.sh" "$work/good/molebridge-v0.8.0-rc.1.tar.gz" "$ref" >/dev/null || fail "good bundle refused"
pass "a good bundle installs"

sh "$here/check-bundle.sh" "$work/good/molebridge-v0.8.0-rc.1.tar.gz" "ghcr.io/irashack/molebridge:v0.8.0@$digest" >/dev/null 2>&1 &&
    fail "accepted a bundle for another reference"
pass "refuses a bundle pinned to another reference"

# An unpinned image slipped past the packer: edit the extracted archive by hand.
mkdir -p "$work/bad/x"
tar -xzf "$work/good/molebridge-v0.8.0-rc.1.tar.gz" -C "$work/bad/x"
sed 's#image: ghcr.io/irashack/molebridge:.*#image: ghcr.io/irashack/molebridge:0.8#' "$work/bad/x/molebridge-v0.8.0-rc.1/compose.yaml" > "$work/bad/c" &&
    cp "$work/bad/c" "$work/bad/x/molebridge-v0.8.0-rc.1/compose.yaml"
tar -czf "$work/bad/unpinned.tar.gz" -C "$work/bad/x" molebridge-v0.8.0-rc.1
sh "$here/check-bundle.sh" "$work/bad/unpinned.tar.gz" "$ref" >/dev/null 2>&1 && fail "accepted an unpinned image"
pass "refuses an unpinned image"

# A gluetun form that tells its preflight the wrong kind, and a form missing a service.
mkdir -p "$work/bad/k"
tar -xzf "$work/good/molebridge-v0.8.0-rc.1.tar.gz" -C "$work/bad/k"
sed 's/MOLEBRIDGE_KIND: overlay/MOLEBRIDGE_KIND: sidecar/' "$work/bad/k/molebridge-v0.8.0-rc.1/compose.gluetun.yaml" > "$work/bad/c" &&
    cp "$work/bad/c" "$work/bad/k/molebridge-v0.8.0-rc.1/compose.gluetun.yaml"
tar -czf "$work/bad/kind.tar.gz" -C "$work/bad/k" molebridge-v0.8.0-rc.1
sh "$here/check-bundle.sh" "$work/bad/kind.tar.gz" "$ref" >/dev/null 2>&1 && fail "accepted a gluetun form with the wrong kind"
pass "refuses a gluetun form that tells its preflight the wrong kind"
mkdir -p "$work/bad/s"
tar -xzf "$work/good/molebridge-v0.8.0-rc.1.tar.gz" -C "$work/bad/s"
grep -v 'switchyard:\|image: ghcr.io/irashack/molebridge' "$work/bad/s/molebridge-v0.8.0-rc.1/compose.yaml" > "$work/bad/c"
printf '  switchyard:\n    image: %s\n' "$ref" >> "$work/bad/c"
cp "$work/bad/c" "$work/bad/s/molebridge-v0.8.0-rc.1/compose.yaml"
tar -czf "$work/bad/noexit.tar.gz" -C "$work/bad/s" molebridge-v0.8.0-rc.1
sh "$here/check-bundle.sh" "$work/bad/noexit.tar.gz" "$ref" >/dev/null 2>&1 && fail "accepted a native form without its exit service"
pass "refuses a native form without its exit service"

# The native sidecar form: port-sync runs only in its profile, and an unpinned
# image there must still be caught; the services and the kinds must be right.
bad_native() { # name sed-expression
    mkdir -p "$work/bad/n-$1"
    tar -xzf "$work/good/molebridge-v0.8.0-rc.1.tar.gz" -C "$work/bad/n-$1"
    sed "$2" "$work/bad/n-$1/molebridge-v0.8.0-rc.1/compose.native-sidecar.yaml" > "$work/bad/c" &&
        cp "$work/bad/c" "$work/bad/n-$1/molebridge-v0.8.0-rc.1/compose.native-sidecar.yaml"
    tar -czf "$work/bad/n-$1.tar.gz" -C "$work/bad/n-$1" molebridge-v0.8.0-rc.1
}
bad_native unpinned '/port-sync:/,$ s#image: ghcr.io/irashack/molebridge:.*#image: ghcr.io/irashack/molebridge:0.8#'
sh "$here/check-bundle.sh" "$work/bad/n-unpinned.tar.gz" "$ref" >/dev/null 2>&1 && fail "accepted an unpinned port-sync image"
pass "refuses a native sidecar whose port-sync image is not pinned"
bad_native noport '/port-sync:/,$ s#port-sync:#port-sync-gone:#'
sh "$here/check-bundle.sh" "$work/bad/n-noport.tar.gz" "$ref" >/dev/null 2>&1 && fail "accepted a native sidecar without port-sync"
pass "refuses a native sidecar without its port-sync service"
bad_native backend 's/TUNNEL_BACKEND: native/TUNNEL_BACKEND: gluetun/'
sh "$here/check-bundle.sh" "$work/bad/n-backend.tar.gz" "$ref" >/dev/null 2>&1 && fail "accepted a native sidecar with the wrong backend"
pass "refuses a native sidecar form that is not the native backend"
bad_native panelkind '/switchyard:/,/example-app:/ s/EXIT_KIND: sidecar/EXIT_KIND: overlay/'
sh "$here/check-bundle.sh" "$work/bad/n-panelkind.tar.gz" "$ref" >/dev/null 2>&1 && fail "accepted a native sidecar panel of the wrong kind"
pass "refuses a native sidecar form whose panel is not the sidecar kind"
mkdir -p "$work/bad/m"
tar -xzf "$work/good/molebridge-v0.8.0-rc.1.tar.gz" -C "$work/bad/m"
rm "$work/bad/m/molebridge-v0.8.0-rc.1/.env.native-sidecar.example"
tar -czf "$work/bad/nonative.tar.gz" -C "$work/bad/m" molebridge-v0.8.0-rc.1
sh "$here/check-bundle.sh" "$work/bad/nonative.tar.gz" "$ref" >/dev/null 2>&1 && fail "accepted a bundle without the native sidecar's env example"
pass "refuses a bundle without the native sidecar's env example"

rm "$work/bad/x/molebridge-v0.8.0-rc.1/routing/gluetun-preflight"
tar -czf "$work/bad/nopreflight.tar.gz" -C "$work/bad/x" molebridge-v0.8.0-rc.1
sh "$here/check-bundle.sh" "$work/bad/nopreflight.tar.gz" "$ref" >/dev/null 2>&1 && fail "accepted a bundle without the preflight"
pass "refuses a bundle without the preflight"
echo "all check-bundle tests passed"
