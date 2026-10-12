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
EOM
cat > "$src/compose.gluetun.yaml" <<'EOM'
services:
  gluetun:
    image: docker.io/example/gluetun:1
    volumes:
      - ./routing/gluetun-preflight:/usr/local/bin/molebridge-gluetun-preflight:ro
  exit:
    image: ghcr.io/irashack/molebridge:0.8
EOM
cat > "$src/compose.sidecar.yaml" <<'EOM'
services:
  gluetun:
    image: docker.io/example/gluetun:1
    volumes:
      - ./routing/gluetun-preflight:/usr/local/bin/molebridge-gluetun-preflight:ro
  exit:
    image: ghcr.io/irashack/molebridge:0.8
EOM
echo 'PROVIDER=mullvad' > "$src/.env.example"
echo 'X=1' > "$src/.env.sidecar.example"
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

rm "$work/bad/x/molebridge-v0.8.0-rc.1/routing/gluetun-preflight"
tar -czf "$work/bad/nopreflight.tar.gz" -C "$work/bad/x" molebridge-v0.8.0-rc.1
sh "$here/check-bundle.sh" "$work/bad/nopreflight.tar.gz" "$ref" >/dev/null 2>&1 && fail "accepted a bundle without the preflight"
pass "refuses a bundle without the preflight"
echo "all check-bundle tests passed"
