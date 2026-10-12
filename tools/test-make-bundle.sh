#!/usr/bin/env sh
# Tests tools/make-bundle.sh on a fake source tree: the image rewrite in every
# form, the member list and metadata, determinism, and the refusals. Needs GNU
# tar (tar, or gtar on a Mac); without it the test says so and skips.
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
bundle=$here/make-bundle.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
fail() { echo "FAIL $1" >&2; exit 1; }
pass() { echo "PASS $1"; }

have_gnu_tar=
for t in gtar tar; do
    if command -v "$t" >/dev/null 2>&1 && "$t" --version 2>/dev/null | grep -q 'GNU tar'; then have_gnu_tar=$t; break; fi
done
[ -n "$have_gnu_tar" ] || { echo "SKIP make-bundle tests: GNU tar not found"; exit 0; }
tar=$have_gnu_tar

digest=sha256:0000000000000000000000000000000000000000000000000000000000000000
other=sha256:1111111111111111111111111111111111111111111111111111111111111111
ref=ghcr.io/irashack/molebridge:v0.8.0@$digest

src=$work/src
mkdir -p "$src/routing"
cat > "$src/compose.yaml" <<'EOM'
services:
  exit:
    image: ghcr.io/irashack/molebridge:0.8
  panel:
    image: "${MOLEBRIDGE_IMAGE:-ghcr.io/irashack/molebridge:0.8.0}"  # panel
  other:
    image: docker.io/example/other:1.0
EOM
cat > "$src/compose.gluetun.yaml" <<'EOM'
services:
  exit:
    image: ghcr.io/irashack/molebridge@sha256:2222222222222222222222222222222222222222222222222222222222222222
  tool:
    image: ghcr.io/irashack/molebridge
EOM
cat > "$src/compose.sidecar.yaml" <<'EOM'
# Pull ghcr.io/irashack/molebridge:<tag> for the sidecar.
services:
  exit:
    image: ghcr.io/irashack/molebridge:v0.8.0-rc.1@sha256:3333333333333333333333333333333333333333333333333333333333333333
EOM
printf 'MOLEBRIDGE_IMAGE=ghcr.io/irashack/molebridge:0.8\nPROVIDER=mullvad\n' > "$src/.env.example"
printf 'X=1\n' > "$src/.env.sidecar.example"
printf '#!/usr/bin/env sh\necho "docker run ghcr.io/irashack/molebridge:<tag> gluetun-auth"\n' > "$src/routing/gluetun-preflight"
printf 'MIT\n' > "$src/LICENSE"
printf 'notices\n' > "$src/THIRD_PARTY.md"
chmod 0600 "$src/compose.yaml"; chmod 0755 "$src/routing/gluetun-preflight"

run() { BUNDLE_SOURCE=$src sh "$bundle" "$@"; }
refuses() { # description expected-text args...
    desc=$1; text=$2; shift 2
    if run "$@" >"$work/out" 2>"$work/err"; then fail "$desc: accepted"; fi
    grep -q "$text" "$work/err" || { cat "$work/err" >&2; fail "$desc: wrong message"; }
    pass "refuses $desc"
}

mkdir -p "$work/o1"
archive=$(run v0.8.0 "$digest" "$work/o1")
[ "$archive" = "$work/o1/molebridge-v0.8.0.tar.gz" ] || fail "archive path: $archive"
members=$($tar -tzf "$archive" | tr '\n' ' ')
want="molebridge-v0.8.0/ molebridge-v0.8.0/.env.example molebridge-v0.8.0/.env.sidecar.example molebridge-v0.8.0/LICENSE molebridge-v0.8.0/THIRD_PARTY.md molebridge-v0.8.0/compose.gluetun.yaml molebridge-v0.8.0/compose.sidecar.yaml molebridge-v0.8.0/compose.yaml molebridge-v0.8.0/routing/ molebridge-v0.8.0/routing/gluetun-preflight "
[ "$members" = "$want" ] || fail "member list: $members"
pass "member list"

mkdir -p "$work/x1"
$tar -xzf "$archive" -C "$work/x1"
x=$work/x1/molebridge-v0.8.0
[ "$(grep -c "$ref" "$x/compose.yaml")" = 2 ] || fail "compose.yaml rewrites"
grep -q 'image: docker.io/example/other:1.0' "$x/compose.yaml" || fail "other image changed"
grep -q "image: \"\${MOLEBRIDGE_IMAGE:-$ref}\"  # panel" "$x/compose.yaml" || fail "default and comment kept"
grep -q "^    image: $ref\$" "$x/compose.gluetun.yaml" || fail "digest reference"
[ "$(grep -c "$ref" "$x/compose.gluetun.yaml")" = 2 ] || fail "bare name rewritten"
grep -q "Pull $ref for the sidecar" "$x/compose.sidecar.yaml" || fail "placeholder in a comment"
grep -q "image: $ref\$" "$x/compose.sidecar.yaml" || fail "tag and digest replaced"
grep -q "^MOLEBRIDGE_IMAGE=$ref\$" "$x/.env.example" || fail ".env rewrite"
grep -q "docker run $ref gluetun-auth" "$x/routing/gluetun-preflight" || fail "preflight diagnostic"
grep -q ':0.8\|<tag>\|2222\|3333' "$x"/compose*.yaml "$x/.env.example" "$x/routing/gluetun-preflight" && fail "old reference left"
pass "image references rewritten in every form"

# Metadata: owner 0, one mtime, normalized modes.
listing=$($tar -tvzf "$archive" --numeric-owner)
echo "$listing" | grep -qv ' 0/0 ' && fail "owner not 0/0"
echo "$listing" | grep -q '2000-01-01 00:00' || fail "mtime not fixed"
echo "$listing" | awk '{print $4, $5}' | grep -qv '^2000-01-01 00:00$' && fail "an mtime differs"
echo "$listing" | grep 'compose.yaml' | grep -q '^-rw-r--r--' || fail "mode of compose.yaml"
echo "$listing" | grep 'gluetun-preflight' | grep -q '^-rwxr-xr-x' || fail "mode of preflight"
pass "owner, mtime and modes"

# Determinism: again, elsewhere, with different source mtimes and umask.
touch -t 202501010101 "$src"/compose*.yaml "$src/LICENSE"
mkdir -p "$work/o2"
(umask 077; run v0.8.0 "$digest" "$work/o2" >/dev/null)
cmp -s "$archive" "$work/o2/molebridge-v0.8.0.tar.gz" || fail "archives differ between runs"
pass "deterministic"
SOURCE_DATE_EPOCH=1700000000 run v0.8.0 "$digest" "$work/o2" >/dev/null
cmp -s "$archive" "$work/o2/molebridge-v0.8.0.tar.gz" && fail "SOURCE_DATE_EPOCH ignored"
pass "SOURCE_DATE_EPOCH changes the mtime"

# A different digest changes the archive; the optional file is included.
printf 'G=1\n' > "$src/.env.gluetun.example"
run v0.8.0-rc.1 "$other" "$work/o2" >/dev/null
$tar -tzf "$work/o2/molebridge-v0.8.0-rc.1.tar.gz" | grep -q '/.env.gluetun.example$' || fail "optional env example missing"
$tar -xzOf "$work/o2/molebridge-v0.8.0-rc.1.tar.gz" molebridge-v0.8.0-rc.1/compose.yaml | grep -q "molebridge:v0.8.0-rc.1@$other" || fail "rc reference"
pass "release candidate tag and optional file"

# Refusals.
refuses "a bad tag" 'tag must look like' 0.8.0 "$digest" "$work/o3"
refuses "a branch name as tag" 'tag must look like' main "$digest" "$work/o3"
refuses "a short digest" 'digest must be' v0.8.0 sha256:abc "$work/o3"
refuses "an uppercase digest" 'digest must be' v0.8.0 "sha256:$(printf 'A%.0s' $(seq 1 64))" "$work/o3"
rm "$src/LICENSE"
refuses "a missing file" 'missing bundle file: LICENSE' v0.8.0 "$digest" "$work/o3"
printf 'MIT\n' > "$src/LICENSE"
cp "$src/compose.yaml" "$work/compose.yaml.bak"
printf 'services:\n  exit:\n    image: docker.io/example/other:1.0\n' > "$src/compose.yaml"
refuses "a compose file with no Molebridge image" 'has no Molebridge image reference' v0.8.0 "$digest" "$work/o3"
printf 'services:\n  exit:\n    image: ghcr.io/irashack/molebridge-ci:x\n' > "$src/compose.yaml"
refuses "another package under the same owner" 'still names the image' v0.8.0 "$digest" "$work/o3"
printf 'services:\n  exit:\n    image: ghcr.io/irashack/molebridge:\n' > "$src/compose.yaml"
refuses "an unparseable reference" 'still names the image' v0.8.0 "$digest" "$work/o3"
cp "$work/compose.yaml.bak" "$src/compose.yaml"
rm "$src/compose.sidecar.yaml"; ln -s compose.yaml "$src/compose.sidecar.yaml"
refuses "a symlink" 'missing bundle file: compose.sidecar.yaml' v0.8.0 "$digest" "$work/o3"
[ ! -e "$work/o3" ] || fail "output created by a refused run"
echo "all make-bundle tests passed"
