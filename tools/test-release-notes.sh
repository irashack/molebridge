#!/usr/bin/env sh
# Tests tools/release-notes.sh: the identities and the commit appear where the
# policy needs them, candidates and releases differ as intended, and bad input
# is refused.
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
notes=$here/release-notes.sh
fail() { echo "FAIL $1" >&2; exit 1; }
pass() { echo "PASS $1"; }
c=1234567890abcdef1234567890abcdef12345678
i=sha256:$(printf 'a%.0s' $(seq 1 64))
a=sha256:$(printf 'b%.0s' $(seq 1 64))
b=sha256:$(printf 'c%.0s' $(seq 1 64))
ci=sha256:$(printf 'd%.0s' $(seq 1 64))
ca=sha256:$(printf 'e%.0s' $(seq 1 64))
cb=sha256:$(printf 'f%.0s' $(seq 1 64))
core="--core-digest $ci --core-amd64 $ca --core-arm64 $cb"
wf=https://github.com/irashack/molebridge/.github/workflows

rel=$(sh "$notes" --kind release --tag v0.8.0 --build-tag v0.8.0-rc.2 --commit "$c" --digest "$i" --amd64 "$a" --arm64 "$b" $core)
echo "$rel" | grep -qF "$wf/release.yml@refs/tags/v0.8.0-rc.2" || fail "build identity"
echo "$rel" | grep -qF "$wf/release.yml@refs/tags/v0.8.0 " || echo "$rel" | grep -qF "$wf/release.yml@refs/tags/v0.8.0\\" || fail "release identity"
echo "$rel" | grep -qF "$wf/acceptance.yml@refs/heads/main" || fail "acceptance identity"
echo "$rel" | grep -qF "ghcr.io/irashack/molebridge@$i" || fail "index reference"
echo "$rel" | grep -qF -- "--source-digest $c" || fail "source commit"
echo "$rel" | grep -qF "attestations/live-acceptance/v1" || fail "acceptance predicate type"
for envfile in .env.example .env.gluetun.example .env.sidecar.example .env.native-sidecar.example; do
    echo "$rel" | grep -qF "$envfile" || fail "release notes do not name $envfile"
done
echo "$rel" | grep -qF "ghcr.io/irashack/molebridge-core@$ci" || fail "core index reference"
for d in "$ca" "$cb"; do echo "$rel" | grep -qF "$d" || fail "core manifest $d"; done
[ "$(echo "$rel" | grep -cF "oci://ghcr.io/irashack/molebridge-core@$ci")" -eq 2 ] || fail "core provenance and acceptance steps"
pass "release notes name the three identities and the commit"
pass "release notes verify molebridge-core too"

cand=$(sh "$notes" --kind candidate --tag v0.8.0-rc.2 --commit "$c" --digest "$i" --amd64 "$a" --arm64 "$b" $core)
echo "$cand" | grep -qF "acceptance.yml" && fail "candidate notes mention acceptance verification"
echo "$cand" | grep -qF "has not passed live acceptance" || fail "candidate warning"
[ "$(echo "$cand" | grep -cF "oci://ghcr.io/irashack/molebridge-core@$ci")" -eq 1 ] || fail "candidate core provenance step"
pass "candidate notes carry the warning and no acceptance step"

refuses() { desc=$1; shift; if sh "$notes" "$@" >/dev/null 2>&1; then fail "accepted $desc"; fi; pass "refuses $desc"; }
refuses "a release without a build tag" --kind release --tag v0.8.0 --commit "$c" --digest "$i" --amd64 "$a" --arm64 "$b" $core
refuses "a candidate with another build tag" --kind candidate --tag v0.8.0-rc.2 --build-tag v0.8.0-rc.1 --commit "$c" --digest "$i" --amd64 "$a" --arm64 "$b" $core
refuses "a bad digest" --kind candidate --tag v0.8.0-rc.2 --commit "$c" --digest sha256:abc --amd64 "$a" --arm64 "$b" $core
refuses "a bad commit" --kind candidate --tag v0.8.0-rc.2 --commit abc --digest "$i" --amd64 "$a" --arm64 "$b" $core
refuses "missing core digests" --kind candidate --tag v0.8.0-rc.2 --commit "$c" --digest "$i" --amd64 "$a" --arm64 "$b"
refuses "a bad tag" --kind candidate --tag main --commit "$c" --digest "$i" --amd64 "$a" --arm64 "$b" $core
echo "all release-notes tests passed"
