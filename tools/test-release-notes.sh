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
wf=https://github.com/irashack/molebridge/.github/workflows

rel=$(sh "$notes" --kind release --tag v0.8.0 --build-tag v0.8.0-rc.2 --commit "$c" --digest "$i" --amd64 "$a" --arm64 "$b")
echo "$rel" | grep -qF "$wf/release.yml@refs/tags/v0.8.0-rc.2" || fail "build identity"
echo "$rel" | grep -qF "$wf/release.yml@refs/tags/v0.8.0 " || echo "$rel" | grep -qF "$wf/release.yml@refs/tags/v0.8.0\\" || fail "release identity"
echo "$rel" | grep -qF "$wf/acceptance.yml@refs/heads/main" || fail "acceptance identity"
echo "$rel" | grep -qF "ghcr.io/irashack/molebridge@$i" || fail "index reference"
echo "$rel" | grep -qF -- "--source-digest $c" || fail "source commit"
echo "$rel" | grep -qF "attestations/live-acceptance/v1" || fail "acceptance predicate type"
for envfile in .env.example .env.gluetun.example .env.sidecar.example .env.native-sidecar.example; do
    echo "$rel" | grep -qF "$envfile" || fail "release notes do not name $envfile"
done
pass "release notes name the three identities and the commit"

cand=$(sh "$notes" --kind candidate --tag v0.8.0-rc.2 --commit "$c" --digest "$i" --amd64 "$a" --arm64 "$b")
echo "$cand" | grep -qF "acceptance.yml" && fail "candidate notes mention acceptance verification"
echo "$cand" | grep -qF "has not passed live acceptance" || fail "candidate warning"
pass "candidate notes carry the warning and no acceptance step"

refuses() { desc=$1; shift; if sh "$notes" "$@" >/dev/null 2>&1; then fail "accepted $desc"; fi; pass "refuses $desc"; }
refuses "a release without a build tag" --kind release --tag v0.8.0 --commit "$c" --digest "$i" --amd64 "$a" --arm64 "$b"
refuses "a candidate with another build tag" --kind candidate --tag v0.8.0-rc.2 --build-tag v0.8.0-rc.1 --commit "$c" --digest "$i" --amd64 "$a" --arm64 "$b"
refuses "a bad digest" --kind candidate --tag v0.8.0-rc.2 --commit "$c" --digest sha256:abc --amd64 "$a" --arm64 "$b"
refuses "a bad commit" --kind candidate --tag v0.8.0-rc.2 --commit abc --digest "$i" --amd64 "$a" --arm64 "$b"
refuses "a bad tag" --kind candidate --tag main --commit "$c" --digest "$i" --amd64 "$a" --arm64 "$b"
echo "all release-notes tests passed"
