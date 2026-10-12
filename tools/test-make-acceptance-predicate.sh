#!/usr/bin/env sh
# Tests tools/make-acceptance-predicate.sh, and that what it writes passes
# tools/verify-acceptance.sh. Needs jq.
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
gen=$here/make-acceptance-predicate.sh
verify=$here/verify-acceptance.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
fail() { echo "FAIL $1" >&2; exit 1; }
pass() { echo "PASS $1"; }

hex=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
commit=1234567890abcdef1234567890abcdef12345678
cat > "$work/coverage.json" <<'EOM'
{"platforms":["docker-engine-linux","podman-rootless-quadlet","netbird-cloud"],
 "providers":["mullvad","pia","nordvpn"],"kinds":["native","gluetun","sidecar"],
 "drills":[{"id":"clean-install-from-bundle","result":"passed","note":"dropped"},{"id":"client-held","result":"passed"},{"id":"upgrade-from-0.7","result":"passed"}]}
EOM
echo '["https://example.net/evidence/1","run 42 notes"]' > "$work/evidence.json"

gen() {
    sh "$gen" --repo irashack/molebridge --commit "$commit" --tag v0.8.0-rc.1 \
        --image ghcr.io/irashack/molebridge --digest "sha256:$hex" \
        --bundle-name molebridge-v0.8.0-rc.1.tar.gz --bundle-sha256 "$(printf 'b%.0s' $(seq 1 64))" \
        --coverage "$work/coverage.json" --evidence "$work/evidence.json"
}
refuses() {
    desc=$1; text=$2; shift 2
    if "$@" >"$work/out" 2>"$work/err"; then fail "$desc: accepted"; fi
    grep -q "$text" "$work/err" || { cat "$work/err" >&2; fail "$desc: wrong message"; }
    [ ! -s "$work/out" ] || fail "$desc: wrote a predicate"
    pass "refuses $desc"
}

gen > "$work/predicate.json"
jq -e '.result == "passed" and .commit == "'"$commit"'" and .candidate.digest == "sha256:'"$hex"'" and .policy_version == "1"
       and (.drills | length == 3) and (.drills[0] | keys == ["id","result"]) and (.evidence | length == 2)' "$work/predicate.json" >/dev/null ||
    fail "predicate content"
pass "writes the predicate"

# What it writes is what the promotion policy accepts.
jq -n --slurpfile p "$work/predicate.json" --arg hex "$hex" '
  [{verificationResult: {statement: {subject: [{name: "ghcr.io/irashack/molebridge", digest: {sha256: $hex}}],
    predicateType: "https://github.com/irashack/molebridge/attestations/live-acceptance/v1", predicate: $p[0]},
    signature: {certificate: {subjectAlternativeName: "https://github.com/irashack/molebridge/.github/workflows/acceptance.yml@refs/heads/main",
      issuer: "https://token.actions.githubusercontent.com", githubWorkflowRepository: "irashack/molebridge"}}}}]' > "$work/results.json"
sh "$verify" acceptance --results "$work/results.json" --repo irashack/molebridge \
    --identity "https://github.com/irashack/molebridge/.github/workflows/acceptance.yml@refs/heads/main" \
    --issuer https://token.actions.githubusercontent.com --digest "sha256:$hex" --commit "$commit" \
    --image ghcr.io/irashack/molebridge >/dev/null || fail "promotion policy rejects the generated predicate"
pass "generated predicate satisfies the promotion policy"

jq '.drills |= map(select(.id != "client-held"))' "$work/coverage.json" > "$work/c2.json"
refuses "a missing drill" 'client-held' sh "$gen" --repo irashack/molebridge --commit "$commit" --tag v0.8.0-rc.1 --image ghcr.io/irashack/molebridge --digest "sha256:$hex" --bundle-name molebridge-v0.8.0-rc.1.tar.gz --bundle-sha256 "$(printf 'b%.0s' $(seq 1 64))" --coverage "$work/c2.json" --evidence "$work/evidence.json"
jq '.drills[0].result = "failed"' "$work/coverage.json" > "$work/c3.json"
refuses "a failed drill" 'did not pass' sh "$gen" --repo irashack/molebridge --commit "$commit" --tag v0.8.0-rc.1 --image ghcr.io/irashack/molebridge --digest "sha256:$hex" --bundle-name molebridge-v0.8.0-rc.1.tar.gz --bundle-sha256 "$(printf 'b%.0s' $(seq 1 64))" --coverage "$work/c3.json" --evidence "$work/evidence.json"
jq '.providers = ["mullvad"]' "$work/coverage.json" > "$work/c4.json"
refuses "a missing provider" 'provider pia' sh "$gen" --repo irashack/molebridge --commit "$commit" --tag v0.8.0-rc.1 --image ghcr.io/irashack/molebridge --digest "sha256:$hex" --bundle-name molebridge-v0.8.0-rc.1.tar.gz --bundle-sha256 "$(printf 'b%.0s' $(seq 1 64))" --coverage "$work/c4.json" --evidence "$work/evidence.json"
echo '{"platforms":"all"}' > "$work/c5.json"
refuses "malformed coverage" 'coverage is malformed' sh "$gen" --repo irashack/molebridge --commit "$commit" --tag v0.8.0-rc.1 --image ghcr.io/irashack/molebridge --digest "sha256:$hex" --bundle-name molebridge-v0.8.0-rc.1.tar.gz --bundle-sha256 "$(printf 'b%.0s' $(seq 1 64))" --coverage "$work/c5.json" --evidence "$work/evidence.json"
echo '[]' > "$work/e2.json"
refuses "no evidence" 'evidence must be' sh "$gen" --repo irashack/molebridge --commit "$commit" --tag v0.8.0-rc.1 --image ghcr.io/irashack/molebridge --digest "sha256:$hex" --bundle-name molebridge-v0.8.0-rc.1.tar.gz --bundle-sha256 "$(printf 'b%.0s' $(seq 1 64))" --coverage "$work/coverage.json" --evidence "$work/e2.json"
refuses "a final tag" 'candidate tag' sh "$gen" --repo irashack/molebridge --commit "$commit" --tag v0.8.0 --image ghcr.io/irashack/molebridge --digest "sha256:$hex" --bundle-name molebridge-v0.8.0.tar.gz --bundle-sha256 "$(printf 'b%.0s' $(seq 1 64))" --coverage "$work/coverage.json" --evidence "$work/evidence.json"
refuses "a short commit" 'commit must be' sh "$gen" --repo irashack/molebridge --commit abc --tag v0.8.0-rc.1 --image ghcr.io/irashack/molebridge --digest "sha256:$hex" --bundle-name molebridge-v0.8.0-rc.1.tar.gz --bundle-sha256 "$(printf 'b%.0s' $(seq 1 64))" --coverage "$work/coverage.json" --evidence "$work/evidence.json"
echo "all make-acceptance-predicate tests passed"
