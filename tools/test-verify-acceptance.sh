#!/usr/bin/env sh
# Tests tools/verify-acceptance.sh, the promotion policy: a good build
# provenance and a good live-acceptance attestation are accepted; a wrong
# identity, issuer, digest, image name, commit, repository, predicate type,
# result, policy version, coverage or drill each refuse promotion. Needs jq.
# The fixtures mimic the JSON `gh attestation verify --format json` prints.
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
verify=$here/verify-acceptance.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
fail() { echo "FAIL $1" >&2; exit 1; }
pass() { echo "PASS $1"; }

repo=irashack/molebridge
issuer=https://token.actions.githubusercontent.com
image=ghcr.io/irashack/molebridge
hex=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
digest=sha256:$hex
commit=1234567890abcdef1234567890abcdef12345678
prov_id=https://github.com/$repo/.github/workflows/release.yml@refs/tags/v0.8.0-rc.1
acc_id=https://github.com/$repo/.github/workflows/acceptance.yml@refs/heads/main
acc_type=https://github.com/irashack/molebridge/attestations/live-acceptance/v1
prov_type=https://slsa.dev/provenance/v1

cat > "$work/policy.json" <<'EOM'
{"version":"1","platforms":["docker-engine-linux","podman-rootless-quadlet","netbird-cloud"],"providers":["mullvad","pia","nordvpn"],"kinds":["native","gluetun","sidecar"],"drills":["clean-install-from-bundle","client-held","upgrade-from-0.7"]}
EOM

# entry <san> <predicate-type> <source-commit> <predicate-json>
entry() {
    jq -n --arg san "$1" --arg pt "$2" --arg sc "$3" --arg hex "$hex" --arg image "$image" \
        --arg issuer "$issuer" --arg repo "$repo" --argjson pred "$4" '
      {attestation: {}, verificationResult: {statement: {
         "_type": "https://in-toto.io/Statement/v1",
         subject: [{name: $image, digest: {sha256: $hex}}],
         predicateType: $pt, predicate: $pred},
       signature: {certificate: {subjectAlternativeName: $san, issuer: $issuer,
         githubWorkflowRepository: $repo, sourceRepositoryDigest: $sc}}}}'
}
good_pred=$(cat <<EOM
{"result":"passed","repository":"$repo","commit":"$commit",
 "candidate":{"tag":"v0.8.0-rc.1","image":"$image","digest":"$digest"},
 "bundle":{"name":"molebridge-v0.8.0-rc.1.tar.gz","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
 "policy_version":"1",
 "platforms":["docker-engine-linux","podman-rootless-quadlet","netbird-cloud"],
 "providers":["mullvad","pia","nordvpn"],"kinds":["native","gluetun","sidecar"],
 "drills":[{"id":"clean-install-from-bundle","result":"passed"},{"id":"client-held","result":"passed"},{"id":"upgrade-from-0.7","result":"passed"}],
 "evidence":["https://example.net/evidence/1"]}
EOM
)
wrap() { jq -s '.' ; }

prov_good() { entry "$prov_id" "$prov_type" "$commit" '{"buildDefinition":{}}' | wrap; }
acc_with() { # jq filter applied to the good predicate
    pred=$(printf '%s' "$good_pred" | jq -c "$1")
    entry "$acc_id" "$acc_type" "$commit" "$pred" | wrap
}

check_prov() { # results-file, extra args to override
    f=$1; shift
    sh "$verify" provenance --results "$f" --repo "$repo" --identity "$prov_id" --issuer "$issuer" \
        --digest "$digest" --commit "$commit" --image "$image" "$@"
}
check_acc() {
    f=$1; shift
    sh "$verify" acceptance --results "$f" --repo "$repo" --identity "$acc_id" --issuer "$issuer" \
        --digest "$digest" --commit "$commit" --image "$image" --policy "$work/policy.json" "$@"
}
accepts() { # description, command...
    desc=$1; shift
    "$@" >/dev/null 2>"$work/err" || { cat "$work/err" >&2; fail "$desc: refused"; }
    pass "accepts $desc"
}
refuses() { # description, expected message fragment, command...
    desc=$1; text=$2; shift 2
    if "$@" >/dev/null 2>"$work/err"; then fail "$desc: accepted"; fi
    grep -q "$text" "$work/err" || { cat "$work/err" >&2; fail "$desc: wrong message (wanted: $text)"; }
    pass "refuses $desc"
}

# Build provenance.
prov_good > "$work/prov.json"
accepts "a good build provenance" check_prov "$work/prov.json"
refuses "provenance by another identity" 'signer identity' check_prov "$work/prov.json" --identity "https://github.com/$repo/.github/workflows/other.yml@refs/tags/v0.8.0-rc.1"
refuses "provenance from a branch run when a tag run is required" 'signer identity' check_prov "$work/prov.json" --identity "https://github.com/$repo/.github/workflows/release.yml@refs/heads/main"
refuses "provenance from another issuer" 'OIDC issuer' check_prov "$work/prov.json" --issuer https://issuer.example.net
refuses "provenance for another digest" 'subject is not' check_prov "$work/prov.json" --digest "sha256:$(printf 'c%.0s' $(seq 1 64))"
refuses "provenance for another image name" 'subject is not' check_prov "$work/prov.json" --image ghcr.io/irashack/molebridge-ci
refuses "provenance for another commit" 'source commit' check_prov "$work/prov.json" --commit fedcba0987654321fedcba0987654321fedcba09
refuses "provenance in another repository" 'workflow repository' check_prov "$work/prov.json" --repo example/other
refuses "a provenance entry of another predicate type" 'predicate type' check_prov "$work/prov.json" --predicate-type https://example.net/other/v1
entry "$prov_id" "$prov_type" "$commit" '{}' | jq '.verificationResult.signature.certificate.sourceRepositoryDigest = "fedcba0987654321fedcba0987654321fedcba09"' | wrap > "$work/prov-badcommit.json"
refuses "provenance whose certificate names another commit" 'source commit' check_prov "$work/prov-badcommit.json"

# Live acceptance.
acc_with '.' > "$work/acc.json"
accepts "a good acceptance attestation" check_acc "$work/acc.json"
refuses "acceptance by the build workflow's identity" 'signer identity' check_acc "$work/acc.json" --identity "$prov_id"
refuses "acceptance by an identity on another ref" 'signer identity' check_acc "$work/acc.json" --identity "https://github.com/$repo/.github/workflows/acceptance.yml@refs/heads/feature"
refuses "acceptance for another digest" 'subject is not' check_acc "$work/acc.json" --digest "sha256:$(printf 'd%.0s' $(seq 1 64))"
refuses "acceptance naming another commit" 'acceptance commit' check_acc "$work/acc.json" --commit fedcba0987654321fedcba0987654321fedcba09
acc_with '.result = "failed"' > "$work/f.json"
refuses "a failed result" 'result is not passed' check_acc "$work/f.json"
acc_with 'del(.result)' > "$work/f.json"
refuses "a missing result" 'result is not passed' check_acc "$work/f.json"
acc_with '.drills |= map(select(.id != "client-held"))' > "$work/f.json"
refuses "a missing drill" 'drill is missing' check_acc "$work/f.json"
acc_with '.drills |= map(if .id == "upgrade-from-0.7" then .result = "failed" else . end)' > "$work/f.json"
refuses "a failed drill" 'drill did not pass' check_acc "$work/f.json"
acc_with 'del(.drills)' > "$work/f.json"
refuses "no drills at all" 'drill is missing' check_acc "$work/f.json"
acc_with '.drills += [{"id":"extra","result":"failed"}]' > "$work/f.json"
refuses "an extra failed drill" 'a drill did not pass' check_acc "$work/f.json"
acc_with '.providers = ["mullvad","pia"]' > "$work/f.json"
refuses "a missing provider" 'provider coverage' check_acc "$work/f.json"
acc_with '.platforms = ["docker-engine-linux"]' > "$work/f.json"
refuses "a missing platform" 'platform coverage' check_acc "$work/f.json"
acc_with '.kinds = ["native"]' > "$work/f.json"
refuses "a missing kind" 'kind coverage' check_acc "$work/f.json"
acc_with '.policy_version = "2"' > "$work/f.json"
refuses "an unknown policy version" 'policy version' check_acc "$work/f.json"
acc_with '.candidate.digest = "sha256:'"$(printf 'e%.0s' $(seq 1 64))"'"' > "$work/f.json"
refuses "a candidate digest that is not the subject" 'candidate digest' check_acc "$work/f.json"
acc_with '.repository = "example/other"' > "$work/f.json"
refuses "another repository in the predicate" 'acceptance repository' check_acc "$work/f.json"
acc_with 'del(.bundle)' > "$work/f.json"
refuses "no bundle digest" 'bundle digest' check_acc "$work/f.json"
acc_with '.evidence = []' > "$work/f.json"
refuses "no evidence" 'no evidence' check_acc "$work/f.json"
refuses "an acceptance entry of the wrong predicate type" 'predicate type' check_acc "$work/acc.json" --predicate-type https://example.net/other/v1

# A failed attestation by the right signer for the digest vetoes a good one.
{ acc_with '.' | jq '.[0]'; acc_with '.result = "failed"' | jq '.[0]'; } | wrap > "$work/mixed.json"
refuses "a good attestation beside a failed one by the same signer" 'result is not passed' check_acc "$work/mixed.json"
# An unrelated entry (another signer) does not veto.
{ acc_with '.' | jq '.[0]'; entry "https://github.com/$repo/.github/workflows/other.yml@refs/heads/main" "$acc_type" "$commit" '{"result":"failed"}'; } | wrap > "$work/mixed2.json"
accepts "a good attestation beside an unrelated signer's entry" check_acc "$work/mixed2.json"

# Malformed input.
echo '[]' > "$work/f.json"
refuses "an empty result list" 'no attestations' check_acc "$work/f.json"
echo '{"not":"an array"}' > "$work/f.json"
refuses "results that are not an array" 'not a JSON array' check_acc "$work/f.json"
echo 'not json' > "$work/f.json"
refuses "results that are not JSON" 'not a JSON array' check_acc "$work/f.json"
echo '[{"verificationResult":{}}]' > "$work/f.json"
refuses "an entry without a statement" 'no attestation meets' check_acc "$work/f.json"
refuses "a missing results file" 'no results file' check_acc "$work/none.json"
refuses "a short digest argument" 'digest must be' check_acc "$work/acc.json" --digest sha256:abc
refuses "a short commit argument" 'commit must be' check_acc "$work/acc.json" --commit abc123
echo "all verify-acceptance tests passed"
