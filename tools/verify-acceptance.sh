#!/usr/bin/env sh
# The policy half of release promotion. The workflow first runs
#   gh attestation verify oci://<image>@<digest> ... --format json > results.json
# (gh checks the Sigstore signatures, the certificate chain and the flags it
# is given). This script then reads that JSON and applies Molebridge's own
# policy again, from the verified certificate and statement fields, so a wrong
# identity, subject, commit or result cannot slip through a mistyped flag:
#
#   provenance   the build attestation: SLSA provenance v1, signed by the build
#                workflow identity, GitHub's OIDC issuer, for this index digest
#                and this source commit.
#   acceptance   the live-acceptance attestation: the project's own predicate
#                type, signed by the acceptance workflow identity, for this
#                index digest, result passed, this source commit, a policy
#                version this checkout knows, complete coverage and every
#                required drill passed.
#
#   sh tools/verify-acceptance.sh provenance|acceptance --results FILE \
#       --repo OWNER/REPO --identity SAN --issuer URL --digest sha256:HEX \
#       --commit SHA [--image NAME] [--policy FILE] [--predicate-type URI]
#
# Exit status 0 only when at least one attestation meets every requirement and
# no attestation by that identity for that digest reports another result. Every
# message is fixed text; nothing from the attestation is echoed.
set -eu
LC_ALL=C
export LC_ALL

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
die() { echo "verify-acceptance: refused: $1" >&2; exit 1; }
usage() {
    echo "usage: verify-acceptance.sh provenance|acceptance --results FILE --repo OWNER/REPO --identity SAN --issuer URL --digest sha256:HEX --commit SHA [--image NAME] [--policy FILE] [--predicate-type URI]" >&2
    exit 2
}
command -v jq >/dev/null 2>&1 || die "jq is required"

[ $# -ge 1 ] || usage
mode=$1
shift
case "$mode" in provenance | acceptance) ;; *) usage ;; esac

results=
repo=
identity=
issuer=
digest=
commit=
image=
policy=$here/acceptance-policy.json
ptype=
while [ $# -gt 0 ]; do
    [ $# -ge 2 ] || usage
    case "$1" in
        --results) results=$2 ;;
        --repo) repo=$2 ;;
        --identity) identity=$2 ;;
        --issuer) issuer=$2 ;;
        --digest) digest=$2 ;;
        --commit) commit=$2 ;;
        --image) image=$2 ;;
        --policy) policy=$2 ;;
        --predicate-type) ptype=$2 ;;
        *) usage ;;
    esac
    shift 2
done
[ -n "$results" ] && [ -n "$repo" ] && [ -n "$identity" ] && [ -n "$issuer" ] && [ -n "$digest" ] && [ -n "$commit" ] || usage
if [ -z "$ptype" ]; then
    case "$mode" in
        provenance) ptype=https://slsa.dev/provenance/v1 ;;
        acceptance) ptype=https://github.com/irashack/molebridge/attestations/live-acceptance/v1 ;;
    esac
fi
printf '%s' "$digest" | grep -Eq '^sha256:[0-9a-f]{64}$' || die "digest must be sha256: and 64 lowercase hex digits"
printf '%s' "$commit" | grep -Eq '^[0-9a-f]{40}$' || die "commit must be a 40-digit lowercase hex SHA"
[ -f "$results" ] || die "no results file"
jq -e 'type == "array"' "$results" >/dev/null 2>&1 || die "results are not a JSON array"
if [ "$mode" = acceptance ]; then
    [ -f "$policy" ] || die "no policy file"
    jq -e '.version | type == "string"' "$policy" >/dev/null 2>&1 || die "policy file is malformed"
fi

hex=${digest#sha256:}
# One verdict per entry: the list of problems, empty when the entry is good,
# plus whether the entry is "ours" (identity, issuer and subject all match), so
# a failed result by the right signer cannot be outvoted by another entry.
verdicts=$(jq -c \
    --arg mode "$mode" --arg repo "$repo" --arg identity "$identity" --arg issuer "$issuer" \
    --arg hex "$hex" --arg commit "$commit" --arg image "$image" --arg ptype "$ptype" \
    --slurpfile policy "$policy" '
  def listed($want): . as $have | ($want | map(. as $w | $have | index($w) != null) | all);
  def cert: .verificationResult.signature.certificate;
  def stmt: .verificationResult.statement;
  .[] |
  (try (
    (stmt.subject // []) as $subjects
    | ($subjects | map(select(.digest.sha256 == $hex and ($image == "" or .name == $image))) | length > 0) as $subject_ok
    | (cert.subjectAlternativeName == $identity) as $identity_ok
    | (cert.issuer == $issuer) as $issuer_ok
    | {
        ours: ($identity_ok and $issuer_ok and $subject_ok and stmt.predicateType == $ptype),
        problems: ([
          (if $identity_ok then empty else "signer identity is not the expected one" end),
          (if $issuer_ok then empty else "OIDC issuer is not the expected one" end),
          (if $subject_ok then empty else "subject is not the expected image digest" end),
          (if cert.githubWorkflowRepository == $repo then empty else "workflow repository is not the expected one" end),
          (if stmt.predicateType == $ptype then empty else "predicate type is not the expected one" end),
          (if $mode == "provenance" then
             (if cert.sourceRepositoryDigest == $commit then empty else "source commit is not the expected one" end)
           else
             (stmt.predicate // {}) as $p
             | ($policy[0]) as $pol
             | (if $p.result == "passed" then empty else "acceptance result is not passed" end),
               (if $p.repository == $repo then empty else "acceptance repository is not the expected one" end),
               (if $p.commit == $commit then empty else "acceptance commit is not the expected one" end),
               (if $p.candidate.digest == ("sha256:" + $hex) then empty else "acceptance candidate digest is not the expected one" end),
               (if ($p.bundle.sha256 // "" | test("^[0-9a-f]{64}$")) then empty else "acceptance bundle digest is missing" end),
               (if $p.policy_version == $pol.version then empty else "acceptance policy version is not the one this source knows" end),
               (if (($p.platforms // []) | type == "array") and (($p.platforms // []) | listed($pol.platforms // ["unset"])) then empty else "platform coverage is incomplete" end),
               (if (($p.providers // []) | type == "array") and (($p.providers // []) | listed($pol.providers // ["unset"])) then empty else "provider coverage is incomplete" end),
               (if (($p.kinds // []) | type == "array") and (($p.kinds // []) | listed($pol.kinds // ["unset"])) then empty else "kind coverage is incomplete" end),
               (($p.drills // []) as $drills
                | if ($drills | type) != "array" then "drill list is malformed"
                  else ($pol.drills // ["unset"]) | map(. as $id
                         | ($drills | map(select(.id == $id)) ) as $found
                         | if ($found | length) == 0 then "a required drill is missing"
                           elif ($found | map(.result == "passed") | all) then empty
                           else "a required drill did not pass" end) | unique | .[]
                  end),
               (if (($p.drills // []) | type == "array") and (($p.drills // []) | map(.result == "passed") | all) then empty else "a drill did not pass" end),
               (if (($p.evidence // []) | type == "array") and (($p.evidence // []) | length > 0) then empty else "no evidence references" end)
           end)
        ] | unique)
      }
  ) catch {ours: false, problems: ["entry is malformed"]})' "$results" 2>/dev/null) || die "results could not be read"

[ -n "$verdicts" ] || die "no attestations in the results"
good=$(printf '%s\n' "$verdicts" | jq -s '[.[] | select(.problems | length == 0)] | length')
# An entry by the expected signer for this digest that reports anything but a
# passing, complete result vetoes the rest (a later pass does not outvote it).
vetoes=$(printf '%s\n' "$verdicts" | jq -s '[.[] | select(.ours and (.problems | length > 0))] | length')
if [ "$good" -ge 1 ] && [ "$vetoes" -eq 0 ]; then
    echo "verify-acceptance: $mode attestation accepted for $digest"
    exit 0
fi
{
    echo "verify-acceptance: refused: no attestation meets the $mode policy"
    printf '%s\n' "$verdicts" | jq -rs '[.[].problems[]] | unique | .[] | "  - " + .'
} >&2
exit 1
