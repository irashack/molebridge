#!/usr/bin/env sh
# Writes the live-acceptance predicate (predicate type
# https://github.com/irashack/molebridge/attestations/live-acceptance/v1) to
# standard output, for acceptance.yml to attest. It refuses unless the
# maintainer's coverage satisfies the policy, so a "passed" attestation can
# only come from complete coverage with every required drill passed.
#
#   sh tools/make-acceptance-predicate.sh --repo OWNER/REPO --commit SHA \
#       --tag v0.8.0-rc.1 --image ghcr.io/irashack/molebridge --digest sha256:HEX \
#       --bundle-name FILE --bundle-sha256 HEX --coverage coverage.json \
#       --evidence evidence.json [--policy tools/acceptance-policy.json]
#
# coverage.json: {"platforms":[...],"providers":[...],"kinds":[...],
#                 "drills":[{"id":"client-held","result":"passed"},...]}
# evidence.json: ["https://...", "..."], at least one reference.
set -eu
LC_ALL=C
export LC_ALL
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
die() { echo "make-acceptance-predicate: refused: $1" >&2; exit 1; }
usage() {
    echo "usage: make-acceptance-predicate.sh --repo R --commit SHA --tag T --image NAME --digest sha256:HEX --bundle-name FILE --bundle-sha256 HEX --coverage FILE --evidence FILE [--policy FILE]" >&2
    exit 2
}
command -v jq >/dev/null 2>&1 || die "jq is required"

repo='' commit='' tag='' image='' digest='' bname='' bsha='' coverage='' evidence=''
policy=$here/acceptance-policy.json
while [ $# -gt 0 ]; do
    [ $# -ge 2 ] || usage
    case "$1" in
        --repo) repo=$2 ;;
        --commit) commit=$2 ;;
        --tag) tag=$2 ;;
        --image) image=$2 ;;
        --digest) digest=$2 ;;
        --bundle-name) bname=$2 ;;
        --bundle-sha256) bsha=$2 ;;
        --coverage) coverage=$2 ;;
        --evidence) evidence=$2 ;;
        --policy) policy=$2 ;;
        *) usage ;;
    esac
    shift 2
done
[ -n "$repo" ] && [ -n "$commit" ] && [ -n "$tag" ] && [ -n "$image" ] && [ -n "$digest" ] &&
    [ -n "$bname" ] && [ -n "$bsha" ] && [ -n "$coverage" ] && [ -n "$evidence" ] || usage

printf '%s' "$repo" | grep -Eq '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$' || die "repository must be OWNER/REPO"
printf '%s' "$commit" | grep -Eq '^[0-9a-f]{40}$' || die "commit must be a 40-digit lowercase hex SHA"
printf '%s' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+$' || die "tag must be a candidate tag like v0.8.0-rc.1"
printf '%s' "$image" | grep -Eq '^[a-z0-9.-]+(/[a-z0-9._-]+)+$' || die "image must be a fully qualified untagged name"
printf '%s' "$digest" | grep -Eq '^sha256:[0-9a-f]{64}$' || die "digest must be sha256: and 64 lowercase hex digits"
printf '%s' "$bsha" | grep -Eq '^[0-9a-f]{64}$' || die "bundle digest must be 64 lowercase hex digits"
printf '%s' "$bname" | grep -Eq '^molebridge-v[0-9.]+(-rc\.[0-9]+)?\.tar\.gz$' || die "bundle name is not a Molebridge bundle name"
[ -f "$policy" ] || die "no policy file"
[ -f "$coverage" ] || die "no coverage file"
[ -f "$evidence" ] || die "no evidence file"

jq -e '
  def strs: type == "array" and all(.[]; type == "string" and test("^[A-Za-z0-9._-]{1,64}$"));
  type == "object"
  and (.platforms | strs) and (.providers | strs) and (.kinds | strs)
  and (.drills | type == "array"
       and all(.[]; type == "object" and (.id | type == "string" and test("^[A-Za-z0-9._-]{1,64}$"))
                    and (.result | type == "string" and test("^[a-z]{1,16}$"))))' "$coverage" >/dev/null 2>&1 ||
    die "coverage is malformed"
jq -e 'type == "array" and length > 0 and length <= 50 and all(.[]; type == "string" and length >= 1 and length <= 500 and test("^[[:print:]]+$"))' "$evidence" >/dev/null 2>&1 ||
    die "evidence must be 1 to 50 printable references"

# Complete coverage and every drill passed, else nothing is written.
missing=$(jq -rn --slurpfile c "$coverage" --slurpfile p "$policy" '
  $c[0] as $c | $p[0] as $p
  | [ ($p.platforms[] | select(. as $w | ($c.platforms | index($w)) == null) | "platform " + .),
      ($p.providers[] | select(. as $w | ($c.providers | index($w)) == null) | "provider " + .),
      ($p.kinds[] | select(. as $w | ($c.kinds | index($w)) == null) | "kind " + .),
      ($p.drills[] | . as $id | select(($c.drills | map(select(.id == $id and .result == "passed")) | length) == 0) | "drill " + . + " (missing or not passed)"),
      ($c.drills[] | select(.result != "passed") | "drill " + .id + " did not pass")
    ] | unique | .[]') || die "policy could not be read"
if [ -n "$missing" ]; then
    {
        echo "make-acceptance-predicate: refused: coverage is incomplete or a drill did not pass:"
        printf '%s\n' "$missing" | sed 's/^/  - /'
    } >&2
    exit 1
fi

jq -n --slurpfile c "$coverage" --slurpfile p "$policy" --slurpfile e "$evidence" \
    --arg repo "$repo" --arg commit "$commit" --arg tag "$tag" --arg image "$image" --arg digest "$digest" \
    --arg bname "$bname" --arg bsha "$bsha" '
  {
    result: "passed",
    repository: $repo,
    commit: $commit,
    candidate: {tag: $tag, image: $image, digest: $digest},
    bundle: {name: $bname, sha256: $bsha},
    policy_version: $p[0].version,
    platforms: $c[0].platforms,
    providers: $c[0].providers,
    kinds: $c[0].kinds,
    drills: [$c[0].drills[] | {id, result}],
    evidence: $e[0]
  }'
