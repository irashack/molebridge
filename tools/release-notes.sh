#!/usr/bin/env sh
# Writes the body of a GitHub release: what the release is, the policy that
# says what to trust, and the verification steps in order. Used by release.yml
# for candidates and for promoted releases.
#
#   sh tools/release-notes.sh --kind candidate|release --tag TAG --commit SHA \
#       --digest sha256:INDEX --amd64 sha256:A --arm64 sha256:B \
#       [--build-tag RC_TAG]
#
# --build-tag is the candidate tag whose workflow run built the image; for a
# candidate it is the tag itself, so it may be left out.
set -eu
LC_ALL=C
export LC_ALL
die() { echo "release-notes: $1" >&2; exit 1; }
kind='' tag='' commit='' digest='' amd64='' arm64='' build_tag=''
while [ $# -gt 0 ]; do
    [ $# -ge 2 ] || die "missing value for $1"
    case "$1" in
        --kind) kind=$2 ;;
        --tag) tag=$2 ;;
        --commit) commit=$2 ;;
        --digest) digest=$2 ;;
        --amd64) amd64=$2 ;;
        --arm64) arm64=$2 ;;
        --build-tag) build_tag=$2 ;;
        *) die "unknown option $1" ;;
    esac
    shift 2
done
case "$kind" in candidate | release) ;; *) die "--kind must be candidate or release" ;; esac
printf '%s' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$' || die "bad tag"
printf '%s' "$commit" | grep -Eq '^[0-9a-f]{40}$' || die "bad commit"
for d in "$digest" "$amd64" "$arm64"; do
    printf '%s' "$d" | grep -Eq '^sha256:[0-9a-f]{64}$' || die "bad digest"
done
[ -n "$build_tag" ] || build_tag=$tag
printf '%s' "$build_tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+$' || die "the build tag must be a candidate tag"
if [ "$kind" = candidate ] && [ "$build_tag" != "$tag" ]; then die "a candidate is built by its own tag"; fi
if [ "$kind" = release ] && [ "$build_tag" = "$tag" ]; then die "a release is promoted from a candidate"; fi

repo=irashack/molebridge
image=ghcr.io/irashack/molebridge
issuer=https://token.actions.githubusercontent.com
wf=https://github.com/$repo/.github/workflows
build_id=$wf/release.yml@refs/tags/$build_tag
release_id=$wf/release.yml@refs/tags/$tag
accept_id=$wf/acceptance.yml@refs/heads/main
accept_type=https://github.com/irashack/molebridge/attestations/live-acceptance/v1
bundle=molebridge-$tag.tar.gz

if [ "$kind" = candidate ]; then
    echo "Release candidate $tag. It has not passed live acceptance; do not install it on an exit you rely on."
else
    echo "Molebridge $tag, promoted without rebuilding from candidate $build_tag, which passed live acceptance (experimental software; see the README)."
fi
cat <<EOM

Source commit: \`$commit\`
Image index: \`$image:$tag@$digest\`
Bundle: \`$bundle\` (Compose files with the image pinned to that reference, the \`.env\` examples, \`routing/gluetun-preflight\`, license notices)

## What to trust

| Material | Signed by (workflow identity) | Subject |
|---|---|---|
| Build provenance (SLSA) and SBOMs | \`$build_id\` | the image index and each architecture's manifest |
EOM
if [ "$kind" = release ]; then
    cat <<EOM
| Live-acceptance attestation | \`$accept_id\` | the image index; predicate type \`$accept_type\` |
| Image index signature | \`$release_id\` | the image index |
| Bundle signature and provenance | \`$release_id\` | \`$bundle\` |
EOM
else
    cat <<EOM
| Image index signature | \`$build_id\` | the image index |
| Bundle signature and provenance | \`$build_id\` | \`$bundle\` |
EOM
fi
cat <<EOM

OIDC issuer for every signature: \`$issuer\`. Expected source commit: \`$commit\`.
Tools: cosign v3.1.3, the GitHub CLI (gh) 2.102.0 or later, jq.

## Verify, in this order

1. Download the bundle and its Sigstore bundle (certificate and transparency-log entry) from this release's assets, then verify the bundle archive before extracting it:

   \`\`\`sh
   cosign verify-blob \\
     --bundle $bundle.sigstore.json \\
     --certificate-identity $( [ "$kind" = release ] && echo "$release_id" || echo "$build_id" ) \\
     --certificate-oidc-issuer $issuer \\
     $bundle
   gh attestation verify $bundle --repo $repo \\
     --cert-identity $( [ "$kind" = release ] && echo "$release_id" || echo "$build_id" ) \\
     --cert-oidc-issuer $issuer
   tar -xzf $bundle
   \`\`\`

2. Verify the image index signature, bound to the repository, the workflow identity, the issuer and the source commit. The image to verify is the pinned reference in the extracted \`compose.yaml\`:

   \`\`\`sh
   cosign verify \\
     --certificate-identity $( [ "$kind" = release ] && echo "$release_id" || echo "$build_id" ) \\
     --certificate-oidc-issuer $issuer \\
     --certificate-github-workflow-repository $repo \\
     --certificate-github-workflow-sha $commit \\
     $image@$digest
   \`\`\`

3. Verify the build provenance names this commit and the build workflow:

   \`\`\`sh
   gh attestation verify oci://$image@$digest --repo $repo \\
     --cert-identity $build_id \\
     --cert-oidc-issuer $issuer \\
     --source-digest $commit \\
     --predicate-type https://slsa.dev/provenance/v1
   \`\`\`

EOM
step=4
if [ "$kind" = release ]; then
    cat <<EOM
4. Verify the live-acceptance attestation, and read its result, commit and coverage:

   \`\`\`sh
   gh attestation verify oci://$image@$digest --repo $repo \\
     --cert-identity $accept_id \\
     --cert-oidc-issuer $issuer \\
     --predicate-type $accept_type \\
     --format json | jq '.[].verificationResult.statement.predicate'
   \`\`\`

   \`result\` must be \`passed\`, \`commit\` must be \`$commit\`, and the platforms, providers, kinds and drills must be the ones you need.

EOM
    step=5
fi
cat <<EOM
$step. Verify each architecture's SBOM attestation (the manifests the signed index references):

   \`\`\`sh
   for manifest in $amd64 $arm64; do
     gh attestation verify oci://$image@\$manifest --repo $repo \\
       --cert-identity $build_id \\
       --cert-oidc-issuer $issuer \\
       --predicate-type https://spdx.dev/Document/v2.3
   done
   \`\`\`

   The SBOM documents are also attached to this release.

$((step + 1)). Start the exit with the verified files only: edit \`.env\` from \`.env.example\` (or \`.env.sidecar.example\`), then \`docker compose up -d\`. The Compose files reference the image by digest, so the image that runs is the one verified above.

Architecture manifests: linux/amd64 \`$amd64\`, linux/arm64 \`$arm64\`.
EOM
