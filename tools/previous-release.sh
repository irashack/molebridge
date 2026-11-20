#!/usr/bin/env sh
# Builds the previous release's molebridge binary for CI's upgrade drill
# (internal/exit/systemrig_upgrade_test.go) and checks that it is the binary
# the release shipped.
#
#   GH_TOKEN=... sh tools/previous-release.sh OUT_DIR
#
# The previous release is the newest final tag (vX.Y.Z, no -rc) that is an
# ancestor of HEAD and does not point at HEAD itself, so it moves forward with
# each release and needs no edit. The binary is built from that tag's source
# with the release flags (tools/check-reproducible.sh) and the Go toolchain
# the tag's Dockerfile names, stamped with the candidate tag the release was
# promoted from, as the release image's binary is. It must then hash equal to
# /usr/local/bin/molebridge in the release's linux/amd64 image, pulled by the
# index digest the GitHub release names (an immutable release, read through
# the API with GH_TOKEN). It needs git with the tags fetched, gh, docker and
# the Go command, and the network to reach the GitHub API, ghcr.io and, when
# the tag names another Go release, the Go toolchain download.
#
# Writes OUT_DIR/molebridge and OUT_DIR/previous.env (PREVIOUS_TAG,
# PREVIOUS_BUILD_TAG, PREVIOUS_COMMIT, PREVIOUS_IMAGE, PREVIOUS_SHA256).
set -eu
LC_ALL=C
export LC_ALL
die() { echo "previous-release: $1" >&2; exit 1; }
[ $# -eq 1 ] || die "usage: previous-release.sh OUT_DIR"
out=$1
repo=${GITHUB_REPOSITORY:-irashack/molebridge}
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

sum() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

head=$(git rev-parse HEAD)
prev=''
for t in $(git tag --merged HEAD --list 'v[0-9]*' --sort=-v:refname); do
    case "$t" in *[!0-9v.]*) continue ;; esac
    printf '%s\n' "$t" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || continue
    [ "$(git rev-parse "$t^{commit}")" = "$head" ] && continue
    prev=$t
    break
done
[ -n "$prev" ] || die "no final release tag is an ancestor of HEAD (fetch the tags: fetch-depth 0)"
commit=$(git rev-parse "$prev^{commit}")
echo "previous-release: the previous release is $prev ($commit)"

# What the release says it is: its source commit, the candidate it was
# promoted from, and the image index.
body=$(gh release view "$prev" -R "$repo" --json body,isDraft,isPrerelease \
    -q 'if .isDraft or .isPrerelease then "" else .body end') || die "can't read the GitHub release $prev"
[ -n "$body" ] || die "$prev is not a published final release"
build_tag=$(printf '%s\n' "$body" | sed -n "s/^Molebridge $prev, promoted without rebuilding from candidate \\(v[0-9.]*-rc\\.[0-9]*\\),.*/\\1/p" | head -n 1)
[ -n "$build_tag" ] || die "the release notes of $prev name no candidate"
noted_commit=$(printf '%s\n' "$body" | sed -n 's/^Source commit: `\([0-9a-f]\{40\}\)`$/\1/p' | head -n 1)
[ "$noted_commit" = "$commit" ] || die "the release notes of $prev name commit '$noted_commit', the tag is $commit"
image=$(printf '%s\n' "$body" | sed -n "s/^Image index: \`\\(ghcr\\.io\\/[a-z0-9/-]*molebridge:$prev@sha256:[0-9a-f]\\{64\\}\\)\`.*/\\1/p" | head -n 1)
[ -n "$image" ] || die "the release notes of $prev name no image index"
echo "previous-release: promoted from $build_tag; image $image"

# The tag's Go toolchain, from its Dockerfile's golang image.
gover=$(git show "$prev:Dockerfile" | sed -n 's/^FROM .*golang:\([0-9][0-9.]*\)-alpine@.*/\1/p' | head -n 1)
[ -n "$gover" ] || die "can't read the Go version from $prev's Dockerfile"

work=$(mktemp -d)
cid=''
cleanup() {
    [ -z "$cid" ] || docker rm "$cid" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$work/src" "$out"
git archive "$prev" | tar -x -C "$work/src"
(cd "$work/src" &&
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOFLAGS=-mod=vendor GOTOOLCHAIN="go$gover" \
    go build -trimpath -buildvcs=false -ldflags="-s -w -X main.version=$build_tag" -o "$work/molebridge" ./cmd/molebridge) ||
    die "build of $prev failed"
built=$(sum "$work/molebridge")
echo "previous-release: built $prev with go$gover: $built"

docker pull -q --platform linux/amd64 "$image" >/dev/null || die "can't pull $image"
cid=$(docker create --platform linux/amd64 "$image")
docker cp "$cid:/usr/local/bin/molebridge" "$work/released" >/dev/null
released=$(sum "$work/released")
[ "$built" = "$released" ] || die "the build of $prev ($built) differs from the released linux/amd64 binary ($released)"
echo "previous-release: equal to the released linux/amd64 binary"

got=$("$work/molebridge" version) || die "the built binary's version role failed"
[ "$got" = "molebridge $build_tag" ] || die "the built binary says '$got', want 'molebridge $build_tag'"
install -m 0755 "$work/molebridge" "$out/molebridge"
{
    echo "PREVIOUS_TAG=$prev"
    echo "PREVIOUS_BUILD_TAG=$build_tag"
    echo "PREVIOUS_COMMIT=$commit"
    echo "PREVIOUS_IMAGE=$image"
    echo "PREVIOUS_SHA256=$built"
} >"$out/previous.env"
echo "previous-release: $out/molebridge is $prev"
