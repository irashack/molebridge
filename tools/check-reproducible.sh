#!/usr/bin/env sh
# Builds the molebridge binary twice, from two copies of the source in
# different directories, with the flags the Dockerfile uses, and requires equal
# SHA-256 sums for linux/amd64 and linux/arm64. The OCI image is not claimed
# reproducible (Alpine packages and the NetBird archive are fetched at build
# time and pinned by digest and checksum); the binary is. VERSION is the
# Dockerfile's build argument of that name (default dev), given to both builds.
#   [VERSION=v0.10.0-rc.1] sh tools/check-reproducible.sh
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
fail() { echo "FAIL $1" >&2; exit 1; }
version=${VERSION:-dev}
case "$version" in *[!0-9A-Za-z.+-]*) fail "VERSION must be a tag such as v0.10.0-rc.1" ;; esac

sum() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

for n in one two; do
    mkdir -p "$work/$n/src"
    # The tree git tracks (and untracked files it does not ignore), as a clean
    # checkout would carry it.
    (cd "$root" && git ls-files -z --cached --others --exclude-standard | tar --null -T - -cf -) |
        (cd "$work/$n/src" && tar -xf -)
done

for arch in amd64 arm64; do
    for n in one two; do
        (cd "$work/$n/src" &&
            CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOFLAGS=-mod=vendor GOTOOLCHAIN=local \
            go build -trimpath -buildvcs=false -ldflags="-s -w -X main.version=$version" -o "$work/$n-$arch" ./cmd/molebridge) ||
            fail "build $n for $arch"
    done
    a=$(sum "$work/one-$arch")
    b=$(sum "$work/two-$arch")
    [ "$a" = "$b" ] || fail "linux/$arch builds differ: $a $b"
    echo "PASS linux/$arch reproducible ($version): $a"
done

# The flag reached the binary: run the build that matches this machine, if one does.
case "$(uname -s)/$(uname -m)" in
    Linux/x86_64) native=amd64 ;;
    Linux/aarch64 | Linux/arm64) native=arm64 ;;
    *) native= ;;
esac
if [ -n "$native" ]; then
    got=$("$work/one-$native" version) || fail "the linux/$native build's version role failed"
    [ "$got" = "molebridge $version" ] || fail "the linux/$native build says '$got', want 'molebridge $version'"
    echo "PASS the binary reports molebridge $version"
fi
