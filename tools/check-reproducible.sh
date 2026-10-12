#!/usr/bin/env sh
# Builds the molebridge binary twice, from two copies of the source in
# different directories, with the flags the Dockerfile uses, and requires equal
# SHA-256 sums for linux/amd64 and linux/arm64. The OCI image is not claimed
# reproducible (Alpine packages and the NetBird archive are fetched at build
# time and pinned by digest and checksum); the binary is.
#   sh tools/check-reproducible.sh
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
fail() { echo "FAIL $1" >&2; exit 1; }

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
            go build -trimpath -buildvcs=false -ldflags="-s -w" -o "$work/$n-$arch" ./cmd/molebridge) ||
            fail "build $n for $arch"
    done
    a=$(sum "$work/one-$arch")
    b=$(sum "$work/two-$arch")
    [ "$a" = "$b" ] || fail "linux/$arch builds differ: $a $b"
    echo "PASS linux/$arch reproducible: $a"
done
