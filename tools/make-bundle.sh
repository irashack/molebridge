#!/usr/bin/env sh
# Builds the installable bundle molebridge-<tag>.tar.gz: the Compose files, the
# .env examples, routing/gluetun-preflight, LICENSE and THIRD_PARTY.md, with
# every reference to the Molebridge image (ghcr.io/irashack/molebridge, in any
# form: bare name, a tag, a digest, a ${VAR:-default}, a <tag> placeholder)
# rewritten to the exact release reference
#   ghcr.io/irashack/molebridge:<tag>@<index digest>
# The rewrite keys on the image name, not on which file or key holds it, and
# the script refuses a bundle that would still carry any other reference, or a
# Compose file with none (an unpinned image would defeat the signature).
# Each Compose file also loses its `build:` keys and the comment block right
# above each: the bundle has no Dockerfile, and an installer that ran
# `compose build` or `up --build` would otherwise fail under the digest.
#
#   sh tools/make-bundle.sh <tag> <sha256:index-digest> [output-directory]
#
# <tag> is the release or candidate tag, v0.8.0 or v0.8.0-rc.1. The archive is
# deterministic: sorted names, one fixed mtime (SOURCE_DATE_EPOCH, default
# 946684800), owner 0:0, normalized modes, gzip without a name or timestamp.
# That needs GNU tar (tar, or gtar on a Mac).
#
# BUNDLE_SOURCE overrides the source tree (the default is the repository root).
set -eu
LC_ALL=C
export LC_ALL

usage() {
    echo "usage: make-bundle.sh <tag> <sha256:digest> [output-directory]" >&2
    exit 2
}
die() {
    echo "make-bundle: $1" >&2
    exit 1
}
[ $# -ge 2 ] && [ $# -le 3 ] || usage
tag=$1
digest=$2
outdir=${3:-.}
printf '%s' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$' ||
    die "tag must look like v0.8.0 or v0.8.0-rc.1: $tag"
printf '%s' "$digest" | grep -Eq '^sha256:[0-9a-f]{64}$' ||
    die "digest must be sha256: and 64 lowercase hex digits"

name=ghcr.io/irashack/molebridge
ref=$name:$tag@$digest
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
src=${BUNDLE_SOURCE:-$root}
epoch=${SOURCE_DATE_EPOCH:-946684800}
printf '%s' "$epoch" | grep -Eq '^[0-9]+$' || die "SOURCE_DATE_EPOCH must be a number"

tar_cmd=
for candidate in gtar tar; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" --version 2>/dev/null | grep -q 'GNU tar'; then
        tar_cmd=$candidate
        break
    fi
done
[ -n "$tar_cmd" ] || die "GNU tar is required (gtar on a Mac)"

# Required files, then any optional ones.
required=".env.example .env.gluetun.example .env.sidecar.example .env.native-sidecar.example compose.yaml compose.gluetun.yaml compose.sidecar.yaml compose.native-sidecar.yaml routing/gluetun-preflight LICENSE THIRD_PARTY.md"
optional=""
files=
for f in $required; do
    [ -f "$src/$f" ] && [ ! -L "$src/$f" ] || die "missing bundle file: $f"
    files="$files $f"
done
for f in $optional; do
    if [ -e "$src/$f" ] || [ -L "$src/$f" ]; then
        [ -f "$src/$f" ] && [ ! -L "$src/$f" ] || die "not a regular file: $f"
        files="$files $f"
    fi
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
stage=$work/molebridge-$tag
mkdir -p "$stage/routing"

# The image name followed by an optional :tag (or a :<placeholder>) and an
# optional @sha256: digest, and not by anything that would make it a longer
# name (molebridge-ci, molebridge/x) or another tag character.
pattern='ghcr\.io/irashack/molebridge(:([A-Za-z0-9_][A-Za-z0-9_.-]*|<[A-Za-z_-]+>))?(@sha256:[0-9a-fA-F]+)?([^A-Za-z0-9_.:@/-]|$)'
# strip_build: a Compose file without its `build:` keys. A key goes with every
# deeper-indented line under it and the comment lines directly above it at any
# indent; blank lines inside the block go too, one after it stays.
strip_build() {
    awk '
        function indent(line) { match(line, /^ */); return RLENGTH }
        skip >= 0 {
            if ($0 ~ /^[ \t]*$/) { blanks = blanks $0 "\n"; next }
            if (indent($0) > skip) { blanks = ""; next }
            skip = -1; printf "%s", blanks; blanks = ""
        }
        /^ *#/ { held = held $0 "\n"; next }
        /^ *build:/ { skip = indent($0); held = ""; next }
        { printf "%s", held; held = ""; print }
        END { printf "%s%s", held, blanks }
    ' skip=-1 "$1"
}
for f in $files; do
    dest=$stage/$f
    case "$f" in
        compose*.yaml)
            strip_build "$src/$f" | sed -E "s#$pattern#$ref\\4#g" > "$dest"
            if grep -Eq '^[[:space:]]*["'"'"']?build["'"'"']?[[:space:]]*:' "$dest"; then
                die "$f still has a build: key this script does not remove"
            fi
            ;;
        .env*.example | routing/gluetun-preflight)
            sed -E "s#$pattern#$ref\\4#g" "$src/$f" > "$dest"
            ;;
        *)
            cp "$src/$f" "$dest"
            ;;
    esac
    case "$f" in
        compose*.yaml | .env*.example | routing/gluetun-preflight)
            # Nothing may remain that names the image in another form.
            if sed "s#$ref#@@ref@@#g" "$dest" | grep -q "$name"; then
                die "$f still names the image in a form this script does not rewrite"
            fi
            ;;
    esac
    case "$f" in
        compose*.yaml)
            grep -qF "$ref" "$dest" || die "$f has no Molebridge image reference to pin"
            ;;
    esac
    case "$f" in
        routing/gluetun-preflight) chmod 0755 "$dest" ;;
        *) chmod 0644 "$dest" ;;
    esac
done
chmod 0755 "$stage" "$stage/routing"

mkdir -p "$outdir"
outdir=$(CDPATH='' cd -- "$outdir" && pwd)
archive=$outdir/molebridge-$tag.tar.gz
"$tar_cmd" -C "$work" --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
    --format=ustar -cf "$work/bundle.tar" "molebridge-$tag"
gzip -n -9 < "$work/bundle.tar" > "$work/bundle.tar.gz"
mv "$work/bundle.tar.gz" "$archive"
echo "$archive"
