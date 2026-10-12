#!/usr/bin/env sh
# Checks the documentation's links: every relative link and image in the
# Markdown files (and the HTML in the README) must point at a file or
# directory that exists, and every #anchor must match a heading of the file it
# names, by GitHub's rule for heading anchors (lowercase, punctuation dropped,
# spaces to hyphens, a repeated heading numbered -1, -2). Links to other sites
# are not fetched. Text inside code fences is ignored.
#
#   sh tools/check-doc-links.sh        exit 1 and list every broken link
#
# POSIX sh and awk only; reads the checkout, writes nothing in it.
set -eu
LC_ALL=C
export LC_ALL
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

files=$(ls README.md CONTRIBUTING.md ROADMAP.md SECURITY.md CHANGELOG.md AGENTS.md THIRD_PARTY.md docs/*.md 2>/dev/null)

# 1. The anchors of every file: <work>/<path with / as _>.anchors
for f in $files; do
    awk -v out="$work/$(printf '%s' "$f" | tr '/' '_').anchors" '
        /^(```|~~~~)/ { fence = !fence; next }
        fence { next }
        /^#+ / {
            text = $0
            sub(/^#+ +/, "", text)
            sub(/ +#+ *$/, "", text)
            while (match(text, /\[[^]]*\]\([^)]*\)/)) {
                link = substr(text, RSTART, RLENGTH)
                label = link
                sub(/\]\(.*$/, "", label)
                sub(/^\[/, "", label)
                text = substr(text, 1, RSTART - 1) label substr(text, RSTART + RLENGTH)
            }
            gsub(/`/, "", text)
            gsub(/[*]/, "", text)
            text = tolower(text)
            gsub(/[^a-z0-9 _-]/, "", text)
            gsub(/ /, "-", text)
            n = seen[text]++
            print (n ? text "-" n : text) > out
        }
        END { close(out) }
    ' "$f"
    [ -f "$work/$(printf '%s' "$f" | tr '/' '_').anchors" ] || : > "$work/$(printf '%s' "$f" | tr '/' '_').anchors"
done

# 2. The links.
status=0
for f in $files; do
    dir=$(dirname "$f")
    awk -v file="$f" -v dir="$dir" -v work="$work" '
        function key(path) { gsub(/\//, "_", path); return work "/" path ".anchors" }
        function normalize(path,    parts, n, i, out, m, stack) {
            n = split(path, parts, "/")
            m = 0
            for (i = 1; i <= n; i++) {
                if (parts[i] == "" || parts[i] == ".") continue
                if (parts[i] == ".." ) { if (m > 0) m--; else return "../"; continue }
                stack[++m] = parts[i]
            }
            out = ""
            for (i = 1; i <= m; i++) out = out (i > 1 ? "/" : "") stack[i]
            return out
        }
        function exists(path,    cmd, rc) {
            cmd = "test -e \"" path "\""
            rc = system(cmd)
            return rc == 0
        }
        function has_anchor(path, frag,    k, line, found) {
            k = key(path)
            found = 0
            while ((getline line < k) > 0) if (line == frag) { found = 1; break }
            close(k)
            return found
        }
        function check(target, lineno,    path, frag, full, hash) {
            if (target ~ /^(https?:|mailto:|tel:)/) return
            hash = index(target, "#")
            if (hash) { path = substr(target, 1, hash - 1); frag = substr(target, hash + 1) }
            else { path = target; frag = "" }
            if (path == "") full = file
            else full = normalize((dir == "." ? "" : dir "/") path)
            if (full == "../" || !exists(full)) {
                printf "%s:%d: %s does not exist\n", file, lineno, target
                bad = 1
                return
            }
            if (frag != "" && full ~ /\.md$/ && !has_anchor(full, frag)) {
                printf "%s:%d: %s has no heading #%s\n", file, lineno, full, frag
                bad = 1
            }
        }
        /^(```|~~~~)/ { fence = !fence; next }
        fence { next }
        {
            line = $0
            # Markdown links and images: ](target)
            rest = line
            while (match(rest, /\]\([^) ]+[) ]/)) {
                t = substr(rest, RSTART + 2, RLENGTH - 3)
                check(t, NR)
                rest = substr(rest, RSTART + RLENGTH)
            }
            # HTML attributes: href="..." and src="..."
            rest = line
            while (match(rest, /(href|src)="[^"]+"/)) {
                t = substr(rest, RSTART, RLENGTH)
                sub(/^(href|src)="/, "", t)
                sub(/"$/, "", t)
                check(t, NR)
                rest = substr(rest, RSTART + RLENGTH)
            }
        }
        END { exit bad ? 1 : 0 }
    ' "$f" || status=1
done

if [ "$status" -ne 0 ]; then
    echo "check-doc-links: broken links" >&2
    exit 1
fi
echo "check-doc-links: every link and anchor resolves"
