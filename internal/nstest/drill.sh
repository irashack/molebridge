#!/bin/sh
# Runs the routing drills (go test -tags drill) in a privileged throwaway
# container. Network namespaces are created inside the container only.
#
#   internal/nstest/drill.sh [go test arguments...]
#
# Default: go test -tags drill -count=1 ./internal/...
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
image=molebridge-drill:local
docker build -q -t "$image" -f "$here/internal/nstest/Dockerfile" "$here/internal/nstest" >/dev/null
[ "$#" -gt 0 ] || set -- -count=1 ./internal/...
# DRILL_CPUS limits the container (the CI runner has 2 vCPUs).
exec docker run --rm --privileged ${DRILL_CPUS:+--cpus="$DRILL_CPUS"} \
    -v "$here":/src -w /src \
    -v molebridge-drill-gocache:/root/.cache/go-build \
    -e GOFLAGS=-mod=vendor -e CGO_ENABLED=0 \
    "$image" go test -tags drill "$@"
