# syntax=docker/dockerfile:1
#
# The single Molebridge image: the molebridge binary (every role) and the
# pinned NetBird client. Roles are chosen by argument, never guessed from the
# environment (docs/architecture.md).
#
# Base images are pinned by tag and by the multi-arch index digest. Rebuild
# deliberately when one changes, then run docs/verification.md.

# Stage 1: the binary. The build runs on the builder's own architecture and
# cross-compiles for the target, so the arm64 image needs no emulation.
# golang:1.27.3-alpine, index digest read with `docker buildx imagetools inspect`.
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /src
# The build context is the allowlist in Dockerfile.dockerignore (Go sources, vendor/,
# embedded assets). vendor/ is used when the module has dependencies; a module
# with none builds with -mod=vendor as well.
COPY . .
RUN CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" GOTOOLCHAIN=local GOFLAGS=-mod=vendor \
    go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/molebridge ./cmd/molebridge

# Stage 2: the NetBird client release archive, checked against the hashes
# committed here. The hashes are the linux_amd64 and linux_arm64 lines of
#   https://github.com/netbirdio/netbird/releases/download/v0.80.0/netbird_0.80.0_checksums.txt
# Update the version and both hashes together.
# Alpine 3.24.2, as before: https://hub.docker.com/_/alpine
FROM --platform=$BUILDPLATFORM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS netbird
ARG TARGETARCH
ARG NETBIRD_VERSION=0.80.0
ARG NETBIRD_SHA256_AMD64=47ffaba4fc3929f31795bd6c5232d6c29744d3169e2c93e6d9c84624f0ef6405
ARG NETBIRD_SHA256_ARM64=8cbd99fa068a7b0f3968b2d31dc341acc17dd1e97c3053e61ed5905dbdae7341
RUN apk add --no-cache ca-certificates
WORKDIR /netbird
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) sha="$NETBIRD_SHA256_AMD64" ;; \
      arm64) sha="$NETBIRD_SHA256_ARM64" ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    archive="netbird_${NETBIRD_VERSION}_linux_${TARGETARCH}.tar.gz"; \
    wget -q -O "$archive" "https://github.com/netbirdio/netbird/releases/download/v${NETBIRD_VERSION}/${archive}"; \
    echo "${sha}  ${archive}" | sha256sum -c -; \
    tar -xzf "$archive" netbird LICENSE LICENSES/AGPL-3.0.txt LICENSES/BSD-3-Clause.txt LICENSES/REUSE.toml; \
    test -x netbird; \
    chmod 0755 netbird; \
    find LICENSE LICENSES -type d -exec chmod 0755 '{}' +; \
    find LICENSE LICENSES -type f -exec chmod 0644 '{}' +

# Stage 3: the image. Alpine, the CA bundle, the binary and the client.
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
LABEL org.opencontainers.image.title="Molebridge" \
      org.opencontainers.image.description="Exit-node supervisor, routing contract and Switchyard panel for a NetBird overlay" \
      org.opencontainers.image.source="https://github.com/irashack/molebridge" \
      org.opencontainers.image.licenses="MIT AND BSD-3-Clause"
# Tools come from the pinned base image's signed Alpine repositories. busybox
# stays for `docker exec` diagnostics; the binary never starts a shell.
RUN apk add --no-cache ca-certificates \
 && install -d -m 0755 -o 0 -g 0 /usr/share/licenses/molebridge /usr/share/licenses/netbird
COPY --from=build --chown=0:0 --chmod=0755 /out/molebridge /usr/local/bin/molebridge
COPY --from=netbird --chown=0:0 --chmod=0755 /netbird/netbird /usr/local/bin/netbird
# License notices travel with the binaries (THIRD_PARTY.md lists every
# component; the NetBird client is BSD-3-Clause). The directories are made
# above because COPY --chmod would create them with a file's mode.
COPY --from=netbird --chown=0:0 /netbird/LICENSE /usr/share/licenses/netbird/LICENSE
COPY --from=netbird --chown=0:0 /netbird/LICENSES/ /usr/share/licenses/netbird/LICENSES/
COPY --chown=0:0 --chmod=0644 LICENSE THIRD_PARTY.md /usr/share/licenses/molebridge/
COPY --chown=0:0 --chmod=0644 internal/applier/PIA-CA-LICENSE.txt /usr/share/licenses/molebridge/PIA-CA-LICENSE.txt
COPY --chown=0:0 --chmod=0644 panel/static/JetBrainsMono-OFL.txt /usr/share/licenses/molebridge/JetBrainsMono-OFL.txt
ENTRYPOINT ["/usr/local/bin/molebridge"]
