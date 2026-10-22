# The image the routing drills run in: the Go toolchain used to build
# Molebridge, plus the iproute2, nftables and iputils the drills use to
# disturb a namespace from the outside and to look at it.
FROM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c
RUN apk add --no-cache iproute2 nftables iputils busybox-extras
