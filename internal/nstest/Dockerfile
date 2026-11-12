# The image the routing drills run in: the Go toolchain used to build
# Molebridge, plus the iproute2, nftables and iputils the drills use to
# disturb a namespace from the outside and to look at it.
FROM golang:1.27.3-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18
RUN apk add --no-cache iproute2 nftables iputils busybox-extras
