# The image the routing drills run in: the Go toolchain used to build
# Molebridge, plus the iproute2, nftables and iputils the drills use to
# disturb a namespace from the outside and to look at it.
FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280
RUN apk add --no-cache iproute2 nftables iputils busybox-extras
