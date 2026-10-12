# The image the routing drills run in: the Go toolchain used to build
# Molebridge, plus the iproute2, nftables and iputils the drills use to
# disturb a namespace from the outside and to look at it.
FROM golang:1.27.1-alpine
RUN apk add --no-cache iproute2 nftables iputils busybox-extras
