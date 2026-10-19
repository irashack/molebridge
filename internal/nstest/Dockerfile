# The image the routing drills run in: the Go toolchain used to build
# Molebridge, plus the iproute2, nftables and iputils the drills use to
# disturb a namespace from the outside and to look at it.
FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d
RUN apk add --no-cache iproute2 nftables iputils busybox-extras
