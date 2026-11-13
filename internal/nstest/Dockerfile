# The image the routing drills run in: the Go toolchain used to build
# Molebridge, plus the iproute2, nftables and iputils the drills use to
# disturb a namespace from the outside and to look at it.
FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf
RUN apk add --no-cache iproute2 nftables iputils busybox-extras
