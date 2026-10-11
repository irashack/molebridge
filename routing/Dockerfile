FROM docker.io/library/alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

# Tools come from the pinned base image's signed Alpine repositories. Rebuild
# deliberately when upgrading, then run docs/verification.md. bash is for
# wg-quick; Molebridge's own scripts run under busybox sh.
RUN apk add --no-cache bash iproute2 wireguard-tools tini

# Root-owned, as a process without DAC_OVERRIDE needs to read them (the
# containers run with cap_drop ALL). The directory is made first: COPY --chmod
# would create it with the file's mode, 0644, which such a process cannot enter.
RUN install -d -m 0755 -o 0 -g 0 /usr/local/lib/molebridge
COPY --chown=0:0 --chmod=0755 routing/10-exit-routing /usr/local/lib/molebridge/10-exit-routing
COPY --chown=0:0 --chmod=0644 routing/contract-rules /usr/local/lib/molebridge/contract-rules
COPY --chown=0:0 --chmod=0755 routing/molebridge-exit /usr/local/bin/molebridge-exit

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/molebridge-exit"]
