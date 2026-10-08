FROM lscr.io/linuxserver/wireguard:1.0.20260223-r0-ls122@sha256:dca67384e3e9a5bcc288461fa983e6fcb0e248e5a2d8e5b3e5d3f753bfac3e35

# LinuxServer requires root-owned init scripts. Bundle this one instead of
# requiring the user's Git checkout to contain root-owned directories.
COPY --chown=0:0 --chmod=0755 routing/10-exit-routing /custom-cont-init.d/10-exit-routing
# The gluetun backend's guard sidecar reads the rule set it shares with
# NetBird's gate from here. The directory is made first: COPY --chmod would
# create it with the file's mode, 0644, which a root process without
# DAC_OVERRIDE (the guard runs with cap_drop ALL and NET_ADMIN only) cannot
# enter.
RUN install -d -m 0755 -o 0 -g 0 /usr/local/lib/molebridge
COPY --chown=0:0 --chmod=0644 routing/gluetun-rules /usr/local/lib/molebridge/gluetun-rules
