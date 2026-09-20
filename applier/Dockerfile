FROM docker.io/library/python:3.14.7-slim@sha256:cad9a2c871761c413caa6fdd6441c783451e740a48aaeba60ae62a8b53525ef6

# Tools come from the pinned base image's signed Debian repositories.
# Rebuild deliberately when upgrading, then run docs/verification.md.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 wireguard-tools curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY molebridge /app/molebridge
COPY applier /app/applier
ENTRYPOINT ["python", "-m", "applier.apply"]
