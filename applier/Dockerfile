FROM docker.io/library/python:3.14.7-slim@sha256:51dafde81dbdb6ebde285137a295cf18a47ca95234fe388a343719cb97305b3d

# Tools come from the pinned base image's signed Debian repositories.
# Rebuild deliberately when upgrading, then run docs/verification.md.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 wireguard-tools curl ca-certificates nftables \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY molebridge /app/molebridge
COPY applier /app/applier
ENTRYPOINT ["python", "-m", "applier.apply"]
