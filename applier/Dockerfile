FROM docker.io/library/python:3.14.7-slim@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2

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
