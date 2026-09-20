#!/usr/bin/env sh
# Compatibility entrypoint for the Python applier image.
set -eu
exec python -m applier.apply "$@"
