#!/bin/sh
# Online build-time assembly; the resulting runtime performs no downloads.
set -eu
umask 022
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SRC=$(CDPATH= cd -- "$HERE/../.." && pwd)
OUT=${1:?usage: assemble.sh OUTPUT_DIRECTORY}
case "$OUT" in /tmp/*|/var/tmp/*) ;; *) echo "refusing non-staging output: $OUT" >&2; exit 64;; esac
LOCK="$HERE/ubuntu-noble-amd64.lock"
IMAGE=$(sed -n 's/^base_image=//p' "$LOCK")
test -n "$IMAGE"
OUTPUT_UID=$(id -u)
OUTPUT_GID=$(id -g)
mkdir -p "$(dirname "$OUT")"
# The digest, exact requested versions, downloaded closure, and every artifact
# hash are recorded. Rebuilds do not silently accept a changed top-level version.
docker run --rm --platform linux/amd64 \
  -e OUTPUT_UID -e OUTPUT_GID -v "$SRC:/src:ro" -v "$(dirname "$OUT"):/output" "$IMAGE" \
  sh -c 'target="/output/$1"; rm -rf "$target"; mkdir -p "$target"; ln -s "$target" /out; sh /src/packaging/rootfs/in-container.sh; chown -R "$OUTPUT_UID:$OUTPUT_GID" "$target"' \
  -- "$(basename "$OUT")"
