#!/usr/bin/env sh
set -eu

ARCHIVE="${1:?Usage: load-and-run-airgap.sh IMAGE_TAR [PORT] [DATA_PATH] [BIND_ADDRESS]}"
PORT="${2:-8765}"
DATA_PATH="${3:-./netatlas-data}"
BIND_ADDRESS="${4:-0.0.0.0}"
TAG="netatlas:1.2.4"

if [ -f "$ARCHIVE.sha256" ]; then
  EXPECTED_HASH=$(tr -d '\r' < "$ARCHIVE.sha256" | awk 'NR == 1 { print $1 }')
  ACTUAL_HASH=$(sha256sum "$ARCHIVE" | awk '{ print $1 }')
  if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
    printf 'Checksum verification failed for %s\n' "$ARCHIVE" >&2
    exit 1
  fi
  printf 'Checksum verified for %s\n' "$ARCHIVE"
fi
docker load --input "$ARCHIVE"
mkdir -p "$DATA_PATH"
RESOLVED_DATA_PATH="$(cd "$DATA_PATH" && pwd)"
# Normalize bind-mount ownership with the already-loaded image. This works offline
# and avoids root-owned folders blocking the non-root NetAtlas process (UID 10001).
docker run --rm --user 0:0 -v "$RESOLVED_DATA_PATH:/app/data:Z" "$TAG" \
  sh -c 'chown -R 10001:10001 /app/data && chmod 0750 /app/data'
docker rm -f netatlas >/dev/null 2>&1 || true
docker run -d --name netatlas --restart unless-stopped \
  --cap-add NET_RAW --cap-add NET_ADMIN --security-opt no-new-privileges:true \
  -p "$BIND_ADDRESS:$PORT:8765" -v "$RESOLVED_DATA_PATH:/app/data:Z" "$TAG"
printf 'NetAtlas is starting on %s:%s\n' "$BIND_ADDRESS" "$PORT"
printf 'Remote URL: http://<NETATLAS-NODE-IP>:%s\n' "$PORT"
