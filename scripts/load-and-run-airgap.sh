#!/usr/bin/env sh
set -eu

ARCHIVE="${1:?Usage: load-and-run-airgap.sh IMAGE_TAR [PORT] [DATA_PATH] [BIND_ADDRESS]}"
PORT="${2:-8765}"
DATA_PATH="${3:-./netatlas-data}"
BIND_ADDRESS="${4:-0.0.0.0}"
TAG="netatlas:1.2.3"

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
docker rm -f netatlas >/dev/null 2>&1 || true
docker run -d --name netatlas --restart unless-stopped \
  --cap-add NET_RAW --cap-add NET_ADMIN --security-opt no-new-privileges:true \
  -p "$BIND_ADDRESS:$PORT:8765" -v "$(cd "$DATA_PATH" && pwd):/app/data" "$TAG"
printf 'NetAtlas is starting on %s:%s\n' "$BIND_ADDRESS" "$PORT"
printf 'Remote URL: http://<NETATLAS-NODE-IP>:%s\n' "$PORT"
