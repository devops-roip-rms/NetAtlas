#!/usr/bin/env sh
set -eu

TAG="${1:-netatlas:1.2.2}"
PLATFORM="${2:-linux/amd64}"
APP_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DIST="$APP_ROOT/dist"
SAFE_PLATFORM=$(printf '%s' "$PLATFORM" | tr '/' '-')
ARCHIVE="$DIST/netatlas-1.2.2-$SAFE_PLATFORM.tar"

docker info >/dev/null
mkdir -p "$DIST"
docker build --platform "$PLATFORM" --build-arg APP_VERSION=1.2.2 --tag "$TAG" "$APP_ROOT"
docker save --output "$ARCHIVE" "$TAG"
(cd "$DIST" && sha256sum "$(basename "$ARCHIVE")" > "$(basename "$ARCHIVE").sha256")
cp "$APP_ROOT/scripts/load-and-run-airgap.ps1" "$DIST/"
cp "$APP_ROOT/scripts/load-and-run-airgap.sh" "$DIST/"
cp "$APP_ROOT/AIRGAP.md" "$DIST/"
cp "$APP_ROOT/ROADMAP.md" "$DIST/"
cp "$APP_ROOT/CHANGELOG.md" "$DIST/"
printf 'Offline bundle created: %s\n' "$ARCHIVE"
