#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$repo/clients/android/app/libs"
cd "$repo"
go tool gomobile init
go tool gomobile bind \
  -target=android \
  -androidapi 26 \
  -trimpath \
  -o clients/android/app/libs/tlsnet.aar \
  ./mobilecore

case "${1:-}" in
  --skip-apk)
    ;;
  --release)
    gradle --no-daemon -p clients/android :app:assembleRelease
    ;;
  "")
    gradle --no-daemon -p clients/android :app:assembleDebug
    ;;
  *)
    echo "usage: $0 [--release|--skip-apk]" >&2
    exit 2
    ;;
esac
