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

if [[ "${1:-}" != "--skip-apk" ]]; then
  gradle --no-daemon -p clients/android :app:assembleDebug
fi
