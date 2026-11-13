#!/usr/bin/env bash
set -euo pipefail

repository="ykkaabb/tlsnet"
role=${1:-}
if [[ "$role" != "relay" && "$role" != "gateway" && "$role" != "client" ]]; then
  echo "usage: curl .../bootstrap-linux.sh | sudo bash -s -- relay|gateway|client" >&2
  exit 2
fi
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "run the bootstrap through sudo" >&2; exit 1; }
[[ -r /dev/tty ]] || { echo "an interactive terminal is required for the password prompt" >&2; exit 1; }

case "$(uname -m)" in
  x86_64|amd64) architecture=amd64 ;;
  aarch64|arm64) architecture=arm64 ;;
  *) echo "unsupported Linux architecture: $(uname -m)" >&2; exit 1 ;;
esac

temporary=$(mktemp -d -t tlsnet-bootstrap.XXXXXXXX)
cleanup() {
  rm -rf --one-file-system "$temporary"
}
trap cleanup EXIT

authorization=()
if [[ -n ${TLSNET_GITHUB_TOKEN:-} ]]; then
  authorization=(-H "Authorization: Bearer $TLSNET_GITHUB_TOKEN")
fi

fetch() {
  local url=$1 destination=$2
  if command -v curl >/dev/null 2>&1; then
    curl --fail --silent --show-error --location "${authorization[@]}" \
      -H "X-GitHub-Api-Version: 2022-11-28" "$url" -o "$destination"
  elif command -v wget >/dev/null 2>&1; then
    local headers=()
    if [[ -n ${TLSNET_GITHUB_TOKEN:-} ]]; then
      headers=(--header="Authorization: Bearer $TLSNET_GITHUB_TOKEN")
    fi
    wget -q "${headers[@]}" -O "$destination" "$url"
  else
    echo "curl or wget is required" >&2
    exit 1
  fi
}

api="https://api.github.com/repos/$repository/releases/latest"
if ! fetch "$api" "$temporary/release.json"; then
  echo "Could not read the latest TlsNet release." >&2
  exit 1
fi
tag=$(sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' "$temporary/release.json" | head -n 1)
[[ -n "$tag" ]] || { echo "latest release has no tag" >&2; exit 1; }

asset="tlsnet-$tag-linux-$architecture.tar.gz"
base="https://github.com/$repository/releases/download/$tag"
echo "Downloading TlsNet $tag for linux/$architecture..."
fetch "$base/$asset" "$temporary/$asset"
fetch "$base/SHA256SUMS" "$temporary/SHA256SUMS"
expected=$(awk -v name="$asset" '$2 == name || $2 == "*" name { print $1; exit }' "$temporary/SHA256SUMS")
[[ -n "$expected" ]] || { echo "release checksum for $asset is missing" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$temporary/$asset" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$temporary/$asset" | awk '{print $1}')
elif command -v openssl >/dev/null 2>&1; then
  actual=$(openssl dgst -sha256 "$temporary/$asset" | awk '{print $NF}')
else
  echo "sha256sum, shasum, or openssl is required to verify the download" >&2
  exit 1
fi
[[ "$actual" == "$expected" ]] || { echo "TlsNet archive SHA-256 mismatch" >&2; exit 1; }

mkdir "$temporary/package"
tar -xzf "$temporary/$asset" -C "$temporary/package"
"$temporary/package/scripts/setup-linux.sh" "$role" "$temporary/package/tlsnet" </dev/tty
