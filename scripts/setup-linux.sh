#!/usr/bin/env bash
set -euo pipefail

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "run this setup as root" >&2; exit 1; }

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$script_dir/.." && pwd)
role=${1:-}
if [[ -n "$role" && "$role" != "relay" && "$role" != "gateway" && "$role" != "client" ]]; then
  echo "usage: sudo $0 [relay|gateway|client] [tlsnet-binary]" >&2
  exit 2
fi
binary=${2:-$root/tlsnet}
installer="$script_dir/install-linux.sh"

[[ -x "$binary" ]] || { echo "TlsNet binary is missing or not executable: $binary" >&2; exit 1; }
[[ -x "$installer" ]] || { echo "installer is missing or not executable: $installer" >&2; exit 1; }

installed_config=/etc/tlsnet/config.toml
if [[ -f "$installed_config" ]]; then
  read -r -p "Reuse existing $installed_config? [Y/n] " answer
  if [[ ! ${answer:-y} =~ ^[Nn]$ ]]; then
    exec "$installer" "$binary" "$installed_config"
  fi
fi

temporary=$(mktemp -d -t tlsnet-setup.XXXXXXXX)
cleanup() {
  if [[ -f "$temporary/config.toml" ]]; then
    chmod 0600 "$temporary/config.toml" 2>/dev/null || true
  fi
  rm -rf --one-file-system "$temporary"
}
trap cleanup EXIT

configure_args=(configure -o "$temporary/config.toml")
if [[ -n "$role" ]]; then
  configure_args+=(-role "$role")
fi
"$binary" "${configure_args[@]}"
"$installer" "$binary" "$temporary/config.toml"

echo
echo "Setup complete. Useful commands:"
echo "  systemctl status tlsnet --no-pager -l"
echo "  journalctl -u tlsnet -f"
echo "  ip address show tlsnet0"
