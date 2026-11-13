#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: sudo $0 <tlsnet-binary> <config.toml>" >&2
  exit 2
}

[[ $# -eq 2 ]] || usage
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "run this installer as root" >&2; exit 1; }

binary=$(readlink -f "$1")
config=$(readlink -f "$2")
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$script_dir/.." && pwd)
unit="$root/packaging/linux/tlsnet.service"
if [[ ! -f "$unit" ]]; then
  unit="$script_dir/tlsnet.service"
fi

[[ -x "$binary" ]] || { echo "binary is missing or not executable: $binary" >&2; exit 1; }
[[ -f "$config" ]] || { echo "configuration is missing: $config" >&2; exit 1; }
[[ -f "$unit" ]] || { echo "systemd unit is missing: $unit" >&2; exit 1; }

"$binary" check -c "$config"
install -d -m 0750 /etc/tlsnet
install -m 0755 "$binary" /usr/local/bin/tlsnet.new
install -m 0600 "$config" /etc/tlsnet/config.toml.new
install -m 0644 "$unit" /etc/systemd/system/tlsnet.service.new
mv -f /usr/local/bin/tlsnet.new /usr/local/bin/tlsnet
mv -f /etc/tlsnet/config.toml.new /etc/tlsnet/config.toml
mv -f /etc/systemd/system/tlsnet.service.new /etc/systemd/system/tlsnet.service

systemctl daemon-reload
systemctl enable --now tlsnet.service
systemctl --no-pager --full status tlsnet.service
