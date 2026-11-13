#!/usr/bin/env bash
set -euo pipefail

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "run this uninstaller as root" >&2; exit 1; }

systemctl disable --now tlsnet.service 2>/dev/null || true
rm -f /etc/systemd/system/tlsnet.service /usr/local/bin/tlsnet
systemctl daemon-reload
systemctl reset-failed tlsnet.service 2>/dev/null || true

if [[ ${1:-} == "--purge" ]]; then
  rm -rf --one-file-system /etc/tlsnet
  echo "TlsNet and /etc/tlsnet were removed"
else
  echo "TlsNet was removed; /etc/tlsnet/config.toml was preserved"
fi
