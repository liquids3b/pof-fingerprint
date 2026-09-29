#!/usr/bin/env bash
#
# Удаление pof-fingerprint: сервис, файлы, пользователь.
#   sudo /opt/pof-fingerprint/uninstall.sh
#   sudo PREFIX=/srv/pof /srv/pof/uninstall.sh
#
# Конфиг с api_key сохраняется в /root/pof-fingerprint-config.json — на случай,
# если вы передумаете.
set -euo pipefail

PREFIX="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="pof-fingerprint"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
SERVICE_USER="${SERVICE_USER:-pof}"
KEEP_CONFIG="${KEEP_CONFIG:-1}"

say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }

[[ "$(id -u)" == "0" ]] || { echo "запустите от root" >&2; exit 1; }

if command -v systemctl >/dev/null && [[ -f "$UNIT_PATH" ]]; then
  say "останавливаю и удаляю сервис"
  systemctl disable --now "$SERVICE_NAME" || true
  rm -f "$UNIT_PATH"
  systemctl daemon-reload || true
fi

if [[ "$KEEP_CONFIG" == "1" && -f "$PREFIX/config.json" ]]; then
  say "сохраняю config.json в /root/${SERVICE_NAME}-config.json"
  install -m 0600 "$PREFIX/config.json" "/root/${SERVICE_NAME}-config.json"
fi

say "удаляю $PREFIX"
rm -rf "$PREFIX"

if id -u "$SERVICE_USER" >/dev/null 2>&1; then
  say "удаляю пользователя $SERVICE_USER"
  userdel "$SERVICE_USER" || true
fi

say "готово. Конфиг nginx, если ставили: /etc/nginx/snippets/pof-fingerprint.conf"
