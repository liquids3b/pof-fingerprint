#!/usr/bin/env bash
# Запуск сервиса (используется systemd и для отладки вручную).
#
#   ./run.sh                      # захват + API, как под systemd
#   ./run.sh --capture-only       # только захват, без HTTP
#   ./run.sh --read dump.pcap     # разобрать готовый дамп и выйти
#
# Аргументы передаются в src/pof.py без изменений.
set -euo pipefail

PREFIX="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$PREFIX/venv/bin/python"
if [[ ! -x "$PY" ]]; then
  PY="$(command -v python3 || command -v python)"
fi

exec "$PY" "$PREFIX/src/pof.py" --config "$PREFIX/config.json" "$@"
