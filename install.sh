#!/usr/bin/env bash
#
# Установка pof-fingerprint на сервер (Debian/Ubuntu, systemd).
#
#   sudo ./install.sh                # /opt/pof-fingerprint, страница http://IP:8351/
#   sudo ./install.sh --nginx        # плюс сниппет nginx; сервис остаётся на 127.0.0.1
#   sudo ./install.sh --local-only   # bind 127.0.0.1: наружу публикуете сами (nginx)
#   sudo ./install.sh --no-service   # только файлы, без systemd
#   sudo PREFIX=/srv/pof ./install.sh  # другой каталог
#   sudo bash install.sh             # так запускается даже из каталога с noexec (/tmp)
#
# Скрипт идемпотентен: повторный запуск обновляет код и перезапускает сервис.
set -euo pipefail

PREFIX="${PREFIX:-/opt/pof-fingerprint}"
SERVICE_USER="${SERVICE_USER:-pof}"
SERVICE_NAME="pof-fingerprint"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"

WITH_NGINX=0
WITH_SERVICE=1
WITH_LOCAL_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --nginx) WITH_NGINX=1 ;;
    --local-only) WITH_LOCAL_ONLY=1 ;;
    --no-service) WITH_SERVICE=0 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "неизвестный аргумент: $arg" >&2; exit 2 ;;
  esac
done

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m!!!\033[0m %s\n' "$*" >&2; exit 1; }

# Значение ключа из уже установленного конфига (нужен и до его чтения ниже:
# по api_host решаем, открывать ли порт в firewall).
read_config() {
  python3 -c "import json,sys;print(json.load(open(sys.argv[1]))[sys.argv[2]])" \
          "$PREFIX/config.json" "$1"
}

# Почему падает `sudo ./install.sh`: файл без бита +x (zip/scp его теряют) или
# каталог на noexec-монтировании (на части VPS это /tmp). Скрипту это не мешает
# работать, если запустить его через bash, поэтому не падаем, а подсказываем.
if [[ ! -x "$SRC_DIR/install.sh" ]]; then
  warn "у $SRC_DIR/install.sh нет бита +x — запускайте «sudo bash $SRC_DIR/install.sh»"
fi
if command -v findmnt >/dev/null 2>&1 \
   && findmnt -no OPTIONS --target "$SRC_DIR" 2>/dev/null | grep -q noexec; then
  warn "$SRC_DIR смонтирован с noexec: ./install.sh отсюда не запустится"
  warn "используйте «sudo bash $SRC_DIR/install.sh»; для постоянной установки"
  warn "держите исходники вне /tmp (его могут вычистить при перезагрузке)"
fi

[[ "$(id -u)" == "0" ]] || die "запустите от root: sudo $0 $*"
command -v python3 >/dev/null || die "нужен python3 (apt install -y python3 python3-venv)"

# --- 1. системный пользователь ------------------------------------------------
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  say "создаю системного пользователя $SERVICE_USER"
  useradd --system --home-dir "$PREFIX" --shell /usr/sbin/nologin "$SERVICE_USER"
fi

# --- 2. файлы -----------------------------------------------------------------
# Каталог могли скопировать из Windows (scp, архив, zip) — тогда в скриптах стоят
# CRLF, и `#!/usr/bin/env bash\r` просто не запускается: «env: $'bash\r': No such
# file or directory», а systemd на таком run.sh отдаёт status=127. Поэтому всё,
# что копируем на сервер, пишем без CR, а не «как лежит в исходниках».
install_text() {  # install_text MODE SRC DEST
  tr -d '\r' < "$2" > "$3"
  chmod "$1" "$3"
}
say "копирую файлы в $PREFIX"
install -d -m 0755 "$PREFIX"
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$PREFIX/log"
install_text 0644 "$SRC_DIR/config.json" "$PREFIX/config.json.new"
install_text 0644 "$SRC_DIR/requirements.txt" "$PREFIX/requirements.txt"
install_text 0755 "$SRC_DIR/run.sh" "$PREFIX/run.sh"
install_text 0755 "$SRC_DIR/uninstall.sh" "$PREFIX/uninstall.sh"
if [[ -f "$SRC_DIR/README.md" ]]; then
  install_text 0644 "$SRC_DIR/README.md" "$PREFIX/README.md"
fi
rm -rf "$PREFIX/src" "$PREFIX/tools" "$PREFIX/database"
cp -r "$SRC_DIR/src" "$SRC_DIR/tools" "$SRC_DIR/database" "$PREFIX/"
# Байткод, оставшийся от локальных запусков, на сервере не нужен.
rm -rf "$PREFIX/src/__pycache__" "$PREFIX/tools/__pycache__" "$PREFIX"/__pycache__
chown -R root:root "$PREFIX/src" "$PREFIX/tools" "$PREFIX/database"

# Существующий config.json не перетираем: там лежит api_key.
if [[ -f "$PREFIX/config.json" ]]; then
  say "config.json уже есть, оставляю как есть (новый — config.json.new)"
else
  mv "$PREFIX/config.json.new" "$PREFIX/config.json"
fi
chmod 0640 "$PREFIX/config.json"
chown root:"$SERVICE_USER" "$PREFIX/config.json"

# --- 2b. api_host: страница по IP сервера --------------------------------------
# «Открыть http://<ip-сервера>:8351/ в браузере» работает только при bind на
# 0.0.0.0. Раньше по умолчанию здесь был 127.0.0.1 (сервис прятали за nginx),
# поэтому старый конфиг переводим на 0.0.0.0 — иначе обновление оставило бы
# установку без страницы. Кому нужен только локальный bind (nginx с TLS,
# X-Real-IP) — запускайте с --local-only или --nginx.
set_host() {  # set_host HOST: меняем один api_host, api_key и прочее не трогаем
  python3 - "$PREFIX/config.json" "$1" <<'PY'
import json, sys
path, host = sys.argv[1], sys.argv[2]
with open(path, encoding='utf-8') as handle:
    config = json.load(handle)
if config.get('api_host') == host:
    sys.exit(0)
config['api_host'] = host
with open(path, 'w', encoding='utf-8') as handle:
    json.dump(config, handle, indent=2)
    handle.write('\n')
print(host)
PY
}

WANT_HOST="0.0.0.0"
if [[ "$WITH_NGINX" == "1" || "$WITH_LOCAL_ONLY" == "1" ]]; then
  WANT_HOST="127.0.0.1"
fi
HOST="$(read_config api_host 2>/dev/null || echo "$WANT_HOST")"
if [[ "$HOST" == "$WANT_HOST" ]]; then
  :
elif [[ "$HOST" == "127.0.0.1" ]]; then
  say "api_host был 127.0.0.1, ставлю 0.0.0.0: страница откроется по адресу сервера"
  set_host "$WANT_HOST" >/dev/null
elif [[ "$WANT_HOST" == "127.0.0.1" ]]; then
  say "api_host=$HOST, ставлю 127.0.0.1: наружу сервис публикует nginx"
  set_host "$WANT_HOST" >/dev/null
else
  say "api_host=$HOST оставляю как есть"
fi

# --- 3. python ----------------------------------------------------------------
# Сторонних зависимостей нет (только стандартная библиотека), поэтому venv —
# это просто изоляция от системных пакетов. Если python3-venv не установлен,
# спокойно работаем системным интерпретатором.
say "готовлю python"
if [[ ! -x "$PREFIX/venv/bin/python" ]]; then
  if python3 -m venv "$PREFIX/venv" >/dev/null 2>&1; then
    say "venv создан: $PREFIX/venv"
  else
    say "python3-venv недоступен, использую системный python3"
  fi
fi
# В requirements.txt могут быть одни комментарии: тогда ставить нечего и ходить
# в PyPI (на закрытом сервере его может и не быть) незачем — pip запускаем,
# только если есть строка с настоящим пакетом.
if [[ -x "$PREFIX/venv/bin/python" && -s "$PREFIX/requirements.txt" ]] \
   && grep -qE '^[[:space:]]*[^#[:space:]]' "$PREFIX/requirements.txt"; then
  "$PREFIX/venv/bin/pip" install --quiet --upgrade pip
  "$PREFIX/venv/bin/pip" install --quiet -r "$PREFIX/requirements.txt"
fi

# --- 4. api key ---------------------------------------------------------------
# Пустой ключ = открытый доступ. Ставим случайный, чтобы /fingerprints, /stats
# и /database не торчали наружу без пароля.
if grep -q '"api_key": ""' "$PREFIX/config.json"; then
  KEY="$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | cut -c1-24)"
  python3 - "$PREFIX/config.json" "$KEY" <<'PY'
import json, sys
path, key = sys.argv[1], sys.argv[2]
with open(path, encoding='utf-8') as handle:
    config = json.load(handle)
config['api_key'] = key
with open(path, 'w', encoding='utf-8') as handle:
    json.dump(config, handle, indent=2)
    handle.write('\n')
PY
  say "сгенерирован api_key: $KEY"
  say "он записан в $PREFIX/config.json (ищите ?key=... в примерах ниже)"
fi

# --- 5. параметры из конфига ---------------------------------------------------
# read_config() и HOST посчитаны выше (секция 2b).
PORT="$(read_config api_port)"
KEY="$(read_config api_key)"
# Ключ "database" необязательный (в config.py у него есть значение по умолчанию),
# поэтому читаем его мягко: из-за минимального config.json скрипт падать не должен.
DATABASE="$(read_config database 2>/dev/null || true)"
# Своя таблица отпечатков (database/mydb.pof.json) лежит в .gitignore, поэтому
# на свежем клонировании её на сервере не будет. Сервис от этого не падает, но
# молча отвечает "os": null — предупреждаем сразу, а не потом по логам.
if [[ -n "$DATABASE" && ! -f "$PREFIX/$DATABASE" && ! -f "$DATABASE" ]]; then
  warn "таблицы отпечатков нет: $DATABASE (API будет отвечать \"os\": null)"
  warn "положите файл рядом с конфигом или соберите: tools/import_db.py (чужая"
  warn "таблица) либо tools/build_db.py (свои дампы), см. README"
fi

# --- 6. systemd ---------------------------------------------------------------
if [[ "$WITH_SERVICE" == "1" ]]; then
  command -v systemctl >/dev/null || die "systemctl не найден, используйте --no-service"
  say "ставлю systemd юнит $UNIT_PATH"
  sed -e "s|/opt/pof-fingerprint|$PREFIX|g" \
      -e "s|^User=.*|User=$SERVICE_USER|" \
      -e "s|^Group=.*|Group=$SERVICE_USER|" \
      "$SRC_DIR/deploy/pof-fingerprint.service" | tr -d '\r' > "$UNIT_PATH"
  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME"
  # Именно restart, а не `enable --now`: на обновлении (git pull + install.sh)
  # сервис уже запущен, и --now оставил бы работать старый код из памяти.
  systemctl restart "$SERVICE_NAME"
  sleep 1
  systemctl --no-pager --lines=5 status "$SERVICE_NAME" || true
fi

# --- 7. nginx (необязательно) -------------------------------------------------
if [[ "$WITH_NGINX" == "1" ]]; then
  if command -v nginx >/dev/null; then
    say "добавляю location /fingerprint в nginx (порт $PORT)"
    install -d -m 0755 /etc/nginx/snippets
    sed -e "s|http://127.0.0.1:8351|http://127.0.0.1:$PORT|" \
        "$SRC_DIR/deploy/nginx-pof.conf" | tr -d '\r' > /etc/nginx/snippets/pof-fingerprint.conf
    say "подключите сниппет в нужный server{}: include snippets/pof-fingerprint.conf;"
    say "затем: nginx -t && systemctl reload nginx"
  else
    say "nginx не установлен, сниппет лежит в $SRC_DIR/deploy/nginx-pof.conf"
  fi
fi

# --- 8. доступ из браузера ------------------------------------------------------
# Адрес, по которому сервер видно снаружи: сначала спрашиваем ядро (src основного
# маршрута), а если iproute2 нет — берём первый адрес из hostname -I.
external_address() {
  local address
  address="$(ip -4 route get 1.1.1.1 2>/dev/null \
    | awk '{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}')" || true
  if [[ -z "$address" ]]; then
    address="$(hostname -I 2>/dev/null | awk '{print $1}')" || true
  fi
  printf '%s' "$address"
}

# Порт открываем сами, если firewall уже включён: ufw на Ubuntu/Debian,
# firewalld на RHEL-семействе. Облачный firewall (Vultr Firewall, Security
# Group) скрипту не виден — про него напоминаем отдельно.
open_firewall() {  # open_firewall PORT
  local port="$1"
  if command -v ufw >/dev/null 2>&1 \
     && ufw status 2>/dev/null | grep -qi '^Status: active'; then
    if ufw allow "$port"/tcp >/dev/null 2>&1; then
      say "ufw: порт $port/tcp открыт"
    fi
  elif command -v firewall-cmd >/dev/null 2>&1 \
       && firewall-cmd --state >/dev/null 2>&1; then
    if firewall-cmd --permanent --add-port="$port"/tcp >/dev/null 2>&1 \
       && firewall-cmd --reload >/dev/null 2>&1; then
      say "firewalld: порт $port/tcp открыт"
    fi
  fi
}

ADDR="$(external_address)"
URL="http://${ADDR:-<ip-сервера>}:$PORT/"
if [[ "$HOST" == "0.0.0.0" || "$HOST" == "::" ]]; then
  say "страница в браузере: $URL"
  open_firewall "$PORT"
  if [[ -n "$ADDR" ]]; then
    say "плюс откройте порт $PORT/tcp в облачном firewall провайдера"
    say "(Vultr Firewall / Security Group) — он живёт вне сервера"
  fi
fi
if [[ "$WITH_SERVICE" == "1" ]]; then
  say "проверяю API на 127.0.0.1:$PORT"
  if curl -fsS "http://127.0.0.1:$PORT/health"; then
    echo
  else
    die "сервис не отвечает: systemctl status $SERVICE_NAME; journalctl -u $SERVICE_NAME -n 50"
  fi
  if [[ -n "$ADDR" && "$HOST" != "127.0.0.1" && "$HOST" != "::1" ]]; then
    if curl -fsS --max-time 5 "http://$ADDR:$PORT/health" >/dev/null 2>&1; then
      say "снаружи тоже отвечает: $URL"
    else
      warn "по $URL ответа нет: порт закрыт firewall'ом (ufw/облачные правила)?"
    fi
  fi
  say "готово"
else
  say "юнит не ставился (--no-service). Запуск вручную: sudo $PREFIX/run.sh"
fi

# Строка про браузер: имеет смысл только при публичном bind.
BROWSER_LINE="  в браузере:     только localhost: публикуйте через nginx (README)"
if [[ "$HOST" == "0.0.0.0" || "$HOST" == "::" ]]; then
  BROWSER_LINE="  в браузере:     $URL"
fi

cat <<EOF

Дальше:
$BROWSER_LINE
  проверить:      curl -s "http://127.0.0.1:$PORT/fingerprint?detail=0"
  статистика:     curl -s "http://127.0.0.1:$PORT/stats?key=$KEY"
  логи:           journalctl -u $SERVICE_NAME -f
  база:           python3 $PREFIX/src/pof.py --list-database --config $PREFIX/config.json
  свой дамп:      tcpdump -i any -w /tmp/syn.pcap 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'
  удалить:        sudo $PREFIX/uninstall.sh
EOF
