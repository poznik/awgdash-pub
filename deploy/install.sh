#!/bin/bash
# awgdash · установка/обновление на сервере. Запускать под root:
#   ssh <сервер> 'sudo -n bash -s' < deploy/install.sh
# Ожидает бинарник в /tmp/awgdash и юнит в /tmp/awgdash.service (кладёт make deploy). Идемпотентен.
set -euo pipefail
BIN=/opt/awgdash/awgdash
ENV=/etc/awgdash/awgdash.env

# Порт слушателя берётся из уже существующего .env: узлы парка могут слушать не 10088
# (у каждого свой порт), и проверять после установки надо именно их порт.
listen_port() {
  local listen=""
  [ -f "$ENV" ] && listen=$(sed -n 's/^AWGDASH_LISTEN=//p' "$ENV" | tail -1)
  listen=${listen##*:}
  case "$listen" in
    ''|*[!0-9]*) echo 10088 ;;
    *) echo "$listen" ;;
  esac
}

id awgdash >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin awgdash
install -d -o root -g root -m 0755 /opt/awgdash /etc/awgdash
install -d -o awgdash -g awgdash -m 0750 /var/lib/awgdash /var/lib/awgdash/backups /var/lib/awgdash/conf-backup
install -m 0755 -o root -g root /tmp/awgdash "$BIN.new" && mv -f "$BIN.new" "$BIN"
install -m 0644 -o root -g root /tmp/awgdash.service /etc/systemd/system/awgdash.service
rm -f /tmp/awgdash /tmp/awgdash.service

if [ ! -f "$ENV" ]; then
  umask 077
  cat > "$ENV" <<EOT
AWGDASH_MODE=${AWGDASH_MODE:-hub}
AWGDASH_LISTEN=${AWGDASH_LISTEN:-127.0.0.1:10088}
AWGDASH_DB=/var/lib/awgdash/awgdash.db
AWGDASH_DATA_DIR=/var/lib/awgdash
AWGDASH_AWG_CONF_DIR=/etc/amnezia/amneziawg
AWGDASH_SERVER_SLUG=$(hostname -s)
AWGDASH_SERVER_TITLE=$(hostname -s)
AWGDASH_TZ=UTC
AWGDASH_NODE_TOKEN=$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 40)
AWGDASH_SESSION_KEY=$(head -c 32 /dev/urandom | base64)
AWGDASH_FOREIGN_MANAGERS=wg-dashboard.service
AWGDASH_ADMIN_HOST=${AWGDASH_ADMIN_HOST:-}
EOT
  chmod 0600 "$ENV"; chown root:root "$ENV"
  echo "создан $ENV. Администратор заводится отдельно:"
  echo "  awgdash admin create <имя>   — пароль печатается один раз"
  echo "  внешнее имя задать в AWGDASH_ADMIN_HOST; Telegram и age — позже (M6/M7)"
fi

PORT=$(listen_port)
MODE=$(sed -n 's/^AWGDASH_MODE=//p' "$ENV" | tail -1)
# У узла открытого /healthz нет вовсе — только /v1/health под токеном. Проверять хаб и узел
# одним запросом нельзя: узел ответил бы 404 и установка выглядела бы сломанной.
if [ "$MODE" = node ]; then
  PROBE=("-H" "Authorization: Bearer $(sed -n 's/^AWGDASH_NODE_TOKEN=//p' "$ENV" | tail -1)")
  PATH_HEALTH=/v1/health
else
  PROBE=()
  PATH_HEALTH=/healthz
fi
systemctl daemon-reload
systemctl enable awgdash >/dev/null 2>&1 || true
systemctl restart awgdash
for i in 1 2 3 4 5 6 7 8 9 10; do curl -sf -m 2 "${PROBE[@]}" "http://127.0.0.1:$PORT$PATH_HEALTH" >/dev/null 2>&1 && break; sleep 1; done
systemctl is-active awgdash
echo "--- health (режим ${MODE:-hub}, порт $PORT):"; curl -sf -m 5 "${PROBE[@]}" "http://127.0.0.1:$PORT$PATH_HEALTH" || { echo "health не отвечает"; journalctl -u awgdash -n 30 --no-pager -o cat; exit 1; }
echo "--- версия:"; "$BIN" version
echo "--- слушатели:"; ss -lntp | grep -E ":$PORT" || echo "($PORT не слушается!)"
