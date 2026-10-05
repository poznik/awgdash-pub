#!/bin/bash
# awgdash · тестовый интерфейс awg-t0 в отдельном сетевом пространстве имён.
#
# Нужен, чтобы проверять запись в интерфейс (awg set, перезапись файла, verify, reconcile),
# не приближаясь к боевому интерфейсу. Всё живёт в netns awgdash-t0 и в /run — после `down`
# или перезагрузки не остаётся ничего.
#
#   sudo bash awg-t0.sh up     — поднять
#   sudo bash awg-t0.sh down   — снести
#   sudo bash awg-t0.sh env    — показать команду прогона интеграционных тестов
#
# Боевой интерфейс и его конфиг не затрагиваются: скрипт не вызывает
# awg-quick и systemctl и не пишет ничего вне /run/awgdash-t0.
set -euo pipefail

NS=awgdash-t0
IFACE=awg-t0
ROOT=/run/awgdash-t0
CONF_DIR="$ROOT/etc"
CONF="$CONF_DIR/$IFACE.conf"
AWG=${AWG:-awg}
# Порт слушателя. Интерфейс создаётся в корневом netns и лишь потом переезжает в тестовый, а сокет
# у AmneziaWG остаётся в том пространстве, где устройство создано, — значит порт должен быть свободен
# в КОРНЕВОМ netns. Если 51820 занят, стенд поднимают с другим портом: PORT=51999.
PORT=${PORT:-51820}

# Параметры обфускации — по образцу боевого интерфейса, но значения свои: файл и рантайм
# обязаны совпасть 12/12, а сами числа для проверки не важны.
JC=6; JMIN=20; JMAX=90
S1=40; S2=30; S3=12; S4=24
H1=100000001; H2=200000001; H3=300000001; H4=400000001
I1='<b 0xc70000000108><r 8><b 0x00004100><r 4>'

up() {
  mkdir -p "$CONF_DIR"
  chmod 0700 "$ROOT"

  local priv pub peer1 peer2 psk
  priv=$("$AWG" genkey)
  pub=$(printf '%s' "$priv" | "$AWG" pubkey)
  peer1=$(printf '%s' "$("$AWG" genkey)" | "$AWG" pubkey)
  peer2=$(printf '%s' "$("$AWG" genkey)" | "$AWG" pubkey)
  psk=$("$AWG" genpsk)

  # Файл в формате awg-quick — с ним работает панель.
  umask 077
  cat > "$CONF" <<EOT
[Interface]
Address = 10.77.0.1/24
MTU = 1280
# комментарий: панель обязана сохранить его байт в байт
ListenPort = $PORT
PrivateKey = $priv
Jc = $JC
Jmin = $JMIN
Jmax = $JMAX
S1 = $S1
S2 = $S2
S3 = $S3
S4 = $S4
H1 = $H1
H2 = $H2
H3 = $H3
H4 = $H4
I1 = $I1

[Peer]
PublicKey = $peer1
AllowedIPs = 10.77.0.2/32

[Peer]
PublicKey = $peer2
PresharedKey = $psk
AllowedIPs = 10.77.0.3/32
EOT

  # Тот же конфиг без ключей awg-quick — его понимает `awg setconf`.
  local setconf="$ROOT/setconf.conf"
  grep -v -E '^(Address|MTU|DNS|Table|PostUp|PostDown|PreUp|PreDown|SaveConfig|#)' "$CONF" > "$setconf"

  ip netns add "$NS" 2>/dev/null || true
  ip link add "$IFACE" type amneziawg
  ip link set "$IFACE" netns "$NS"
  ip netns exec "$NS" "$AWG" setconf "$IFACE" "$setconf"
  ip -n "$NS" addr add 10.77.0.1/24 dev "$IFACE"
  ip -n "$NS" link set "$IFACE" mtu 1280 up

  echo "интерфейс $IFACE поднят в netns $NS"
  ip netns exec "$NS" "$AWG" show "$IFACE" | head -5
  env_vars
}

down() {
  ip netns del "$NS" 2>/dev/null || true
  ip link del "$IFACE" 2>/dev/null || true
  rm -rf "$ROOT"
  echo "тестовое окружение снесено (netns $NS, $ROOT)"
}

env_vars() {
  # Тестовый процесс запускается внутри netns — тогда обычный `awg` работает с тестовым
  # интерфейсом, а обёртка не нужна (/run смонтирован с noexec).
  cat > "$ROOT/env" <<EOT
AWGDASH_IT_IFACE=$IFACE
AWGDASH_IT_CONF_DIR=$CONF_DIR
AWGDASH_IT_AWG_BIN=$(command -v "$AWG")
AWGDASH_IT_BACKUP_DIR=$ROOT/conf-backup
EOT
  cat <<EOT
--- прогон интеграционных тестов (бинарник кладётся отдельно):
  sudo ip netns exec $NS env \$(cat $ROOT/env | xargs) /tmp/node.test -test.run TestIntegration -test.v
EOT
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  env) env_vars ;;
  *) echo "использование: $0 up|down|env" >&2; exit 2 ;;
esac
