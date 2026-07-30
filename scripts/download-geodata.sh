#!/usr/bin/env bash
# Скачивает базы геоданных Xray. Без них ядро отказывается стартовать с
# конфигом, где есть правила geoip:/geosite:, — а панель их обычно ставит.
set -euo pipefail

DEST="${1:-/var/lib/darkprince-vpn/geodata}"
BASE="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download"

mkdir -p "$DEST"
for name in geoip.dat geosite.dat; do
    echo "Скачиваю $name…"
    curl -fL --retry 3 -o "$DEST/$name" "$BASE/$name"
done
echo "Готово: $DEST"
