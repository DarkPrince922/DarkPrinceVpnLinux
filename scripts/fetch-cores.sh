#!/usr/bin/env bash
# Скачивает то, что приложение не умеет делать само: ядро Xray и мост
# tun2socks. Всё складывается в core/ рядом с приложением.
#
# В репозитории эти файлы не хранятся: вместе они весят десятки мегабайт,
# а обновляются независимо от приложения. Версии те же, что у Windows-версии:
# расходиться клиентам нельзя, иначе один и тот же конфиг панели будет
# работать по-разному.

set -euo pipefail

OUT=${1:-"$(dirname "$0")/../src-tauri/core"}
XRAY_VERSION=${XRAY_VERSION:-v26.7.28}
TUN2SOCKS_VERSION=${TUN2SOCKS_VERSION:-v2.7.0}

case "$(uname -m)" in
    x86_64)  XRAY_ARCH=64;    TUN_ARCH=amd64 ;;
    aarch64) XRAY_ARCH=arm64-v8a; TUN_ARCH=arm64 ;;
    *) echo "неизвестная архитектура: $(uname -m)" >&2; exit 1 ;;
esac

mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "Скачиваю Xray-core $XRAY_VERSION…"
curl -fsSL -o "$TMP/xray.zip" \
    "https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION/Xray-linux-$XRAY_ARCH.zip"
unzip -q -o "$TMP/xray.zip" -d "$TMP/xray"
install -m755 "$TMP/xray/xray" "$OUT/xray"
# базы geoip/geosite нужны правилам роутинга из конфига панели
for dat in geoip.dat geosite.dat; do
    [ -f "$TMP/xray/$dat" ] && install -m644 "$TMP/xray/$dat" "$OUT/$dat"
done

echo "Скачиваю tun2socks $TUN2SOCKS_VERSION…"
curl -fsSL -o "$TMP/tun2socks.zip" \
    "https://github.com/xjasonlyu/tun2socks/releases/download/$TUN2SOCKS_VERSION/tun2socks-linux-$TUN_ARCH.zip"
unzip -q -o "$TMP/tun2socks.zip" -d "$TMP/tun2socks"
install -m755 "$TMP/tun2socks/tun2socks-linux-$TUN_ARCH" "$OUT/tun2socks"

echo "Готово: $OUT"
ls -lh "$OUT"
