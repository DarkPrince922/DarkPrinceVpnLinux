#!/usr/bin/env bash
# Проставляет версию приложения во все места, где она записана.
#
# Версия у релиза одна — из тега, — но лежит она в четырёх файлах, и разъехаться
# им нельзя. Особенно важен tauri.conf.json: именно эту версию приложение
# сравнивает с манифестом обновлений. Если она отстаёт от выпущенной, апдейтер
# предлагает одно и то же обновление бесконечно.
#
#   scripts/set-version.sh 1.2.0
#
# Файл менять руками не нужно: скрипт зовут из релизного workflow, а в
# репозитории остаётся версия последнего релиза.

set -euo pipefail

version=${1:-}
if [ -z "$version" ]; then
    echo "укажите версию: $0 1.2.0" >&2
    exit 1
fi
# тег приходит как v1.2.0, а в файлах версия без буквы
version=${version#v}

if ! printf '%s' "$version" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "версия должна быть вида 1.2.0, а не «$version»" >&2
    exit 1
fi

root=$(cd "$(dirname "$0")/.." && pwd)

# tauri.conf.json: ключ "version" в файле один, поэтому правим строкой, а не
# перезаписью JSON целиком — так в файле не меняется ничего лишнего
python3 - "$root/src-tauri/tauri.conf.json" "$version" <<'PY'
import re, sys
path, version = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8").read()
patched, count = re.subn(r'"version": "[^"]*"', f'"version": "{version}"', text, count=1)
if count != 1:
    sys.exit(f"в {path} не нашёлся ключ version")
open(path, "w", encoding="utf-8").write(patched)
PY

# Cargo.toml: версия пакета — первая строка вида version = "...".
# У зависимостей версия записана внутри фигурных скобок и под шаблон не идёт.
python3 - "$root/src-tauri/Cargo.toml" "$version" <<'PY'
import re, sys
path, version = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8").read()
patched, count = re.subn(r'(?m)^version = "[^"]*"', f'version = "{version}"', text, count=1)
if count != 1:
    sys.exit(f"в {path} не нашлась версия пакета")
open(path, "w", encoding="utf-8").write(patched)
PY

# Cargo.lock: без этого сборка пакета для Arch падает — там cargo зовётся с
# --locked, и он справедливо ругается, что замок разошёлся с Cargo.toml
python3 - "$root/src-tauri/Cargo.lock" "$version" <<'PY'
import re, sys
path, version = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8").read()
# версию правим только внутри блока своего пакета, чужие не трогаем
pattern = re.compile(r'(\[\[package\]\]\nname = "darkprince-vpn"\nversion = ")[^"]*(")')
patched, count = pattern.subn(rf'\g<1>{version}\g<2>', text, count=1)
if count != 1:
    sys.exit(f"в {path} не нашёлся пакет darkprince-vpn")
open(path, "w", encoding="utf-8").write(patched)
PY

# PKGBUILD: pacman по этой версии понимает, что вышло обновление
python3 - "$root/packaging/PKGBUILD" "$version" <<'PY'
import re, sys
path, version = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8").read()
patched, count = re.subn(r'(?m)^pkgver=.*$', f'pkgver={version}', text, count=1)
if count != 1:
    sys.exit(f"в {path} не нашлась pkgver")
open(path, "w", encoding="utf-8").write(patched)
PY

echo "версия $version проставлена"
grep -H '"version"' "$root/src-tauri/tauri.conf.json"
grep -Hm1 '^version = ' "$root/src-tauri/Cargo.toml"
grep -Hm1 '^pkgver=' "$root/packaging/PKGBUILD"
