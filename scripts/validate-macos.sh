#!/bin/sh
# 只读原生预检；不启动隧道，不修改宿主网络。
set -eu
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec python3 "$script_dir/validate_macos.py" "$@"
