#!/bin/sh
# 普通用户终端启动短时句柄生命周期实验。
set -eu
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec python3 "$script_dir/macos_lease.py" "$@"
