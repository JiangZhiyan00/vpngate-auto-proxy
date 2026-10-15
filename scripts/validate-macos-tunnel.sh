#!/bin/sh
# 普通用户启动；只有本机隧道子阶段会在终端请求管理员权限。
set -eu
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec python3 "$script_dir/macos_tunnel.py" "$@"
