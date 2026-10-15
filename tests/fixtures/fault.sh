#!/bin/sh
# 仅作用于 setup.sh 创建的专用夹具。
set -eu
[ "${VAP_NETWORK_TEST:-}" = 1 ] || exit 1
directory="${1:?需要夹具目录}"
action="${2:?需要操作}"
case "$action" in
 node)
  protocol="${3:?需要承载}"
  case "$protocol" in tcp|udp) ;; *) exit 2;; esac
  case "${4:?需要 up 或 down}" in
   down)
    pid=$(cat "$directory/$protocol.pid")
    [ -r "/proc/$pid/cmdline" ] || exit 1
    tr '\000' ' ' < "/proc/$pid/cmdline" | grep -F -- "$directory/server-$protocol.conf" >/dev/null || exit 1
    kill "$pid"
    ;;
   up)
    if [ -f "$directory/$protocol.pid" ] && kill -0 "$(cat "$directory/$protocol.pid")" 2>/dev/null; then echo "节点进程仍然存在" >&2; exit 1; fi
    ip netns exec vap_fixture openvpn --config "$directory/server-$protocol.conf" --daemon --writepid "$directory/$protocol.pid" --log "$directory/$protocol.log"
    ;;
   *) exit 2;;
  esac
  ;;
 state)
  # 输入是完整 JSON 对象，原子替换，避免正在处理的请求读到半个文件。
  python3 - "$directory" "${3:?需要状态对象}" <<'PY'
import json, os, pathlib, sys
directory = pathlib.Path(sys.argv[1])
value = json.loads(sys.argv[2])
assert isinstance(value, dict)
path = directory / 'state.tmp'
path.write_text(json.dumps(value))
os.replace(path, directory / 'state.json')
PY
  ;;
 *) exit 2;;
esac
