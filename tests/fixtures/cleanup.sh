#!/bin/sh
set -eu
[ "${VAP_NETWORK_TEST:-}" = 1 ] || exit 1
directory="${1:?需要夹具目录}"
# 仅在隔离测试容器中使用固定夹具网络空间。
if ip netns list | awk '{print $1}' | awk '$0=="vap_fixture"{found=1} END {exit !found}'; then
 ip netns pids vap_fixture | xargs -r kill
 for attempt in 1 2 3 4 5; do [ -z "$(ip netns pids vap_fixture)" ] && break; sleep 1; done
 ip netns pids vap_fixture | xargs -r kill -KILL
 ip netns delete vap_fixture
fi
if [ -f "$directory/source.pid" ]; then
 pid="$(cat "$directory/source.pid")"
 # 检查命令行归属后才发送信号，避免过期 pid 误伤其他进程。
 if [ -r "/proc/$pid/cmdline" ] && tr '\000' ' ' < "/proc/$pid/cmdline" | awk -v d="$directory" 'index($0,"services.py --source") && index($0,d){found=1} END {exit !found}'; then kill "$pid"; fi
fi
if ip link show vfixture0 >/dev/null 2>&1; then ip link delete vfixture0; fi
