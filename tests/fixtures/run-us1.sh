#!/bin/sh
# 在专用 Linux 测试环境运行故事一；不以本脚本代替真实局域网设备验收。
set -eu
[ "${VAP_NETWORK_TEST:-}" = 1 ] || { echo "必须显式设置 VAP_NETWORK_TEST=1" >&2; exit 1; }
[ "$(uname -s)" = Linux ] || { echo "需要专用 Linux 测试环境" >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo "受控网络验收需要管理员权限" >&2; exit 1; }
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_dir="$(CDPATH= cd -- "$script_dir/../.." && pwd)"
cd "$repo_dir"
for tool in cargo ip nft openvpn openssl python3 setpriv nsenter; do
 command -v "$tool" >/dev/null || { echo "缺少验收工具：$tool" >&2; exit 1; }
done
[ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ] || { echo "测试环境未准备 IPv4 转发" >&2; exit 1; }
fixture_root="$(mktemp -d /tmp/vap-us1.XXXXXX)"
export VAP_FIXTURE_DIR="$fixture_root/services"
fixture_ready=0
finish() {
 result=$?
 trap - EXIT
 if [ "$fixture_ready" = 1 ] && ! "$script_dir/cleanup.sh" "$VAP_FIXTURE_DIR"; then
  echo "受控夹具清理失败：$fixture_root" >&2
  exit 1
 fi
 if [ "$result" = 0 ]; then
  rm -rf "$fixture_root"
 else
  echo "验收失败，保留私有夹具诊断：$fixture_root" >&2
 fi
 exit "$result"
}
trap finish EXIT
"$script_dir/setup.sh" "$VAP_FIXTURE_DIR"
fixture_ready=1
for scenario in startup:: capacity:: network_foundation:: tunnels::; do
 cargo test --locked --offline --test integration "$scenario" -- --ignored --test-threads=1 --nocapture
done
cargo test --locked --offline --test contracts socks:: -- --ignored --test-threads=1 --nocapture
echo "故事一受控容器测试通过；真实局域网设备访问仍须另行验证。"
