#!/bin/sh
# 受控 Linux 验收；运行位置由部署者选择，不将容器结果冒充原生矩阵。
set -eu
case_name=us2
duration=1800
while [ "$#" -gt 0 ]; do
 case "$1" in
  --case) [ "$#" -ge 2 ] || exit 2; case_name=$2; shift 2 ;;
  --duration-seconds) [ "$#" -ge 2 ] || exit 2; duration=$2; shift 2 ;;
  *) echo "未知参数：$1" >&2; exit 2 ;;
 esac
done
case "$duration" in ''|*[!0-9]*) echo "持续秒数必须为正整数" >&2; exit 2;; esac
[ "$duration" -ge 3 ] || { echo "持续验收至少三秒，完整验收需要一千八百秒" >&2; exit 2; }
repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_dir"
case "$case_name" in
 all)
  [ "$duration" -ge 15 ] || { echo "容量聚合短试至少十五秒" >&2; exit 2; }
  cargo fmt --check
  cargo clippy --locked --all-targets -- -D warnings
  cargo test --locked
  cargo build --locked --release
  for scenario in us1 us2 us3 us4; do
   "$repo_dir/scripts/validate-linux.sh" --case "$scenario" --duration-seconds "$duration"
  done
  soak_binary="${CARGO_TARGET_DIR:-$repo_dir/target}/release/vpngate-auto-proxy"
  "$repo_dir/scripts/validate-soak.sh" --deployment native --clients 5 --connections 50 --duration-seconds "$duration" --binary "$soak_binary" --output "${VAP_SOAK_REPORT:-/tmp/vap-soak-native-report.json}"
  echo "本次环境及指定时长的聚合用例通过；目标原生矩阵、安全策略与完整长测仍须独立验收。"
  exit 0 ;;
 us1) exec tests/fixtures/run-us1.sh ;;
 us2|us3|us4) ;;
 *) echo "场景必须是 us1/us2/us3/us4/all" >&2; exit 2 ;;
esac
[ "${VAP_NETWORK_TEST:-}" = 1 ] && [ "$(uname -s)" = Linux ] && [ "$(id -u)" = 0 ] || { echo "需要显式授权的专用 Linux 管理员测试环境" >&2; exit 1; }
for tool in cargo ip nft openvpn openssl python3 setpriv nsenter tcpdump; do command -v "$tool" >/dev/null || { echo "缺少验收工具：$tool" >&2; exit 1; }; done
[ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ] || { echo "测试环境未准备 IPv4 转发" >&2; exit 1; }
fixture_root="$(mktemp -d /tmp/vap-validation.XXXXXX)"
export VAP_FIXTURE_DIR="$fixture_root/services"
export VAP_CANDIDATE_SOAK_SECONDS="$duration"
export VAP_RECOVERY_WAIT_SECONDS="$duration"
fixture_ready=0
finish() {
 result=$?
 trap - EXIT
 if [ "$fixture_ready" = 1 ] && ! tests/fixtures/cleanup.sh "$VAP_FIXTURE_DIR"; then echo "夹具清理失败：$fixture_root" >&2; exit 1; fi
 if [ "$result" = 0 ]; then rm -rf "$fixture_root"; else echo "验收失败，诊断目录：$fixture_root" >&2; fi
 exit "$result"
}
trap finish EXIT
tests/fixtures/setup.sh "$VAP_FIXTURE_DIR"
fixture_ready=1
cargo test --locked --offline --test contracts storage:: -- --test-threads=1
cargo test --locked --offline --test contracts scheduler:: -- --test-threads=1
case "$case_name" in
 us2) scenario=candidates ;;
 us3) scenario=failover; cargo test --locked --offline --test contracts failover:: -- --test-threads=1 ;;
 us4) scenario=lifecycle; cargo test --locked --offline --test contracts cli:: -- --test-threads=1 ;;
esac
cargo test --locked --offline --test integration "$scenario::" -- --ignored --test-threads=1 --nocapture
if [ "$duration" -ge 1800 ]; then echo "本次 Linux 环境的受控测试通过；其他平台及部署矩阵须分别验证。"; else echo "短时冒烟通过，不能替代三十分钟稳定性验收。"; fi
