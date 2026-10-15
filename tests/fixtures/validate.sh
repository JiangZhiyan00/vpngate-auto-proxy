#!/bin/sh
# 独立验证夹具，不代替产品启动、隔离或代理验收。
set -eu
[ "${VAP_NETWORK_TEST:-}" = 1 ] || exit 1
directory="${1:?需要已经启动的夹具目录}"
namespace=vap_fixture_check
[ ! -e "/run/netns/$namespace" ] || { echo "夹具验证名称已占用" >&2; exit 1; }
cleanup() {
 if [ -e "/run/netns/$namespace" ]; then
  ip netns pids "$namespace" | xargs -r kill -KILL
  ip netns delete "$namespace"
 fi
 ip link delete vfcheck0 2>/dev/null || true
 nft delete table inet vap_fixture_check 2>/dev/null || true
}
trap cleanup EXIT
ip netns add "$namespace"
ip link add vfcheck0 type veth peer name vfcheck1
ip addr add 10.232.0.1/30 dev vfcheck0
ip link set vfcheck0 up
ip link set vfcheck1 netns "$namespace"
ip netns exec "$namespace" ip addr add 10.232.0.2/30 dev vfcheck1
ip netns exec "$namespace" ip link set vfcheck1 up
ip netns exec "$namespace" ip link set lo up
ip netns exec "$namespace" ip route add 11.53.0.2/32 via 10.232.0.1
nft -f - <<'RULES'
table inet vap_fixture_check {
 chain postrouting {
  type nat hook postrouting priority srcnat; policy accept;
  ip saddr 10.232.0.2 ip daddr 11.53.0.2 oifname "vfixture0" masquerade
 }
}
RULES
curl -fsS http://127.0.0.1:18080/ > "$directory/source.csv"
python3 - "$directory/source.csv" <<'PY'
import csv, sys
with open(sys.argv[1]) as source:
    lines = source.read().splitlines()
rows = list(csv.reader(lines[1:-1]))
assert len(rows) == 3 and len(rows[0]) == 15
assert {row[0] for row in rows[1:]} == {"tcp", "udp"}
PY
for protocol in tcp udp; do
 ip netns exec "$namespace" openvpn --config "$directory/$protocol.ovpn" --dev tun-check --route-noexec --daemon --writepid "$directory/check-$protocol.pid" --log "$directory/check-$protocol.log"
 ready=0
 for attempt in $(seq 1 100); do
  if grep -q 'Initialization Sequence Completed' "$directory/check-$protocol.log"; then ready=1; break; fi
  sleep 0.1
 done
 [ "$ready" = 1 ] || { echo "夹具隧道未就绪：$protocol" >&2; exit 1; }
 ip netns exec "$namespace" ip route add 11.54.0.2/32 dev tun-check
 ip netns exec "$namespace" ip route add 1.1.1.1/32 dev tun-check
 for target in /generate_204 / /redirect; do
  status=$(ip netns exec "$namespace" curl --noproxy '*' --max-time 3 -sS -L -o /dev/null -w '%{http_code}' "http://11.54.0.2$target")
  case "$status" in 200|204) ;; *) echo "夹具响应错误：$status" >&2; exit 1;; esac
 done
 ip netns exec "$namespace" curl --noproxy '*' --max-time 3 --cacert "$directory/ca.crt" -fsS https://11.54.0.2/ > /dev/null
 status=$(ip netns exec "$namespace" curl --noproxy '*' --max-time 3 -sS -o /dev/null -w '%{http_code}' http://11.54.0.2/failure)
 [ "$status" = 503 ] || exit 1
 result=0
 ip netns exec "$namespace" curl --noproxy '*' --max-time 0.2 -sS -o /dev/null http://11.54.0.2/slow 2>/dev/null || result=$?
 [ "$result" = 28 ] || { echo "夹具超时行为错误" >&2; exit 1; }
 result=0
 ip netns exec "$namespace" curl --noproxy '*' --max-time 3 -sS -o /dev/null https://11.54.0.2/ 2>/dev/null || result=$?
 [ "$result" = 60 ] || { echo "夹具 TLS 校验行为错误" >&2; exit 1; }
 ip netns exec "$namespace" python3 - <<'PY'
import socket, struct
query = struct.pack('!HHHHHH', 7, 0x100, 1, 0, 0, 0) + b'\x07fixture\x07example\0' + struct.pack('!HH', 1, 1)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(3)
    sock.sendto(query, ('1.1.1.1', 53))
    assert sock.recv(4096).endswith(socket.inet_aton('11.54.0.2'))
PY
 kill "$(cat "$directory/check-$protocol.pid")"
 for attempt in $(seq 1 50); do
  ip netns exec "$namespace" ip link show tun-check >/dev/null 2>&1 || break
  sleep 0.1
 done
 echo "夹具验证通过：$protocol"
done
