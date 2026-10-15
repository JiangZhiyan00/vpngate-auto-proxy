#!/bin/sh
# 仅在专用夹具容器中将受控节点映射到测试桥接地址。
set -eu
directory="${VAP_FIXTURE_DIR:?需要夹具目录}"
tests/fixtures/setup.sh "$directory"
python3 - "$directory/state.json" <<'PY'
import json,sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({"source_ip":"11.52.0.2"}))
PY
nft -f - <<'RULES'
table inet fixture_docker {
 chain prerouting {
  type nat hook prerouting priority dstnat; policy accept;
  iifname "eth0" ip daddr 11.52.0.2 tcp dport 1194 dnat to 11.53.0.2:1194
  iifname "eth0" ip daddr 11.52.0.2 udp dport 1195 dnat to 11.53.0.2:1195
  iifname "eth0" ip daddr 11.52.0.2 tcp dport 20002-39999 dnat to 11.53.0.2
  iifname "eth0" ip daddr 11.52.0.2 udp dport 20002-39999 dnat to 11.53.0.2
 }
 chain postrouting {
  type nat hook postrouting priority srcnat; policy accept;
  oifname "vfixture0" ip daddr 11.53.0.2 masquerade
 }
}
RULES
touch "$directory/docker-ready"
exec sleep infinity
