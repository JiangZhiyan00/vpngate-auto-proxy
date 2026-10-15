#!/bin/sh
# 只能在专用测试容器运行；不修改宿主或复用既有测试资源。
set -eu
[ "${VAP_NETWORK_TEST:-}" = 1 ] || { echo "必须显式设置 VAP_NETWORK_TEST=1" >&2; exit 1; }
directory="${1:?需要私有夹具目录}"
[ ! -e "$directory" ] || { echo "夹具目录已存在，拒绝覆盖" >&2; exit 1; }
mkdir -m 700 "$directory"
directory="$(cd "$directory" && pwd)"
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
namespace="vap_fixture"
ip netns list | awk '{print $1}' | awk '$0=="vap_fixture"{found=1} END {exit !found}' && { echo "夹具网络空间已存在" >&2; exit 1; }
# 确认名称未被占用后才安装失败清理，避免误删别人的夹具。
completed=0
trap '[ "$completed" = 1 ] || "$script_dir/cleanup.sh" "$directory"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$directory/ca.key" -out "$directory/ca.crt" -subj /CN=VAP-Test-CA -days 2 >/dev/null 2>&1
for role in server client; do
 openssl req -newkey rsa:2048 -nodes -keyout "$directory/$role.key" -out "$directory/$role.csr" -subj "/CN=$role" >/dev/null 2>&1
 if [ "$role" = server ]; then printf 'keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:11.54.0.2\n' > "$directory/extensions"; else printf 'keyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n' > "$directory/extensions"; fi
 openssl x509 -req -in "$directory/$role.csr" -CA "$directory/ca.crt" -CAkey "$directory/ca.key" -CAcreateserial -out "$directory/$role.crt" -days 2 -extfile "$directory/extensions" >/dev/null 2>&1
done
ip netns add "$namespace"
# 此调整只针对夹具命名空间，让其无低端口能力也可提供测试 DNS/HTTP。
nsenter "--net=/run/netns/$namespace" unshare --mount --propagation private sh -c 'mount -t proc proc /proc && echo 0 > /proc/sys/net/ipv4/ip_unprivileged_port_start'
ip link add vfixture0 type veth peer name vfixture1
ip addr add 11.53.0.1/30 dev vfixture0
ip link set vfixture0 up
ip link set vfixture1 netns "$namespace"
ip netns exec "$namespace" ip addr add 11.53.0.2/30 dev vfixture1
ip netns exec "$namespace" ip link set vfixture1 up
ip netns exec "$namespace" ip link set lo up
ip netns exec "$namespace" ip link add fixture_target type dummy
ip netns exec "$namespace" ip addr add 11.54.0.2/32 dev fixture_target
ip netns exec "$namespace" ip addr add 1.1.1.1/32 dev fixture_target
ip netns exec "$namespace" ip link set fixture_target up
ip netns exec "$namespace" nft -f - <<'RULES'
table inet fixture_ports {
 chain prerouting {
  type nat hook prerouting priority dstnat; policy accept;
  ip daddr 11.53.0.2 tcp dport 20002-39999 redirect to :1194
  ip daddr 11.53.0.2 udp dport 20002-39999 redirect to :1195
 }
}
RULES
for protocol in tcp udp; do
 if [ "$protocol" = tcp ]; then port=1194; subnet=10.77.0.0; server_proto=tcp-server; client_proto=tcp-client; else port=1195; subnet=10.78.0.0; server_proto=udp; client_proto=udp; fi
 cat > "$directory/server-$protocol.conf" <<CONF
dev tun-$protocol
proto $server_proto
port $port
topology subnet
duplicate-cn
server $subnet 255.255.255.0
ca $directory/ca.crt
cert $directory/server.crt
key $directory/server.key
dh none
tls-version-min 1.2
data-ciphers AES-256-GCM:AES-128-GCM
keepalive 2 10
verb 3
CONF
 {
  printf 'client\ndev tun\nproto %s\nremote 11.53.0.2 %s\nnobind\nremote-cert-tls server\ntls-version-min 1.2\ndata-ciphers AES-256-GCM:AES-128-GCM\n' "$client_proto" "$port"
  for block in ca cert key; do
   case "$block" in ca) file=ca.crt;; cert) file=client.crt;; key) file=client.key;; esac
   printf '<%s>\n' "$block"; cat "$directory/$file"; printf '</%s>\n' "$block"
  done
 } > "$directory/$protocol.ovpn"
 ip netns exec "$namespace" openvpn --config "$directory/server-$protocol.conf" --daemon --writepid "$directory/$protocol.pid" --log "$directory/$protocol.log"
done
ip netns exec "$namespace" python3 "$script_dir/services.py" --directory "$directory" > "$directory/services.log" 2>&1 &
echo "$!" > "$directory/services.pid"
python3 "$script_dir/services.py" --source --directory "$directory" > "$directory/source.log" 2>&1 &
echo "$!" > "$directory/source.pid"
completed=1
echo "$directory"
