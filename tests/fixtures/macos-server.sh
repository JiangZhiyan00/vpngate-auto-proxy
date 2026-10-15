#!/bin/sh
# 只在专属受控容器内运行；不修改宿主。
set -eu
case "${VAP_FIXTURE_TRANSPORT:-tcp}" in
 tcp) fixture_protocol=tcp-server ;;
 udp) fixture_protocol=udp4 ;;
 *) echo '受控隧道承载无效' >&2; exit 2 ;;
esac
umask 077
mkdir /tmp/vap-native
cd /tmp/vap-native
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -subj /CN=VAP-Native-CA -days 2 >/dev/null 2>&1
for role in server client; do
 openssl req -newkey rsa:2048 -nodes -keyout "$role.key" -out "$role.csr" -subj "/CN=$role" >/dev/null 2>&1
 if [ "$role" = server ]; then usage=serverAuth; else usage=clientAuth; fi
 printf 'keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=%s\n' "$usage" > extensions
 openssl x509 -req -in "$role.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -out "$role.crt" -days 2 -extfile extensions >/dev/null 2>&1
done
printf 'dev tun\nproto %s\n' "$fixture_protocol" > server.conf
cat >> server.conf <<'CONF'
port 1194
topology subnet
server 10.231.66.0 255.255.255.0
ca /tmp/vap-native/ca.crt
cert /tmp/vap-native/server.crt
key /tmp/vap-native/server.key
dh none
tls-version-min 1.2
data-ciphers AES-256-GCM:AES-128-GCM
allow-compression no
script-security 1
keepalive 2 10
verb 3
CONF
python3 /fixture/macos_echo.py &
if [ -n "${VAP_FIXTURE_ID:-}" ]; then
 python3 /fixture/macos_dns.py &
fi
exec openvpn --config server.conf
