#!/bin/sh
# 从固定官方源码构建本地验证依赖，不写系统目录、不启动服务。
set -eu
umask 077
[ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ] || {
 echo "此准备脚本仅用于当前苹果 ARM64 验收目标" >&2
 exit 2
}
[ "$(id -u)" != 0 ] || { echo "请以普通用户构建依赖" >&2; exit 2; }
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repository="$(CDPATH= cd -- "$script_dir/.." && pwd)"
version=2.6.23
digest=4041c709162bec1325abf5aa8cf27a255cc477c634b15ee310411c701fc40a96
source_url="https://swupdate.openvpn.org/community/releases/openvpn-$version.tar.gz"
directory="$repository/validation-output/macos-deps"
mkdir -p "$directory"
archive="$directory/openvpn-$version.tar.gz"
if [ ! -f "$archive" ]; then
 /usr/bin/curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 --max-time 60 "$source_url" -o "$archive.part"
 mv "$archive.part" "$archive"
fi
actual="$(/usr/bin/shasum -a 256 "$archive" | cut -d ' ' -f 1)"
[ "$actual" = "$digest" ] || { echo "源码摘要不匹配，停止构建" >&2; exit 2; }
openssl_prefix="$(/opt/homebrew/bin/brew --prefix openssl@3)"
[ -f "$openssl_prefix/include/openssl/ssl.h" ] || { echo "缺少现有加密库开发文件" >&2; exit 2; }
[ -d "$directory/openvpn-$version" ] || /usr/bin/tar -xzf "$archive" -C "$directory"
prefix="$directory/openvpn-$version-local"
cd "$directory/openvpn-$version"
OPENSSL_CFLAGS="-I$openssl_prefix/include" OPENSSL_LIBS="-L$openssl_prefix/lib -lssl -lcrypto" \
 ./configure --prefix="$prefix" --disable-lzo --disable-lz4 --disable-pkcs11 \
 --disable-plugins --disable-plugin-auth-pam --disable-plugin-down-root --disable-dco \
 > configure-local.log 2>&1 || { echo "配置失败，请查看 $PWD/configure-local.log" >&2; exit 1; }
make -j 4 > build-local.log 2>&1 || { echo "构建失败，请查看 $PWD/build-local.log" >&2; exit 1; }
make install > install-local.log 2>&1 || { echo "本地安装失败，请查看 $PWD/install-local.log" >&2; exit 1; }
"$prefix/sbin/openvpn" --version
python3 - "$prefix/sbin/openvpn" "$archive" "$source_url" "$openssl_prefix" <<'PY'
import hashlib,json,platform,subprocess,sys
from pathlib import Path
binary,archive,url,openssl=sys.argv[1:]
report={
 "source_url":url,
 "source_sha256":hashlib.sha256(Path(archive).read_bytes()).hexdigest(),
 "binary_path":binary,
 "binary_sha256":hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
 "architecture":platform.machine(),
 "version":subprocess.check_output([binary,"--version"],text=True),
 "dynamic_libraries":subprocess.check_output(["/usr/bin/otool","-L",binary],text=True),
 "openssl_prefix":openssl,
 "source_transport":"HTTPS；固定摘要用于复现，未验证发布签名",
 "native_tunnel_validated":False,
}
Path(archive).with_name("provenance.json").write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n")
PY
printf '本地验证依赖已准备：%s\n' "$prefix/sbin/openvpn"
