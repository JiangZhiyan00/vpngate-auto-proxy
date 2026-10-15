#!/bin/sh
# 固定源码的独立实验构建，不覆盖标准依赖，不安装到系统。
set -eu
umask 077
[ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ] || exit 2
[ "$(id -u)" != 0 ] || { echo "请以普通用户构建实验依赖" >&2; exit 2; }
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repository="$(CDPATH= cd -- "$script_dir/.." && pwd)"
directory="$repository/validation-output/macos-deps"
archive="$directory/openvpn-2.6.23.tar.gz"
[ -f "$archive" ] || { echo "请先执行 scripts/prepare-macos-openvpn.sh" >&2; exit 2; }
actual="$(/usr/bin/shasum -a 256 "$archive" | cut -d ' ' -f 1)"
[ "$actual" = 4041c709162bec1325abf5aa8cf27a255cc477c634b15ee310411c701fc40a96 ] || {
 echo "固定源码摘要不符，停止构建" >&2; exit 2;
}
source_dir="$(mktemp -d "$directory/openvpn-lease-source-XXXXXXXX")"
/usr/bin/tar -xzf "$archive" -C "$source_dir" --strip-components 1
cd "$source_dir"
/usr/bin/patch -p1 < "$script_dir/patches/openvpn-2.6.23-utun-fd.patch"
openssl_prefix="$(/opt/homebrew/bin/brew --prefix openssl@3)"
prefix="$directory/openvpn-2.6.23-lease-local"
OPENSSL_CFLAGS="-I$openssl_prefix/include" OPENSSL_LIBS="-L$openssl_prefix/lib -lssl -lcrypto" \
 ./configure --prefix="$prefix" --disable-lzo --disable-lz4 --disable-pkcs11 \
 --disable-plugins --disable-plugin-auth-pam --disable-plugin-down-root --disable-dco \
 > configure-local.log 2>&1 || { echo "配置失败：$source_dir/configure-local.log" >&2; exit 1; }
make -j 4 > build-local.log 2>&1 || { echo "构建失败：$source_dir/build-local.log" >&2; exit 1; }
make install > install-local.log 2>&1 || { echo "本地安装失败：$source_dir/install-local.log" >&2; exit 1; }
python3 - "$prefix" "$archive" "$script_dir/patches/openvpn-2.6.23-utun-fd.patch" "$source_dir" <<'PY'
import hashlib,json,subprocess,sys
from pathlib import Path
prefix,archive,patch,source=map(Path,sys.argv[1:])
binary=prefix/'sbin/openvpn'
digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
r=dict(experimental_only=True,source_url='https://swupdate.openvpn.org/community/releases/openvpn-2.6.23.tar.gz',
       source_sha256=digest(archive),patch_sha256=digest(patch),binary_sha256=digest(binary),
       source_directory=str(source),binary_path=str(binary),
       license='外部程序继续遵循其 GPL-2.0 及原有例外；补丁仅作本地实验，不构成正式依赖选型或公开分发。',
       version=subprocess.check_output([str(binary),'--version'],text=True),
       native_tunnel_validated=False)
(prefix/'provenance.json').write_text(json.dumps(r,ensure_ascii=False,indent=2)+'\n')
PY
printf '实验依赖已构建：%s\n' "$prefix/sbin/openvpn"
