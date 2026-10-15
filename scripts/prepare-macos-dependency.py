#!/usr/bin/env python3
"""普通用户构建独立安装候选；不写系统目录，不覆盖既有实验依赖。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = '4041c709162bec1325abf5aa8cf27a255cc477c634b15ee310411c701fc40a96'
PATCH = 'cdf11425bb5806f87eb6fb5ee289adba86e7de3c08bbe550a777785d05b986fa'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(output, openssl, validator):
    if platform.system() != 'Darwin' or platform.machine() != 'arm64' or os.getuid() == 0 or os.geteuid() == 0:
        raise ValueError('只能由当前苹果 ARM64 主机的普通用户构建')
    if output.exists() or output.is_symlink():
        raise ValueError('输出路径已经存在，拒绝覆盖')
    archive = ROOT / 'validation-output/macos-deps/openvpn-2.6.23.tar.gz'
    patch = ROOT / 'scripts/patches/openvpn-2.6.23-utun-fd.patch'
    if digest(archive) != SOURCE or digest(patch) != PATCH:
        raise ValueError('固定源码或借用补丁摘要不符')
    output.parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='macos-dependency-build-', dir=output.parent))
    source = work / 'source'
    source.mkdir()
    inputs = work / 'crypto'
    inputs.mkdir()
    # 构建与材料清单使用同一份静态库快照。
    for name in ('libssl.a', 'libcrypto.a'):
        shutil.copyfile(openssl / 'lib' / name, inputs / name)
    shutil.copytree(openssl / 'include', inputs / 'include')
    version_text = (inputs / 'include/openssl/opensslv.h').read_text()
    match = re.search(r'^\s*#\s*define\s+OPENSSL_VERSION_STR\s+"(\d+\.\d+\.\d+)"', version_text, re.M)
    if not match:
        raise ValueError('加密库头文件缺少明确版本')
    crypto_version = match.group(1)
    env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'TMPDIR': '/tmp',
           'OPENSSL_CFLAGS': '-I' + str(inputs / 'include'),
           'OPENSSL_LIBS': str(inputs / 'libssl.a') + ' ' + str(inputs / 'libcrypto.a'),
           'CFLAGS': '-O2 -arch arm64', 'LDFLAGS': '-arch arm64'}
    # 编译器链接参数是字符串；拒绝可能被构建工具解释为参数分隔或命令替换的路径。
    for path in (work, inputs):
        if not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(path)):
            raise ValueError('构建临时路径含编译工具不支持的字符')
    subprocess.run(['/usr/bin/tar', '-xzf', str(archive), '-C', str(source), '--strip-components', '1'], check=True, env=env)
    with patch.open('rb') as stream:
        subprocess.run(['/usr/bin/patch', '-p1'], cwd=source, stdin=stream, env=env, check=True, capture_output=True)
    configure = ['./configure', '--prefix=/usr/local/libexec/vpngate-auto-proxy/openvpn-2.6.23',
                 '--disable-lzo', '--disable-lz4', '--disable-pkcs11', '--disable-plugins',
                 '--disable-plugin-auth-pam', '--disable-plugin-down-root', '--disable-dco',
                 '--with-openssl-engine=no']
    for args, name in ((configure, 'configure.log'), (['/usr/bin/make', '-j', '4'], 'build.log')):
        with (work / name).open('wb') as log:
            result = subprocess.run(args, cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT)
        if result.returncode:
            raise ValueError('构建失败，诊断文件：' + str(work / name))
    stage = work / 'bundle'
    stage.mkdir(mode=0o700)
    files = {'openvpn': source / 'src/openvpn/openvpn', 'openvpn-source.tar.gz': archive,
             'utun-fd.patch': patch, 'COPYING': source / 'COPYING',
             'COPYRIGHT.GPL': source / 'COPYRIGHT.GPL', 'AUTHORS': source / 'AUTHORS',
             'openssl-LICENSE.txt': openssl / 'LICENSE.txt', 'libssl.a': inputs / 'libssl.a',
             'libcrypto.a': inputs / 'libcrypto.a'}
    for name, path in files.items():
        shutil.copyfile(path, stage / name)
        (stage / name).chmod(0o700 if name == 'openvpn' else 0o600)
    record = dict(format_version=1, version='2.6.23', source_sha256=SOURCE, patch_sha256=PATCH,
                  crypto_version=crypto_version, files={name: digest(stage / name) for name in files})
    (stage / 'bundle.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n')
    (stage / 'bundle.json').chmod(0o600)
    # 只在普通用户环境中运行候选；管理员安装入口绝不执行该程序。
    safe_env = {'PATH': env['PATH'], 'LANG': 'C', 'OPENSSL_CONF': '/dev/null',
                'OPENSSL_MODULES': str(stage), 'OPENSSL_ENGINES': str(stage)}
    version = subprocess.run([str(stage / 'openvpn'), '--version'], env=safe_env, capture_output=True, text=True, check=True, timeout=5)
    if not version.stdout.startswith('OpenVPN 2.6.23 ') or 'OpenSSL ' + crypto_version not in version.stdout:
        raise ValueError('候选程序与构建输入版本不符')
    check = subprocess.run([str(validator), 'mac-dependency', '--bundle', str(stage)], env=safe_env, capture_output=True, text=True, timeout=10)
    if check.returncode:
        raise ValueError('候选材料核验失败：' + check.stderr.strip())
    # macOS 的不覆盖重命名由同一项目程序提供；此处普通用户创建最终目录，独占发布材料。
    output.mkdir(mode=0o700)
    try:
        for path in stage.iterdir():
            shutil.copyfile(path, output / path.name)
            (output / path.name).chmod(path.stat().st_mode & 0o777)
    except BaseException:
        shutil.rmtree(output)
        raise
    return dict(bundle=str(output), build_directory=str(work), validation=json.loads(check.stdout),
                native_tunnel_validated=False, installed=False)


def main():
    parser = argparse.ArgumentParser(description='构建独立的苹果依赖安装候选')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--openssl-prefix', type=Path, default=Path('/opt/homebrew/opt/openssl@3'))
    parser.add_argument('--validator', type=Path, default=ROOT / 'target/debug/vpngate-auto-proxy')
    args = parser.parse_args()
    try:
        report = build(args.output.absolute(), args.openssl_prefix.absolute(), args.validator.absolute())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, '依赖准备失败：' + str(error) + '\n')
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
