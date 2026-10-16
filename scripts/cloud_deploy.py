"""离线容器包的初始化、部署预检和生命周期操作。"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import stat
import subprocess
import sys

from cloud_image_identity import archive_identities, verify_image
from docker_profiles import require_profiles


PROJECT = 'vpngate-auto-proxy'
COMPOSE_FILES = {'compose.yaml', 'image.env', 'deploy/compose.apparmor.yaml'}
REQUIRED_FILES = COMPOSE_FILES | {'bundle.json', 'images.tar', 'manage.sh', 'run.sh',
                                 'scripts/cloud_deploy.py', 'scripts/cloud_image_identity.py',
                                 'scripts/docker_profiles.py', 'deploy/apparmor/vpngate-auto-proxy'}
CAPS = {'NET_ADMIN', 'SYS_ADMIN', 'SETUID', 'SETGID', 'SETPCAP', 'KILL', 'CHOWN', 'DAC_OVERRIDE', 'FOWNER'}


def file_digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def verify_files(root, selected=None):
    records = {}
    for line in (root / 'SHA256SUMS').read_text().splitlines():
        try:
            expected, name = line.split('  ', 1)
        except ValueError as error:
            raise RuntimeError('包内校验清单格式无效') from error
        relative = Path(name)
        if (relative.is_absolute() or '..' in relative.parts or not relative.parts
                or name in records or len(expected) != 64
                or any(c not in '0123456789abcdef' for c in expected)):
            raise RuntimeError('包内校验清单路径或摘要无效')
        records[name] = expected
    required = REQUIRED_FILES if selected is None else set(selected)
    if not required <= records.keys():
        raise RuntimeError('包内校验清单缺少必需文件')
    for name, expected in records.items():
        # 运行配置明确允许用户修改，其余交付内容继续逐项校验。
        if name == 'config.json' or (selected is not None and name not in selected):
            continue
        path = root / name
        if (not path.is_file() or path.is_symlink() or root.resolve() not in path.resolve().parents
                or file_digest(path) != expected):
            raise RuntimeError('包内文件校验失败：' + name)


def read_credentials(root):
    path = root / 'credentials.local.json'
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) not in (0o400, 0o600)
                    or metadata.st_uid != os.geteuid() or metadata.st_size > 4096):
                raise RuntimeError('凭据须为当前用户拥有、权限 0400 或 0600 的独立普通文件，且不超过 4 KiB')
            value = json.loads(stream.read(4097))
        if (not isinstance(value, dict) or set(value) != {'username', 'password'}
                or any(not isinstance(value[key], str) or not 1 <= len(value[key].encode()) <= 255
                       for key in ('username', 'password'))):
            raise RuntimeError('凭据格式无效，用户名和密码须各为 1—255 个 UTF-8 字节')
        return value
    except (OSError, ValueError) as error:
        raise RuntimeError('无法读取有效凭据，请先执行 bash manage.sh init 并核对文件权限') from error


def initialize(root):
    path = root / 'credentials.local.json'
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        read_credentials(root)
        print('凭据已存在且有效，保留原内容。')
        return
    with os.fdopen(descriptor, 'w') as stream:
        json.dump({'username': 'proxy', 'password': secrets.token_urlsafe(32)}, stream)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    print('凭据已写入 credentials.local.json，请自行查看并保管。')


def execute(command, root, capture=True, timeout=60):
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith('COMPOSE_') and not key.startswith('VAP_')
                   and key != 'DOCKER_DEFAULT_PLATFORM'}
    environment['TZ'] = 'Asia/Shanghai'
    return subprocess.run(command, cwd=root, env=environment, text=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None, timeout=timeout)


def required(command, root):
    result = execute(command, root)
    if result.returncode:
        raise RuntimeError('部署检查命令失败：' + result.stderr[-2000:])
    return result.stdout


def security_options(root):
    value = json.loads(required(['docker', 'info', '--format', '{{json .SecurityOptions}}'], root))
    if any('rootless' in option for option in value):
        raise RuntimeError('容器部署需要有根引擎，当前为无根模式')
    return value


def compose_command(root, apparmor):
    command = ['docker', 'compose', '--project-name', PROJECT, '--env-file', str(root / 'image.env'),
               '-f', str(root / 'compose.yaml')]
    if apparmor:
        command += ['-f', str(root / 'deploy/compose.apparmor.yaml')]
    return command


def validate_config(root):
    path = root / 'config.json'
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise RuntimeError('config.json 须为不超过 64 KiB 的普通文件')
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise RuntimeError('config.json 须为 JSON 对象')
    for key, expected in {'listen': '0.0.0.0:1080', 'credentials_file': '/run/secrets/proxy_credentials',
                          'data_dir': '/var/lib/vap', 'runtime_dir': '/run/vap'}.items():
        if value.get(key) != expected:
            raise RuntimeError('离线部署配置须保持容器映射一致：' + key + '=' + expected)
    legacy = value.get('allow_legacy_vpngate_crypto', False)
    if not isinstance(legacy, bool):
        raise RuntimeError('旧算法兼容开关须为 JSON 布尔值')
    return legacy


def validate_compose(value, tag, apparmor, root):
    proxy = value['services']['proxy']
    ports = proxy.get('ports', [])
    devices = proxy.get('devices', [])
    volumes = proxy.get('volumes', [])
    secrets = proxy.get('secrets', [])
    secret = value.get('secrets', {}).get('proxy_credentials', {})
    data_volume = value.get('volumes', {}).get('proxy-data', {})
    expected_security = {'no-new-privileges:true'}
    if apparmor:
        expected_security.add('apparmor=vpngate-auto-proxy')
    if (proxy['image'] != tag or proxy.get('pull_policy') != 'never' or not proxy.get('read_only')
            or proxy.get('privileged', False) or proxy.get('network_mode') == 'host'
            or set(proxy.get('cap_drop', [])) != {'ALL'} or set(proxy.get('cap_add', [])) != CAPS
            or set(proxy.get('security_opt', [])) != expected_security
            or len(ports) != 1 or ports[0].get('host_ip') != '127.0.0.1'
            or ports[0].get('target') != 1080 or str(ports[0].get('published')) != '1080'
            or len(devices) != 1 or devices[0].get('source') != '/dev/net/tun'
            or devices[0].get('target') != '/dev/net/tun'
            or proxy.get('sysctls') != {'net.ipv4.ip_forward': '1'}
            or len(volumes) != 2
            or not any(v.get('type') == 'bind' and v.get('source') == str(root / 'config.json')
                       and v.get('target') == '/etc/vap/config.json' and v.get('read_only') for v in volumes)
            or not any(v.get('type') == 'volume' and v.get('source') == 'proxy-data'
                       and v.get('target') == '/var/lib/vap' for v in volumes)
            or len(secrets) != 1 or secrets[0].get('source') != 'proxy_credentials'
            or secrets[0].get('target') != '/run/secrets/proxy_credentials'
            or secret.get('file') != str(root / 'credentials.local.json')
            or data_volume.get('name') != PROJECT + '_proxy-data'
            or proxy.get('stop_grace_period') != '15s'):
        raise RuntimeError('容器配置与已验证的镜像、权限或回环端口契约不符')


def _check(root):
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise RuntimeError('本离线包需要 x86_64 Linux 主机')
    if not Path('/dev/net/tun').is_char_device():
        raise RuntimeError('缺少 /dev/net/tun，主机须提供 TUN 支持')
    verify_files(root)
    read_credentials(root)
    legacy_crypto_opt_in = validate_config(root)
    manifest = json.loads((root / 'bundle.json').read_text())
    item = manifest['images'][0]
    actual = json.loads(required(['docker', 'image', 'inspect', item['tag']], root))[0]
    identities = archive_identities(root / 'images.tar', item)
    verify_image(actual, item, identities)
    security = security_options(root)
    apparmor = any('name=apparmor' in value for value in security)
    base = compose_command(root, apparmor)
    required(['docker', 'compose', 'version'], root)
    rendered = json.loads(required(base + ['config', '--format', 'json'], root))
    validate_compose(rendered, item['tag'], apparmor, root)
    require_profiles(security, [(item['tag'], 'vpngate-auto-proxy')])
    report = {'recorded_at': datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat(),
              'status': 'passed', 'project': PROJECT, 'image_id': actual['Id'], 'verified_ids': sorted(identities),
              'apparmor_profile_applied': apparmor, 'security_options': security,
              'config_sha256': file_digest(root / 'config.json'), 'public_exit_validated': False}
    report['legacy_crypto_opt_in'] = legacy_crypto_opt_in
    output = root / 'validation-output'
    output.mkdir(exist_ok=True)
    (output / 'deployment-check.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    return base


def check(root):
    output = root / 'validation-output'
    output.mkdir(exist_ok=True)
    report = output / 'deployment-check.json'
    initial = {'recorded_at': datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat(),
               'status': 'running', 'public_exit_validated': False}
    report.write_text(json.dumps(initial, ensure_ascii=False, indent=2) + '\n')
    try:
        return _check(root)
    except BaseException:
        report.write_text(json.dumps({**initial, 'status': 'failed'}, ensure_ascii=False, indent=2) + '\n')
        raise


def manage(root, action):
    if action == 'init':
        initialize(root)
        return 0
    if action in ('check', 'up'):
        base = check(root)
        if action == 'check':
            print('部署预检通过；实际出口就绪请在启动后查询 ready。')
            return 0
        result = execute(base + ['up', '-d', '--no-build', '--pull', 'never', 'proxy'], root, capture=False)
        if result.returncode == 0:
            print('服务已启动。查看状态：bash manage.sh status；查询出口就绪：bash manage.sh ready')
        return result.returncode
    # 状态、日志和停止不依赖镜像归档或出口就绪，保留故障时的操作能力。
    verify_files(root, selected=COMPOSE_FILES)
    security = security_options(root)
    base = compose_command(root, any('name=apparmor' in value for value in security))
    if action in ('status', 'ready'):
        arguments = ['exec', '-T', 'proxy', 'vap', 'status', '--runtime-dir', '/run/vap', '--json']
        if action == 'ready':
            arguments += ['--check-ready']
    elif action == 'stop':
        arguments = ['stop', '--timeout', '15', 'proxy']
    else:
        arguments = ['logs', '--tail', '100', 'proxy']
    return execute(base + arguments, root, capture=False).returncode


def main():
    parser = argparse.ArgumentParser(description='管理离线容器部署，停止时保留缓存卷')
    parser.add_argument('action', choices=['init', 'check', 'up', 'status', 'ready', 'stop', 'logs'])
    options = parser.parse_args()
    try:
        return manage(Path(__file__).resolve().parents[1], options.action)
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        # 配置、凭据解析错误的原始内容不进入输出。
        message = str(error) if isinstance(error, RuntimeError) else '部署操作失败，请核对文件格式、权限及容器引擎状态'
        print(message, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
