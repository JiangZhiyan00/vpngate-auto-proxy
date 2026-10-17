#!/usr/bin/env python3
"""版本化宿主策略准备；只管理项目唯一策略，不安装代理或修改其他服务。"""
import argparse
import base64
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import stat
import subprocess
import sys
from datetime import datetime, timezone, timedelta

PROJECT = 'vpngate-auto-proxy'
POLICY_TARGET = '/etc/apparmor.d/' + PROJECT
RECORD_TARGET = '/var/lib/vap-host/record.json'
TRANSACTION_TARGET = '/var/lib/vap-host/transaction.json'
LIMIT = 1024 * 1024
# 打包器替换这一行；源码文件不会隐式从工作区读取策略。
EMBEDDED_RELEASE = None


class Rejected(Exception):
    """已明确拒绝或失败；退出 1。"""


class RecoveryRequired(Rejected):
    """恢复无法确认；退出 4。"""


def require(value, message):
    if not value:
        raise Rejected(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def strict_tag(value):
    return isinstance(value, str) and re.fullmatch(r'v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)', value)


def hex_value(value, length):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(length) + '}', value)


class Release:
    def __init__(self, tag, commit, policy, installer_sha256):
        require(strict_tag(tag), '版本必须为无前导零的 vX.Y.Z')
        require(hex_value(commit, 40), '来源必须为完整提交摘要')
        require(hex_value(installer_sha256, 64), '安装器摘要无效')
        require(isinstance(policy, bytes) and 0 < len(policy) <= LIMIT, '内嵌策略大小无效')
        self.tag, self.commit, self.policy = tag, commit, policy
        self.policy_sha256, self.installer_sha256 = digest(policy), installer_sha256


def metadata(info, owner, directory=False, mode=None, sticky=False):
    require(info.st_uid == owner and (owner != 0 or info.st_gid == 0), '路径属主不符合要求')
    actual = stat.S_IMODE(info.st_mode)
    if directory:
        require(stat.S_ISDIR(info.st_mode), '路径不是目录')
        require(not actual & 0o022 or sticky and bool(actual & stat.S_ISVTX), '父目录存在危险写权限')
    else:
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, '文件必须为普通独立文件')
    if mode is not None:
        require(actual == mode, '路径权限不符合要求')


class ProtectedFiles:
    """从固定根目录逐段持有描述符；测试根只由 Python 测试接口注入。"""
    def __init__(self, root=Path('/'), owner=0):
        self.root, self.owner = Path(root), owner
        self.observations = {}

    @contextlib.contextmanager
    def parent(self, target, create=False):
        require(target.startswith('/') and '..' not in target.split('/'), '内部目标路径无效')
        parts = target.strip('/').split('/')
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            metadata(os.fstat(fd), self.owner, directory=True)
            traversed = []
            for part in parts[:-1]:
                traversed.append(part)
                try:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                except FileNotFoundError:
                    require(create and traversed == ['var', 'lib', 'vap-host'], '必要宿主目录缺失')
                    os.mkdir(part, 0o700, dir_fd=fd)
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                    os.fsync(fd)
                os.close(fd)
                fd = child
                relative = '/' + '/'.join(traversed)
                metadata(os.fstat(fd), self.owner, directory=True,
                         mode=0o700 if relative == '/var/lib/vap-host' else None,
                         sticky=relative == '/run/lock')
            yield fd, parts[-1]
        except OSError as error:
            raise Rejected('受保护路径无法打开或身份无效') from error
        finally:
            os.close(fd)

    def read(self, target, mode):
        try:
            with self.parent(target) as (fd, name):
                try:
                    source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
                except FileNotFoundError:
                    self.observations[target] = None
                    return None
                try:
                    before = os.fstat(source)
                    metadata(before, self.owner, mode=mode)
                    require(before.st_size <= LIMIT, '受保护文件超过大小限制')
                    data = bytearray()
                    while len(data) <= LIMIT:
                        block = os.read(source, min(65536, LIMIT + 1 - len(data)))
                        if not block:
                            break
                        data.extend(block)
                    after = os.fstat(source)
                    current = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    require(identity(before) == identity(after) == identity(current) and len(data) == before.st_size,
                            '文件在读取期间发生变化')
                    self.observations[target] = identity(before)
                    return bytes(data)
                finally:
                    os.close(source)
        except Rejected:
            # 只允许完全不存在的项目登记目录，不掩盖链接或权限错误。
            if target in (RECORD_TARGET, TRANSACTION_TARGET):
                with self.parent('/var/lib/vap-host') as (fd, name):
                    try:
                        os.stat(name, dir_fd=fd, follow_symlinks=False)
                    except FileNotFoundError:
                        self.observations[target] = None
                        return None
            raise

    def replace(self, target, expected, data, mode):
        expected_identity = self.observations.get(target)
        require(self.read(target, mode) == expected, '提交前文件已发生变化')
        require(self.observations[target] == expected_identity, '提交前文件节点身份已发生变化')
        with self.parent(target, create=True) as (fd, name):
            # 重新遍历并核对目录描述符，防止路径重定向。
            with self.parent(target) as (check, _):
                require(identity(os.fstat(fd))[:2] == identity(os.fstat(check))[:2], '提交目录身份发生变化')
            if data is None:
                if expected is not None:
                    os.unlink(name, dir_fd=fd)
                    os.fsync(fd)
                return
            temporary = '.' + name + '.' + secrets.token_hex(16)
            out = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=fd)
            try:
                os.fchmod(out, mode)
                with os.fdopen(out, 'wb', closefd=False) as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(out)
                require(self.read(target, mode) == expected, '原子替换前文件已改变')
                require(self.observations[target] == expected_identity, '原子替换前节点身份已改变')
                os.rename(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
                os.fsync(fd)
            finally:
                os.close(out)
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(temporary, dir_fd=fd)

    @contextlib.contextmanager
    def lock(self):
        with self.parent('/run/lock/vap-host-init.lock') as (fd, name):
            lock = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600, dir_fd=fd)
            try:
                metadata(os.fstat(lock), self.owner, mode=0o600)
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as error:
                    raise Rejected('另一个项目初始化正在运行') from error
                require(identity(os.fstat(lock)) == identity(os.stat(name, dir_fd=fd, follow_symlinks=False)), '锁身份变化')
                yield
            finally:
                os.close(lock)


def identity(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True) + '\n').encode()


def read_json(data, fields):
    def unique_pairs(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, '项目材料包含重复字段')
            value[key] = item
        return value
    try:
        value = json.loads(data, object_pairs_hook=unique_pairs)
    except (ValueError, TypeError) as error:
        raise Rejected('项目登记或事务格式无效') from error
    require(isinstance(value, dict) and set(value) == set(fields), '项目登记或事务字段无效')
    return value


class NativeHost:
    """只执行已存在的受保护宿主工具，输出不公开透传。"""
    uid = 0

    def tool(self, name):
        for parent in ('/usr/sbin', '/usr/bin', '/sbin', '/bin'):
            candidate = Path(parent) / name
            if not candidate.exists():
                continue
            resolved = candidate.resolve(strict=True)
            for part in (resolved, *resolved.parents):
                info = part.stat()
                require(info.st_uid == 0 and not stat.S_IMODE(info.st_mode) & 0o022, '宿主工具路径权限无效')
            require(resolved.is_file() and os.access(resolved, os.X_OK), '必要宿主工具不可执行')
            return str(resolved)
        raise Rejected('缺少必要宿主工具：' + name)

    def command(self, name, *args, data=None):
        try:
            result = subprocess.run([self.tool(name), *args], input=data, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=30, check=False,
                                    env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
        except (OSError, subprocess.TimeoutExpired) as error:
            raise Rejected('宿主检查命令无法完成：' + name) from error
        require(result.returncode == 0 and len(result.stdout) <= LIMIT, '宿主检查命令失败：' + name)
        return result.stdout.decode('utf-8', errors='strict').strip()

    def preflight(self):
        require(sys.version_info >= (3, 10) and sys.platform == 'linux' and platform.machine() == 'x86_64', '仅支持 Python 3.10 以上的 Linux x86_64')
        require(os.getuid() == os.geteuid() == 0, '必须由实际及有效管理员用户执行')
        release = {}
        for line in Path('/etc/os-release').read_text().splitlines():
            key, sep, value = line.partition('=')
            if sep:
                release[key] = value.strip('"')
        require((release.get('ID'), release.get('VERSION_ID')) in {('debian', '12'), ('ubuntu', '24.04')}, '宿主发行版未在支持矩阵中')
        require(Path('/proc/1/comm').read_text().strip() == 'systemd' and Path('/run/systemd/system').is_dir(), '必须在真实 systemd 宿主执行')
        require(not Path('/.dockerenv').exists() and not Path('/run/.containerenv').exists(), '不能在容器内初始化宿主')
        detected = subprocess.run([self.tool('systemd-detect-virt'), '--container', '--quiet'],
                                  env={'PATH': '/usr/bin:/usr/sbin:/bin:/sbin', 'LC_ALL': 'C'}, timeout=10, check=False)
        require(detected.returncode == 1, '检测到容器或无法确认宿主环境')
        for namespace in ('mnt', 'pid', 'user', 'net', 'uts', 'ipc', 'cgroup'):
            require(os.readlink('/proc/self/ns/' + namespace) == os.readlink('/proc/1/ns/' + namespace), '执行进程不在宿主命名空间')
        require(Path('/proc/self/uid_map').read_text().split() == ['0', '0', '4294967295'], '宿主用户命名空间无法确认')
        require(Path('/sys/module/apparmor/parameters/enabled').read_text().strip() == 'Y', 'AppArmor 未启用')
        require(Path('/sys/kernel/security/apparmor/profiles').is_file(), 'AppArmor 内核列表不可用')
        tunnel = Path('/dev/net/tun').lstat()
        require(stat.S_ISCHR(tunnel.st_mode) and tunnel.st_uid == 0
                and os.major(tunnel.st_rdev) == 10 and os.minor(tunnel.st_rdev) == 200,
                '隧道设备缺失、为链接或身份错误')
        for parent in Path('/dev/net/tun').parents:
            info = parent.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not stat.S_IMODE(info.st_mode) & 0o022,
                    '隧道设备目录不受管理员保护')
        for path in ('/etc/apparmor.d/tunables/global', '/etc/apparmor.d/abstractions/base'):
            self.protected_system_file(path)
        require(not any(key in os.environ for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG')), '请在未指定 Docker 远端或自定义上下文的宿主环境执行')
        context = json.loads(self.command('docker', 'context', 'inspect'))
        require(isinstance(context, list) and len(context) == 1
                and context[0].get('Endpoints', {}).get('docker', {}).get('Host') == 'unix:///var/run/docker.sock', '仅支持默认本机 Docker 套接字')
        options = json.loads(self.command('docker', 'info', '--format', '{{json .SecurityOptions}}'))
        require(isinstance(options, list) and not any('rootless' in item for item in options)
                and any('apparmor' in item for item in options), 'Docker 必须有根且启用 AppArmor')
        unit = dict(line.split('=', 1) for line in self.command('systemctl', 'show', 'apparmor.service',
                    '--property=LoadState,ActiveState,UnitFileState,FragmentPath,ExecStart,Before,ConditionResult').splitlines() if '=' in line)
        require(unit.get('LoadState') == 'loaded' and unit.get('UnitFileState') == 'enabled'
                and unit.get('ActiveState') == 'active'
                and unit.get('ConditionResult') == 'yes' and 'sysinit.target' in unit.get('Before', '').split(), 'AppArmor 持久启动链未就绪')
        self.protected_system_file(unit.get('FragmentPath', ''))
        start_paths = ['/lib/apparmor/apparmor.systemd', '/usr/lib/apparmor/apparmor.systemd']
        selected = next((path for path in start_paths if 'path=' + path + ' ;' in unit.get('ExecStart', '')
                         and 'argv[]=' + path + ' start ;' in unit.get('ExecStart', '')), None)
        require(selected is not None, 'AppArmor 不是支持的标准启动加载链')
        self.protected_system_file(selected)
        self.protected_system_file(str(Path(selected).parent / 'functions'))
        for path in ('/etc/apparmor.d/disable/' + PROJECT, '/etc/apparmor.d/force-complain/' + PROJECT):
            require(not os.path.lexists(path), '项目策略被禁用或强制为宽松模式')
        self.tool('apparmor_parser')
        self.boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()

    def protected_system_file(self, value):
        path = Path(value)
        require(path.is_absolute() and path.is_file(), '标准系统文件缺失')
        path = path.resolve(strict=True)
        for item in (path, *path.parents):
            info = item.stat()
            require(info.st_uid == 0 and not stat.S_IMODE(info.st_mode) & 0o022, '标准系统文件路径不受保护')

    def kernel_mode(self):
        found = []
        for line in Path('/sys/kernel/security/apparmor/profiles').read_text().splitlines():
            if line.startswith(PROJECT + ' '):
                found.append(line)
        require(len(found) <= 1, '内核存在多个同名策略状态')
        if not found:
            return None
        require(found[0] in (PROJECT + ' (enforce)', PROJECT + ' (complain)'), '内核策略模式无法确认')
        return 'enforce' if found[0].endswith('(enforce)') else 'complain'

    def consumers(self):
        # 同时检查所有线程；进程消失可以接受，其他不可读情况拒绝。
        for pid in Path('/proc').iterdir():
            if not pid.name.isdigit():
                continue
            try:
                for task in (pid / 'task').iterdir():
                    value = (task / 'attr/current').read_text().strip()
                    label = value.rsplit(' (', 1)[0]
                    require(not any(part == PROJECT or part.startswith(PROJECT + '//')
                                    for part in label.split('//&')), '策略仍有活动消费者，请先停止对应代理')
            except FileNotFoundError:
                continue
            except (PermissionError, OSError) as error:
                raise Rejected('无法完整确认策略消费者') from error

    def parse(self, policy):
        names = self.command('apparmor_parser', '--skip-read-cache', '--skip-kernel-load', '--names', data=policy)
        require(names.splitlines() == [PROJECT], '策略必须仅定义项目精确名称')
        self.command('apparmor_parser', '--skip-read-cache', '--skip-kernel-load', data=policy)

    def load(self, policy):
        self.command('apparmor_parser', '--skip-read-cache', '--replace', data=policy)

    def unload(self, policy):
        self.command('apparmor_parser', '--skip-read-cache', '--remove', data=policy)

    def safe_inventory(self):
        # 只读取固定安全字段，不保存环境、挂载内容或完整 inspect。
        containers = []
        identifiers = self.command('docker', 'ps', '--all', '--quiet', '--no-trunc').splitlines()
        for identifier in identifiers:
            require(hex_value(identifier, 64), '容器身份格式无效')
            line = self.command('docker', 'inspect', '--format',
                                '{{json .Id}} {{json .State.Status}} {{json .State.StartedAt}}', identifier)
            fields = line.split()
            require(len(fields) == 3, '容器安全基线格式无效')
            containers.append({'id': json.loads(fields[0]), 'state': json.loads(fields[1]),
                               'started_at': json.loads(fields[2])})
        other_profiles = sorted(line for line in Path('/sys/kernel/security/apparmor/profiles').read_text().splitlines()
                                if not line.startswith(PROJECT + ' '))
        return {'containers': sorted(containers, key=lambda item: item['id']),
                'other_profiles_sha256': digest('\n'.join(other_profiles).encode())}


RECORD_FIELDS = {'schema_version', 'project', 'release_tag', 'source_commit', 'installer_sha256', 'policy_name', 'policy_sha256', 'policy_target', 'target_dev', 'target_ino', 'installed_at', 'boot_id', 'kernel_enforced'}
TRANSACTION_FIELDS = {'schema_version', 'project', 'id', 'stage', 'new_sha256', 'old_policy', 'old_record', 'new_record', 'old_mode',
                      'old_kernel_known',
                      'old_policy_identity', 'old_record_identity', 'new_policy_identity', 'new_record_identity',
                      'restored_policy_identity', 'restored_record_identity', 'restored_record'}


def stored_identity(value):
    if value is None:
        return None
    require(isinstance(value, (list, tuple)) and len(value) == 9
            and all(type(part) is int and part >= 0 for part in value), '事务节点身份格式无效')
    require(stat.S_ISREG(value[2]) and value[5] == 1, '事务节点不是独立普通文件')
    return tuple(value)


class HostSetup:
    def __init__(self, release, host=None, root=Path('/'), owner=0):
        self.release = release
        self.host = host if host is not None else NativeHost()
        self.files = ProtectedFiles(root, owner)

    def record(self, raw, policy):
        if raw is None:
            return None
        value = read_json(raw, RECORD_FIELDS)
        require(type(value['schema_version']) is int and value['schema_version'] == 1 and value['project'] == PROJECT and value['policy_name'] == PROJECT
                and value['policy_target'] == POLICY_TARGET and strict_tag(value['release_tag'])
                and hex_value(value['source_commit'], 40) and hex_value(value['installer_sha256'], 64)
                and policy is not None and value['policy_sha256'] == digest(policy)
                and type(value['target_dev']) is int and type(value['target_ino']) is int
                and isinstance(value['installed_at'], str) and isinstance(value['boot_id'], str)
                and value['kernel_enforced'] is True, '登记损坏或本地策略被修改')
        with self.files.parent(POLICY_TARGET) as (fd, name):
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            require((info.st_dev, info.st_ino) == (value['target_dev'], value['target_ino']), '策略文件身份与登记不一致')
        return value

    def run(self, action='init', previous=None):
        require(action in ('init', 'check', 'adopt', 'update'), '未知操作')
        if action == 'update':
            require(strict_tag(previous), '旧版本格式无效')
        self.host.preflight()
        if action == 'check':
            return self.execute(action, previous)
        with self.files.lock():
            self.recover_pending()
            return self.execute(action, previous)

    def execute(self, action, previous):
        release = self.release
        old_policy = self.files.read(POLICY_TARGET, 0o644)
        old_raw = self.files.read(RECORD_TARGET, 0o600)
        pending = self.files.read(TRANSACTION_TARGET, 0o600)
        if pending is not None:
            transaction = self.transaction(pending)
            require(transaction['stage'] in ('complete', 'rolled_back'), '存在未完成事务，须先进行恢复')
        record = self.record(old_raw, old_policy)
        mode = self.host.kernel_mode()
        same = old_policy == release.policy
        if record:
            require(action != 'adopt', '已有受管登记，不需要接管')
            if record['release_tag'] != release.tag:
                require(action == 'update' and record['release_tag'] == previous, '版本不匹配，须显式绑定旧版本更新')
            else:
                require(action != 'update' or previous == record['release_tag'], '旧版本不匹配')
                require(record['source_commit'] == release.commit and record['installer_sha256'] == release.installer_sha256
                        and same, '同版本材料身份不一致')
        elif old_policy is not None:
            require(same and action == 'adopt', '现有策略无受管登记；仅完全相同官方材料可显式接管')
        else:
            require(mode is None and action == 'init', '发现未知内核策略或缺少受管旧材料')
        if action == 'check':
            require(record is not None and same and mode == 'enforce', '策略尚未完成准备或当前状态不一致')
            return self.result(action, False)
        if record and same and mode == 'enforce' and record['release_tag'] == release.tag:
            return self.result(action, False)
        # 无登记的现有内核策略不能仅凭名称和磁盘字节认定来源。
        # 显式接管在确认无消费者后重新加载官方材料，才能建立本项目登记。
        need_load = action == 'adopt' or not same or mode != 'enforce'
        if need_load or action == 'adopt':
            self.host.consumers()
        self.host.parse(release.policy)
        transaction = {'schema_version': 1, 'project': PROJECT, 'id': secrets.token_hex(16), 'stage': 'prepared',
                       'new_sha256': release.policy_sha256,
                       'old_policy': encode(old_policy), 'old_record': encode(old_raw), 'new_record': None, 'old_mode': mode,
                       'old_kernel_known': record is not None or mode is None,
                       'old_policy_identity': self.files.observations[POLICY_TARGET],
                       'old_record_identity': self.files.observations[RECORD_TARGET],
                       'new_policy_identity': None, 'new_record_identity': None,
                       'restored_policy_identity': None, 'restored_record_identity': None, 'restored_record': None}
        self.save_transaction(transaction)
        try:
            if not same:
                self.files.replace(POLICY_TARGET, old_policy, release.policy, 0o644)
            self.files.read(POLICY_TARGET, 0o644)
            transaction['new_policy_identity'] = self.files.observations[POLICY_TARGET]
            self.advance(transaction, 'file_committed')
            if need_load:
                # 再次检查消费者，不能用先前的进程列表替代提交时检查。
                self.host.consumers()
                self.host.load(release.policy)
            require(self.host.kernel_mode() == 'enforce', '策略加载后未处于强制模式')
            self.advance(transaction, 'kernel_verified')
            with self.files.parent(POLICY_TARGET) as (fd, name):
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            record = {'schema_version': 1, 'project': PROJECT, 'release_tag': release.tag,
                      'source_commit': release.commit, 'installer_sha256': release.installer_sha256,
                      'policy_name': PROJECT, 'policy_sha256': release.policy_sha256, 'policy_target': POLICY_TARGET,
                      'target_dev': info.st_dev, 'target_ino': info.st_ino,
                      'installed_at': datetime.now(timezone(timedelta(hours=8))).isoformat(),
                      'boot_id': self.host.boot_id, 'kernel_enforced': True}
            transaction['new_record'] = encode(json_bytes(record))
            self.save_transaction(transaction)
            self.files.replace(RECORD_TARGET, old_raw, json_bytes(record), 0o600)
            self.files.read(RECORD_TARGET, 0o600)
            transaction['new_record_identity'] = self.files.observations[RECORD_TARGET]
            self.advance(transaction, 'record_committed')
            require(self.files.read(POLICY_TARGET, 0o644) == release.policy, '提交后策略内容变化')
            self.host.preflight()
            self.advance(transaction, 'complete')
            return self.result(action, True)
        except Exception as error:
            try:
                self.advance(transaction, 'rollback_required')
                self.rollback(transaction)
            except Exception as recovery:
                with contextlib.suppress(Exception):
                    self.advance(transaction, 'recovery_required')
                raise RecoveryRequired('恢复无法确认；请保留 /var/lib/vap-host/transaction.json 并检查项目策略') from recovery
            if isinstance(error, Rejected):
                raise
            raise Rejected('策略准备失败，已恢复原材料') from error

    def transaction(self, raw):
        value = read_json(raw, TRANSACTION_FIELDS)
        require(type(value['schema_version']) is int and value['schema_version'] == 1 and value['project'] == PROJECT
                and hex_value(value['id'], 32) and hex_value(value['new_sha256'], 64)
                and value['old_mode'] in (None, 'enforce', 'complain')
                and type(value['old_kernel_known']) is bool
                and value['stage'] in {'prepared', 'file_committed', 'kernel_verified', 'record_committed',
                                       'complete', 'rollback_required', 'rolled_back', 'recovery_required'}, '事务归属或阶段无效')
        decode(value['old_policy']); decode(value['old_record']); decode(value['new_record']); decode(value['restored_record'])
        for key in ('old_policy_identity', 'old_record_identity', 'new_policy_identity', 'new_record_identity',
                    'restored_policy_identity', 'restored_record_identity'):
            stored_identity(value[key])
        return value

    def save_transaction(self, transaction):
        old = self.files.read(TRANSACTION_TARGET, 0o600)
        self.files.replace(TRANSACTION_TARGET, old, json_bytes(transaction), 0o600)

    def advance(self, transaction, stage):
        transaction['stage'] = stage
        self.save_transaction(transaction)

    def recover_pending(self):
        raw = self.files.read(TRANSACTION_TARGET, 0o600)
        if raw is None:
            return
        try:
            transaction = self.transaction(raw)
            if transaction['stage'] in ('complete', 'rolled_back'):
                return
            self.rollback(transaction)
        except Exception as error:
            raise RecoveryRequired('未完成事务无法安全恢复，请检查 /var/lib/vap-host/transaction.json') from error

    def rollback(self, transaction):
        require(transaction['old_kernel_known'], '接管前内核来源未知，不能冒充已恢复旧内核策略')
        old_policy, old_record = decode(transaction['old_policy']), decode(transaction['old_record'])
        now_record = self.files.read(RECORD_TARGET, 0o600)
        require(now_record in (old_record, decode(transaction['new_record']), decode(transaction['restored_record'])), '事务登记已被外部修改')
        require(self.files.observations[RECORD_TARGET] in tuple(stored_identity(transaction[key]) for key in
                ('old_record_identity', 'new_record_identity', 'restored_record_identity')), '事务登记节点归属无法确认')
        if old_record is not None:
            snapshot = read_json(old_record, RECORD_FIELDS)
            require(old_policy is not None and snapshot['policy_sha256'] == digest(old_policy), '原材料快照不一致')
        current = self.files.read(POLICY_TARGET, 0o644)
        require(current == old_policy or current is not None and digest(current) == transaction['new_sha256'], '事务目标已被外部修改')
        require(self.files.observations[POLICY_TARGET] in tuple(stored_identity(transaction[key]) for key in
                ('old_policy_identity', 'new_policy_identity', 'restored_policy_identity')), '事务策略节点归属无法确认')
        mode = self.host.kernel_mode()
        # 原先宽松模式的内核状态不能通过强制加载冒充恢复。
        require(transaction['old_mode'] != 'complain', '无法确认恢复原宽松内核状态')
        if mode != transaction['old_mode'] or current != old_policy:
            self.host.consumers()
            if transaction['old_mode'] == 'enforce':
                require(old_policy is not None, '缺少原内核策略可恢复材料')
                self.host.parse(old_policy)
                self.host.load(old_policy)
            elif mode is not None:
                require(current is not None and digest(current) == transaction['new_sha256'], '不能卸载未知策略')
                self.host.unload(current)
        require(self.host.kernel_mode() == transaction['old_mode'], '恢复内核状态核对失败')
        if current != old_policy:
            self.files.replace(POLICY_TARGET, current, old_policy, 0o644)
            self.files.read(POLICY_TARGET, 0o644)
            transaction['restored_policy_identity'] = self.files.observations[POLICY_TARGET]
            self.save_transaction(transaction)
        # 恢复文件使用新 inode，因此旧登记也须绑定恢复后的真实身份。
        if old_record is not None:
            restored = read_json(old_record, RECORD_FIELDS)
            with self.files.parent(POLICY_TARGET) as (fd, name):
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            restored['target_dev'], restored['target_ino'] = info.st_dev, info.st_ino
            old_record = json_bytes(restored)
        transaction['restored_record'] = encode(old_record)
        self.save_transaction(transaction)
        self.files.replace(RECORD_TARGET, now_record, old_record, 0o600)
        self.files.read(RECORD_TARGET, 0o600)
        transaction['restored_record_identity'] = self.files.observations[RECORD_TARGET]
        self.advance(transaction, 'rolled_back')

    def result(self, action, changed):
        return {'status': 'ready', 'action': action, 'release_tag': self.release.tag,
                'policy_sha256': self.release.policy_sha256, 'disk_verified': True,
                'kernel_enforced': True, 'persistence_configured': True, 'changed': changed,
                'stage': 'complete', 'safe_reason': '项目策略与持久条件检查通过，可以启动代理；出口就绪须另行查询',
                'recovery_required': False, 'recovery_path': None}


def encode(data):
    return None if data is None else base64.b64encode(data).decode('ascii')


def decode(value):
    if value is None:
        return None
    require(isinstance(value, str) and len(value) <= LIMIT * 2, '事务快照大小无效')
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as error:
        raise Rejected('事务快照无效') from error


class ChineseParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for group in self._action_groups:
            if group.title == 'options':
                group.title = '选项'
            elif group.title == 'positional arguments':
                group.title = '位置参数'

    def format_help(self):
        return super().format_help().replace('usage: ', '用法：')

    def print_usage(self, file=None):
        self._print_message(self.format_usage().replace('usage: ', '用法：'), file or sys.stdout)

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, '参数无效，请运行 --help 查看宿主准备说明。\n')


def arguments(argv=None):
    parser = ChineseParser(description='一次准备项目专用宿主策略；支持 Debian 12／Ubuntu 24.04 x86_64、有根本机 Docker 与 AppArmor。', add_help=False)
    parser.add_argument('--help', action='help', help='显示宿主准备说明，无副作用')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--check', action='store_true', help='只读检查，不创建文件或加载策略')
    group.add_argument('--adopt', action='store_true', help='显式接管完全相同的官方策略')
    group.add_argument('--update-from', metavar='旧版本', help='绑定受管旧版本更新，不停止消费者')
    result = parser.parse_args(argv)
    if result.update_from is not None and not strict_tag(result.update_from):
        parser.error('旧版本格式无效')
    return result


def main():
    options = arguments()
    action = 'check' if options.check else 'adopt' if options.adopt else 'update' if options.update_from else 'init'
    release = None
    try:
        require(EMBEDDED_RELEASE is not None, '请使用对应正式版本的单文件安装器；源码不直接加载策略')
        require(set(EMBEDDED_RELEASE) == {'release_tag', 'source_commit', 'policy_base64', 'policy_sha256'}, '内嵌材料字段无效')
        policy = decode(EMBEDDED_RELEASE['policy_base64'])
        release = Release(EMBEDDED_RELEASE['release_tag'], EMBEDDED_RELEASE['source_commit'], policy,
                          digest(Path(__file__).read_bytes()))
        require(release.policy_sha256 == EMBEDDED_RELEASE['policy_sha256'], '内嵌策略摘要不符')
        result = HostSetup(release).run(action, options.update_from)
        print('宿主准备检查通过：磁盘材料、内核强制模式、持久启动条件。')
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (Rejected, OSError, ValueError, TypeError, KeyError) as error:
        uncertain = isinstance(error, RecoveryRequired)
        reason = str(error) if isinstance(error, Rejected) else '必要宿主材料无法读取或检查'
        print('宿主准备未通过：' + reason, file=sys.stderr)
        print(json.dumps({'status': 'failed', 'action': action,
                          'release_tag': release.tag if release else None,
                          'policy_sha256': release.policy_sha256 if release else None,
                          'disk_verified': False, 'kernel_enforced': False, 'persistence_configured': False,
                          'changed': None, 'stage': 'recovery_required' if uncertain else 'rejected',
                          'safe_reason': reason, 'recovery_required': uncertain,
                          'recovery_path': TRANSACTION_TARGET if uncertain else None}, ensure_ascii=False))
        return 4 if uncertain else 1


if __name__ == '__main__':
    sys.exit(main())
