"""隧道控制句柄归属实验；不接入外部隧道程序或生产转发。"""
import argparse
import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

from macos_retained import read_record
from macos_tunnel import REPO, baseline, interfaces
from validate_macos import preflight

# 当前目标系统开发包的 sys/kern_control.h、sys/sys_domain.h 与 net/if_utun.h。
CONTROL_INFO = struct.Struct('=I96s')
CONTROL_ADDRESS = struct.Struct('=BBHII5I')
CTLIOCGINFO = 0xC0644E03
SYSTEM_FAMILY = 32
CONTROL_PROTOCOL = 2
CONTROL_SUBADDRESS = 2
UTUN_IFNAME = 2


def open_control(unit):
    """连接明确单元；内核控制套接字不依赖本地地址查询。"""
    handle = None
    stage = 'create_socket'
    try:
        handle = socket.socket(SYSTEM_FAMILY, socket.SOCK_DGRAM, CONTROL_PROTOCOL)
        stage = 'lookup_control'
        info = bytearray(CONTROL_INFO.pack(0, b'com.apple.net.utun_control'))
        fcntl.ioctl(handle.fileno(), CTLIOCGINFO, info, True)
        control_id = CONTROL_INFO.unpack(info)[0]
        address = ctypes.create_string_buffer(CONTROL_ADDRESS.pack(
            CONTROL_ADDRESS.size, SYSTEM_FAMILY, CONTROL_SUBADDRESS, control_id, unit, 0,0,0,0,0))
        libc = ctypes.CDLL(None, use_errno=True)
        libc.connect.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        libc.connect.restype = ctypes.c_int
        stage = 'connect_control'
        if libc.connect(handle.fileno(), address, CONTROL_ADDRESS.size) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        stage = 'read_interface_name'
        name = handle.getsockopt(CONTROL_PROTOCOL, UTUN_IFNAME, 64).split(b'\0')[0].decode('ascii')
        if not re.fullmatch(r'utun[0-9]+', name):
            raise RuntimeError('新建接口名称无效')
        stage = 'lookup_interface_index'
        index = socket.if_nametoindex(name)
        return handle, name, index
    except BaseException as error:
        error.stage = stage
        if handle is not None:
            handle.close()
        raise


class UtunHandle:
    def __init__(self, unit=0):
        if sys.platform != 'darwin':
            raise RuntimeError('本实验仅支持苹果系统')
        # 动态分配也逐次请求明确的单元；只跳过连接阶段的占用错误。
        # 每次失败关闭独立套接字，不推导接口名称与单元编号的关系。
        for candidate in (range(1, 256) if unit == 0 else (unit,)):
            try:
                self.socket, self.name, self.index = open_control(candidate)
                self.unit = candidate
                return
            except OSError as error:
                if not (unit == 0 and error.errno == errno.EBUSY
                        and getattr(error, 'stage', None) == 'connect_control'):
                    raise
        raise RuntimeError('限定范围内没有可用的隧道控制单元')

    def fileno(self):
        return self.socket.fileno()

    def identity_present(self):
        return self.name in interfaces() and socket.if_nametoindex(self.name) == self.index

    def close(self):
        self.socket.close()


class BorrowedWorker:
    def __init__(self, handle, uid, gid):
        identity = {}
        if os.geteuid() == 0:
            identity = dict(user=uid, group=gid, extra_groups=[])
        elif uid != os.getuid() or gid != os.getgid():
            raise RuntimeError('无权限切换借用进程身份')
        self.process = subprocess.Popen(
            ['/usr/bin/python3', str(Path(__file__).resolve()), '--borrowed-fd', str(handle.fileno())],
            pass_fds=(handle.fileno(),), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, cwd=REPO,
            **identity,
        )

    def ready(self):
        if read_record(self.process).get('event') != 'borrowed_ready':
            raise RuntimeError('借用句柄的工作进程未就绪')

    def close(self):
        try:
            if self.process.poll() is None:
                self.process.kill()
                self.process.wait(timeout=3)
        finally:
            for pipe in (self.process.stdin, self.process.stdout):
                pipe.close()


def exercise_lease(uid, gid):
    report = dict(status='failed', interface_lifetime_validated=False,
                  native_tunnel_validated=False, index_reuse_isolation_validated=False,
                  full_macos_backend_validated=False, checks={},
                  scope='仅未配置业务地址的隧道控制句柄生命周期、占用及回收实验；不验证加密隧道、业务收发、监督进程崩溃或生产隔离')
    checks, handles, worker, before = report['checks'], [], None, None
    started = time.monotonic()
    errors = []
    try:
        before = baseline()
        owner = UtunHandle()
        handles.append(owner)
        report['owned_interface'] = dict(name=owner.name, index=owner.index, control_unit=owner.unit)
        if owner.name in before['interfaces']:
            raise RuntimeError('新接口与启动前资源冲突')
        checks['owned_interface_created'] = owner.identity_present()
        if not checks['owned_interface_created']:
            raise RuntimeError('本次新建接口身份不可确认')
        worker = BorrowedWorker(owner, uid, gid)
        worker.ready()
        worker.process.kill()
        checks['borrower_killed_and_reaped'] = worker.process.wait(timeout=3) == -signal.SIGKILL
        checks['identity_survived_borrower_exit'] = owner.identity_present()
        if not all(checks.values()):
            raise RuntimeError('借用进程异常退出后接口身份未保持')
        try:
            conflicting = UtunHandle(owner.unit)
        except OSError as error:
            report['same_unit_connect_errno'] = error.errno
            checks['same_unit_reserved'] = (error.errno == errno.EBUSY
                and getattr(error, 'stage', None) == 'connect_control')
            if not checks['same_unit_reserved']:
                raise RuntimeError('连接失败不是明确的单元占用，不能作为防护证据') from error
        else:
            handles.append(conflicting)
            raise RuntimeError('旧句柄存活时同单元未被占用保护')
        challenger = UtunHandle()
        handles.append(challenger)
        report['parallel_interface'] = dict(name=challenger.name, index=challenger.index, control_unit=challenger.unit)
        checks['parallel_interface_has_distinct_identity'] = (challenger.index != owner.index
            and challenger.name != owner.name and challenger.unit != owner.unit and owner.identity_present())
        if not checks['parallel_interface_has_distinct_identity']:
            raise RuntimeError('并存新接口与保留接口身份冲突')
        worker.close()
        owner.close()
        deadline = time.monotonic() + 3
        while owner.name in interfaces() and time.monotonic() < deadline:
            time.sleep(0.05)
        checks['interface_removed_after_owner_release'] = owner.name not in interfaces()
        if not checks['interface_removed_after_owner_release']:
            raise RuntimeError('监督句柄释放后接口仍存在')
    except BaseException as error:
        report['error'] = str(error) or type(error).__name__
        if getattr(error, 'stage', None):
            report['error_stage'] = error.stage
    finally:
        cleanup_started = time.monotonic()
        if worker is not None:
            try:
                worker.close()
            except Exception as error:
                errors.append(str(error))
        reaped = worker is None or worker.process.poll() is not None
        checks['borrower_reaped'] = reaped
        if reaped:
            for handle in reversed(handles):
                try:
                    handle.close()
                except Exception as error:
                    errors.append(str(error))
        else:
            errors.append('借用进程未回收，拒绝释放监督句柄')
        try:
            deadline = time.monotonic() + 3
            while any(h.name in interfaces() for h in handles) and time.monotonic() < deadline:
                time.sleep(0.05)
            after = baseline()
            checks['baseline_restored'] = before is not None and before == after
            checks['no_new_interfaces_left'] = before is not None and not (after['interfaces'].keys() - before['interfaces'].keys())
        except Exception as error:
            errors.append(str(error))
        report['borrower_exit_code'] = worker.process.poll() if worker is not None else None
        report['cleanup_seconds'] = round(time.monotonic() - cleanup_started, 3)
        checks['cleanup_within_15_seconds'] = report['cleanup_seconds'] < 15
        report['cleanup_errors'] = errors
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
    if not report.get('error') and not errors and all(checks.values()) and len(handles) == 2:
        report.update(status='passed', interface_lifetime_validated=True)
    return report


def borrowed(fd):
    if fd < 3:
        raise RuntimeError('拒绝借用标准输入输出描述符')
    # 仅持有继承描述符；套接字包装器的自动类型推断也可能查询本地地址。
    try:
        os.fstat(fd)
        print(json.dumps({'event': 'borrowed_ready'}), flush=True)
        sys.stdin.buffer.read(1)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description='短时隧道句柄生命周期实验，不进行三十分钟测试')
    parser.add_argument('--openvpn', default=str(REPO / 'validation-output/macos-deps/openvpn-2.6.23-local/sbin/openvpn'))
    parser.add_argument('--native', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--borrowed-fd', type=int, help=argparse.SUPPRESS)
    options = parser.parse_args()
    if options.borrowed_fd is not None:
        borrowed(options.borrowed_fd)
        return 0
    if not Path(options.openvpn).is_absolute():
        parser.error('依赖程序必须使用绝对路径')
    if not options.native:
        if os.geteuid() == 0:
            parser.error('请从普通用户终端启动包装脚本')
        return subprocess.run(['sudo', '/usr/bin/python3', str(Path(__file__).resolve()),
                               '--native', '--openvpn', options.openvpn], cwd=REPO).returncode
    report = dict(case='lease', status='blocked', interface_lifetime_validated=False,
                  native_tunnel_validated=False, index_reuse_isolation_validated=False,
                  full_macos_backend_validated=False)
    check = preflight(options.openvpn)
    if check['status'] != 'passed':
        report['preflight'] = check
    else:
        uid, gid = int(os.environ.get('SUDO_UID', '0')), int(os.environ.get('SUDO_GID', '0'))
        if uid == 0:
            report.update(status='failed', error='借用工作进程必须使用原普通用户身份')
        else:
            try:
                report.update(exercise_lease(uid, gid))
            except BaseException as error:
                report.update(status='failed', error=str(error) or type(error).__name__)
    folder = Path(tempfile.mkdtemp(prefix='macos-lease-', dir=REPO / 'validation-output'))
    folder.chmod(0o700)
    path = folder / 'report.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    path.chmod(0o600)
    print('验证报告：' + str(path), file=sys.stderr)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report['status'] == 'passed' else 2


if __name__ == '__main__':
    def interrupted(number, frame):
        raise KeyboardInterrupt('验证收到中断信号')
    signal.signal(signal.SIGTERM, interrupted)
    sys.exit(main())
