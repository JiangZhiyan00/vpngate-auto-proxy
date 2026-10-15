"""独立监督通道所有者的强制退出实验；不等同于正式服务监督及重启。"""
import argparse
import array
import errno
import json
import os
from pathlib import Path
import selectors
import select
import signal
import socket
import stat
import subprocess
import sys
import time

from macos_handoff import CustodyGenerationWorker, release_parent, require_removed
from macos_pinned import PinnedTunnel
from macos_retained import read_record
from macos_tunnel import REPO, TARGET, run


def emit(value):
    print(json.dumps(value), flush=True)


def serve(path, channel, hold=False):
    """唯一持有已接收的管理会话与业务控制端；不接收任意命令。"""
    metadata = path.parent.stat()
    if (not path.is_absolute() or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077 or path.exists() or path.is_symlink()):
        raise RuntimeError('监督通道必须使用尚不存在的私有路径')
    manager = None
    worker = None
    management_buffer = b''
    hold_reported = False
    selector = selectors.DefaultSelector()
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(path))
        path.chmod(0o600)
        listener.listen(1)
        selector.register(listener, selectors.EVENT_READ, 'listener')
        selector.register(channel, selectors.EVENT_READ, 'channel')
        emit({'event': 'supervisor_ready'})
        while True:
            for key, _ in selector.select():
                if key.data == 'listener':
                    manager, _ = listener.accept()
                    # 私有目录限定访问；实验不把路径或同用户身份当作正式进程认证。
                    selector.unregister(listener)
                    listener.close()
                    manager.settimeout(3)
                    if not hold:
                        manager.sendall(b'hold release\n')
                    manager.setblocking(False)
                    selector.register(manager, selectors.EVENT_READ, 'manager')
                    emit({'event': 'management_connected'})
                elif key.data == 'manager':
                    # 消费有界批次，避免长驻管理输出塞满外部程序发送缓冲。
                    data = manager.recv(4096)
                    if not data:
                        return
                    if hold and not hold_reported:
                        management_buffer += data
                        while b'\n' in management_buffer:
                            line, management_buffer = management_buffer.split(b'\n', 1)
                            if line.startswith(b'>HOLD:Waiting for hold release:'):
                                hold_reported = True
                                emit({'event': 'management_hold'})
                        if len(management_buffer) > 4096:
                            raise RuntimeError('管理通道记录超过有界帧限制')
                else:
                    data, ancillary, flags, _ = channel.recvmsg(1, socket.CMSG_SPACE(16 * array.array('i').itemsize))
                    received = []
                    malformed = bool(flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC))
                    for level, kind, payload in ancillary:
                        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                            numbers = array.array('i')
                            size = numbers.itemsize
                            if len(payload) % size:
                                malformed = True
                            numbers.frombytes(payload[:len(payload) // size * size])
                            received.extend(numbers)
                        else:
                            malformed = True
                    try:
                        if not data and not received:
                            return
                        if malformed or data != b'A' or len(received) != 1 or worker is not None:
                            raise RuntimeError('监督方业务控制端交接无效')
                        descriptor = received.pop()
                        try:
                            os.set_inheritable(descriptor, False)
                            if not stat.S_ISSOCK(os.fstat(descriptor).st_mode):
                                raise RuntimeError('业务控制端不是套接字')
                            worker = socket.socket(fileno=descriptor)
                            descriptor = None
                            if worker.family != socket.AF_UNIX or worker.type != socket.SOCK_STREAM:
                                raise RuntimeError('业务控制端类型无效')
                        finally:
                            if descriptor is not None:
                                os.close(descriptor)
                        emit({'event': 'worker_control_adopted'})
                    finally:
                        for descriptor in received:
                            os.close(descriptor)
    finally:
        selector.close()
        if worker is not None:
            worker.close()
        if manager is not None:
            manager.close()
        listener.close()
        # 强制退出不会运行此处；路径留给有归属证据的外层清理。
        path.unlink(missing_ok=True)


class ManagementOwner:
    def __init__(self, runtime, hold=False):
        self.path = runtime / 'supervisor.sock'
        self.buffer = b''
        self.channel, child = socket.socketpair()
        try:
            with (runtime / 'supervisor-error.log').open('w') as error:
                self.process = subprocess.Popen(
                    [sys.executable, str(Path(__file__).resolve()), '--serve', str(self.path)]
                    + (['--hold'] if hold else []), stdin=child, stdout=subprocess.PIPE,
                    stderr=error, bufsize=0, cwd=REPO)
        except BaseException:
            self.channel.close()
            raise
        finally:
            child.close()

    def read_event(self):
        # 直接保存二进制分帧余量，避免文本读取器预读第二帧后 select 看不到数据。
        deadline = time.monotonic() + 3
        while b'\n' not in self.buffer:
            remaining = deadline-time.monotonic()
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                raise RuntimeError('监督方未在截止前输出阶段结果')
            data = os.read(self.process.stdout.fileno(), 4096)
            if not data:
                raise RuntimeError('监督方阶段记录提前结束')
            self.buffer += data
            if len(self.buffer) > 4096 and b'\n' not in self.buffer:
                raise RuntimeError('监督方阶段记录超限')
        line, self.buffer = self.buffer.split(b'\n', 1)
        if len(line) > 4096:
            raise RuntimeError('监督方阶段记录超限')
        return json.loads(line)

    def ready(self):
        if self.read_event().get('event') != 'supervisor_ready':
            raise RuntimeError('独立监督通道未就绪')

    def connected(self):
        if self.read_event().get('event') != 'management_connected':
            raise RuntimeError('外部隧道管理会话未连接')

    def adopt(self, descriptor):
        self.channel.settimeout(3)
        if self.channel.sendmsg([b'A'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                        array.array('i', [descriptor]))]) != 1:
            raise RuntimeError('业务控制端未完整交接')
        if self.read_event().get('event') != 'worker_control_adopted':
            raise RuntimeError('监督方未确认唯一持有业务控制端')

    def close(self):
        try:
            self.channel.close()
            if self.process.poll() is None:
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=2)
        finally:
            self.process.stdout.close()
            if self.process.poll() is not None:
                self.path.unlink(missing_ok=True)


def transfer_worker_control(worker, owner):
    stream = worker.process.stdin
    descriptor = stream.fileno()
    stream.flush()
    owner.adopt(descriptor)
    stream.close()
    worker.process.stdin = None
    try:
        os.fstat(descriptor)
    except OSError as error:
        if error.errno != errno.EBADF:
            raise
    else:
        raise RuntimeError('观察方仍持有业务控制端，不能验证监督方退出')


def verify_candidate(options, node, endpoint, uid, gid):
    import secrets
    business = json.loads(run([options.probe, str(node.index), TARGET, '19090',
                              secrets.token_hex(24), endpoint['identity'], '1'],
                             timeout=8, cwd=REPO, user=uid, group=gid, extra_groups=[]).stdout)
    dns = json.loads(run([options.dns_probe, str(node.index), TARGET, '53', endpoint['identity']],
                        timeout=8, cwd=REPO, user=uid, group=gid, extra_groups=[]).stdout)
    if not (business.get('interface_index') == int(node.index) and business.get('identity') == endpoint['identity']
            and business.get('tcp') is True and business.get('udp') is True
            and dns.get('interface_index') == int(node.index) and dns.get('identity') == endpoint['identity']
            and dns.get('dns_udp') is True and dns.get('dns_tcp_fallback') is True and dns.get('resolved_ipv4') == TARGET):
        raise RuntimeError('监督故障前后候选业务或解析归属不符')


def exercise_supervision(options, folder, nodes, runtime, endpoints, uid, gid, evidence, workers):
    checks = {}
    evidence.update(checks=checks, scope='独立控制通道所有者强制退出后，真实隧道管理客户端与持有控制句柄的业务工作进程自行退出；观察及回收进程仍存活，不证明完整生产监督崩溃、零直连或安全重启')
    try:
        owner = ManagementOwner(runtime)
        workers.append(owner)
        owner.ready()
        # 原第三条候选无业务工作进程；先回收，再建立受监督的新实例。
        nodes[2].close()
        from macos_tunnel import interfaces
        node = PinnedTunnel(options, folder, runtime, 2, endpoints[2], set(interfaces()),
                            instance='supervised', management_path=owner.path)
        nodes.append(node)
        node.ready()
        owner.connected()
        evidence['managed_interface'] = {'name': node.interface, 'index': int(node.index)}
        worker = CustodyGenerationWorker(options, node, endpoints[2], runtime, 'supervised', uid, gid)
        workers.append(worker)
        worker.handoff(node.control_handle)
        worker.ready()
        evidence['worker_probe'] = worker.probe()
        transfer_worker_control(worker, owner)
        checks['observer_worker_control_closed'] = True
        release_parent(node)
        checks['observer_utun_descriptor_closed'] = True
        if (owner.process.poll() is not None or worker.process.poll() is not None
                or node.process.poll() is not None or not node.control_handle.identity_present()):
            raise RuntimeError('监督故障前进程或接口身份已丢失')
        verify_candidate(options, nodes[1], endpoints[1], uid, gid)
        checks['candidate_business_dns_before_fault'] = True
        started = time.monotonic()
        deadline = started + 6
        owner.process.kill()
        evidence['supervisor_exit_code'] = owner.process.wait(timeout=max(0.001, deadline-time.monotonic()))
        if evidence['supervisor_exit_code'] != -signal.SIGKILL:
            raise RuntimeError('监督通道所有者未按预期强制退出')
        checks['supervisor_killed_and_reaped'] = True
        # 此阶段只等待；不得主动向隧道或业务进程发信号来制造通过。
        evidence['worker_exit_code'] = worker.process.wait(timeout=max(0.001, deadline-time.monotonic()))
        evidence['tunnel_exit_code'] = node.process.wait(timeout=max(0.001, deadline-time.monotonic()))
        evidence['automatic_exit_seconds'] = round(time.monotonic()-started, 3)
        ack = read_record(worker.process)
        evidence['retirement_ack'] = ack
        if (evidence['worker_exit_code'] != 0 or evidence['tunnel_exit_code'] != 0
                or ack.get('event') != 'retired' or ack.get('generation') != worker.generation):
            raise RuntimeError('监督方退出后的自动停止或代际退休确认不符')
        if 'SIGTERM[soft,management-exit]' not in node.log.read_text():
            raise RuntimeError('外部程序退出原因不是管理会话断开')
        checks['worker_retired_without_observer_signal'] = True
        checks['tunnel_exited_on_management_disconnect'] = True
        require_removed(node)
        checks['interface_removed_after_both_consumers_exit'] = True
        verify_candidate(options, nodes[1], endpoints[1], uid, gid)
        checks['candidate_business_dns_after_fault'] = True
    except BaseException as error:
        evidence['error'] = str(error) or type(error).__name__
        raise


def main():
    parser = argparse.ArgumentParser(description='受控独立监督通道，不提供用户管理接口')
    parser.add_argument('--serve', type=Path, required=True)
    parser.add_argument('--hold', action='store_true')
    options = parser.parse_args()
    # 专属通道映射到标准输入；任何接收错误使独立监督进程退出。
    with socket.socket(fileno=os.dup(0)) as channel:
        serve(options.serve, channel, options.hold)


if __name__ == '__main__':
    main()
