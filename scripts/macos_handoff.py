"""真实控制句柄交接与工作代际回收；不是完整后端或零直连验收。"""
import array
import errno
import json
import os
import secrets
import signal
import socket
import subprocess
import time
import uuid

from macos_abrupt import reconcile_removed_route
from macos_generation import GenerationWorker
from macos_retained import read_record
from macos_tunnel import REPO, TARGET, interfaces, run


class CustodyGenerationWorker(GenerationWorker):
    def __init__(self, options, node, endpoint, runtime, label, uid, gid, expected_index=None):
        self.generation = None
        self.index = int(node.index) if expected_index is None else expected_index
        self.identity = endpoint['identity']
        self.interface = node.interface
        self.authorization = uuid.uuid4()
        self.channel, child = socket.socketpair()
        try:
            with (runtime / f'handoff-{label}-error.log').open('w') as error:
                self.process = subprocess.Popen(
                    [options.generation_worker, str(self.index), TARGET, '19090', self.identity,
                     '--utun-custody-stdin', str(self.authorization)],
                    stdin=child, stdout=subprocess.PIPE, stderr=error, text=True,
                    cwd=REPO, user=uid, group=gid, extra_groups=[])
        except BaseException:
            self.channel.close()
            raise
        finally:
            child.close()

    def handoff(self, handle):
        # 先由编排方登记进程再发送；任何交接失败仍由外层先回收该进程。
        frame = b'VAP1' + self.authorization.bytes + self.index.to_bytes(4, 'big')
        self.channel.settimeout(3)
        count = self.channel.sendmsg([frame], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                              array.array('i', [handle.fileno()]))])
        if count != len(frame):
            raise RuntimeError('控制句柄启动材料未完整发送')
        self.channel.settimeout(None)
        self.process.stdin = self.channel.makefile('w')
        self.channel.close()

    def ready(self):
        value = read_record(self.process)
        if not (value.get('event') == 'ready' and value.get('interface_index') == self.index
                and value.get('custody_interface') == self.interface):
            raise RuntimeError('真实控制句柄校验后的就绪归属不符')
        self.generation = str(uuid.UUID(value['generation']))

    def rejected(self):
        code = self.process.wait(timeout=4)
        if code == 0 or self.process.stdout.read(4097) != '':
            raise RuntimeError('错误接口句柄没有在发布就绪前拒绝')
        return {'exit_code': code, 'ready_published': False}

    def close(self):
        try:
            super().close()
        finally:
            self.channel.close()


def release_parent(node):
    descriptor = node.control_handle.fileno()
    node.control_handle.close()
    try:
        os.fstat(descriptor)
    except OSError as error:
        if error.errno != errno.EBADF:
            raise
    else:
        raise RuntimeError('编排方仍持有控制句柄，不能验证业务代际持有')
    node.control_handle_transferred = True


def require_removed(node):
    deadline = time.monotonic() + 3
    while node.interface in interfaces() and time.monotonic() < deadline:
        time.sleep(0.05)
    if node.interface in interfaces():
        raise RuntimeError('最后工作代际退出后隧道接口仍存在')
    reconcile_removed_route(node)
    node.close()


def exercise_handoff(options, nodes, runtime, endpoints, uid, gid, evidence, workers):
    checks = {}
    evidence.update(checks=checks, scope='真实控制句柄的错误索引拒绝、私有交接、业务代际持有、正常退休及强制退出释放；不验证完整监督崩溃、零直连或生产重启')
    try:
        old = nodes[2]
        bad = CustodyGenerationWorker(options, old, endpoints[2], runtime, 'wrong-index', uid, gid,
                                      expected_index=int(nodes[0].index))
        workers.append(bad)
        bad.handoff(old.control_handle)
        evidence['wrong_index_rejection'] = bad.rejected()
        checks['wrong_index_rejected_without_ready'] = True
        checks['parent_identity_survived_rejection'] = old.control_handle.identity_present()
        if not checks['parent_identity_survived_rejection']:
            raise RuntimeError('拒绝交接影响了监督方持有的接口')
        for position, forced in ((2, False), (1, True)):
            node = nodes[position]
            worker = CustodyGenerationWorker(options, node, endpoints[position], runtime,
                                            'forced' if forced else 'retire', uid, gid)
            workers.append(worker)
            worker.handoff(node.control_handle)
            worker.ready()
            evidence[f'worker_{position}_probe'] = worker.probe()
            release_parent(node)
            checks[f'parent_{position}_descriptor_closed'] = True
            node.process.kill()
            if node.process.wait(timeout=3) != -signal.SIGKILL:
                raise RuntimeError('目标隧道未按预期强制退出')
            if worker.process.poll() is not None or not node.control_handle.identity_present():
                raise RuntimeError('业务代际存活时旧接口身份未保持')
            checks[f'worker_{position}_pins_identity_after_tunnel_exit'] = True
            if not forced:
                for candidate, endpoint in zip(nodes[:2], endpoints[:2]):
                    business = json.loads(run([options.probe, str(candidate.index), TARGET, '19090',
                                              secrets.token_hex(24), endpoint['identity'], '1'],
                                             timeout=8, cwd=REPO, user=uid, group=gid, extra_groups=[]).stdout)
                    dns = json.loads(run([options.dns_probe, str(candidate.index), TARGET, '53', endpoint['identity']],
                                        timeout=8, cwd=REPO, user=uid, group=gid, extra_groups=[]).stdout)
                    if not (business.get('identity') == endpoint['identity']
                            and business.get('interface_index') == int(candidate.index)
                            and business.get('tcp') is True and business.get('udp') is True
                            and dns.get('identity') == endpoint['identity']
                            and dns.get('interface_index') == int(candidate.index)
                            and dns.get('dns_udp') is True and dns.get('dns_tcp_fallback') is True
                            and dns.get('resolved_ipv4') == TARGET):
                        raise RuntimeError('句柄交接期间存活候选的业务或解析归属不符')
                checks['other_tunnels_business_dns_verified'] = True
                evidence['retirement_ack'] = worker.retire()
            else:
                worker.process.kill()
                if worker.process.wait(timeout=3) != -signal.SIGKILL:
                    raise RuntimeError('工作进程未按预期强制退出')
            require_removed(node)
            checks[f'interface_{position}_removed_after_worker_exit'] = True
    except BaseException as error:
        evidence['error'] = str(error) or type(error).__name__
        raise
