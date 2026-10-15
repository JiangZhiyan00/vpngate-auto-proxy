"""异常退出后原套接字与真实索引复用的行为刻画，不作防漏结论。"""
import hashlib
import secrets
import signal
import subprocess
import time

from macos_generation import GenerationWorker
from macos_retained import read_record
from macos_reuse import exercise_reuse
from macos_tunnel import REPO, TARGET, interfaces, run


class RetainedProbe:
    # 共用已验证的有界进程回收，不复用代际协议。
    close = GenerationWorker.close

    def __init__(self, options, node, identity, payload, runtime, uid, gid, control_handle=None):
        with (runtime / 'abrupt-probe-error.log').open('w') as error:
            self.process = subprocess.Popen(
                [options.probe, str(node.index), TARGET, '19090', payload, identity, '1', 'retained'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=error, text=True,
                cwd=REPO, user=uid, group=gid, extra_groups=[],
                pass_fds=(control_handle.fileno(),) if control_handle is not None else (),
            )


def reconcile_removed_route(node):
    """仅核对本次接口销毁造成的路由自动删除；保留仍存在的路由清理责任。"""
    if node.process.poll() is None or node.interface in interfaces():
        raise RuntimeError('进程或接口未消失，拒绝更新路由清理状态')
    content = run(['/usr/sbin/netstat', '-rn', '-f', 'inet']).stdout
    present = any(len(fields) >= 4 and fields[0] == TARGET and fields[3] == node.interface
                  for fields in (line.split() for line in content.splitlines()))
    if not present:
        node.route_added = False


def classify_response(value, index, old_identity, new_identity, payload):
    if value.get('interface_index') != index or value.get('identity') != old_identity:
        raise RuntimeError('保留套接字观察归属不符')
    result = {}
    for protocol in ('tcp', 'udp'):
        response = value.get(f'retained_{protocol}_response')
        digest = value.get(f'retained_{protocol}_response_sha256')
        if type(response) is not bool or (response and (not isinstance(digest, str)
                or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest))) or (not response and digest is not None):
            raise RuntimeError('保留套接字响应及摘要字段无效')
        result[protocol] = 'none' if not response else 'other'
        challenge = (payload + '-after-removal').encode()
        candidates = {'echo': challenge} if protocol == 'tcp' else {
            'original': old_identity.encode() + b':' + challenge,
            'replacement': new_identity.encode() + b':' + challenge,
        }
        for label, expected in candidates.items():
            if digest == hashlib.sha256(expected).hexdigest():
                result[protocol] = label
    for key in ('retained_tcp_write_succeeded', 'retained_udp_send_succeeded'):
        if type(value.get(key)) is not bool:
            raise RuntimeError('保留套接字发送观察字段无效')
    return result


def exercise_abrupt(options, folder, nodes, activity, runtime, endpoints, uid, gid, evidence, workers):
    checks = {}
    evidence.update(checks=checks, scope='本次隧道进程强制终止、原套接字保留及真实索引复用后的两秒响应观察；无响应不证明零直连，不验证生产恢复')
    node = nodes[2]
    old_index, old_identity = int(node.index), endpoints[2]['identity']
    payload = secrets.token_hex(24)
    try:
        worker = RetainedProbe(options, node, old_identity, payload, runtime, uid, gid)
        workers.append(worker)
        value = read_record(worker.process)
        if not (value.get('interface_index') == old_index and value.get('identity') == old_identity
                and value.get('tcp') is True and value.get('udp') is True and worker.process.poll() is None):
            raise RuntimeError('故障前原套接字正向对照失败')
        evidence['original_probe'] = value
        checks['original_tcp_udp_verified'] = True
        if node.process.poll() is not None:
            raise RuntimeError('目标隧道进程已提前退出')
        node.process.kill()  # 仅本次持有的直接子进程，不按名称或接口查杀。
        code = node.process.wait(timeout=3)
        checks['owned_tunnel_killed'] = code == -signal.SIGKILL
        deadline = time.monotonic() + 3
        while node.interface in interfaces() and time.monotonic() < deadline:
            time.sleep(0.05)
        reconcile_removed_route(node)
        checks['interface_removed_with_probe_alive'] = worker.process.poll() is None
        if not all(checks.values()):
            raise RuntimeError('异常退出阶段条件未满足')
        evidence['reuse'] = {}
        exercise_reuse(options, folder, nodes, activity, runtime, endpoints, uid, gid, evidence['reuse'])
        checks['actual_reuse_and_different_exit_verified'] = evidence['reuse']['checks']['cached_numeric_index_reaches_replacement']
        if worker.process.poll() is not None:
            raise RuntimeError('索引复用前保留套接字探针已退出')
        worker.process.stdin.write('c')
        worker.process.stdin.flush()
        value = read_record(worker.process)
        evidence['retained_socket_observation'] = value
        evidence['response_classification'] = classify_response(value, old_index, old_identity, endpoints[0]['identity'], payload)
        checks['observation_complete'] = True
        checks['probe_exited_normally'] = worker.process.wait(timeout=3) == 0
        if not all(checks.values()):
            raise RuntimeError('异常退出行为刻画未完成')
    except BaseException as error:
        evidence['error'] = str(error) or type(error).__name__
        raise
