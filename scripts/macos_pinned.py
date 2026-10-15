"""保留控制句柄的真实隧道候选方案；仍不代表完整苹果后端。"""
import hashlib
import json
import errno
import os
import secrets
import signal
import time
from pathlib import Path

from macos_abrupt import RetainedProbe, classify_response, reconcile_removed_route
from macos_lease import BorrowedWorker, UtunHandle
from macos_parallel import Tunnel
from macos_retained import read_record
from macos_tunnel import REPO, TARGET, interfaces, run


def validate_dependency(binary):
    path = Path(binary)
    record = json.loads((path.parent.parent / 'provenance.json').read_text())
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    if not (record.get('experimental_only') is True
            and record.get('source_sha256') == '4041c709162bec1325abf5aa8cf27a255cc477c634b15ee310411c701fc40a96'
            and record.get('patch_sha256') == digest(REPO / 'scripts/patches/openvpn-2.6.23-utun-fd.patch')
            and record.get('binary_sha256') == digest(path)):
        raise RuntimeError('实验隧道依赖的来源、补丁或二进制摘要不符，请重新构建')
    return {k:record[k] for k in ('experimental_only','source_sha256','patch_sha256','binary_sha256')}


class PinnedTunnel(Tunnel):
    def __init__(self, *args, **kwargs):
        handle = UtunHandle()
        try:
            super().__init__(*args, control_handle=handle, **kwargs)
        except BaseException:
            handle.close()
            raise


def exercise_pinned(options, folder, nodes, activity, runtime, endpoints, uid, gid, evidence, workers, custody=False):
    checks = {}
    evidence.update(checks=checks, scope='监督方保留控制句柄时，隧道进程强制退出、不同出口并存及原套接字两秒无响应；不证明零直连、监督进程崩溃安全或完整苹果隔离')
    if custody:
        evidence['scope'] = '受控句柄持有进程与隧道进程均强制退出、编排方已关闭原句柄后，业务探针保留同一控制句柄及原套接字；仅验证本次身份保持与两秒响应，不证明生产监督崩溃安全、零直连或完整苹果隔离'
    old = nodes[2]
    old_index, old_identity = int(old.index), endpoints[2]['identity']
    payload = secrets.token_hex(24)
    try:
        owner = None
        if custody:
            owner = BorrowedWorker(old.control_handle, uid, gid)
            workers.append(owner)
            owner.ready()
        worker = RetainedProbe(options, old, old_identity, payload, runtime, uid, gid,
                               **({'control_handle': old.control_handle} if custody else {}))
        workers.append(worker)
        positive = read_record(worker.process)
        if not (positive.get('interface_index') == old_index and positive.get('identity') == old_identity
                and positive.get('tcp') is True and positive.get('udp') is True and worker.process.poll() is None):
            raise RuntimeError('故障前原套接字正向对照失败')
        evidence['original_probe'] = positive
        checks['original_tcp_udp_verified'] = True
        if custody:
            descriptor = old.control_handle.fileno()
            old.control_handle.close()
            try:
                os.fstat(descriptor)
            except OSError as error:
                checks['orchestrator_descriptor_closed'] = error.errno == errno.EBADF
            else:
                checks['orchestrator_descriptor_closed'] = False
            old.control_handle_transferred = checks['orchestrator_descriptor_closed']
            if not checks['orchestrator_descriptor_closed'] or owner.process.poll() is not None:
                raise RuntimeError('关闭编排方句柄或受控持有进程存活检查失败')
            owner.process.kill()
            evidence['holder_exit_code'] = owner.process.wait(timeout=3)
            checks['owned_holder_killed_and_reaped'] = evidence['holder_exit_code'] == -signal.SIGKILL
            checks['probe_alive_after_holder_exit'] = worker.process.poll() is None
            if not all(checks.values()):
                raise RuntimeError('受控句柄持有进程退出阶段未完成')
        if old.process.poll() is not None:
            raise RuntimeError('目标隧道进程已提前退出')
        old.process.kill()
        checks['owned_tunnel_killed'] = old.process.wait(timeout=3) == -signal.SIGKILL
        checks['old_interface_pinned_after_kill'] = old.control_handle.identity_present()
        if not all(checks.values()):
            raise RuntimeError('隧道异常退出后原接口身份未保持')
        if activity.poll() is not None:
            raise RuntimeError('建立其他出口前活动探针已提前退出')
        activity.terminate()
        activity.wait(timeout=3)
        if activity.poll() is None:
            raise RuntimeError('活动探针未回收，拒绝释放其接口')
        nodes[0].close()
        replacement = PinnedTunnel(options, folder, runtime, 0, endpoints[0], set(interfaces()), instance='replacement')
        nodes.append(replacement)
        replacement.ready()
        evidence['replacement_interface'] = dict(name=replacement.interface,index=int(replacement.index),identity=endpoints[0]['identity'])
        checks['replacement_has_distinct_identity'] = (int(replacement.index) != old_index
            and replacement.interface != old.interface and endpoints[0]['identity'] != old_identity
            and old.control_handle.identity_present())
        if not checks['replacement_has_distinct_identity']:
            raise RuntimeError('新出口与保留旧接口身份冲突')
        for node, endpoint, label in ((replacement,endpoints[0],'replacement'),(nodes[1],endpoints[1],'candidate_1')):
            business = json.loads(run([options.probe,str(node.index),TARGET,'19090',secrets.token_hex(24),endpoint['identity'],'1'],
                                      timeout=8,cwd=REPO,user=uid,group=gid,extra_groups=[]).stdout)
            dns = json.loads(run([options.dns_probe,str(node.index),TARGET,'53',endpoint['identity']],
                                 timeout=8,cwd=REPO,user=uid,group=gid,extra_groups=[]).stdout)
            if not (business.get('identity') == endpoint['identity'] and business.get('interface_index') == int(node.index)
                    and business.get('tcp') is True and business.get('udp') is True
                    and dns.get('identity') == endpoint['identity'] and dns.get('interface_index') == int(node.index)
                    and dns.get('dns_udp') is True and dns.get('dns_tcp_fallback') is True and dns.get('resolved_ipv4') == TARGET):
                raise RuntimeError('新出口或候选的业务及解析归属不符')
            checks[label+'_business_dns_verified'] = True
        if worker.process.poll() is not None:
            raise RuntimeError('故障观察前原套接字探针已退出')
        checks['old_identity_pinned_before_challenge'] = old.control_handle.identity_present()
        if not checks['old_identity_pinned_before_challenge']:
            raise RuntimeError('故障观察前旧接口身份已丢失')
        worker.process.stdin.write('c')
        worker.process.stdin.flush()
        observed = read_record(worker.process)
        evidence['retained_socket_observation'] = observed
        evidence['response_classification'] = classify_response(observed,old_index,old_identity,endpoints[0]['identity'],payload)
        checks['retained_tcp_no_response_in_2_seconds'] = observed['retained_tcp_response'] is False
        checks['retained_udp_no_response_in_2_seconds'] = observed['retained_udp_response'] is False
        if not checks['retained_tcp_no_response_in_2_seconds'] or not checks['retained_udp_no_response_in_2_seconds']:
            raise RuntimeError('隧道进程退出后原套接字仍收到响应')
        exit_check = 'business_probe_exited_normally' if custody else 'probe_exited_before_interface_release'
        checks[exit_check] = worker.process.wait(timeout=3) == 0
        if not checks[exit_check]:
            raise RuntimeError('原探针未正常退出')
        if custody:
            deadline = time.monotonic() + 3
            while old.interface in interfaces() and time.monotonic() < deadline:
                time.sleep(0.05)
            checks['interface_removed_after_last_business_holder_exit'] = old.interface not in interfaces()
            if not checks['interface_removed_after_last_business_holder_exit']:
                raise RuntimeError('业务探针退出后原接口仍存在，不能确认最后句柄释放')
            reconcile_removed_route(old)
        else:
            checks['old_identity_still_pinned_before_release'] = old.control_handle.identity_present()
        if not all(checks.values()):
            raise RuntimeError('原探针未退出或旧接口身份未保持，禁止释放')
        old.close()
        checks['old_interface_removed_after_probe_exit'] = old.interface not in interfaces()
        if not all(checks.values()):
            raise RuntimeError('保留句柄的故障阶段检查未全部通过')
    except BaseException as error:
        evidence['error'] = str(error) or type(error).__name__
        raise
