"""真实接口索引复用的行为刻画；不实现或宣称代际隔离。"""
import json
import secrets

from macos_tunnel import REPO, TARGET, interfaces, run


def verify_observation(old_index, replacement_index, old_identity, replacement_identity, value):
    if int(old_index) != int(replacement_index):
        raise RuntimeError('新接口未复用旧索引；本次不能验证索引复用行为')
    if old_identity == replacement_identity:
        raise RuntimeError('跨代际实验的远端身份必须不同')
    if not (value.get('interface_index') == int(old_index)
            and value.get('identity') == replacement_identity
            and value.get('tcp') is True and value.get('udp') is True):
        raise RuntimeError('旧数字索引未得到新远端的完整流式及数据报正向证据')


def exercise_reuse(options, folder, nodes, activity, runtime, endpoints, uid, gid, evidence):
    from macos_parallel import Tunnel
    checks = {}
    evidence.update(checks=checks, scope='旧数字索引在真实复用后的新建连接归属；不验证原套接字、代际防护或生产恢复')
    retired = nodes[2]
    old_index = int(retired.index)
    old_identity = endpoints[2]['identity']
    replacement_endpoint = endpoints[0]
    evidence['old_interface'] = {'name': retired.interface, 'index': old_index, 'identity': old_identity}
    evidence['target_role'] = '第三条原隧道；创建替代接口前固定目标索引'
    try:
        if activity.poll() is not None:
            raise RuntimeError('接口重建前活动探针已提前退出')
        activity.terminate()
        activity.wait(timeout=3)
        checks['old_activity_reaped_before_replacement'] = activity.poll() is not None
        # 保持首次实验的销毁顺序；释放活动远端用于不同身份的替代隧道。
        nodes[2].close()
        nodes[0].close()
        checks['old_interface_removed'] = retired.interface not in interfaces()
        if not checks['old_interface_removed']:
            raise RuntimeError('旧接口未消失，禁止建立替代隧道')
        existing = set(interfaces())
        replacement = Tunnel(options, folder, runtime, 0, replacement_endpoint, existing, instance='replacement')
        nodes.append(replacement)  # 就绪失败时仍由外层按创建顺序逆序回收。
        replacement.ready()
        evidence['replacement_interface'] = {'name': replacement.interface, 'index': int(replacement.index), 'identity': replacement_endpoint['identity']}
        checks['actual_index_reused'] = int(replacement.index) == old_index
        if not checks['actual_index_reused']:
            raise RuntimeError('新接口未复用旧索引；本次不能验证索引复用行为')
        # 这里只缓存数字索引，等价于当前底层固定接口类型的可复制索引值；不是代际租约。
        value = json.loads(run(
            [options.probe, str(old_index), TARGET, '19090', secrets.token_hex(24), replacement_endpoint['identity'], '1'],
            timeout=8, cwd=REPO, user=uid, group=gid, extra_groups=[],
        ).stdout)
        evidence['cached_numeric_index_observation'] = value
        verify_observation(old_index, replacement.index, old_identity, replacement_endpoint['identity'], value)
        checks['cached_numeric_index_reaches_replacement'] = True
        for node, endpoint, label in ((replacement, replacement_endpoint, 'replacement'), (nodes[1], endpoints[1], 'candidate_1')):
            business = json.loads(run(
                [options.probe, node.index, TARGET, '19090', secrets.token_hex(24), endpoint['identity'], '1'],
                timeout=8, cwd=REPO, user=uid, group=gid, extra_groups=[],
            ).stdout)
            verify_observation(node.index, node.index, old_identity, endpoint['identity'], business)
            dns = json.loads(run(
                [options.dns_probe, node.index, TARGET, '53', endpoint['identity']],
                timeout=8, cwd=REPO, user=uid, group=gid, extra_groups=[],
            ).stdout)
            if not (dns.get('identity') == endpoint['identity'] and dns.get('interface_index') == int(node.index)
                    and dns.get('dns_udp') is True and dns.get('dns_tcp_fallback') is True
                    and dns.get('resolved_ipv4') == TARGET):
                raise RuntimeError('接口重建后的解析归属不符')
            checks[label + '_business_dns_verified'] = True
        if not all(checks.values()):
            raise RuntimeError('接口索引复用行为实验的阶段检查未全部通过')
    except BaseException as error:
        evidence['error'] = str(error) or type(error).__name__
        raise
