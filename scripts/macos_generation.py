"""受控代际退出与索引复用；不覆盖外部重建竞争或生产故障恢复。"""
import json
import subprocess
import uuid

from macos_retained import read_record
from macos_reuse import exercise_reuse
from macos_tunnel import REPO, TARGET


class GenerationWorker:
    def __init__(self, options, node, endpoint, runtime, label, uid, gid):
        self.generation = None
        self.index = int(node.index)
        self.identity = endpoint['identity']
        with (runtime / f'generation-{label}-error.log').open('w') as error:
            self.process = subprocess.Popen(
                [options.generation_worker, str(node.index), TARGET, '19090', self.identity],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=error, text=True,
                cwd=REPO, user=uid, group=gid, extra_groups=[],
            )

    def ready(self):
        value = read_record(self.process)
        if value.get('event') != 'ready' or value.get('interface_index') != self.index:
            raise RuntimeError('代际工作进程启动归属不符')
        self.generation = str(uuid.UUID(value['generation']))

    def request(self, operation, generation=None):
        self.process.stdin.write(json.dumps({'op': operation, 'generation': generation or self.generation}) + '\n')
        self.process.stdin.flush()
        return read_record(self.process)

    def probe(self):
        value = self.request('probe')
        if not (value.get('event') == 'verified' and value.get('generation') == self.generation
                and value.get('identity') == self.identity and value.get('interface_index') == self.index
                and value.get('tcp') is True and value.get('udp') is True):
            raise RuntimeError('代际工作进程双向收发或身份检查失败')
        return value

    def retire(self):
        value = self.request('revoke')
        if value.get('event') != 'retired' or value.get('generation') != self.generation:
            raise RuntimeError('代际撤销确认归属不符')
        if self.process.wait(timeout=3) != 0:
            raise RuntimeError('代际工作进程未正常退出')
        return value

    def close(self):
        try:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=2)
        finally:
            for pipe in (self.process.stdin, self.process.stdout):
                if pipe is not None:
                    pipe.close()


def exercise_generation(options, folder, nodes, activity, runtime, endpoints, uid, gid, evidence, workers):
    checks = {}
    evidence.update(checks=checks, scope='受控旧工作进程退出后释放接口，实际复用后新工作进程拒绝旧代际；不验证外部重建竞争、零直连或生产恢复')
    try:
        old = GenerationWorker(options, nodes[2], endpoints[2], runtime, 'old', uid, gid)
        workers.append(old)  # 任何启动或阶段校验失败，外层仍先回收工作进程。
        old.ready()
        evidence['old_generation'] = old.generation
        evidence['old_worker_probe'] = old.probe()
        evidence['retirement_ack'] = old.retire()
        checks['old_worker_exited_before_interface_release'] = old.process.poll() == 0
        if not checks['old_worker_exited_before_interface_release']:
            raise RuntimeError('旧工作进程未回收，禁止释放接口')
        # 沿用已验证的真实复用门槛与不同远端正向对照。
        evidence['reuse'] = {}
        exercise_reuse(options, folder, nodes, activity, runtime, endpoints, uid, gid, evidence['reuse'])
        checks['actual_reuse_and_different_exit_verified'] = evidence['reuse']['checks']['cached_numeric_index_reaches_replacement']
        new = GenerationWorker(options, nodes[-1], endpoints[0], runtime, 'replacement', uid, gid)
        workers.append(new)
        new.ready()
        evidence['replacement_generation'] = new.generation
        checks['distinct_generation_ids'] = old.generation != new.generation
        rejected = new.request('probe', old.generation)
        evidence['old_generation_request'] = rejected
        checks['old_generation_rejected'] = (rejected.get('event') == 'rejected'
            and rejected.get('reason') == 'stale_generation' and rejected.get('generation') == new.generation)
        if not checks['distinct_generation_ids'] or not checks['old_generation_rejected']:
            raise RuntimeError('替代工作进程未拒绝旧代际请求')
        evidence['replacement_worker_probe'] = new.probe()
        checks['replacement_generation_verified'] = True
        new.retire()
        checks['replacement_worker_exited_normally'] = new.process.poll() == 0
        if not all(checks.values()):
            raise RuntimeError('受控代际退出与请求拒绝检查未全部通过')
    except BaseException as error:
        evidence['error'] = str(error) or type(error).__name__
        raise
