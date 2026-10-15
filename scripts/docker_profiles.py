"""通过无网络、无能力的临时探针确认指定安全策略可实际应用。"""
import json
import os
import subprocess
import uuid


def require_profiles(security, images):
    if not any('name=apparmor' in value for value in security):
        return
    for image, profile in images:
        token = uuid.uuid4().hex
        name = 'vap-policy-check-' + token[:12]
        label = 'io.vpngate-auto-proxy.preflight'
        command = ['docker', 'run', '--rm', '--pull', 'never', '--name', name,
                   '--label', f'{label}={token}', '--network', 'none', '--cap-drop', 'ALL',
                   '--security-opt', 'no-new-privileges', '--security-opt', 'apparmor=' + profile,
                   '--read-only', '--entrypoint', '/bin/true', image]
        environment = {key: value for key, value in os.environ.items()
                       if key != 'DOCKER_DEFAULT_PLATFORM'}
        failure = None
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=20, env=environment)
            if result.returncode:
                failure = result.stderr[-2000:]
        except subprocess.TimeoutExpired:
            failure = '策略探针启动超时'
        finally:
            # 引擎启动失败或客户端超时时，仍只删除本次标签匹配的探针。
            try:
                inspected = subprocess.run(['docker', 'container', 'inspect', name],
                                           capture_output=True, text=True, timeout=10, env=environment)
                if inspected.returncode == 0:
                    records = json.loads(inspected.stdout)
                    if records[0].get('Config', {}).get('Labels', {}).get(label) == token:
                        removed = subprocess.run(['docker', 'rm', '-f', name],
                                                 capture_output=True, text=True, timeout=10, env=environment)
                        if removed.returncode:
                            failure = '策略探针回收失败：' + name
            except (subprocess.TimeoutExpired, OSError, ValueError, IndexError):
                if failure is None:
                    failure = '策略探针归属检查失败：' + name
        if failure is not None:
            raise RuntimeError(f'安全策略 {profile} 无法应用或探针运行失败。请先执行：\n'
                               f'sudo apparmor_parser -r -W deploy/apparmor/{profile}\n{failure}')
