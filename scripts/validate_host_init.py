#!/usr/bin/env python3
"""只读采集真实宿主策略及重启证据；不加载策略、不操作容器。"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from datetime import datetime, timezone, timedelta

ROOT = Path(__file__).resolve().parents[1]


def installer_module():
    spec = importlib.util.spec_from_file_location('vap_host_init', Path(__file__).with_name('host-init.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def collect(phase, before=None, module=None, host=None, files=None):
    module = module or installer_module()
    host = host or module.NativeHost()
    files = files or module.ProtectedFiles()
    # 重启后首先读取内核现态，本工具从不重新加载或初始化。
    first_mode = host.kernel_mode()
    host.preflight()
    policy = files.read(module.POLICY_TARGET, 0o644)
    raw = files.read(module.RECORD_TARGET, 0o600)
    module.require(policy is not None and raw is not None, '宿主策略或登记缺失')
    record = module.read_json(raw, module.RECORD_FIELDS)
    release = module.Release(record['release_tag'], record['source_commit'], policy, record['installer_sha256'])
    setup = module.HostSetup(release, host, root=files.root, owner=files.owner)
    setup.record(raw, policy)
    module.require(first_mode == 'enforce' and host.kernel_mode() == 'enforce', '首次读取时项目策略未处于强制模式')
    expected = hashlib.sha256((ROOT / 'deploy/apparmor/vpngate-auto-proxy').read_bytes()).hexdigest()
    module.require(release.policy_sha256 == expected, '当前受测源码策略与宿主策略不一致')
    result = {'schema_version': 1, 'project': module.PROJECT, 'phase': phase,
              'recorded_at': datetime.now(timezone(timedelta(hours=8))).isoformat(),
              'release_tag': release.tag, 'source_commit': release.commit,
              'policy_sha256': release.policy_sha256, 'record_sha256': module.digest(raw),
              'installer_sha256': release.installer_sha256, 'boot_id': host.boot_id,
              'first_kernel_mode': first_mode, 'kernel_enforced': True,
              'persistence_configured': True, 'initialization_performed': False,
              'other_services': host.safe_inventory(),
              'status': 'passed', 'reboot_validated': False}
    if phase == 'after-reboot':
        module.require(isinstance(before, dict) and before.get('phase') == 'before-reboot'
                       and before.get('status') == 'passed', '缺少通过的重启前报告')
        for key in ('project', 'release_tag', 'source_commit', 'policy_sha256', 'record_sha256', 'installer_sha256'):
            module.require(result[key] == before.get(key), '重启前后受测材料身份发生变化')
        module.require(result['boot_id'] != before.get('boot_id'), '启动身份未变化，不能算作重启验证')
        result['reboot_validated'] = True
    return result


def main():
    parser = argparse.ArgumentParser(description='只读采集专用测试宿主重启证据；不会重启宿主')
    parser.add_argument('--phase', required=True, choices=['before-reboot', 'after-reboot'])
    parser.add_argument('--before', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    if (options.phase == 'after-reboot') != bool(options.before):
        parser.error('只有重启后阶段必须提供 --before')
    module = installer_module()
    try:
        before = json.loads(options.before.read_text()) if options.before else None
        result = collect(options.phase, before, module=module)
        # 独立报告仅新建，不覆盖历史证据；报告路径由维护者明确提供。
        options.output.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(options.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
        print('只读验收通过；报告：' + str(options.output))
        return 0
    except (OSError, ValueError, RuntimeError, module.Rejected):
        print('宿主只读验收未通过，请核对版本、登记、内核强制模式及重启身份。', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
