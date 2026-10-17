"""受控容器日志验收；复用调用方归属资源和清理，不连接公共节点。"""
import datetime
import json
import re
import time

LEVELS = {'error': 0, 'warn': 1, 'info': 2, 'debug': 3}
NOISY = {'runtime_summary', 'pending_started', 'candidate_started', 'candidate_result',
         'tunnel_connected', 'active_check_succeeded', 'round_started', 'round_finished'}


def events_from_logs(text):
    return [json.loads(line) for line in text.splitlines() if line.startswith('{')]


def validate_level(events, selected):
    for event in events:
        if event.get('level') not in LEVELS or LEVELS[event['level']] > LEVELS[selected]:
            raise RuntimeError('日志等级未遵循同一过滤矩阵')
    if selected != 'debug' and any(event['event_type'] in NOISY for event in events):
        raise RuntimeError('普通等级出现调试噪声')


def validate_frequency(events, seconds):
    summaries = [event for event in events if event['event_type'] == 'runtime_summary']
    if len(summaries) < 2:
        raise RuntimeError('缺少真实周期摘要正对照')
    times = [datetime.datetime.fromisoformat(re.sub(r'(\.\d{6})\d+', r'\1', event['timestamp']).replace('Z', '+00:00'))
             for event in summaries]
    # 单调时钟的精确规则由暂停时钟契约测试覆盖；日志墙上时间允许 50 毫秒采样差异。
    if any((right - left).total_seconds() < seconds - 0.05 for left, right in zip(times, times[1:])):
        raise RuntimeError('周期摘要超过配置频率')
    return len(summaries)


def exercise_logging(launch, ready, status, stop, state, run, files, product, containers,
                     password, image, apparmor, base, ownership):
    print('验证四等级、两种配置模式及启动白名单', flush=True)
    state({'source_count': 1})
    instances = []
    for index, (selected, seconds, environment) in enumerate([
            ('info', 60, True), ('warn', 60, False), ('error', 60, True),
            ('debug', 1, False), ('debug', 60, True), ('debug', 300, False)]):
        name = product + '-logs-' + str(index)
        configuration = {**base, 'timezone': 'Asia/Tokyo', 'max_connections': 20,
                         'candidate_batch_size': 1, 'candidate_concurrency': 1,
                         'source_refresh_seconds': 5, 'log_level': selected,
                         'log_summary_interval_seconds': seconds}
        if selected == 'info':
            configuration.pop('log_level')
            configuration.pop('log_summary_interval_seconds')
        filename = 'logs-' + str(index) + '.json'
        (files / filename).write_text(json.dumps(configuration))
        launched = time.monotonic()
        launch(name, '11.52.0.' + str(6 + index), filename, publish=index == 0, environment=environment)
        # 就绪等待前先验证真实监听后摘要可见，不用出口就绪时刻代替启动时刻。
        deadline = time.monotonic() + 5
        summary = None
        while time.monotonic() < deadline:
            result = run('docker', 'logs', name, check=False)
            rows = events_from_logs(result.stdout + result.stderr)
            found = [row for row in rows if row['event_type'] == 'startup_summary']
            if selected in ('info', 'debug') and len(found) == 1:
                summary = found[0]
                break
            if selected in ('warn', 'error') and status(name):
                if found:
                    raise RuntimeError('严格等级意外打印启动摘要')
                break
            time.sleep(0.1)
        if selected in ('info', 'debug'):
            if summary is None:
                raise RuntimeError('可用输出目标下启动摘要未在五秒内可见')
            expected = {'listen_address': '0.0.0.0', 'port': 1080, 'protocol': 'socks5',
                        'listen_scope': 'container_internal', 'countries': ['JP'],
                        'timezone': 'Asia/Tokyo', 'max_connections': 20, 'log_level': selected,
                        'log_summary_interval_seconds': seconds, 'data_dir': '/var/lib/vap',
                        'runtime_dir': '/run/vap', 'authentication_enabled': True}
            if summary.get('config') != expected or summary.get('ready') is not False:
                raise RuntimeError('启动摘要字段与实际有效配置不一致')
        identity = ready(name)['instance_id']
        instances.append({'name': name, 'level': selected, 'seconds': seconds,
                          'mode': 'environment' if environment else 'file', 'instance_id': identity,
                          'launched': launched})

    # 相同受控来源与出口故障作用于全部实例；日志量不能改变故障阻断与恢复。
    state({'source_count': 1, 'source_code': 503, 'code': 503})
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        values = [status(item['name']) for item in instances]
        if all(value and not value['ready'] and value['source']['last_error'] for value in values):
            break
        time.sleep(0.2)
    else:
        raise RuntimeError('降低日志后故障阻断或来源失败状态不一致')
    state({'source_count': 1})
    for item in instances:
        ready(item['name'])

    print('开始十分钟默认安静及 1／60／300 秒调试摘要验证', flush=True)
    quiet = instances[0]
    before_result = run('docker', 'logs', quiet['name'], check=False)
    before_rows = events_from_logs(before_result.stdout + before_result.stderr)
    started = time.monotonic()
    deadline = started + 600
    next_progress = started + 30
    while time.monotonic() < deadline:
        # 继续观察实际业务出口，不以日志缺失推断实例健康。
        value = status(quiet['name'])
        if not value or not value['ready'] or value['instance_id'] != quiet['instance_id']:
            raise RuntimeError('默认安静场景出口或实例身份发生异常')
        if time.monotonic() >= next_progress:
            print('默认安静场景已运行 ' + str(int(time.monotonic() - started)) + ' 秒', flush=True)
            next_progress = time.monotonic() + 30
        time.sleep(min(1, max(0, deadline - time.monotonic())))

    results = []
    for item in instances:
        result = run('docker', 'logs', item['name'], check=False)
        text = result.stdout + result.stderr
        if password in text or 'http://' in text or 'https://' in text or 'PRIVATE KEY' in text:
            raise RuntimeError('公开运行日志含敏感材料或完整地址')
        rows = events_from_logs(text)
        validate_level(rows, item['level'])
        summaries = [row for row in rows if row['event_type'] == 'startup_summary']
        if len(summaries) != (1 if item['level'] in ('info', 'debug') else 0):
            raise RuntimeError('出口恢复重复打印启动摘要或过滤失效')
        count = validate_frequency(rows, item['seconds']) if item['level'] == 'debug' else 0
        if item['level'] in ('info', 'debug') and not any(row['event_type'] == 'active_promoted' for row in rows):
            raise RuntimeError('缺少信息生命周期正对照')
        if item['level'] != 'error' and not any(row['event_type'] == 'active_blocked' for row in rows):
            raise RuntimeError('缺少同一故障序列的警告正对照')
        if item is quiet:
            tail = rows[len(before_rows):]
            if any(row['event_type'] in NOISY for row in tail):
                raise RuntimeError('默认十分钟场景仍有调试刷屏')
        # 在每个有效等级下触发相同无网络资源的配置错误，错误仍可见且不回显秘密。
        invalid = item['name'] + '-invalid'
        containers.append(invalid)
        args = ['docker', 'run', '--rm', '--name', invalid, '--label', ownership, '--network', 'none', '--read-only',
                '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '-e', 'VAP_LOG_LEVEL=' + item['level'],
                '-e', 'VAP_SOURCE_URL=https://private-user:private-token-marker@example.invalid/private-key-marker']
        if apparmor:
            args += ['--security-opt', 'apparmor=vpngate-auto-proxy']
        failure = run(*args, image, 'container-config', check=False)
        if failure.returncode != 2 or not failure.stderr or failure.stdout:
            raise RuntimeError('配置失败未保留原错误语义')
        if any(marker in failure.stderr for marker in ('private-user', 'private-token-marker', 'private-key-marker', 'example.invalid', 'startup_summary')):
            raise RuntimeError('启动失败回显敏感值或打印成功摘要')
        stop(item['name'])
        results.append({'level': item['level'], 'interval_seconds': item['seconds'],
                        'config_mode': item['mode'], 'summary_count': count,
                        'startup_count': len(summaries), 'instance_id': item['instance_id']})
    return {'status': 'passed', 'quiet_seconds': time.monotonic() - started,
            'level_matrix': results, 'fault_block_recovery_validated': True,
            'sensitive_markers_validated': True, 'startup_fields_validated': True}
