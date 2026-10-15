#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
export TZ=Asia/Shanghai
mode=${1:-smoke}
case "$mode" in load|smoke|capacity|all) ;; *) echo "用法：bash run.sh load|smoke|capacity|all" >&2; exit 2;; esac
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || { echo "本包需要 x86_64 Linux" >&2; exit 1; }
for tool in python3 docker; do command -v "$tool" >/dev/null || { echo "缺少工具：$tool" >&2; exit 1; }; done
python3 - <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, str(Path('scripts').resolve()))
from cloud_deploy import verify_files
try:
    verify_files(Path('.'))
except (RuntimeError, OSError) as error:
    raise SystemExit(str(error)) from error
PY
if [ "$mode" = load ]; then
  docker load -i images.tar
  exit 0
fi
command -v curl >/dev/null || { echo "缺少工具：curl" >&2; exit 1; }
[ -c /dev/net/tun ] || { echo "缺少 /dev/net/tun，需要云服务器提供 TUN 支持" >&2; exit 1; }
readarray -t images < <(python3 - "$mode" <<'PY'
import datetime, json, platform, subprocess, sys
from pathlib import Path
sys.path.insert(0, str(Path('scripts').resolve()))
from cloud_image_identity import archive_identities, verify_image
manifest = json.loads(Path('bundle.json').read_text())
observed = []
for item in manifest['images']:
    actual = json.loads(subprocess.check_output(['docker', 'image', 'inspect', item['tag']]))[0]
    try:
        identities = archive_identities('images.tar', item)
        verify_image(actual, item, identities)
    except (ValueError, KeyError) as error:
        raise SystemExit(str(error)) from error
    observed.append({**item, 'observed_id': actual['Id'], 'verified_ids': sorted(identities)})
Path('validation-output').mkdir(exist_ok=True)
environment = {
    'recorded_at': datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat(),
    'system': platform.system(), 'machine': platform.machine(), 'kernel': platform.release(),
    'os_release': Path('/etc/os-release').read_text() if Path('/etc/os-release').is_file() else None,
    'docker': json.loads(subprocess.check_output(['docker', 'info', '--format', '{{json .ServerVersion}}'])),
    'security_options': json.loads(subprocess.check_output(['docker', 'info', '--format', '{{json .SecurityOptions}}'])),
    'cgroup_version': json.loads(subprocess.check_output(['docker', 'info', '--format', '{{json .CgroupVersion}}'])),
    'images': observed,
}
Path('validation-output/environment.json').write_text(json.dumps(environment, ensure_ascii=False, indent=2) + '\n')
if any('rootless' in item for item in environment['security_options']):
    raise SystemExit('本次验收需要有根 Docker，当前引擎是无根模式')
if sys.argv[1] in ('capacity', 'all') and environment['cgroup_version'] != '2':
    raise SystemExit('容量资源采样需要控制组第二版，当前 Docker 环境不满足')
for item in observed:
    print(item['tag'])
PY
)
[ "${#images[@]}" = 2 ] || { echo "镜像核验未通过" >&2; exit 1; }
mkdir -p validation-output
log="validation-output/${mode}-$(date +%Y%m%d-%H%M%S).log"
status=0
case "$mode" in
  smoke|all)
    python3 scripts/validate_docker.py --skip-build --case "$mode" --duration-seconds 1800 \
      --image "${images[0]}" --fixture-image "${images[1]}" 2>&1 | tee "$log" || status=$?
    ;;
  capacity)
    python3 scripts/validate_soak.py --deployment docker --clients 5 --connections 50 --duration-seconds 1800 \
      --image "${images[0]}" --fixture-image "${images[1]}" \
      --output validation-output/soak-cloud.json 2>&1 | tee "$log" || status=$?
    ;;
esac
python3 - "$mode" "$log" "$status" <<'PY'
import datetime, json, sys
from pathlib import Path
mode, log, status = sys.argv[1], sys.argv[2], int(sys.argv[3])
record = {'recorded_at': datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat(),
          'mode': mode, 'exit_code': status, 'status': 'passed' if status == 0 else 'failed', 'log': log}
Path(f'validation-output/{mode}-result.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n')
PY
if [ "$status" = 0 ]; then echo "本次执行成功，日志：$log"; else echo "本次执行失败，日志：$log" >&2; fi
exit "$status"
