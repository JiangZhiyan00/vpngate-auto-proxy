#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
export TZ=Asia/Shanghai
[ "${1:-}" = load ] || { echo "用法：bash run.sh load；服务管理使用 bash manage.sh" >&2; exit 2; }
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || { echo "本发布包需要 x86_64 Linux" >&2; exit 1; }
python3 - <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, str(Path('scripts').resolve()))
from cloud_deploy import verify_files
verify_files(Path('.'))
PY
docker load -i images.tar
