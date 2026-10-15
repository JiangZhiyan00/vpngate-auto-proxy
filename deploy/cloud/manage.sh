#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
export TZ=Asia/Shanghai
exec python3 scripts/cloud_deploy.py "$@"
