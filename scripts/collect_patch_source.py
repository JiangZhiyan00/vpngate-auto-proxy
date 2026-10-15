"""项目源码包含外部实验补丁时，一并提供其固定上游完整来源。"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

from collect_alpine_sources import download

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = 'openvpn-2.6.23.tar.gz'
EXPECTED = '4041c709162bec1325abf5aa8cf27a255cc477c634b15ee310411c701fc40a96'
URL = 'https://swupdate.openvpn.org/community/releases/' + ARCHIVE


def main():
    parser = argparse.ArgumentParser(description='归档项目实验补丁对应的上游来源，不构建或分发实验二进制')
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    options.output.mkdir(parents=True, exist_ok=True)
    path = options.output / ARCHIVE
    cached = ROOT / 'validation-output/macos-deps' / ARCHIVE
    if not path.exists() and cached.is_file() and hashlib.sha256(cached.read_bytes()).hexdigest() == EXPECTED:
        shutil.copyfile(cached, path)
    if not path.exists():
        download(URL, path)
    if hashlib.sha256(path.read_bytes()).hexdigest() != EXPECTED:
        raise ValueError('实验补丁上游来源摘要不符')
    patch = ROOT / 'scripts/patches/openvpn-2.6.23-utun-fd.patch'
    report = {'schema_version': 1, 'status': 'passed', 'archive': ARCHIVE, 'url': URL,
              'sha256': EXPECTED, 'patch_sha256': hashlib.sha256(patch.read_bytes()).hexdigest(),
              'scope': '仅随项目源码保留实验补丁与固定上游完整来源；不分发补丁后二进制，不证明苹果原生后端完成'}
    (options.output / 'manifest.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print('实验补丁对应的固定上游完整来源已归档')


if __name__ == '__main__':
    main()
