"""对指定 Docker amd64 产物完成材料核验后，登记有明确范围的分发结论。"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess

from release_materials import verify_sources

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description='核验并登记当前 Docker amd64 分发材料')
    parser.add_argument('--image', required=True)
    parser.add_argument('--sources', type=Path, required=True)
    options = parser.parse_args()
    inventory, files = verify_sources(ROOT, options.sources)
    image = json.loads(subprocess.check_output(['docker', 'image', 'inspect', options.image], text=True))[0]
    if image['Id'] != inventory['runtime_image']['id'] or image['Architecture'] != 'amd64' or image['Os'] != 'linux':
        raise ValueError('分发核验仅适用于清单中的 Linux amd64 镜像')
    subprocess.run(['python3', str(ROOT / 'scripts/verify-license-image.py'), '--image', options.image], check=True)
    scope = {'platform': 'linux/amd64', 'deployment': 'Docker', 'image_id': image['Id'],
             'source_materials': '随完整发布包提供',
             'excluded': ['苹果原生二进制', 'Linux 原生二进制', '受控夹具镜像', '能力实验镜像']}
    inventory['distribution_review_complete'] = True
    inventory['system_package_sources_bundled'] = True
    inventory['distribution_review_scope'] = scope
    path = ROOT / 'docs/third-party/inventory.json'
    path.write_text(json.dumps(inventory, ensure_ascii=False, indent=2) + '\n')
    alpine_path = options.sources / 'alpine/manifest.json'
    alpine = json.loads(alpine_path.read_text())
    # 仅审查状态字段变化；来源、版本和正文刚刚已逐项核验。
    alpine['inventory_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
    alpine_path.write_text(json.dumps(alpine, ensure_ascii=False, indent=2) + '\n')
    verify_sources(ROOT, options.sources)
    report = {'schema_version': 1, 'status': 'passed', 'scope': scope,
              'recorded_at': datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat(),
              'inventory_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
              'verified_source_files': len(files), 'project_license': 'MIT',
              'system_packages': len(inventory['runtime_image']['packages']),
              'notes': '保留各组件原许可、完整来源与构建材料；后续产物或目标变化须重新核验，不授权其他平台的二进制分发'}
    (ROOT / 'docs/third-party/docker-review.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print('指定 Docker amd64 产物的分发材料核验完成')


if __name__ == '__main__':
    main()
