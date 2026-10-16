"""从已校验的系统源码中保留原始声明，并登记最终程序的动态链接库。"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import zipfile

from collect_rust_distribution import safe_member

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description='收集镜像系统库声明及实际链接关系')
    parser.add_argument('--sources', type=Path, required=True)
    parser.add_argument('--image', required=True)
    options = parser.parse_args()
    manifest = json.loads((options.sources / 'manifest.json').read_text())
    if manifest['status'] != 'passed':
        raise ValueError('系统包源码尚未全部核验通过')
    destination = ROOT / 'docs/third-party/runtime/alpine'
    if destination.exists():
        shutil.rmtree(destination)
    records = []

    def store(origin, archive, name, content):
        path = safe_member(name)
        if len(content) > 10 * 1024 * 1024:
            raise ValueError('系统来源声明超限')
        output = destination / origin / archive / Path(*path.parts)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(content)
        records.append({'path': str(output.relative_to(ROOT)),
                        'sha256': hashlib.sha256(content).hexdigest()})

    def is_notice(name):
        return any(word in Path(name).name.upper() for word in
                   ('LICENSE', 'LICENCE', 'COPYRIGHT', 'COPYING', 'NOTICE', 'AUTHORS'))

    for origin in manifest['origins']:
        for source in origin['sources']:
            path = options.sources / origin['directory'] / source['name']
            if hashlib.sha512(path.read_bytes()).hexdigest() != source['sha512']:
                raise ValueError('系统来源内容与清单不一致：' + source['name'])
            if not source['name'].endswith(('.gz', '.xz', '.bz2', '.zip', '.tgz')):
                continue
            if zipfile.is_zipfile(path):
                with zipfile.ZipFile(path) as archive:
                    for entry in archive.infolist():
                        if not entry.is_dir() and is_notice(entry.filename):
                            store(origin['origin'], source['name'], entry.filename, archive.read(entry))
            elif tarfile.is_tarfile(path):
                with tarfile.open(path) as archive:
                    for entry in archive:
                        if entry.isfile() and is_notice(entry.name):
                            if entry.size > 10 * 1024 * 1024:
                                raise ValueError('系统来源声明超限')
                            store(origin['origin'], source['name'], entry.name, archive.extractfile(entry).read())
    if not records:
        raise ValueError('系统来源中未找到声明')
    base = ['docker', 'run', '--rm', '--platform', 'linux/amd64', '--network', 'none',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--read-only']
    linked = subprocess.check_output(base + ['--entrypoint', 'scanelf', options.image,
                                             '-n', '/usr/local/bin/vap'], text=True)
    ownership = subprocess.check_output(base + ['--entrypoint', 'sh', options.image, '-c',
        'apk info --who-owns /usr/lib/libssl.so.3 /usr/lib/libcrypto.so.3 /usr/lib/libgcc_s.so.1 /lib/libc.musl-x86_64.so.1'], text=True)
    if not all(library in linked for library in ('libssl.so.3', 'libcrypto.so.3', 'libgcc_s.so.1', 'libc.musl-x86_64.so.1')):
        raise ValueError('最终程序的动态链接关系与材料清单不符')
    report = {'schema_version': 1, 'source_image_id': manifest['image_id'],
              'status': 'passed', 'linked_libraries': linked, 'library_package_ownership': ownership,
              'system_origins': len(manifest['origins']), 'notices': records}
    output = ROOT / 'docs/third-party/runtime/alpine-distribution.json'
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(f'系统包原始声明 {len(records)} 份及四个动态链接库已登记')


if __name__ == '__main__':
    main()
