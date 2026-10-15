"""从随发布物提供的校验原包恢复 Cargo 离线目录来源。"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile
import tempfile


def restore(sources, destination):
    manifest = json.loads((sources / 'manifest.json').read_text())
    if manifest.get('status') != 'passed' or destination.exists() or destination.is_symlink():
        raise ValueError('来源清单未通过或输出目录已存在')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.vap-vendor-', dir=destination.parent) as temporary:
        root = Path(temporary) / 'vendor'
        root.mkdir()
        for package in manifest['crates']:
            name = package['name'] + '-' + package['version']
            if '/' in name or name in ('.', '..'):
                raise ValueError('依赖标识越界')
            archive_name = PurePosixPath(package['archive'])
            if len(archive_name.parts) != 1 or archive_name.is_absolute():
                raise ValueError('来源原包路径越界')
            archive = sources / 'crates' / package['archive']
            if archive.is_symlink() or hashlib.sha256(archive.read_bytes()).hexdigest() != package['sha256']:
                raise ValueError('来源原包摘要不符')
            files = {}
            with tarfile.open(archive) as stream:
                for member in stream:
                    path = PurePosixPath(member.name)
                    if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] != name:
                        raise ValueError('来源原包成员越界')
                    if member.isdir():
                        continue
                    if not member.isfile() or member.name in files:
                        raise ValueError('来源原包包含链接或重复成员')
                    relative = PurePosixPath(*path.parts[1:]).as_posix()
                    if relative in files or relative == '.cargo-checksum.json':
                        raise ValueError('来源原包包含重复成员或保留文件')
                    target = root / Path(*path.parts)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    data = stream.extractfile(member).read()
                    target.write_bytes(data)
                    target.chmod(0o755 if member.mode & 0o111 else 0o644)
                    files[relative] = hashlib.sha256(data).hexdigest()
            (root / name / '.cargo-checksum.json').write_text(
                json.dumps({'package': package['sha256'], 'files': files}, sort_keys=True) + '\n')
        root.rename(destination)


def main():
    parser = argparse.ArgumentParser(description='从发布源码材料恢复 Cargo 离线依赖')
    parser.add_argument('--sources', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    restore(options.sources, options.output)
    print('Cargo 离线来源目录已恢复')


if __name__ == '__main__':
    main()
