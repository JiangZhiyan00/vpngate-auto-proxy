"""归档锁定 crate 完整原包、嵌套声明及实际构建工具链标准库声明。"""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import urllib.error

from collect_alpine_sources import download

ROOT = Path(__file__).resolve().parents[1]


def safe_member(name):
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts:
        raise ValueError('来源归档含越界路径')
    return path


def collect_crates(inventory, destination, notices):
    # 仅读取 Cargo 自己生成的锁文件中的三个规范字符串字段，不执行 TOML 或包内容。
    expected = {}
    for block in (ROOT / 'Cargo.lock').read_text().split('[[package]]')[1:]:
        fields = dict(re.findall(r'^(name|version|checksum) = "([^"\n]+)"$', block, re.MULTILINE))
        if 'checksum' in fields:
            if not re.fullmatch('[0-9a-f]{64}', fields['checksum']):
                raise ValueError('锁文件包摘要格式无效')
            expected[fields['name'], fields['version']] = fields['checksum']
    cache = Path.home() / '.cargo/registry/cache'
    records = []
    destination.mkdir(parents=True, exist_ok=True)
    production = {(package['name'], package['version']) for package in inventory['rust_packages']}
    for key in sorted(expected):
        filename = '-'.join(key) + '.crate'
        candidates = list(cache.glob('*/' + filename)) + [destination / filename]
        source = next((path for path in candidates
                       if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == expected[key]), None)
        if source is None:
            source = destination / filename
            download(f'https://static.crates.io/crates/{key[0]}/{filename}', source)
            if hashlib.sha256(source.read_bytes()).hexdigest() != expected[key]:
                raise ValueError('来源包与锁文件摘要不符：' + filename)
        if source != destination / filename:
            shutil.copyfile(source, destination / filename)
        nested = []
        with tarfile.open(source) as archive:
            for member in archive:
                path = safe_member(member.name)
                if not member.isfile() or not any(word in path.name.upper()
                                                  for word in ('LICENSE', 'LICENCE', 'COPYING', 'COPYRIGHT', 'NOTICE', 'AUTHORS')):
                    continue
                if member.size > 10 * 1024 * 1024:
                    raise ValueError('来源声明文件超限')
                content = archive.extractfile(member).read()
                output = notices / Path(*path.parts)
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(content)
                nested.append({'path': path.as_posix(), 'sha256': hashlib.sha256(content).hexdigest()})
        if not nested:
            nested = collect_workspace_notices(source, notices, '-'.join(key))
        records.append({'name': key[0], 'version': key[1], 'archive': filename,
                        'sha256': expected[key], 'size': source.stat().st_size, 'notices': nested,
                        'usage': '程序或构建依赖' if key in production else '锁文件中的测试或其他目标依赖'})
    return records


def collect_workspace_notices(source, destination, package):
    """少数发布包遗漏工作区许可，按包内 VCS 提交补齐原文，不使用主分支。"""
    with tarfile.open(source) as archive:
        prefix = package + '/'
        vcs = json.loads(archive.extractfile(prefix + '.cargo_vcs_info.json').read())
        manifest = archive.extractfile(prefix + 'Cargo.toml').read().decode()
    commit = vcs['git']['sha1']
    repository = re.search(r'^repository = "https://github.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"$', manifest, re.MULTILINE)
    if not re.fullmatch('[0-9a-f]{40}', commit) or not repository:
        raise ValueError('缺失声明且无法核对固定的上游提交：' + package)
    records = []
    for name in ('LICENSE-MIT', 'LICENSE-APACHE', 'LICENSE', 'COPYING', 'COPYRIGHT', 'NOTICE', 'AUTHORS'):
        path = destination / package / ('workspace-' + name)
        path.parent.mkdir(parents=True, exist_ok=True)
        url = f'https://raw.githubusercontent.com/{repository[1]}/{commit}/{name}'
        try:
            download(url, path)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                continue
            raise
        records.append({'path': package + '/' + path.name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                        'supplemental_url': url, 'source_commit': commit})
    if not records:
        raise ValueError('固定工作区提交也未找到声明：' + package)
    return records


def collect_toolchain(builder, destination):
    command = ['docker', 'run', '--rm', '--platform', 'linux/amd64', '--network', 'none',
               '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--read-only']
    version = subprocess.check_output(command + ['--entrypoint', 'rustc', builder, '-vV'], text=True)
    if 'release: 1.90.0\n' not in version or 'host: x86_64-unknown-linux-musl\n' not in version:
        raise ValueError('标准库材料必须来自指定版本与架构的实际工具链')
    sysroot = subprocess.check_output(command + ['--entrypoint', 'rustc', builder, '--print', 'sysroot'], text=True).strip()
    content = subprocess.check_output(command + ['--entrypoint', 'tar', builder, '-C',
                                                sysroot + '/share/doc/rust', '-cf', '-',
                                                'COPYRIGHT-library.html', 'licenses'])
    records = []
    with tarfile.open(fileobj=io.BytesIO(content)) as archive:
        for member in archive:
            path = safe_member(member.name)
            if not member.isfile():
                continue
            value = archive.extractfile(member).read()
            output = destination / Path(*path.parts)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(value)
            records.append({'path': path.as_posix(), 'sha256': hashlib.sha256(value).hexdigest()})
    if not records:
        raise ValueError('标准库归属材料为空')
    image_id = json.loads(subprocess.check_output(['docker', 'image', 'inspect', builder], text=True))[0]['Id']
    return {'builder_image_id': image_id, 'rustc_version': version, 'notices': records}


def main():
    parser = argparse.ArgumentParser(description='收集 Docker 发布所需 Rust 来源及声明')
    parser.add_argument('--builder-image', required=True)
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    inventory = json.loads((ROOT / 'docs/third-party/inventory.json').read_text())
    if inventory['cargo_lock_sha256'] != hashlib.sha256((ROOT / 'Cargo.lock').read_bytes()).hexdigest():
        raise ValueError('依赖清单与锁文件不一致')
    options.output.mkdir(parents=True, exist_ok=True)
    notices = ROOT / 'docs/third-party/nested'
    if notices.exists():
        shutil.rmtree(notices)
    crates = collect_crates(inventory, options.output / 'crates', notices)
    toolchain = collect_toolchain(options.builder_image, ROOT / 'docs/third-party/runtime/rust-1.90.0')
    url = 'https://static.rust-lang.org/dist/rust-src-1.90.0.tar.xz'
    path = options.output / 'rust-src-1.90.0.tar.xz'
    download(url + '.sha256', path.with_name(path.name + '.sha256'))
    expected = path.with_name(path.name + '.sha256').read_text().split()[0]
    if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        download(url, path)
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise ValueError('Rust 标准库来源摘要与官方发布摘要不符')
    report = {'schema_version': 1, 'cargo_lock_sha256': inventory['cargo_lock_sha256'],
              'status': 'passed', 'crates': crates, 'toolchain': toolchain,
              'rust_source': {'url': url, 'archive': path.name, 'sha256': expected},
              'scope': '实际锁定程序及构建依赖完整来源、嵌套声明、固定工具链标准库来源和原始版权材料'}
    (options.output / 'manifest.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    (ROOT / 'docs/third-party/runtime/rust-distribution.json').write_text(
        json.dumps({'schema_version': 1, 'toolchain': toolchain,
                    'crate_archives': len(crates), 'notice_files': sum(len(p['notices']) for p in crates),
                    'rust_source': report['rust_source']}, ensure_ascii=False, indent=2) + '\n')
    print(f'Rust 来源与声明完成：{len(crates)} 个完整来源包、{sum(len(p["notices"]) for p in crates)} 份声明')


if __name__ == '__main__':
    main()
