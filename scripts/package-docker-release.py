"""仅打包已核验的产品镜像和完整来源材料，不分发受控夹具或能力实验镜像。"""
import argparse
from image_program import program_bytes
import datetime
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

from cloud_image_identity import archive_identities
from release_materials import verify_sources

ROOT = Path(__file__).resolve().parents[1]
DEPLOY_FILES = [
    'scripts/cloud_deploy.py', 'scripts/cloud_image_identity.py', 'scripts/docker_profiles.py',
    'deploy/apparmor/vpngate-auto-proxy', 'deploy/compose.apparmor.yaml',
    'LICENSE', 'THIRD_PARTY_NOTICES.md',
]
SOURCE_FILES = ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'Dockerfile',
                'LICENSE', 'THIRD_PARTY_NOTICES.md', 'README.md', '.dockerignore', '.gitignore', '.env.example',
                'config.example.json', 'compose.yaml', 'docs/deployment.md', 'docs/reuse-map.md',
                '.github/workflows/docker-publish.yml', 'docs/dockerhub-release.md',
                'specs/002-rename-cli-vap/contracts/cli.md',
                'specs/002-rename-cli-vap/contracts/deployment.md']
SOURCE_DIRECTORIES = ['src', 'scripts', 'tests', 'examples', 'deploy', 'docs/third-party']


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(1024 * 1024):
            value.update(block)
    return value.hexdigest()


def project_files():
    files = [ROOT / name for name in SOURCE_FILES]
    for name in SOURCE_DIRECTORIES:
        files.extend(path for path in (ROOT / name).rglob('*') if path.is_file()
                     and '__pycache__' not in path.parts and path.suffix != '.pyc'
                     and path.suffix not in ('.log', '.tmp') and not path.name.startswith('.env')
                     and path.name not in ('credentials.local.json', 'config.local.json'))
    if any(path.is_symlink() for path in files):
        raise ValueError('项目来源白名单包含符号链接')
    return sorted(set(files))


def main():
    parser = argparse.ArgumentParser(description='生成 Docker x86_64 公开发布候选包')
    parser.add_argument('--image', required=True)
    parser.add_argument('--sources', type=Path, required=True)
    parser.add_argument('--validation', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    inventory, sources = verify_sources(ROOT, options.sources)
    image = json.loads(subprocess.check_output(['docker', 'image', 'inspect', options.image], text=True))[0]
    validation = json.loads(options.validation.read_text())
    if (image['Id'] != inventory['runtime_image']['id'] or image['Architecture'] != 'amd64'
            or image['Os'] != 'linux' or image['Config'].get('Labels', {}).get('io.vpngate-auto-proxy.experimental')
            or validation.get('status') != 'passed' or validation['image_id'] != image['Id']):
        raise ValueError('镜像或发布验证未通过，或误用了实验镜像')
    if (not inventory.get('distribution_review_complete') or not inventory.get('system_package_sources_bundled')
            or inventory.get('distribution_review_scope', {}).get('image_id') != image['Id']):
        raise ValueError('当前镜像的公开分发材料审查尚未完成')
    subprocess.run(['python3', str(ROOT / 'scripts/verify-license-image.py'), '--image', options.image], check=True)
    binary = program_bytes(options.image)
    if hashlib.sha256(binary).hexdigest() != validation['binary_sha256']:
        raise ValueError('最终程序与发布验证摘要不一致')
    destination = options.output.resolve()
    archive = destination.with_name(destination.name + '.tar.gz')
    if not re.fullmatch('[A-Za-z0-9_.-]+', destination.name) or destination.exists() or archive.exists():
        raise ValueError('输出名无效或目标已存在')
    files = project_files()
    destination.mkdir(parents=True)
    for relative in DEPLOY_FILES:
        output = destination / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, output)
    for name, source in [('README.md', 'deploy/release/README.md'), ('run.sh', 'deploy/release/run.sh'),
                         ('manage.sh', 'deploy/cloud/manage.sh'), ('compose.yaml', 'deploy/cloud/compose.yaml'),
                         ('config.json', 'deploy/config.container.example.json')]:
        shutil.copyfile(ROOT / source, destination / name)
    shutil.copyfile(options.validation, destination / 'release-validation.json')
    (destination / 'image.env').write_text('VAP_IMAGE=' + options.image + '\n')
    source_archive = destination / 'source-materials.tar.gz'
    source_readme = destination / '.source-readme.md'
    source_readme.write_text('''# 发布源码材料

`project/` 是冻结的项目源码，`rust/crates/` 是与 Cargo.lock 摘要一致的完整依赖原包，`rust/manifest.json` 登记嵌套声明与工具链来源。`alpine/` 按实际镜像包记录上游源码、补丁及完整配方目录；每个来源的 `recipe/` 保留 APKBUILD、安装脚本和触发器。原始许可位于相应源码及 project/docs/third-party 中。

在 source 目录执行 `python3 project/scripts/restore_vendor.py --sources rust --output vendor`，再进入 project，在具备 Rust 1.90.0、构建工具链及 OpenSSL 开发库的 Linux 环境执行：

```sh
cargo build --locked --offline --release --config 'source.crates-io.replace-with="release-vendor"' --config 'source.release-vendor.directory="../vendor"'
```

这一步无需从注册表下载依赖。标准库组件来源及摘要见 rust/manifest.json，系统包按固定 Alpine 配方在相应构建环境重建，不能把单个配方直接运行在生产宿主上。构建工具链须自行预装。本材料不把尚未验收的原生系统或其他架构标为已支持。
''')
    with tarfile.open(source_archive, 'w:gz', compresslevel=3) as stream:
        stream.add(source_readme, arcname='source/README.md')
        for path in sources:
            stream.add(path, arcname='source/' + path.relative_to(options.sources).as_posix())
        for path in files:
            stream.add(path, arcname='source/project/' + path.relative_to(ROOT).as_posix())
    source_readme.unlink()
    subprocess.run(['docker', 'save', '-o', str(destination / 'images.tar'), options.image], check=True)
    item = {'tag': options.image, 'id': image['Id'], 'architecture': 'amd64', 'os': 'linux'}
    item['verified_archive_ids'] = sorted(archive_identities(destination / 'images.tar', item))
    manifest = {
        'schema_version': 1, 'delivery_revision': 'docker-preview-20261015',
        'created_at': datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat(),
        'purpose': 'Debian 12 x86_64 有根 Docker 测试版发布候选', 'images': [item],
        'binary_sha256': validation['binary_sha256'], 'cargo_lock_sha256': inventory['cargo_lock_sha256'],
        'source_archive_sha256': digest(source_archive),
        'project_source_sha256': {path.relative_to(ROOT).as_posix(): digest(path) for path in files},
        'publication_performed': False,
    }
    (destination / 'bundle.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    (destination / 'SHA256SUMS').write_text(''.join(f'{digest(path)}  {path.relative_to(destination).as_posix()}\n'
        for path in sorted(destination.rglob('*')) if path.is_file()))
    with tarfile.open(archive, 'w:gz', compresslevel=3) as stream:
        stream.add(destination, arcname=destination.name)
    archive.with_name(archive.name + '.sha256').write_text(f'{digest(archive)}  {archive.name}\n')
    print('发布候选包：' + str(archive))
    print('压缩包 SHA256：' + digest(archive))


if __name__ == '__main__':
    main()
