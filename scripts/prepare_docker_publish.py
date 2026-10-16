"""为版本标签构建并验收镜像，冻结与该镜像一致的完整源码材料。"""
import argparse
from image_program import program_bytes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def validate_release(tag, image):
    if not re.fullmatch(r'v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)', tag):
        raise ValueError('版本标签必须形如 v1.0.0，不接受预发布或前导零')
    if not re.fullmatch(r'[a-z0-9]+(?:[._-][a-z0-9]+)*/[a-z0-9]+(?:[._-][a-z0-9]+)*', image):
        raise ValueError('镜像仓库必须形如账号/vpngate-auto-proxy，使用小写字符')
    namespace, _ = image.split('/', 1)
    # Docker 将首段含点、冒号或恰为 localhost 的名字解析为注册表地址。
    # 冒号已被格式校验拒绝；此处限制实际目标，仓库名中的点仍然合法。
    if '.' in namespace or namespace == 'localhost':
        raise ValueError('发布目标仅限 Docker Hub 命名空间/仓库，不接受注册表地址')
    return image + ':' + tag


def build_inputs():
    files = [ROOT / name for name in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml',
                                      'Dockerfile', 'deploy/entrypoint.sh', 'deploy/Dockerfile.release')]
    files += sorted((ROOT / 'src').rglob('*.rs'))
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}


def run(*args):
    subprocess.run(args, cwd=ROOT, check=True)


def main():
    parser = argparse.ArgumentParser(description='准备已验收的 Docker Hub 发布镜像及源码')
    parser.add_argument('--tag', required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--require-apparmor', action='store_true')
    parser.add_argument('--fixture-image', help='本机复用已有的 Linux amd64 受控夹具')
    parser.add_argument('--sources', type=Path, help='复用已校验的来源缓存；仍执行全部核验')
    options = parser.parse_args()
    image = validate_release(options.tag, options.image)
    frozen_inputs = build_inputs()
    output = ROOT / 'validation-output' / ('publish-' + options.tag)
    output.mkdir(parents=True, exist_ok=False)
    sources = options.sources.resolve() if options.sources else output / 'sources'
    base, builder, fixture = 'vap-release-base:' + options.tag, 'vap-release-builder:' + options.tag, 'vap-release-fixture:' + options.tag
    # 此脚本的所有容器均固定为已验收的架构；不修改宿主时区。
    os.environ['DOCKER_DEFAULT_PLATFORM'] = 'linux/amd64'
    run('docker', 'build', '--platform', 'linux/amd64', '--target', 'builder', '-t', builder, '.')
    run('docker', 'build', '--platform', 'linux/amd64', '-t', base, '.')
    run('python3', 'scripts/collect-license-inventory.py', '--image', base)
    run('python3', 'scripts/collect_alpine_sources.py', '--output', str(sources / 'alpine'))
    run('python3', 'scripts/collect_rust_distribution.py', '--builder-image', builder, '--output', str(sources / 'rust'))
    run('python3', 'scripts/collect_patch_source.py', '--output', str(sources / 'extras'))
    run('python3', 'scripts/collect_runtime_notices.py', '--sources', str(sources / 'alpine'), '--image', base)
    run('docker', 'build', '--platform', 'linux/amd64', '-f', 'deploy/Dockerfile.release',
        '--build-arg', 'RUNTIME_IMAGE=' + base, '--build-arg', 'RELEASE_VERSION=' + options.tag, '-t', image, '.')
    run('python3', 'scripts/collect-license-inventory.py', '--image', image)
    run('python3', 'scripts/collect_alpine_sources.py', '--output', str(sources / 'alpine'))
    run('python3', 'scripts/finalize_distribution_review.py', '--image', image, '--sources', str(sources))
    if options.fixture_image:
        fixture = options.fixture_image
        fixture_identity = json.loads(subprocess.check_output(['docker', 'image', 'inspect', fixture], text=True))[0]
        if fixture_identity['Architecture'] != 'amd64' or fixture_identity['Os'] != 'linux':
            raise ValueError('复用夹具必须为 Linux amd64')
    else:
        run('docker', 'build', '--platform', 'linux/amd64', '-f', 'tests/fixtures/Dockerfile', '-t', fixture, '.')
    command = ['python3', 'scripts/validate_docker.py', '--image', image, '--fixture-image', fixture,
               '--skip-build', '--environment-config']
    if options.require_apparmor:
        command.append('--require-apparmor')
    run(*command)
    identity = json.loads(subprocess.check_output(['docker', 'image', 'inspect', image], text=True))[0]
    binary = program_bytes(image)
    report = output / 'validation.json'
    report.write_text(json.dumps({'status': 'passed', 'image_id': identity['Id'],
                                 'binary_sha256': hashlib.sha256(binary).hexdigest(),
                                 'scope': 'Docker amd64 受控短试及分发材料核验；未重跑三十分钟容量试验'}, ensure_ascii=False, indent=2) + '\n')
    if build_inputs() != frozen_inputs:
        raise RuntimeError('构建期间源码发生变化，拒绝冻结与镜像不一致的源码')
    run('python3', 'scripts/package-docker-release.py', '--image', image, '--sources', str(sources),
        '--validation', str(report), '--output', str(output / 'bundle'))
    archive = output / ('vpngate-source-' + options.tag + '.tar.gz')
    shutil.copyfile(output / 'bundle/source-materials.tar.gz', archive)
    with archive.open('rb') as stream:
        value = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
        digest = value.hexdigest()
    (output / 'SHA256SUMS').write_text(digest + '  ' + archive.name + '\n')
    print('镜像及对应源码已准备：' + image)


if __name__ == '__main__':
    main()
