"""Docker 发布材料门槛：来源或原文缺失、摘要不符时拒绝打包。"""
import hashlib
import json
from pathlib import Path
import re


def verified(root, relative, expected, algorithm='sha256'):
    relative = Path(relative)
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('发布材料路径越界')
    path = root / relative
    if not path.is_file() or path.is_symlink() or root.resolve() not in path.resolve().parents:
        raise ValueError('发布材料缺失或为链接：' + str(relative))
    for parent in path.parents:
        if parent == root:
            break
        if parent.is_symlink():
            raise ValueError('发布材料父目录为链接')
    digest = hashlib.new(algorithm)
    with path.open('rb') as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    if digest.hexdigest() != expected:
        raise ValueError('发布材料摘要不符：' + str(relative))
    return path


def verify_sources(root, sources):
    inventory = json.loads((root / 'docs/third-party/inventory.json').read_text())
    if inventory['cargo_lock_sha256'] != hashlib.sha256((root / 'Cargo.lock').read_bytes()).hexdigest():
        raise ValueError('发布清单与锁文件不一致')
    alpine = json.loads((sources / 'alpine/manifest.json').read_text())
    rust = json.loads((sources / 'rust/manifest.json').read_text())
    if (alpine.get('status') != 'passed' or alpine.get('failures') or rust.get('status') != 'passed'
            or alpine['image_id'] != inventory['runtime_image']['id']
            or alpine['inventory_sha256'] != hashlib.sha256((root / 'docs/third-party/inventory.json').read_bytes()).hexdigest()
            or rust['cargo_lock_sha256'] != inventory['cargo_lock_sha256']):
        raise ValueError('来源材料未通过或不属于当前锁文件与镜像')
    origins = {(package['origin'], package['source_commit']) for package in inventory['runtime_image']['packages']}
    if origins != {(origin['origin'], origin['source_commit']) for origin in alpine['origins']}:
        raise ValueError('系统包来源未完整覆盖实际镜像')
    if alpine['package_count'] != len(inventory['runtime_image']['packages']):
        raise ValueError('系统包数量与实际镜像不一致')
    accepted = []
    for origin in alpine['origins']:
        if origin['missing'] or not origin.get('recipe_files'):
            raise ValueError('系统来源或配方目录未完整取得')
        recipes = [item for item in origin['recipe_files'] if item['path'] == 'APKBUILD']
        if len(recipes) != 1 or recipes[0]['sha256'] != origin['recipe_sha256']:
            raise ValueError('来源配方与完整配方快照不一致')
        base = Path('alpine') / origin['directory']
        accepted.append(verified(sources, base / 'APKBUILD', origin['recipe_sha256']))
        for file in origin['recipe_files']:
            accepted.append(verified(sources, base / 'recipe' / file['path'], file['sha256']))
        for file in origin['sources']:
            accepted.append(verified(sources, base / file['name'], file['sha512'], 'sha512'))
    production = {(package['name'], package['version']) for package in inventory['rust_packages']}
    if not production <= {(package['name'], package['version']) for package in rust['crates']}:
        raise ValueError('Rust 来源未完整覆盖程序与构建依赖')
    locked = {}
    for block in (root / 'Cargo.lock').read_text().split('[[package]]')[1:]:
        fields = dict(re.findall(r'^(name|version|checksum) = "([^"\n]+)"$', block, re.MULTILINE))
        if 'checksum' in fields:
            locked[fields['name'], fields['version']] = fields['checksum']
    observed = {(package['name'], package['version']): package['sha256'] for package in rust['crates']}
    if observed != locked or len(observed) != len(rust['crates']):
        raise ValueError('离线来源未精确覆盖锁文件全部依赖')
    for package in rust['crates']:
        accepted.append(verified(sources, Path('rust/crates') / package['archive'], package['sha256']))
        for notice in package['notices']:
            verified(root, Path('docs/third-party/nested') / notice['path'], notice['sha256'])
    for notice in rust['toolchain']['notices']:
        verified(root, Path('docs/third-party/runtime/rust-1.90.0') / notice['path'], notice['sha256'])
    accepted.append(verified(sources, Path('rust') / rust['rust_source']['archive'], rust['rust_source']['sha256']))
    runtime = json.loads((root / 'docs/third-party/runtime/alpine-distribution.json').read_text())
    if runtime['status'] != 'passed' or runtime['system_origins'] != len(origins):
        raise ValueError('系统原始声明和链接库核验未完成')
    for notice in runtime['notices']:
        verified(root, notice['path'], notice['sha256'])
    extra = json.loads((sources / 'extras/manifest.json').read_text())
    if extra.get('status') != 'passed':
        raise ValueError('项目源码中的外部补丁来源材料未完成')
    accepted.append(verified(sources, Path('extras') / extra['archive'], extra['sha256']))
    verified(root, 'scripts/patches/openvpn-2.6.23-utun-fd.patch', extra['patch_sha256'])
    accepted += [sources / 'alpine/manifest.json', sources / 'rust/manifest.json', sources / 'extras/manifest.json']
    return inventory, sorted(set(accepted))
