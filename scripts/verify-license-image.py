"""核对最终镜像内锁定 Rust 依赖的原始许可文本与本地清单。"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
PREFIX = "/usr/share/licenses/vpngate-auto-proxy/rust/"


def output(*args):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE).stdout


def verify_file_digests(expected, actual, description):
    if actual == expected and expected:
        return
    missing = sorted(expected.keys() - actual.keys())
    extra = sorted(actual.keys() - expected.keys())
    changed = sorted(path for path in expected.keys() & actual.keys() if expected[path] != actual[path])
    details = []
    for label, paths in (('缺少', missing), ('多出', extra), ('内容改变', changed)):
        details.append(f'{label} {len(paths)}' + (f'，示例：{paths[0]}' if paths else ''))
    if not expected:
        details.append('源码材料清单为空')
    raise RuntimeError(description + '：' + '；'.join(details))


def main():
    parser = argparse.ArgumentParser(description="核对镜像内第三方原文材料")
    parser.add_argument("--image", default="vpngate-auto-proxy:local")
    options = parser.parse_args()
    inventory = json.loads((ROOT / "docs/third-party/inventory.json").read_text())
    lock_digest = hashlib.sha256((ROOT / "Cargo.lock").read_bytes()).hexdigest()
    if inventory["cargo_lock_sha256"] != lock_digest:
        raise RuntimeError("许可清单与当前锁文件不一致")
    image = json.loads(output("docker", "image", "inspect", options.image))[0]
    if image["Id"] != inventory["runtime_image"]["id"]:
        raise RuntimeError("许可清单与当前运行镜像不一致")
    expected = {}
    for package in inventory["rust_packages"]:
        for notice in package["original_notices"]:
            relative = Path(notice["path"])
            if relative.parts[:3] != ("docs", "third-party", "rust"):
                raise RuntimeError("许可文件路径越过锁定依赖目录")
            path = PREFIX + "/".join(relative.parts[3:])
            if path in expected:
                raise RuntimeError("许可清单包含重复路径")
            expected[path] = notice["sha256"]
    lines = output(
        "docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--read-only", "--entrypoint", "find",
        options.image, PREFIX.rstrip("/"), "-type", "f", "-exec", "sha256sum", "{}", "+",
    ).splitlines()
    actual = {}
    for line in lines:
        digest, separator, path = line.partition("  ")
        if not separator or path in actual:
            raise RuntimeError("镜像许可文件列表格式无效或重复")
        actual[path] = digest
    verify_file_digests(expected, actual, '镜像许可文本不一致')
    extra_count = 0
    for directory in ('nested', 'runtime'):
        root = ROOT / 'docs/third-party' / directory
        if not root.is_dir():
            raise RuntimeError('缺少发布所需的补充材料目录：' + directory)
        prefix = '/usr/share/licenses/vpngate-auto-proxy/' + directory + '/'
        wanted = {prefix + path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in root.rglob('*') if path.is_file()}
        lines = output('docker', 'run', '--rm', '--network', 'none', '--cap-drop', 'ALL',
                       '--security-opt', 'no-new-privileges', '--read-only', '--entrypoint', 'find',
                       options.image, prefix.rstrip('/'), '-type', 'f', '-exec', 'sha256sum', '{}', '+').splitlines()
        observed = dict((line.partition('  ')[2], line.partition('  ')[0]) for line in lines)
        verify_file_digests(wanted, observed, '镜像补充材料与源码不一致：' + directory)
        extra_count += len(wanted)
    for name in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
        path = "/usr/share/licenses/vpngate-auto-proxy/" + name
        content = subprocess.run(
            ["docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL",
             "--security-opt", "no-new-privileges", "--read-only", "--entrypoint", "cat",
             options.image, path], check=True, stdout=subprocess.PIPE,
        ).stdout
        if content != (ROOT / name).read_bytes():
            raise RuntimeError(f"镜像中的 {name} 与当前源码不一致")
    print(f"镜像许可材料核对通过：{len(expected)} 份依赖原文、{extra_count} 份补充材料及项目声明")


if __name__ == "__main__":
    main()
