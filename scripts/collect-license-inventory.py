"""从锁定的本地包元数据及实际镜像生成声明材料，不把清单等同于发布核查完成。"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ["aarch64-unknown-linux-musl", "x86_64-unknown-linux-musl", "x86_64-unknown-linux-gnu", "aarch64-apple-darwin"]


def invoke(*args):
    return subprocess.run(args, cwd=ROOT, check=True, text=True, stdout=subprocess.PIPE).stdout


def production_packages(metadata):
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    pending, selected = [metadata["resolve"]["root"]], set()
    while pending:
        identity = pending.pop()
        if identity in selected:
            continue
        selected.add(identity)
        for dependency in nodes[identity]["deps"]:
            if any(kind["kind"] != "dev" for kind in dependency["dep_kinds"]):
                pending.append(dependency["pkg"])
    return [package for package in metadata["packages"] if package["id"] in selected and package["source"]]


def main():
    parser = argparse.ArgumentParser(description="整理已锁定依赖的原始声明及镜像包清单")
    parser.add_argument("--image", default="vpngate-auto-proxy:local")
    options = parser.parse_args()
    destination = ROOT / "docs/third-party"
    destination.mkdir(exist_ok=True)
    records = {}
    for target in TARGETS:
        metadata = json.loads(invoke("cargo", "metadata", "--locked", "--format-version", "1", "--filter-platform", target))
        for package in production_packages(metadata):
            key = package["name"], package["version"]
            if key not in records:
                source = Path(package["manifest_path"]).parent
                files = [file for file in source.iterdir() if file.is_file() and any(
                    word in file.name.upper() for word in ["LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE"])]
                if package.get("license_file"):
                    declared = source / package["license_file"]
                    if declared.is_file() and declared not in files:
                        files.append(declared)
                if not package.get("license") or not files:
                    raise RuntimeError(f"缺少声明或原始许可文件：{package['name']} {package['version']}")
                notices = []
                directory = destination / "rust" / f"{key[0]}-{key[1]}"
                directory.mkdir(parents=True, exist_ok=True)
                for file in sorted(files):
                    output = directory / file.name
                    shutil.copyfile(file, output)
                    notices.append({"path": str(output.relative_to(ROOT)), "sha256": hashlib.sha256(output.read_bytes()).hexdigest()})
                records[key] = {"name": key[0], "version": key[1], "declared_license": package["license"],
                                "repository": package["repository"], "registry_source": package["source"],
                                "targets": [], "original_notices": notices}
            records[key]["targets"].append(target)
    image = json.loads(invoke("docker", "image", "inspect", options.image))[0]
    database = invoke("docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL", "--security-opt",
                      "no-new-privileges", "--read-only", "--entrypoint", "cat", options.image, "/lib/apk/db/installed")
    packages = []
    for block in database.strip().split("\n\n"):
        values = dict(line.split(":", 1) for line in block.splitlines() if len(line) >= 2 and line[1] == ":")
        if not all(values.get(key) for key in ["P", "V", "L", "o", "c"]):
            raise RuntimeError("实际镜像的系统包缺少版本、声明或来源提交")
        packages.append({"name": values["P"], "version": values["V"], "declared_license": values["L"],
                         "origin": values["o"], "source_commit": values["c"], "upstream_url": values.get("U"),
                         "packaging_commit_url": "https://gitlab.alpinelinux.org/alpine/aports/-/commit/" + values["c"]})
    inventory = {"schema_version": 1, "generated_at": datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat(),
                 "cargo_lock_sha256": hashlib.sha256((ROOT / "Cargo.lock").read_bytes()).hexdigest(),
                 "targets": TARGETS, "rust_packages": [records[key] for key in sorted(records)],
                 "runtime_image": {"id": image["Id"], "architecture": image["Architecture"], "packages": sorted(packages, key=lambda item: item["name"])},
                 "distribution_review_complete": False, "system_package_sources_bundled": False}
    (destination / "inventory.json").write_text(json.dumps(inventory, ensure_ascii=False, indent=2) + "\n")
    print(f"已整理 {len(records)} 个程序及构建依赖、{len(packages)} 个实际镜像系统包；发布核查仍未完成")


if __name__ == "__main__":
    main()
