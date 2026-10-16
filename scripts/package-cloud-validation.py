"""从已构建的 x86_64 镜像生成白名单离线验收包，不包含本地凭据。"""
import argparse
from image_program import program_bytes
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

from cloud_image_identity import archive_identities


ROOT = Path(__file__).resolve().parents[1]
FILES = [
    "scripts/validate_docker.py", "scripts/validate_soak.py", "scripts/soak_client.py",
    "scripts/verify-license-image.py", "scripts/cloud_image_identity.py", "Cargo.lock",
    "scripts/cloud_deploy.py", "scripts/docker_profiles.py", "scripts/image_program.py",
    "tests/fixtures/setup-docker.sh", "tests/fixtures/setup.sh",
    "tests/fixtures/cleanup.sh", "tests/fixtures/services.py",
    "deploy/apparmor/vpngate-auto-proxy", "deploy/compose.apparmor.yaml",
    "deploy/apparmor/vpngate-auto-proxy-fixture",
    "LICENSE", "THIRD_PARTY_NOTICES.md",
]


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser(description="导出云服务器 x86_64 私有验收包")
    parser.add_argument("--image", required=True)
    parser.add_argument("--fixture-image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    images = []
    for tag in (options.image, options.fixture_image):
        image = json.loads(subprocess.check_output(["docker", "image", "inspect", tag]))[0]
        if image["Architecture"] != "amd64" or image["Os"] != "linux":
            raise RuntimeError("只能打包 Linux x86_64 镜像")
        images.append({"tag": tag, "id": image["Id"], "architecture": image["Architecture"], "os": image["Os"]})
    inventory = json.loads((ROOT / "docs/third-party/inventory.json").read_text())
    if inventory["runtime_image"]["id"] != images[0]["id"]:
        raise RuntimeError("请先为指定运行镜像重新生成许可清单并完成镜像原文核验")
    subprocess.run(["python3", str(ROOT / "scripts/verify-license-image.py"), "--image", options.image], check=True)
    binary = program_bytes(options.image)
    if binary[:6] != b"\x7fELF\x02\x01" or int.from_bytes(binary[18:20], "little") != 62:
        raise RuntimeError("镜像内程序不是 x86_64 ELF 可执行文件")
    destination = options.output.resolve()
    archive = destination.with_name(destination.name + ".tar.gz")
    if destination.exists() or archive.exists():
        raise RuntimeError("输出目录或压缩包已存在，拒绝覆盖")
    destination.mkdir(parents=True)
    for relative in FILES:
        output = destination / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, output)
    shutil.copytree(ROOT / "docs/third-party", destination / "docs/third-party")
    for name in ("README.md", "run.sh", "manage.sh", "compose.yaml"):
        shutil.copy2(ROOT / "deploy/cloud" / name, destination / name)
    shutil.copy2(ROOT / "deploy/config.container.example.json", destination / "config.json")
    (destination / "image.env").write_text("VAP_IMAGE=" + options.image + "\n")
    (destination / ".gitignore").write_text("/credentials.local.json\n/validation-output/\n/images.tar\n")
    manifest = {
        "schema_version": 1,
        "delivery_revision": 3,
        "created_at": datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat(),
        "purpose": "用户手动执行的私有云服务器验收与部署候选",
        "images": images,
        "cargo_lock_sha256": digest(ROOT / "Cargo.lock"),
        "binary_sha256": hashlib.sha256(binary).hexdigest(),
        "build_inputs_sha256": {
            path.relative_to(ROOT).as_posix(): digest(path)
            for path in sorted([
                ROOT / "Dockerfile", ROOT / "Cargo.toml", ROOT / "Cargo.lock",
                ROOT / "rust-toolchain.toml", ROOT / "tests/fixtures/Dockerfile.runtime",
                *(ROOT / "src").rglob("*.rs"),
            ])
        },
        "cloud_native_validation_completed": False,
        "macos_native_validation_deferred": True,
    }
    subprocess.run(["docker", "save", "-o", str(destination / "images.tar"), options.image, options.fixture_image], check=True)
    for image in manifest['images']:
        image['verified_archive_ids'] = sorted(archive_identities(destination / 'images.tar', image))
    (destination / "bundle.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    sums = []
    for path in sorted(destination.rglob("*")):
        if path.is_symlink():
            raise RuntimeError("包内不允许符号链接")
        if path.is_file():
            sums.append(f"{digest(path)}  {path.relative_to(destination).as_posix()}")
    (destination / "SHA256SUMS").write_text("\n".join(sums) + "\n")
    with tarfile.open(archive, "w:gz", compresslevel=6) as output:
        output.add(destination, arcname=destination.name)
    checksum = archive.with_name(archive.name + ".sha256")
    checksum.write_text(f"{digest(archive)}  {archive.name}\n")
    print(f"离线包：{archive}")
    print(f"压缩包摘要：{checksum}")


if __name__ == "__main__":
    main()
