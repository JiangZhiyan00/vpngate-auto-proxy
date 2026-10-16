#!/usr/bin/env python3
"""Linux 生产安装及独立旧入口退休；不运行候选程序，不补写历史记录。"""
import argparse
import contextlib
import functools
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import uuid

LIMIT = 64 * 1024 * 1024
PROJECT = "vpngate-auto-proxy"


class Rejected(Exception):
    """校验失败，保持原节点。"""


def ensure(condition, message):
    if not condition:
        raise Rejected(message)


def reject_io(operation):
    @functools.wraps(operation)
    def checked(*args, **kwargs):
        try:
            return operation(*args, **kwargs)
        except (OSError, ValueError, TypeError, KeyError) as error:
            raise Rejected(f"校验或文件操作失败：{error}") from error
    return checked


def require_root():
    ensure(sys.platform == "linux" and os.getuid() == os.geteuid() == 0,
           "仅允许 Linux 实际及有效管理员用户操作")


def absolute(value):
    ensure(isinstance(value, str) and value.startswith("/") and "\0" not in value,
           "必须提供绝对路径")
    ensure(value == "/" or all(p not in ("", ".", "..") for p in value[1:].split("/")),
           "路径不得包含空分量或跳转")
    return value


def digest_format(value):
    ensure(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value),
           "摘要必须为 64 位小写十六进制 SHA256")
    return value


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def directory_metadata(info, exact=False):
    mode = stat.S_IMODE(info.st_mode)
    ensure(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not mode & 0o7022
           and mode & 0o001, "目录链必须由管理员管理、可搜索且不可被组或其他用户写入")
    if exact:
        ensure(info.st_gid == 0 and mode == 0o755, "安装目录必须为 root:root，权限 0755")


@contextlib.contextmanager
def directory(value, protected=True, exact=False):
    """从根描述符逐段打开；不跟随任意路径链接。"""
    value = absolute(value)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if protected:
            directory_metadata(os.fstat(fd))
        for part in value[1:].split("/") if value != "/" else []:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=fd)
            os.close(fd)
            fd = child
            if protected:
                directory_metadata(os.fstat(fd))
        if exact:
            directory_metadata(os.fstat(fd), exact=True)
        yield fd
    finally:
        os.close(fd)


def recheck_directory(value, fd, exact=False):
    with directory(value, exact=exact) as observed:
        left, right = os.fstat(fd), os.fstat(observed)
        ensure((left.st_dev, left.st_ino) == (right.st_dev, right.st_ino), "目标目录身份发生变化")


def source_metadata(info, owners):
    ensure(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid in owners
           and not stat.S_IMODE(info.st_mode) & 0o7022 and 1 <= info.st_size <= LIMIT,
           "源须为允许属主的独立普通文件，大小 1 字节至 64 MiB，且没有危险权限")


@contextlib.contextmanager
def snapshot(value, owners, protected=False, executable=False):
    value = absolute(value)
    parent, name = os.path.split(value)
    with directory(parent, protected=protected) as parent_fd:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent_fd)
        try:
            before = os.fstat(fd)
            source_metadata(before, owners)
            if executable:
                ensure(before.st_gid == 0 and stat.S_IMODE(before.st_mode) == 0o755,
                       "旧公开程序须为 root:root，权限 0755")
            data = bytearray()
            while len(data) <= LIMIT:
                block = os.read(fd, min(1024 * 1024, LIMIT + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
            ensure(len(data) == before.st_size and identity(before) == identity(os.fstat(fd)),
                   "读取期间源文件发生变化")
            ensure(identity(before) == identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)),
                   "源路径已被替换")
            yield bytes(data), before, parent_fd, fd
        finally:
            os.close(fd)


def safe_path_directory(value):
    """PATH 可含管理员保护的目录链接，逐段验证每条链接所在链。"""
    absolute(value)
    parts = value[1:].split("/") if value != "/" else []
    resolved = "/"
    traversed = 0
    while parts:
        part = parts.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            resolved = str(Path(resolved).parent)
            continue
        with directory(resolved) as parent_fd:
            info = os.stat(part, dir_fd=parent_fd, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                ensure(info.st_uid == 0, "PATH 链接必须由管理员管理")
                traversed += 1
                ensure(traversed <= 40, "PATH 链接循环或过深")
                target = os.readlink(part, dir_fd=parent_fd)
                if target.startswith("/"):
                    resolved = "/"
                parts = target.split("/") + parts
            else:
                directory_metadata(info)
                resolved = str(Path(resolved) / part)
    with directory(resolved) as fd:
        info = os.fstat(fd)
        return resolved, (info.st_dev, info.st_ino)


def no_node(fd, name="vap"):
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise Rejected(f"同名节点已存在，拒绝覆盖：{name}")


def path_conflicts(target):
    seen = set()
    for value in [target] + os.environ.get("PATH", "").split(":"):
        canonical, key = safe_path_directory(value)
        if key not in seen:
            with directory(canonical) as fd:
                no_node(fd)
            seen.add(key)


def remove_owned_stage(fd, name, saved):
    try:
        current = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) == (saved.st_dev, saved.st_ino):
            os.unlink(name, dir_fd=fd)
    except FileNotFoundError:
        pass


@reject_io
def install(source, sha256, install_dir="/usr/local/bin"):
    require_root()
    digest_format(sha256)
    absolute(install_dir)
    owners = {0}
    sudo = os.environ.get("SUDO_UID")
    if sudo is not None:
        ensure(re.fullmatch(r"(?:0|[1-9][0-9]*)", sudo), "SUDO_UID 必须为有效的非负用户身份")
        if sudo != "0":
            owners.add(int(sudo))
    with directory(install_dir, exact=True) as parent_fd:
        path_conflicts(install_dir)
        with snapshot(source, owners) as (data, _, _, _):
            ensure(hashlib.sha256(data).hexdigest() == sha256, "选定源摘要不匹配")
        stage = ".vap-install-" + secrets.token_hex(16)
        fd = os.open(stage, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent_fd)
        saved = os.fstat(fd)
        try:
            with os.fdopen(os.dup(fd), "wb") as stream:
                stream.write(data)
                stream.flush()
            os.fchown(fd, 0, 0)
            for name in os.listxattr(fd):
                os.removexattr(fd, name)
            os.fchmod(fd, 0o755)
            os.fsync(fd)
            recheck_directory(install_dir, parent_fd, exact=True)
            path_conflicts(install_dir)
            ensure(identity(os.fstat(fd)) == identity(os.stat(stage, dir_fd=parent_fd, follow_symlinks=False)),
                   "暂存节点身份变化")
            os.link(stage, "vap", src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
            remove_owned_stage(parent_fd, stage, saved)
            final = os.stat("vap", dir_fd=parent_fd, follow_symlinks=False)
            ensure(identity(final) == identity(os.fstat(fd)) and final.st_nlink == 1
                   and final.st_uid == final.st_gid == 0 and stat.S_IMODE(final.st_mode) == 0o755,
                   "发布后的程序身份或权限无效")
            os.lseek(fd, 0, os.SEEK_SET)
            ensure(hashlib.sha256(os.read(fd, LIMIT + 1)).hexdigest() == sha256, "发布后的程序摘要无效")
            os.fsync(parent_fd)
        finally:
            os.close(fd)
            remove_owned_stage(parent_fd, stage, saved)
    return str(Path(install_dir) / "vap")


def load_evidence(stack, value):
    data, info, parent_fd, fd = stack.enter_context(snapshot(value, {0}, protected=True))
    ensure(info.st_gid == 0, "证据必须由 root:root 管理")
    try:
        def unique(pairs):
            result = {}
            for key, item in pairs:
                ensure(key not in result, "证据包含重复字段")
                result[key] = item
            return result
        parsed = json.loads(data, object_pairs_hook=unique)
    except (ValueError, UnicodeError) as error:
        raise Rejected("证据不是有效 JSON") from error
    ensure(isinstance(parsed, dict), "证据必须为对象")
    return parsed, hashlib.sha256(data).hexdigest(), (value, info, parent_fd, fd)


def check_consumers(info, audit_fds=()):
    """完整可见的 /proc 中核对可执行文件、文件描述符与映射；未知即拒绝。"""
    ensure(Path("/proc/1").is_dir(), "无法核对内核消费者")
    key = (info.st_dev, info.st_ino)
    for process in Path("/proc").iterdir():
        if not process.name.isdigit():
            continue
        try:
            # 僵尸或内核线程无 exe；活跃用户进程读取失败不能默认为已退出。
            state = (process / "stat").read_text().rsplit(")", 1)[1].split()[0]
            entries = [process / "exe"] + list((process / "fd").iterdir())
            for path in entries:
                if process.name == str(os.getpid()) and path.parent.name == "fd" and path.name in {str(fd) for fd in audit_fds}:
                    continue
                try:
                    current = path.stat()
                except FileNotFoundError:
                    if path.name == "exe" and state not in ("Z", "X") and (process / "cmdline").read_bytes():
                        raise Rejected("活跃进程的程序身份不可核对")
                    continue
                ensure((current.st_dev, current.st_ino) != key, "旧程序仍有存活消费者")
            for line in (process / "maps").read_text().splitlines():
                fields = line.split(None, 5)
                if len(fields) >= 5:
                    major, minor = (int(p, 16) for p in fields[3].split(":"))
                    ensure((os.makedev(major, minor), int(fields[4])) != key, "旧程序仍有内存映射消费者")
        except FileNotFoundError:
            ensure(not process.exists(), "消费者状态无法完整核对")
        except PermissionError as error:
            raise Rejected("消费者信息不可读，拒绝退休") from error


@reject_io
def retire(entry, installation_record, artifact, stopped_proof):
    require_root()
    absolute(entry)
    path = Path(entry)
    parent = path.parent
    standard = parent in (Path("/usr/local/bin"), Path("/usr/bin"))
    # /opt 只接受直接的应用公开目录；不进入 bin 下或应用下的备份、数据、历史树。
    application_bin = (parent.name == "bin" and parent.parent.parent == Path("/opt")
                       and parent.parent.name.casefold() not in
                       {"backup", "backups", "data", "history", "versions"})
    ensure(path.name == PROJECT and (standard or application_bin),
           "仅允许明确公开 bin 目录中的旧入口；保护目录和备份不允许退休")
    with contextlib.ExitStack() as stack:
        record, record_sha, record_node = load_evidence(stack, installation_record)
        release, release_sha, release_node = load_evidence(stack, artifact)
        stopped, _, stopped_node = load_evidence(stack, stopped_proof)
        ensure(record.get("schema_version") == 1 and record.get("project") == PROJECT
               and record.get("entry_path") == entry and isinstance(record.get("version"), str)
               and record["version"].strip(),
               "安装归属记录不匹配")
        sha = digest_format(record.get("binary_sha256"))
        origin = record.get("release", {})
        ensure(isinstance(origin, dict), "发布来源字段必须为对象")
        ensure(origin.get("path") == artifact and origin.get("sha256") == release_sha
               and isinstance(origin.get("source"), str) and origin["source"].strip(),
               "发布材料来源或摘要不匹配")
        binaries = release.get("binaries")
        ensure(isinstance(binaries, dict) and release.get("project") == PROJECT
               and release.get("version") == record["version"]
               and binaries.get(PROJECT) == sha, "发布版本或程序材料不匹配")
        instances = record.get("instances")
        ensure(isinstance(instances, list) and instances, "缺少可信的实例归属清单")
        ensure(stopped.get("schema_version") == 1 and stopped.get("installation_sha256") == record_sha
               and stopped.get("boot_id") == Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
               "停止证明不属于本次安装和内核启动")
        results = stopped.get("instances")
        ensure(isinstance(results, list) and len(results) == len(instances), "停止结果不完整")
        seen = set()
        for instance, result in zip(instances, results):
            ensure(isinstance(instance, dict) and isinstance(result, dict), "实例及回收结果必须为对象")
            instance_id, runtime = instance.get("id"), instance.get("runtime_dir")
            try:
                ensure(str(uuid.UUID(instance_id)) == instance_id, "实例身份无效")
            except (ValueError, TypeError, AttributeError) as error:
                raise Rejected("实例身份无效") from error
            absolute(runtime)
            ensure(instance_id not in seen and result.get("id") == instance_id
                   and result.get("runtime_dir") == runtime, "实例回收结果归属不匹配")
            seen.add(instance_id)
            response = result.get("response", {})
            ensure(isinstance(response, dict) and response.get("result") == "accepted"
                   and response.get("instance_id") == instance_id
                   and type(result.get("exit_code")) is int and result["exit_code"] == 0
                   and result.get("resources_reaped") is True, "没有正常停止及完整回收结果")
            with directory(str(Path(runtime).parent)):
                ensure(not os.path.lexists(runtime), "实例运行目录仍存在或回收状态未知")
        data, before, parent_fd, fd = stack.enter_context(snapshot(entry, {0}, protected=True, executable=True))
        ensure(hashlib.sha256(data).hexdigest() == sha, "旧公开入口摘要不符")
        check_consumers(before, (fd,))
        # 所有证据、目录及目标都在同一审计期间持有描述符，提交前复核。
        for value, info, evidence_parent, evidence_fd in [record_node, release_node, stopped_node]:
            recheck_directory(str(Path(value).parent), evidence_parent)
            ensure(identity(info) == identity(os.fstat(evidence_fd))
                   == identity(os.stat(Path(value).name, dir_fd=evidence_parent, follow_symlinks=False)),
                   "归属或回收证据发生变化")
        recheck_directory(str(Path(entry).parent), parent_fd)
        ensure(identity(before) == identity(os.fstat(fd))
               == identity(os.stat(Path(entry).name, dir_fd=parent_fd, follow_symlinks=False)),
               "旧入口身份发生变化")
        os.unlink(Path(entry).name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    return entry


def main():
    parser = argparse.ArgumentParser(description="Linux 管理员无覆盖安装；退休为单独显式操作")
    commands = parser.add_subparsers(dest="command", required=True)
    add = commands.add_parser("install", help="校验选定快照并无覆盖安装 vap")
    add.add_argument("--source", required=True)
    add.add_argument("--sha256", required=True)
    add.add_argument("--install-dir", default="/usr/local/bin")
    remove = commands.add_parser("retire", help="依据可信历史记录及正常停止证据退休指定旧公开入口")
    for option in ["entry", "installation-record", "artifact", "stopped-proof"]:
        remove.add_argument("--" + option, required=True)
    arguments = parser.parse_args()
    try:
        if arguments.command == "install":
            result = install(arguments.source, arguments.sha256, arguments.install_dir)
        else:
            result = retire(arguments.entry, arguments.installation_record, arguments.artifact, arguments.stopped_proof)
        print(json.dumps({"operation": arguments.command, "path": result, "service_activated": False}, ensure_ascii=False))
        return 0
    except (Rejected, OSError, ValueError, KeyError, TypeError) as error:
        print(f"操作拒绝：{error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
