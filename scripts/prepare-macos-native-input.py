#!/usr/bin/env python3
"""从明确指定的来源快照提取节点；不联网、不刷新来源时间、不覆盖文件。"""
import argparse
import hashlib
import json
import os
import stat
from pathlib import Path


def prepare(source, node_ids, check_urls, output):
    if not 1 <= len(node_ids) <= 3 or len(set(node_ids)) != len(node_ids):
        raise ValueError("须明确选择一至三个不同节点")
    if not check_urls:
        raise ValueError("须明确提供检测网址")
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 32 * 1024 * 1024:
            raise ValueError("来源须为有界、无硬链接的普通文件")
        raw = stream.read(32 * 1024 * 1024 + 1)
    if len(raw) > 32 * 1024 * 1024:
        raise ValueError("来源文件超过上限")
    snapshot = json.loads(raw)
    if snapshot.get("schema_version") != 1 or not isinstance(snapshot.get("nodes"), list):
        raise ValueError("来源快照格式无效")
    selected = []
    for identity in node_ids:
        matches = [node for node in snapshot["nodes"] if node.get("id") == identity]
        if len(matches) != 1:
            raise ValueError("所选节点不存在或重复")
        selected.append(matches[0])
    data = {"nodes": selected, "check_urls": check_urls, "max_attempts": 3,
            "check_budget_seconds": 15, "startup_budget_seconds": 60,
            "source_ttl_seconds": 3600, "verification_ttl_seconds": 60}
    encoded = (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode()
    if len(encoded) > 1024 * 1024:
        raise ValueError("验证材料超过上限")
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(encoded)
    return {"input": str(Path(output).absolute()), "sha256": hashlib.sha256(encoded).hexdigest(),
            "selected_node_ids": node_ids}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--node-id", action="append", required=True)
    parser.add_argument("--check-url", action="append", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        result = prepare(args.source, args.node_id, args.check_url, args.output)
    except (OSError, ValueError, TypeError, AttributeError, KeyError):
        parser.exit(1, "节点材料准备失败；请核对快照格式、节点选择和输出路径，未打印配置内容。\n")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
