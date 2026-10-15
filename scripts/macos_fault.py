"""原生隧道销毁及管理端点防漏实验；不证明接口索引复用或生产后端。"""
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import struct
import subprocess
import time

from macos_tunnel import REPO, TARGET, interfaces, run


def wait_capture_marker(process, path, marker, timeout=3):
    deadline = time.monotonic() + timeout
    while True:
        if process.poll() is not None:
            raise RuntimeError("等待正对照时抓包子进程提前退出")
        if path.exists():
            if path.stat().st_size > 4 * 1024 * 1024:
                raise RuntimeError("管理路径抓包超过实验限额")
            content = path.read_bytes()
            if all((marker + "-" + protocol).encode() in content for protocol in ("tcp", "udp")):
                return
        if time.monotonic() >= deadline:
            raise RuntimeError("流式或数据报正对照在三秒内未被抓包记录，停止本次实验")
        time.sleep(0.01)


class CaptureValidationError(RuntimeError):
    def __init__(self, checks):
        self.checks = checks
        problems = []
        if not checks["capture_positive_tcp"]:
            problems.append("流式正对照缺失")
        if not checks["capture_positive_udp"]:
            problems.append("数据报正对照缺失")
        if not checks["no_scoped_management_payload"]:
            problems.append("观测到固定接口业务标记")
        super().__init__("管理路径抓包判定失败：" + "；".join(problems))


def capture_packets(content, statistics):
    # 本机 tcpdump 默认经典抓包格式；拒绝空文件、未知格式及观测丢包。
    if len(content) < 24 or content[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        raise RuntimeError("管理路径抓包文件缺失或格式无效")
    endian = "<" if content[:4] == b"\xd4\xc3\xb2\xa1" else ">"
    major, minor, _, _, snaplen, _ = struct.unpack(endian + "HHIIII", content[4:24])
    if (major, minor) != (2, 4) or not 1 <= snaplen <= 1024 * 1024:
        raise RuntimeError("管理路径抓包文件头无效")
    offset, packets = 24, []
    while offset < len(content):
        if offset + 16 > len(content):
            raise RuntimeError("管理路径抓包记录头截断")
        _, _, length, original = struct.unpack(endian + "IIII", content[offset:offset + 16])
        offset += 16
        if not 1 <= length <= snaplen or length != original or offset + length > len(content):
            raise RuntimeError("管理路径抓包记录缺失或截断")
        packets.append(content[offset:offset + length])
        offset += length
    captured = re.search(r"(\d+) packets captured", statistics)
    if not captured or int(captured[1]) != len(packets):
        raise RuntimeError("管理路径抓包记录数与统计不一致")
    dropped = re.search(r"(\d+) packets dropped by kernel", statistics)
    if not dropped or int(dropped[1]) != 0:
        raise RuntimeError("管理路径抓包缺少丢包统计或发生丢包")
    return packets


def inspect_capture(content, statistics, positive, negative):
    packets = capture_packets(content, statistics)
    checks = {
        "capture_positive_tcp": any((positive + "-tcp").encode() in packet for packet in packets),
        "capture_positive_udp": any((positive + "-udp").encode() in packet for packet in packets),
        "no_scoped_management_payload": all(marker.encode() not in packet for marker in negative for packet in packets),
    }
    if not all(checks.values()):
        raise CaptureValidationError(checks)
    return checks


def exercise_fault(options, nodes, activity, runtime, endpoints, uid, gid, evidence):
    capture, errors = runtime / "management.pcap", runtime / "capture.log"
    endpoint = endpoints[0]
    port = str(endpoint["port"])
    positive = secrets.token_hex(20)
    positive_end = secrets.token_hex(20)
    negative = [secrets.token_hex(20) for _ in range(2)]
    checks, attempts = {}, []
    evidence.update(checks=checks, management_attempts=attempts,
                    scope="实验监督取消、接口销毁后新建连接及本机回环节点端点；不含索引复用、遗留恢复或生产切换")
    # 标记仅为本次合成测试数据。保留私有归属映射，使失败后可以原样重审证据。
    markers = runtime / "fault-markers.json"
    markers.write_text(json.dumps({"positive": positive, "positive_end": positive_end, "negative": negative}) + "\n")
    markers.chmod(0o600)
    capture_process = None

    def guard(index, marker, stage):
        result = run([options.guard_probe, str(index), "127.0.0.1", port, marker], timeout=6,
                     cwd=REPO, user=uid, group=gid, extra_groups=[])
        value = json.loads(result.stdout)
        if value.get("interface_index") != int(index) or any(
            type(value.get(key)) is not bool for key in ("tcp_connected", "tcp_written", "udp_sent")
        ):
            raise RuntimeError("防漏探针输出无效")
        value["stage"] = stage
        attempts.append(value)
        return value

    def stop_capture():
        if capture_process is not None and capture_process.poll() is None:
            capture_process.send_signal(signal.SIGINT)
            try:
                capture_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                capture_process.kill()
                capture_process.wait(timeout=2)
                raise RuntimeError("管理路径抓包未正常退出")

    try:
        with errors.open("w") as err:
            capture_process = subprocess.Popen(
                ["/usr/sbin/tcpdump", "--immediate-mode", "-i", "lo0", "-n", "-s", "0", "-U", "-w", str(capture),
                 f"dst host 127.0.0.1 and dst port {port} and (tcp or udp)"],
                stdout=subprocess.DEVNULL, stderr=err, env={**os.environ, "LC_ALL": "C"},
            )
        deadline = time.monotonic() + 5
        while "listening on" not in errors.read_text():
            if capture_process.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("管理路径抓包未就绪：" + errors.read_text()[-512:])
            time.sleep(0.05)
        control = guard(socket.if_nametoindex("lo0"), positive, "开始正对照")
        if not control["tcp_written"] or not control["udp_sent"]:
            raise RuntimeError("管理端点正对照发送失败")
        # 启动提示和成功发送均不能证明内核抓包队列已被消费。
        wait_capture_marker(capture_process, capture, positive)
        checks["capture_ready_before_fault"] = True
        live = guard(nodes[0].index, negative[0], "活动接口")
        checks["live_scope_rejects_management_tcp"] = not live["tcp_connected"]

        # 此处是实验监督进程主动取消自己的业务子进程，并非生产恢复实现。
        started = time.monotonic()
        if activity.poll() is not None:
            raise RuntimeError("故障前活动连接已提前退出")
        activity.terminate()
        activity.wait(timeout=3)
        checks["old_activity_cancelled"] = activity.poll() is not None
        checks["cancellation_within_3_seconds"] = time.monotonic() - started < 3
        nodes[0].close()
        checks["active_interface_removed"] = nodes[0].interface not in interfaces()
        stale = guard(nodes[0].index, negative[1], "已销毁接口")
        checks["removed_scope_rejects_management_tcp_udp"] = not any(
            stale[key] for key in ("tcp_connected", "tcp_written", "udp_sent")
        )
        for key, command in (
            ("removed_scope_rejects_business", [options.probe, nodes[0].index, TARGET, "19090",
                                               secrets.token_hex(24), endpoint["identity"], "1"]),
            ("removed_scope_rejects_dns", [options.dns_probe, nodes[0].index, TARGET, "53", endpoint["identity"]]),
        ):
            result = run(command, check=False, timeout=8, cwd=REPO, user=uid, group=gid, extra_groups=[])
            checks[key] = result.returncode != 0 and not result.stdout.strip()
        for index in (1, 2):
            for command in (
                [options.probe, nodes[index].index, TARGET, "19090", secrets.token_hex(24), endpoints[index]["identity"], "1"],
                [options.dns_probe, nodes[index].index, TARGET, "53", endpoints[index]["identity"]],
            ):
                value = json.loads(run(command, timeout=8, cwd=REPO, user=uid, group=gid, extra_groups=[]).stdout)
                if value.get("identity") != endpoints[index]["identity"] or value.get("interface_index") != int(nodes[index].index):
                    raise RuntimeError("活动隧道销毁后候选归属发生变化")
            checks[f"candidate_{index}_business_dns_survived"] = True
        control_end = guard(socket.if_nametoindex("lo0"), positive_end, "结束正对照")
        if not control_end["tcp_written"] or not control_end["udp_sent"]:
            raise RuntimeError("管理端点结束正对照发送失败")
        wait_capture_marker(capture_process, capture, positive_end)
        checks["capture_observed_end_controls"] = True
        stop_capture()
        if capture_process.returncode != 0:
            raise RuntimeError("管理路径抓包退出异常")
        capture.chmod(0o600)
        if capture.stat().st_size > 4 * 1024 * 1024:
            raise RuntimeError("管理路径抓包超过实验限额")
        try:
            checks.update(inspect_capture(capture.read_bytes(), errors.read_text(), positive, negative))
            final = inspect_capture(capture.read_bytes(), errors.read_text(), positive_end, negative)
            checks["capture_final_positive_tcp_udp"] = final["capture_positive_tcp"] and final["capture_positive_udp"]
        except CaptureValidationError as error:
            checks.update(error.checks)
            raise
        checks["capture_process_reaped"] = capture_process.poll() is not None
        if not all(checks.values()):
            raise RuntimeError("原生故障实验存在未满足断言：" + "、".join(k for k, v in checks.items() if not v))
        return evidence
    except BaseException as error:
        evidence["error"] = str(error) or type(error).__name__
        raise
    finally:
        try:
            stop_capture()
        finally:
            evidence["capture_process_reaped"] = capture_process is not None and capture_process.poll() is not None
            if capture.exists():
                evidence["capture_bytes"] = capture.stat().st_size
