"""只读检查一次实验的私有抓包；不创建接口或更改权限，不输出报文正文。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

from macos_fault import CaptureValidationError, capture_packets, inspect_capture


def diagnose(directory):
    directory = Path(directory)
    if not re.fullmatch(r"/private/tmp/vap-parallel-[a-zA-Z0-9_-]+", str(directory)) or directory.is_symlink():
        raise RuntimeError("只接受本实验的管理员私有目录")
    content, statistics = None, None
    for filename, limit in (("management.pcap", 4 * 1024 * 1024), ("capture.log", 64 * 1024)):
        path = directory / filename
        if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
            raise RuntimeError("诊断文件缺失、超限或为符号链接：" + filename)
        if filename == "management.pcap":
            content = path.read_bytes()
        else:
            statistics = path.read_text()
    packets = capture_packets(content, statistics)
    groups = {}
    for packet in packets:
        for match in re.finditer(rb"(?<![0-9a-f])([0-9a-f]{40})-(tcp|udp)", packet):
            marker, protocol = match[1], match[2].decode()
            if marker not in groups:
                groups[marker] = {"fingerprint": hashlib.sha256(marker).hexdigest()[:16], "tcp_packets": 0, "udp_packets": 0}
            groups[marker][protocol + "_packets"] += 1
    report = {"read_only": True, "capture_bytes": len(content), "packet_count": len(packets),
              "capture_sha256": hashlib.sha256(content).hexdigest(), "marker_groups": list(groups.values()),
              "full_macos_backend_validated": False}
    markers = directory / "fault-markers.json"
    if markers.exists():
        if markers.is_symlink() or not markers.is_file() or markers.stat().st_size > 1024:
            raise RuntimeError("合成标记归属文件无效")
        values = json.loads(markers.read_text())
        if (not re.fullmatch(r"[0-9a-f]{40}", values.get("positive", ""))
                or not isinstance(values.get("negative"), list) or len(values["negative"]) != 2
                or any(not isinstance(v, str) or not re.fullmatch(r"[0-9a-f]{40}", v) for v in values["negative"])):
            raise RuntimeError("合成标记内容无效")
        try:
            report["checks"] = inspect_capture(content, statistics, values["positive"], values["negative"])
        except CaptureValidationError as error:
            report.update(checks=error.checks, error=str(error))
        if "positive_end" in values:
            if not isinstance(values["positive_end"], str) or not re.fullmatch(r"[0-9a-f]{40}", values["positive_end"]):
                raise RuntimeError("结束正对照标记内容无效")
            try:
                report["end_control_checks"] = inspect_capture(content, statistics, values["positive_end"], values["negative"])
            except CaptureValidationError as error:
                report.update(end_control_checks=error.checks, end_control_error=str(error))
        report["marker_ownership_available"] = True
    else:
        report.update(marker_ownership_available=False,
                      limitation="旧版未保留合成标记的正负归属映射；不能仅凭分组确定是否泄漏，不将观测缺失判为通过")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="只读诊断原生故障抓包，不输出报文正文")
    parser.add_argument("directory")
    options = parser.parse_args()
    try:
        print(json.dumps(diagnose(options.directory), ensure_ascii=False, indent=2))
    except Exception as error:
        print(json.dumps({"read_only": True, "status": "failed", "error": str(error)}, ensure_ascii=False, indent=2))
        sys.exit(2)
