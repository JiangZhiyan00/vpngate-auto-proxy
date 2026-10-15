#!/usr/bin/env python3
"""苹果原生只读预检，权限或依赖缺失时返回非零结果。"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys


def command(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=10)
        return {
            "ok": result.returncode == 0,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"ok": False, "error": str(error)}


def preflight(openvpn):
    report = {
        "schema_version": 1,
        "case": "preflight",
        "read_only": True,
        "native_tunnel_validated": False,
        "checks": {},
    }
    checks = report["checks"]
    checks["platform"] = {
        "ok": platform.system() == "Darwin",
        "system": platform.system(),
        "architecture": platform.machine(),
    }
    if not checks["platform"]["ok"]:
        report["status"] = "blocked"
        return report
    checks["system_version"] = command(["/usr/bin/sw_vers", "-productVersion"])
    checks["system_build"] = command(["/usr/bin/sw_vers", "-buildVersion"])
    checks["acceptance_target"] = {
        "ok": checks["system_version"].get("stdout", "").strip() == "27.0.1"
        and checks["system_build"].get("stdout", "").strip() == "26A434"
        and platform.machine() == "arm64",
        "expected_version": "27.0.1",
        "expected_build": "26A434",
        "expected_architecture": "arm64",
    }
    binary = Path(openvpn).expanduser().resolve()
    version = command([str(binary), "--version"])
    version["ok"] = version["ok"] and bool(
        re.match(r"OpenVPN 2\.6\.\d+\b", version.get("stdout", ""))
    )
    version["path"] = str(binary)
    checks["openvpn_2_6"] = version
    checks["binary_architecture"] = command(["/usr/bin/lipo", "-archs", str(binary)])
    checks["binary_architecture"]["ok"] &= "arm64" in checks[
        "binary_architecture"
    ].get("stdout", "").split()
    checks["dynamic_libraries"] = command(["/usr/bin/otool", "-L", str(binary)])
    if version["ok"]:
        try:
            report["openvpn_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        except OSError as error:
            checks["binary_digest"] = {"ok": False, "error": str(error)}
    checks["administrator"] = {"ok": os.geteuid() == 0}
    # 快照只在标准输出返回，由调用者决定是否保存；不写系统文件。
    for name, args in (
        ("interfaces", ["/sbin/ifconfig", "-a"]),
        ("routes", ["/usr/sbin/netstat", "-rn", "-f", "inet"]),
        ("resolver", ["/usr/sbin/scutil", "--dns"]),
    ):
        checks[name] = command(args)
    if os.geteuid() == 0:
        checks["firewall_info"] = command(["/sbin/pfctl", "-s", "info"])
        checks["firewall_rules"] = command(["/sbin/pfctl", "-sr"])
    else:
        checks["firewall_info"] = {"ok": False, "error": "需要管理员权限读取防火墙状态"}
        checks["firewall_rules"] = {"ok": False, "error": "需要管理员权限读取防火墙规则"}
    report["status"] = (
        "passed" if all(check["ok"] for check in checks.values()) else "blocked"
    )
    return report


def main():
    parser = argparse.ArgumentParser(description="苹果原生只读预检；不代表隧道验收通过")
    parser.add_argument("--case", choices=["preflight"], default="preflight")
    parser.add_argument("--openvpn", required=True, help="固定版本外部程序的绝对路径")
    args = parser.parse_args()
    if not Path(args.openvpn).is_absolute():
        parser.error("外部程序必须使用绝对路径")
    report = preflight(args.openvpn)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if report["status"] != "passed":
        print("原生预检未通过，请检查报告中的失败项。", file=sys.stderr)
        return 2
    print("只读预检通过，真实隧道与故障隔离仍需另行验证。", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
