"""短时受控原生隧道实验；仅管理本次进程、接口作用域路由与容器。"""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import tempfile
import time
import uuid

from validate_macos import preflight

REPO = Path(__file__).resolve().parents[1]
LABEL = "io.vpngate-auto-proxy.macos-tunnel"
TARGET = "10.231.66.1"


def run(args, timeout=15, check=True, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, **kwargs)
    if check and result.returncode:
        raise RuntimeError(f"受控命令失败（{Path(str(args[0])).name}）：{result.stderr[-1000:]}")
    return result


def text(args):
    return run(args).stdout


def interfaces():
    content = text(["/sbin/ifconfig", "-a"])
    result = {}
    current = None
    for line in content.splitlines():
        if line and not line[0].isspace():
            current = line.split(":", 1)[0]
            result[current] = []
        elif current and line.strip().startswith("inet "):
            result[current].append(line.strip())
    return result


def baseline():
    routes = []
    for line in text(["/usr/sbin/netstat", "-rn", "-f", "inet"]).splitlines():
        words = line.split()
        # 邻居缓存和派生主机路由会随宿主正常使用变化，不纳入静态路由基线。
        if len(words) >= 4 and words[0] not in ("Destination",) and words[2].startswith("U"):
            if "W" not in words[2] and "L" not in words[2]:
                routes.append(words[:4])
    return {
        "interfaces": interfaces(),
        "routes": sorted(routes),
        "resolver": text(["/usr/sbin/scutil", "--dns"]),
        "firewall_rules": text(["/sbin/pfctl", "-sr"]),
    }


def client_config(directory, transport="tcp"):
    if transport not in ("tcp", "udp"):
        raise ValueError("受控隧道承载只能为流式或数据报协议")
    protocol = "tcp-client" if transport == "tcp" else "udp4"
    result = (
        f"client\nproto {protocol}\nnobind\nremote-cert-tls server\nverify-x509-name server name\n"
        "tls-version-min 1.2\ndata-ciphers AES-256-GCM:AES-128-GCM\n"
        "allow-compression no\nscript-security 1\nroute-nopull\nroute-noexec\nverb 3\n"
    )
    for block, filename, kind in (
        ("ca", "ca.crt", "CERTIFICATE"),
        ("cert", "client.crt", "CERTIFICATE"),
        ("key", "client.key", "PRIVATE KEY"),
    ):
        pem = (directory / filename).read_text()
        pattern = rf"-----BEGIN {kind}-----\n[A-Za-z0-9+/=\n]+\n-----END {kind}-----\n?"
        if len(pem) > 32768 or not re.fullmatch(pattern, pem):
            raise RuntimeError("受控证书材料格式无效")
        result += f"<{block}>\n{pem.strip()}\n</{block}>\n"
    return result


def error_diagnostics(path):
    """只返回有界错误行，原始专属日志仍保留在管理员目录。"""
    try:
        content = path.read_text(errors="replace")
        content = re.sub(r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", "[证书材料已省略]", content, flags=re.S)
        content = re.sub(r"<(key|cert|ca)>.*?</\1>", "[证书材料已省略]", content, flags=re.S)
        lines = content.splitlines()
    except OSError:
        return []
    return [line[:512] for line in lines if any(
        word in line.lower() for word in ("error", "failed", "cannot", "exiting")
    )][-8:]


def native(options):
    report = {"case": "tunnel", "status": "failed", "native_tunnel_validated": False,
              "full_macos_backend_validated": False, "transport": options.transport, "checks": {}}
    check = preflight(options.openvpn)
    if check["status"] != "passed":
        report.update(status="blocked", preflight=check)
        return report
    bundle = Path(options.bundle).resolve()
    endpoint = json.loads((bundle / "endpoint.json").read_text())
    port = endpoint["port"]
    if endpoint.get("transport", "tcp") != options.transport:
        raise RuntimeError("受控远端承载与本次请求不符")
    if type(port) is not int or not 1 <= port <= 65535:
        raise RuntimeError("受控端口无效")
    uid, gid = int(os.environ.get("SUDO_UID", "0")), int(os.environ.get("SUDO_GID", "0"))
    if uid == 0:
        raise RuntimeError("请从普通用户通过包装脚本启动，探针必须降权运行")
    before = baseline()
    if any("10.231.66." in address for values in before["interfaces"].values() for address in values):
        raise RuntimeError("受控实验地址与宿主已有接口冲突")
    if any(route[0].startswith("10.231.66") for route in before["routes"]):
        raise RuntimeError("受控实验地址与宿主已有精确路由冲突")
    runtime = Path(tempfile.mkdtemp(prefix="vap-native-", dir="/private/tmp"))
    report["diagnostic_directory"] = str(runtime)
    configuration = runtime / "client.conf"
    configuration.write_text(client_config(bundle, options.transport))
    configuration.chmod(0o600)
    process, interface, route_added = None, None, False
    started = time.monotonic()
    cleanup_errors = []
    try:
        with (runtime / "openvpn.log").open("w") as log:
            process = subprocess.Popen(
                [options.openvpn, "--config", str(configuration), "--dev", "tun", "--dev-node", "utun",
                 "--remote", "127.0.0.1", str(port)], stdout=log, stderr=log,
                cwd=runtime, start_new_session=True,
            )
            deadline = time.monotonic() + 35
            while time.monotonic() < deadline:
                content = (runtime / "openvpn.log").read_text()
                found = re.search(r"Opened utun device (utun\d+)", content)
                if found:
                    interface = found[1]
                    if interface in before["interfaces"]:
                        raise RuntimeError("拒绝使用宿主预先存在的隧道接口")
                if "Initialization Sequence Completed" in content and interface:
                    break
                if process.poll() is not None:
                    raise RuntimeError("受控原生隧道提前退出，请检查专属日志")
                time.sleep(0.1)
            else:
                raise RuntimeError("受控原生隧道三十五秒内未就绪")
            info = text(["/sbin/ifconfig", "-v", interface])
            match = re.search(r"\bindex (\d+)\b", info)
            if not match or not re.search(r"\binet 10\.231\.66\.\d+\b", info):
                raise RuntimeError("新隧道的索引或受控地址不符合预期")
            # 新接口作用域内只添加测试服务器主机路由，不修改默认或其他作用域路由。
            run(["/sbin/route", "-n", "add", "-host", "-ifscope", interface,
                 TARGET, "-interface", interface])
            route_added = True
            marker = secrets.token_hex(24)
            probe = run([options.probe, match[1], TARGET, "19090", marker], timeout=8,
                        cwd=REPO, user=uid, group=gid, extra_groups=[])
            value = json.loads(probe.stdout)
            if value.get("tcp") is not True or value.get("udp") is not True:
                raise RuntimeError("固定接口探针没有完成双向回显")
            report["checks"]["native_echo"] = value
            report["checks"]["new_interface"] = interface
            report["checks"]["probe_unprivileged"] = uid != 0
    except BaseException as error:
        report["error"] = str(error) or type(error).__name__
    finally:
        cleanup_started = time.monotonic()
        # 任一路由检查失败也必须继续回收本次直接创建的子进程。
        try:
            if route_added:
                result = run(["/sbin/route", "-n", "delete", "-host", "-ifscope", interface,
                              TARGET, "-interface", interface], check=False)
                if result.returncode:
                    cleanup_errors.append("本实例作用域路由删除失败")
        except Exception as error:
            cleanup_errors.append(str(error))
        try:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
        except Exception as error:
            cleanup_errors.append(str(error))
        try:
            deadline = time.monotonic() + 5
            while interface and interface in interfaces() and time.monotonic() < deadline:
                time.sleep(0.1)
            after = baseline()
            report["checks"]["interface_created"] = interface is not None
            report["checks"]["interface_removed"] = interface not in after["interfaces"] if interface else None
            report["checks"]["no_new_interfaces_left"] = not (after["interfaces"].keys() - before["interfaces"].keys())
            report["checks"]["baseline_restored"] = before == after
        except Exception as error:
            cleanup_errors.append(str(error))
            report["checks"]["baseline_restored"] = False
        report["checks"]["process_reaped"] = process is not None and process.poll() is not None
        report["cleanup_seconds"] = round(time.monotonic() - cleanup_started, 3)
        report["checks"]["cleanup_within_15_seconds"] = report["cleanup_seconds"] < 15
        report["cleanup_errors"] = cleanup_errors
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        report["openvpn_exit_code"] = process.poll() if process is not None else None
        if report.get("error"):
            report["openvpn_errors"] = error_diagnostics(runtime / "openvpn.log")
        # 删除含私钥的配置；仅保留专属诊断日志。
        configuration.unlink(missing_ok=True)
    good = report["checks"]
    if not report.get("error") and not cleanup_errors and all(
        good.get(key) for key in ("native_echo", "interface_removed", "baseline_restored", "process_reaped", "cleanup_within_15_seconds")
    ):
        report.update(status="passed", native_tunnel_validated=True)
    return report


def orchestrate(options):
    if os.geteuid() == 0:
        raise RuntimeError("请以普通用户运行包装脚本，管理员子阶段由脚本单独启动")
    token = uuid.uuid4().hex
    name = "vap-macos-" + token[:12]
    network = name + "-network"
    folder = Path(tempfile.mkdtemp(prefix="macos-tunnel-", dir=REPO / "validation-output"))
    folder.chmod(0o700)
    report = {"case": "fixture" if options.fixture_only else "tunnel", "status": "failed",
              "native_tunnel_validated": False, "full_macos_backend_validated": False, "transport": options.transport}

    def docker(*args, **kwargs):
        return run(["docker", *args], timeout=60, **kwargs)

    def remove(kind, identifier):
        result = docker(kind, "inspect", identifier, check=False)
        if result.returncode:
            if "no such" in result.stderr.lower():
                return
            raise RuntimeError("无法检查本次受控资源的归属")
        record = json.loads(result.stdout)[0]
        labels = record.get("Config", {}).get("Labels", {}) if kind == "container" else record.get("Labels", {})
        if labels.get(LABEL) != token:
            raise RuntimeError("受控容器资源归属不符，拒绝删除")
        docker(kind, "rm", *(["-f"] if kind == "container" else []), record["Id"])

    try:
        identifier = docker("network", "create", "--label", f"{LABEL}={token}", network).stdout.strip()
        identifier = docker("run", "-d", "--name", name, "--label", f"{LABEL}={token}",
                            "--network", network, "--cap-drop", "ALL", "--cap-add", "NET_ADMIN",
                            "--device", "/dev/net/tun", "--read-only", "--security-opt", "no-new-privileges",
                            "--tmpfs", "/tmp:rw,nosuid,nodev,mode=1777", "--tmpfs", "/run:rw,nosuid,nodev",
                            "-p", f"127.0.0.1::1194/{options.transport}", "-e", f"VAP_FIXTURE_TRANSPORT={options.transport}", "-v", f"{REPO / 'tests/fixtures'}:/fixture:ro",
                            options.fixture_image, "/bin/sh", "/fixture/macos-server.sh").stdout.strip()
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            result = docker("logs", identifier)
            if "Initialization Sequence Completed" in result.stdout + result.stderr:
                break
            if docker("inspect", "--format", "{{.State.Running}}", identifier).stdout.strip() != "true":
                raise RuntimeError("受控远端提前退出：" + (result.stdout + result.stderr)[-1500:])
            time.sleep(0.2)
        else:
            raise RuntimeError("受控远端未在三十五秒内就绪")
        for filename in ("ca.crt", "client.crt", "client.key"):
            (folder / filename).write_text(docker("exec", identifier, "cat", "/tmp/vap-native/" + filename).stdout)
            (folder / filename).chmod(0o600)
        port_record = json.loads(docker("inspect", identifier).stdout)[0]["NetworkSettings"]["Ports"][f"1194/{options.transport}"]
        if len(port_record) != 1 or port_record[0]["HostIp"] != "127.0.0.1":
            raise RuntimeError("受控端口必须只发布到本机回环")
        (folder / "endpoint.json").write_text(json.dumps({"port": int(port_record[0]["HostPort"]), "transport": options.transport}))
        if options.fixture_only:
            # 在隔离客户端容器内验证证书、握手和两种回显；不冒充苹果原生证据。
            (folder / "client.conf").write_text(client_config(folder, options.transport))
            smoke = (
                'openvpn --config /bundle/client.conf --dev tun --remote "$1" 1194 > /tmp/client.log 2>&1 &\n'
                'pid=$!\ntrap \'kill "$pid" 2>/dev/null || true\' EXIT\n'
                'python3 /fixture/macos_fixture_smoke.py\n'
            )
            client = docker("create", "--name", name + "-client", "--label", f"{LABEL}={token}", "--network", network,
                            "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun",
                            "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,mode=1777",
                            "--security-opt", "no-new-privileges", "-v", f"{folder}:/bundle:ro",
                            "-v", f"{REPO / 'tests/fixtures'}:/fixture:ro", options.fixture_image,
                            "/bin/sh", "-c", smoke, "smoke", name).stdout.strip()
            docker("start", "-a", client)
            code = docker("inspect", "--format", "{{.State.ExitCode}}", client).stdout.strip()
            if code != "0":
                raise RuntimeError("隔离客户端回显验证失败")
            report.update(status="passed", fixture_validated=True)
        else:
            print("受控远端已就绪；即将在本机终端启动管理员原生实验。", file=sys.stderr, flush=True)
            result = subprocess.run(
                ["sudo", "/usr/bin/python3", str(Path(__file__).resolve()), "--native",
                 "--bundle", str(folder), "--transport", options.transport, "--openvpn", options.openvpn, "--probe", options.probe],
                cwd=REPO, stdout=subprocess.PIPE, text=True,
            )
            report = json.loads(result.stdout)
    except BaseException as error:
        report.update(status="failed", error=str(error) or type(error).__name__)
    finally:
        errors = []
        # 即使命令在创建成功与接收标识之间中断，也用固定名称和本次标签查验后回收。
        for kind, identifier in (("container", name + "-client"), ("container", name), ("network", network)):
            try:
                remove(kind, identifier)
            except Exception as error:
                errors.append(str(error))
        for filename in ("ca.crt", "client.crt", "client.key", "client.conf"):
            (folder / filename).unlink(missing_ok=True)
        report["fixture_cleanup_errors"] = errors
        if errors:
            report["status"] = "failed"
        (folder / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        (folder / "report.json").chmod(0o600)
        print(f"验证报告：{folder / 'report.json'}", file=sys.stderr)
    return report


def main():
    parser = argparse.ArgumentParser(description="短时原生隧道与回收实验；不进行三十分钟测试")
    parser.add_argument("--case", choices=["tunnel", "parallel", "dns", "fault", "retained", "reuse", "generation", "abrupt", "pinned", "custody", "handoff", "supervision"], default="tunnel")
    parser.add_argument("--transport", choices=["tcp", "udp"], default="tcp", help="受控隧道承载；与隧道内业务协议分开记录")
    parser.add_argument("--openvpn", default=str(REPO / "validation-output/macos-deps/openvpn-2.6.23-local/sbin/openvpn"))
    parser.add_argument("--probe", default=str(REPO / "target/debug/examples/macos_tunnel_probe"))
    parser.add_argument("--dns-probe", default=str(REPO / "target/debug/examples/macos_dns_probe"))
    parser.add_argument("--generation-worker", default=str(REPO / "target/debug/examples/macos_generation_worker"))
    parser.add_argument("--guard-probe", default=str(REPO / "target/debug/examples/macos_guard_probe"))
    parser.add_argument("--fixture-image", default="vpngate-auto-proxy-fixture:local")
    parser.add_argument("--fixture-only", action="store_true")
    parser.add_argument("--native", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--bundle", help=argparse.SUPPRESS)
    options = parser.parse_args()
    if options.case in ("pinned", "custody", "handoff", "supervision") and options.openvpn == str(REPO / "validation-output/macos-deps/openvpn-2.6.23-local/sbin/openvpn"):
        options.openvpn = str(REPO / "validation-output/macos-deps/openvpn-2.6.23-lease-local/sbin/openvpn")
    for key in ("openvpn", "probe", "dns_probe", "guard_probe", "generation_worker"):
        if not Path(getattr(options, key)).is_absolute():
            parser.error("本机程序必须使用绝对路径")
    def interrupted(number, frame):
        raise KeyboardInterrupt("验证收到中断信号")
    signal.signal(signal.SIGTERM, interrupted)
    try:
        if options.case in ("parallel", "dns", "fault", "retained", "reuse", "generation", "abrupt", "pinned", "custody", "handoff", "supervision"):
            from macos_parallel import native_parallel, orchestrate_parallel
            report = native_parallel(options) if options.native else orchestrate_parallel(options)
        else:
            report = native(options) if options.native else orchestrate(options)
    except Exception as error:
        report = {"status": "failed", "native_tunnel_validated": False, "error": str(error)}
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["status"] == "passed" else 2


if __name__ == "__main__":
    sys.exit(main())
