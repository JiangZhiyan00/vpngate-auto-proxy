"""三个相同内部地址的受控隧道；保留活动连接并核对远端身份。"""
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time
import uuid

from macos_tunnel import REPO, LABEL, TARGET, baseline, client_config, error_diagnostics, interfaces, run
from validate_macos import preflight


class Tunnel:
    def __init__(self, options, folder, runtime, index, endpoint, existing, instance=None, control_handle=None, management_path=None):
        management = []
        if management_path is not None:
            path = Path(management_path)
            metadata = runtime.stat()
            if (not path.is_absolute() or path.parent.resolve() != runtime.resolve()
                    or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077):
                raise RuntimeError("管理通道必须位于本次私有运行目录")
            management = ["--management", str(path), "unix", "--management-client", "--management-hold"]
        self.closed = False
        self.control_handle = control_handle
        self.interface = control_handle.name if control_handle else None
        self.index = None
        self.address = None
        self.route_added = False
        self.existing = existing
        label = index if instance is None else instance
        self.configuration = runtime / f"client-{label}.conf"
        self.log = runtime / f"openvpn-{label}.log"
        self.configuration.write_text(client_config(folder / str(index), getattr(options, "transport", "tcp")))
        self.configuration.chmod(0o600)
        try:
            with self.log.open("w") as log:
                self.process = subprocess.Popen(
                    [options.openvpn, "--config", str(self.configuration), "--dev", "tun",
                     "--dev-node", f"utun-fd:{control_handle.fileno()}" if control_handle else "utun", "--remote", "127.0.0.1", str(endpoint["port"])] + management,
                    stdout=log, stderr=log, cwd=runtime, start_new_session=True,
                    pass_fds=(control_handle.fileno(),) if control_handle else (),
                )
        except BaseException:
            self.configuration.unlink(missing_ok=True)
            raise

    def ready(self):
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            content = self.log.read_text()
            match = re.search(r"Opened utun device (utun\d+)", content)
            if match:
                self.interface = match[1]
                if self.interface in self.existing:
                    raise RuntimeError("拒绝使用预先存在或其他受控工作进程的接口")
            if "Initialization Sequence Completed" in content and self.interface:
                info = run(["/sbin/ifconfig", "-v", self.interface]).stdout
                index = re.search(r"\bindex (\d+)\b", info)
                address = re.search(r"\binet (10\.231\.66\.\d+)\b", info)
                if not index or not address:
                    raise RuntimeError("受控隧道接口索引或地址缺失")
                self.index, self.address = index[1], address[1]
                if self.control_handle and (self.interface != self.control_handle.name
                        or int(self.index) != self.control_handle.index):
                    raise RuntimeError("借用隧道与监督句柄身份不符")
                run(["/sbin/route", "-n", "add", "-host", "-ifscope", self.interface,
                     TARGET, "-interface", self.interface])
                self.route_added = True
                return
            if self.process.poll() is not None:
                raise RuntimeError("受控隧道提前退出：" + "; ".join(error_diagnostics(self.log)))
            time.sleep(0.1)
        raise RuntimeError("受控隧道三十五秒内未就绪")

    def close(self):
        if self.closed:
            return
        errors = []
        try:
            if (self.route_added and getattr(self, "control_handle_transferred", False)
                    and self.process.poll() is not None and self.interface not in interfaces()):
                from macos_abrupt import reconcile_removed_route
                reconcile_removed_route(self)
            if self.route_added:
                result = run(["/sbin/route", "-n", "delete", "-host", "-ifscope", self.interface,
                              TARGET, "-interface", self.interface], check=False)
                if result.returncode:
                    errors.append("受控作用域路由删除失败")
                else:
                    self.route_added = False
        except Exception as error:
            errors.append(str(error))
        try:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=3)
        except Exception as error:
            errors.append(str(error))
        handle = getattr(self, "control_handle", None)
        if handle is not None:
            if self.process.poll() is None:
                errors.append("隧道进程未回收，拒绝释放控制句柄")
            else:
                try:
                    handle.close()
                except Exception as error:
                    errors.append(str(error))
        self.configuration.unlink(missing_ok=True)
        if self.interface:
            try:
                deadline = time.monotonic() + 3
                while self.interface in interfaces() and time.monotonic() < deadline:
                    time.sleep(0.05)
                if self.interface in interfaces():
                    errors.append("受控子进程退出后隧道接口仍存在")
            except Exception as error:
                errors.append(str(error))
        if errors:
            raise RuntimeError("；".join(errors))
        self.closed = True


def cleanup_after_workers(nodes, workers, activity_reaped, errors):
    for worker in reversed(workers):
        try:
            worker.close()
        except Exception as error:
            errors.append(str(error))
    workers_reaped = all(worker.process.poll() is not None for worker in workers)
    if not workers_reaped or not activity_reaped:
        errors.append("业务工作进程未回收，拒绝释放接口；请检查专属日志")
        return workers_reaped
    for node in reversed(nodes):
        try:
            node.close()
        except Exception as error:
            errors.append(str(error))
    return workers_reaped


def native_parallel(options):
    require_dns = options.case == "dns"
    report = {"case": options.case, "status": "failed", "native_tunnel_validated": False,
              "parallel_tunnels_validated": False, "full_macos_backend_validated": False,
              "transport": options.transport, "checks": {}}
    if require_dns:
        report["tunnel_dns_validated"] = False
    if options.case == "fault":
        report["tunnel_fault_validated"] = False
    if options.case == "retained":
        report["retained_echo_blocking_validated"] = False
    if options.case in ("pinned", "custody", "handoff", "supervision"):
        report.update(index_reuse_isolation_validated=False)
        report["supervision_channel_fault_validated" if options.case == "supervision" else "real_custody_handoff_validated" if options.case == "handoff" else "business_custody_fault_validated" if options.case == "custody" else "pinned_tunnel_fault_validated"] = False
    if options.case == "abrupt":
        report.update(abrupt_retained_characterized=False, index_reuse_isolation_validated=False)
    if options.case == "generation":
        report.update(controlled_generation_retirement_validated=False, index_reuse_isolation_validated=False)
    if options.case == "reuse":
        report.update(interface_index_reuse_characterized=False, index_reuse_isolation_validated=False)
    check = preflight(options.openvpn)
    if check["status"] != "passed":
        report.update(status="blocked", preflight=check)
        return report
    if options.case in ("pinned", "custody", "handoff", "supervision"):
        from macos_pinned import validate_dependency
        report["experimental_dependency"] = validate_dependency(options.openvpn)
    folder = Path(options.bundle).resolve()
    endpoints = json.loads((folder / "endpoints.json").read_text())
    if len(endpoints) != 3 or any(
        type(e.get("port")) is not int or not 1 <= e["port"] <= 65535
        or e.get("transport", "tcp") != options.transport
        or not re.fullmatch(r"[0-9a-f]{32}", e.get("identity", "")) for e in endpoints
    ):
        raise RuntimeError("三个受控端点参数不符合要求")
    if len({e["identity"] for e in endpoints}) != 3:
        raise RuntimeError("受控远端标记必须不同")
    uid, gid = int(os.environ.get("SUDO_UID", "0")), int(os.environ.get("SUDO_GID", "0"))
    if uid == 0:
        raise RuntimeError("请从普通用户启动包装脚本，业务探针必须降权")
    before = baseline()
    if any("10.231.66." in a for values in before["interfaces"].values() for a in values) or any(
        route[0].startswith("10.231.66") for route in before["routes"]
    ):
        raise RuntimeError("受控地址与宿主现有资源冲突")
    runtime = Path(tempfile.mkdtemp(prefix="vap-parallel-", dir="/private/tmp"))
    report["diagnostic_directory"] = str(runtime)
    nodes, probe = [], None
    workers = []
    cleanup_errors, phases = [], []
    started = time.monotonic()
    probe_log, probe_error = runtime / "activity.jsonl", runtime / "activity-error.log"

    def probe_args(node, index, rounds=1):
        return [options.probe, node.index, TARGET, "19090", secrets.token_hex(24),
                endpoints[index]["identity"], str(rounds)]

    def records():
        if not probe_log.exists():
            return []
        content = probe_log.read_text()
        # 最后一条正在写入的记录不计入已完成往返。
        return [json.loads(line) for line in content.splitlines(keepends=True) if line.endswith("\n")]

    dns_phases = []

    def check_dns(node, index, stage):
        if not require_dns:
            return
        result = run([options.dns_probe, node.index, TARGET, "53", endpoints[index]["identity"]],
                     timeout=8, cwd=REPO, user=uid, group=gid, extra_groups=[])
        value = json.loads(result.stdout)
        if not (value.get("dns_udp") is True and value.get("dns_tcp_fallback") is True
                and value.get("identity") == endpoints[index]["identity"]
                and value.get("interface_index") == int(node.index)
                and value.get("resolved_ipv4") == TARGET):
            raise RuntimeError("固定接口解析归属或响应不符合预期")
        dns_phases.append({"stage": stage, **value})

    def wait_activity(stage):
        previous = len(records())
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            values = records()
            if probe.poll() is not None:
                raise RuntimeError("活动长连接提前退出：" + probe_error.read_text()[-1500:])
            if len(values) >= previous + 2:
                if not all(v.get("tcp") and v.get("udp") and v.get("identity") == endpoints[0]["identity"]
                           and v.get("interface_index") == int(nodes[0].index) for v in values):
                    raise RuntimeError("活动连接的接口或远端归属发生变化")
                phases.append({"stage": stage, "completed_rounds": len(values)})
                check_dns(nodes[0], 0, stage)
                return
            time.sleep(0.05)
        raise RuntimeError("活动长连接未在规定时间内继续完成往返")

    try:
        for index, endpoint in enumerate(endpoints):
            existing = set(before["interfaces"]) | {n.interface for n in nodes if n.interface}
            factory = Tunnel
            if options.case in ("pinned", "custody", "handoff", "supervision"):
                from macos_pinned import PinnedTunnel
                factory = PinnedTunnel
            node = factory(options, folder, runtime, index, endpoint, existing)
            nodes.append(node)
            node.ready()
            check_dns(node, index, f"隧道 {index} 建立后解析")
            if index == 0:
                with probe_log.open("w") as out, probe_error.open("w") as err:
                    probe = subprocess.Popen(probe_args(node, index, 600), stdout=out, stderr=err,
                                             cwd=REPO, user=uid, group=gid, extra_groups=[])
                wait_activity("活动隧道建立")
            else:
                result = run(probe_args(node, index), timeout=8, cwd=REPO, user=uid, group=gid, extra_groups=[])
                value = json.loads(result.stdout)
                if not value.get("tcp") or not value.get("udp") or value.get("identity") != endpoint["identity"]:
                    raise RuntimeError("候选回显的远端标记不匹配")
                wait_activity(f"候选 {index} 建立并验证")
        report["checks"].update(
            distinct_interfaces=len({n.interface for n in nodes}) == 3,
            distinct_indices=len({n.index for n in nodes}) == 3,
            identical_internal_addresses=len({n.address for n in nodes}) == 1,
            candidate_exit_identity=True,
            probe_unprivileged=True,
        )
        if not all(report["checks"].values()):
            raise RuntimeError("三个接口未同时具备预期的独立身份或相同内部地址")
        report["interfaces"] = [{"name": n.interface, "index": int(n.index), "address": n.address} for n in nodes]
        if options.case == "fault":
            from macos_fault import exercise_fault
            report["fault"] = {}
            exercise_fault(options, nodes, probe, runtime, endpoints, uid, gid, report["fault"])
            report["checks"]["fault_experiment_passed"] = True
        if options.case == "retained":
            from macos_retained import exercise_retained
            report["retained"] = {}
            exercise_retained(options, nodes, probe, runtime, endpoints, uid, gid, report["retained"])
            report["checks"]["retained_echo_experiment_passed"] = True
        if options.case == "reuse":
            from macos_reuse import exercise_reuse
            report["reuse"] = {}
            exercise_reuse(options, folder, nodes, probe, runtime, endpoints, uid, gid, report["reuse"])
            report["checks"]["index_reuse_characterization_passed"] = True
        if options.case == "generation":
            from macos_generation import exercise_generation
            report["generation"] = {}
            exercise_generation(options, folder, nodes, probe, runtime, endpoints, uid, gid, report["generation"], workers)
            report["checks"]["controlled_generation_experiment_passed"] = True
        if options.case == "abrupt":
            from macos_abrupt import exercise_abrupt
            report["abrupt"] = {}
            exercise_abrupt(options, folder, nodes, probe, runtime, endpoints, uid, gid, report["abrupt"], workers)
            report["checks"]["abrupt_characterization_complete"] = True
        if options.case == "supervision":
            from macos_supervision import exercise_supervision
            report["supervision"] = {}
            exercise_supervision(options, folder, nodes, runtime, endpoints, uid, gid, report["supervision"], workers)
            report["checks"]["supervision_channel_fault_experiment_passed"] = True
        if options.case == "handoff":
            from macos_handoff import exercise_handoff
            report["handoff"] = {}
            exercise_handoff(options, nodes, runtime, endpoints, uid, gid, report["handoff"], workers)
            report["checks"]["real_custody_handoff_experiment_passed"] = True
        if options.case in ("pinned", "custody"):
            from macos_pinned import exercise_pinned
            stage = "custody" if options.case == "custody" else "pinned"
            report[stage] = {}
            exercise_pinned(options, folder, nodes, probe, runtime, endpoints, uid, gid, report[stage], workers,
                            custody=options.case == "custody")
            report["checks"][stage + "_fault_experiment_passed"] = True
        for index in (() if options.case in ("reuse", "generation", "abrupt", "pinned", "custody", "handoff") else (2, 1)):
            nodes[index].close()
            if nodes[index].interface in interfaces():
                raise RuntimeError("已停止候选的接口仍存在")
            if options.case not in ("fault", "retained"):
                wait_activity(f"候选 {index} 销毁")
        report["checks"]["active_connection_survived_before_fault" if options.case in ("fault", "retained", "reuse", "generation", "abrupt", "pinned", "custody")
                         else "active_connection_survived"] = True
        if require_dns:
            report["checks"]["dns_isolated_across_lifecycle"] = len(dns_phases) == 8
        report["active_rounds"] = len(records())
        report["activity_phases"] = phases
        if require_dns:
            report["dns_phases"] = dns_phases
    except BaseException as error:
        report["error"] = str(error) or type(error).__name__
    finally:
        cleanup_started = time.monotonic()
        try:
            if probe is not None and probe.poll() is None:
                probe.terminate()
                try:
                    probe.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    probe.kill()
                    probe.wait(timeout=2)
        except Exception as error:
            cleanup_errors.append(str(error))
        workers_reaped = cleanup_after_workers(
            nodes, workers, probe is None or probe.poll() is not None, cleanup_errors)
        report["supervision_process_exit_codes" if options.case == "supervision" else "custody_process_exit_codes" if options.case == "custody" else "retained_probe_exit_codes" if options.case in ("abrupt", "pinned") else "generation_worker_exit_codes"] = [worker.process.poll() for worker in workers] if workers else []
        try:
            after = baseline()
            report["checks"]["baseline_restored"] = before == after
            report["checks"]["no_new_interfaces_left"] = not (after["interfaces"].keys() - before["interfaces"].keys())
        except Exception as error:
            cleanup_errors.append(str(error))
            report["checks"]["baseline_restored"] = False
        report["checks"]["processes_reaped"] = workers_reaped and all(n.process.poll() is not None for n in nodes) and (probe is None or probe.poll() is not None)
        report["cleanup_seconds"] = round(time.monotonic() - cleanup_started, 3)
        report["checks"]["cleanup_within_15_seconds"] = report["cleanup_seconds"] < 15
        report["cleanup_errors"] = cleanup_errors
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        report["openvpn_exit_codes"] = [n.process.poll() for n in nodes]
        report["activity_phases"] = phases
        if report.get("error"):
            report["openvpn_errors"] = [error_diagnostics(n.log) for n in nodes]
    expected_nodes = 4 if options.case in ("reuse", "generation", "abrupt", "pinned", "custody", "supervision") else 3
    if not report.get("error") and not cleanup_errors and all(report["checks"].values()) and len(nodes) == expected_nodes:
        report.update(status="passed", native_tunnel_validated=True, parallel_tunnels_validated=True)
        if require_dns:
            report["tunnel_dns_validated"] = True
        if options.case == "fault":
            report["tunnel_fault_validated"] = True
        if options.case == "retained":
            report["retained_echo_blocking_validated"] = True
        if options.case == "reuse":
            report["interface_index_reuse_characterized"] = True
        if options.case == "generation":
            report["controlled_generation_retirement_validated"] = True
        if options.case == "abrupt":
            report["abrupt_retained_characterized"] = True
        if options.case in ("pinned", "custody", "handoff", "supervision"):
            report["supervision_channel_fault_validated" if options.case == "supervision" else "real_custody_handoff_validated" if options.case == "handoff" else "business_custody_fault_validated" if options.case == "custody" else "pinned_tunnel_fault_validated"] = True
    return report


def orchestrate_parallel(options):
    if os.geteuid() == 0:
        raise RuntimeError("请以普通用户运行包装脚本")
    if options.case in ("pinned", "custody", "handoff", "supervision"):
        from macos_pinned import validate_dependency
        validate_dependency(options.openvpn)
    token = uuid.uuid4().hex
    name = "vap-parallel-" + token[:12]
    network = name + "-network"
    folder = Path(tempfile.mkdtemp(prefix="macos-parallel-", dir=REPO / "validation-output"))
    folder.chmod(0o700)
    report = {"case": options.case + "-fixture" if options.fixture_only else options.case, "status": "failed",
              "native_tunnel_validated": False, "parallel_tunnels_validated": False, "full_macos_backend_validated": False, "transport": options.transport}
    planned = [("container", f"{name}-client-{i}") for i in range(3)]
    planned += [("container", f"{name}-{i}") for i in range(3)] + [("network", network)]

    def docker(*args, **kwargs):
        return run(["docker", *args], timeout=60, **kwargs)

    try:
        docker("network", "create", "--label", f"{LABEL}={token}", network)
        endpoints = []
        for index in range(3):
            identity = uuid.uuid4().hex
            node_name = f"{name}-{index}"
            target = folder / str(index)
            target.mkdir(mode=0o700)
            docker("run", "-d", "--name", node_name, "--label", f"{LABEL}={token}", "--network", network,
                   "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun", "--read-only",
                   "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,nosuid,nodev,mode=1777",
                   "--tmpfs", "/run:rw,nosuid,nodev", "-p", f"127.0.0.1::1194/{options.transport}", "-e", f"VAP_FIXTURE_TRANSPORT={options.transport}", "-e", f"VAP_FIXTURE_ID={identity}",
                   "-v", f"{REPO / 'tests/fixtures'}:/fixture:ro", options.fixture_image,
                   "/bin/sh", "/fixture/macos-server.sh")
            deadline = time.monotonic() + 35
            while time.monotonic() < deadline:
                logs = docker("logs", node_name)
                if "Initialization Sequence Completed" in logs.stdout + logs.stderr:
                    break
                if docker("inspect", "--format", "{{.State.Running}}", node_name).stdout.strip() != "true":
                    raise RuntimeError("受控远端提前退出：" + (logs.stdout + logs.stderr)[-1500:])
                time.sleep(0.2)
            else:
                raise RuntimeError("受控远端未在三十五秒内就绪")
            for filename in ("ca.crt", "client.crt", "client.key"):
                (target / filename).write_text(docker("exec", node_name, "cat", "/tmp/vap-native/" + filename).stdout)
                (target / filename).chmod(0o600)
            ports = json.loads(docker("inspect", node_name).stdout)[0]["NetworkSettings"]["Ports"][f"1194/{options.transport}"]
            if len(ports) != 1 or ports[0]["HostIp"] != "127.0.0.1":
                raise RuntimeError("受控端口必须仅发布到本机回环")
            endpoints.append({"identity": identity, "port": int(ports[0]["HostPort"]), "transport": options.transport})
            if options.fixture_only:
                (target / "client.conf").write_text(client_config(target, options.transport))
                smoke = ('openvpn --config /bundle/client.conf --dev tun --remote "$1" 1194 > /tmp/client.log 2>&1 &\n'
                         'pid=$!\ntrap \'kill "$pid" 2>/dev/null || true\' EXIT\npython3 /fixture/macos_fixture_smoke.py\n')
                client = f"{name}-client-{index}"
                docker("create", "--name", client, "--label", f"{LABEL}={token}", "--network", network,
                       "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun", "--read-only",
                       "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,nosuid,nodev,mode=1777",
                       "-e", f"VAP_FIXTURE_ID={identity}", "-v", f"{target}:/bundle:ro",
                       "-v", f"{REPO / 'tests/fixtures'}:/fixture:ro", options.fixture_image,
                       "/bin/sh", "-c", smoke, "smoke", node_name)
                docker("start", "-a", client)
                if docker("inspect", "--format", "{{.State.ExitCode}}", client).stdout.strip() != "0":
                    raise RuntimeError("受控远端的隔离客户端身份回显失败")
        (folder / "endpoints.json").write_text(json.dumps(endpoints))
        if options.fixture_only:
            report.update(status="passed", fixture_count=3, fixture_validated=True)
            if options.case == "dns":
                report["fixture_dns_validated"] = True
        else:
            print("三个受控远端已就绪；即将在本机终端启动多隧道原生实验。", file=sys.stderr, flush=True)
            result = subprocess.run(
                ["sudo", "/usr/bin/python3", str(REPO / "scripts/macos_tunnel.py"), "--case", options.case, "--native",
                 "--bundle", str(folder), "--transport", options.transport, "--openvpn", options.openvpn, "--probe", options.probe,
                 "--dns-probe", options.dns_probe, "--guard-probe", options.guard_probe,
                 "--generation-worker", options.generation_worker],
                cwd=REPO, stdout=subprocess.PIPE, text=True,
            )
            report = json.loads(result.stdout)
    except BaseException as error:
        report.update(status="failed", error=str(error) or type(error).__name__)
    finally:
        errors = []
        for kind, identifier in planned:
            try:
                result = docker(kind, "inspect", identifier, check=False)
                if result.returncode:
                    if "no such" in result.stderr.lower():
                        continue
                    raise RuntimeError("无法核对受控资源归属")
                record = json.loads(result.stdout)[0]
                labels = record.get("Config", {}).get("Labels", {}) if kind == "container" else record.get("Labels", {})
                if labels.get(LABEL) != token:
                    raise RuntimeError("受控资源归属不符，拒绝删除")
                docker(kind, "rm", *(["-f"] if kind == "container" else []), record["Id"])
            except Exception as error:
                errors.append(str(error))
        for index in range(3):
            for filename in ("ca.crt", "client.crt", "client.key", "client.conf"):
                (folder / str(index) / filename).unlink(missing_ok=True)
        report["fixture_cleanup_errors"] = errors
        if errors:
            report["status"] = "failed"
        destination = folder / "report.json"
        destination.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        destination.chmod(0o600)
        print(f"验证报告：{destination}", file=sys.stderr)
    return report
