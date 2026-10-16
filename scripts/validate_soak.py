"""五个隔离客户端的真实容量试验；短试只验证流程，不替代三十分钟验收。"""
import argparse
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import secrets
import shlex
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

from validate_docker import CAPS, LABEL, REPO, run
from docker_profiles import require_profiles


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def process_memory_command(proc_root="/proc"):
    # 仅跳过读取竞争期间已消失的进程；仍存在但不可读的状态文件必须失败。
    return """records=$(for file in ROOT/[0-9]*/status; do
  if sample=$(cat "$file" 2>/dev/null); then
    printf '%s\\n' "$sample"
  elif [ -e "$file" ]; then
    exit 1
  fi
done) || exit 1
printf '%s\\n' "$records" | awk '/^VmRSS:/ {r += $2} /^VmHWM:/ {p += $2} END {print r*1024, p*1024}'
""".replace("ROOT", shlex.quote(str(proc_root)))


def delete_owned_link(name, alias):
    # 删除网络空间可能异步移除其虚拟网卡对；用成功的全量查询确认缺失，不能吞掉查询错误。
    before = [link for link in json.loads(run("ip", "-j", "link", "show").stdout) if link.get("ifname") == name]
    if not before:
        return
    require(len(before) == 1 and before[0].get("ifalias") == alias, f"客户端接口归属变化：{name}")
    identity = before[0]["ifindex"]
    deleted = run("ip", "link", "del", name, check=False)
    after = json.loads(run("ip", "-j", "link", "show").stdout)
    remaining = [link for link in after if link.get("ifindex") == identity or link.get("ifname") == name]
    require(not remaining, f"客户端接口删除后仍存在或被替换：{name}；退出码 {deleted.returncode}；{deleted.stderr[-512:]}")


def collect(processes, timeout=5):
    result = {}
    with selectors.DefaultSelector() as selector:
        for index, process in enumerate(processes):
            selector.register(process.stdout, selectors.EVENT_READ, index)
        deadline = time.monotonic() + timeout
        while selector.get_map():
            ready = selector.select(max(0, deadline - time.monotonic()))
            require(ready, "隔离客户端未在截止时间内完成命令")
            for key, _ in ready:
                line = key.fileobj.readline()
                require(line, "隔离客户端意外退出")
                value = json.loads(line)
                require("error" not in value, "隔离客户端认证、建连或往返失败")
                result[key.data] = value
                selector.unregister(key.fileobj)
    return [result[index] for index in range(len(processes))]


def send(processes, command):
    for process in processes:
        process.stdin.write(json.dumps({"command": command}) + "\n")
        process.stdin.flush()
    return collect(processes)


class Environment:
    def __init__(self, options):
        self.options = options
        self.token = uuid.uuid4().hex[:10]
        self.containers, self.volumes, self.spaces, self.links, self.children = [], [], {}, {}, []
        self.network = None
        self.service = None
        self.fixture_ready = False
        self.files = Path(tempfile.mkdtemp(prefix="vap-soak-"))
        self.password = secrets.token_hex(16)
        self.credentials = {"username": "capacity", "password": self.password}
        self.config = {"listen": "11.51.0.1:1080", "credentials_file": str(self.files / "credentials.json"),
                       "runtime_dir": str(self.files / "run"), "data_dir": str(self.files / "data"),
                       "source_url": "http://127.0.0.1:18080/", "candidate_interval_seconds": 5,
                       "exit_check_urls": ["http://fixture.example/slow"], "health_interval_seconds": 10,
                       "health_timeout_seconds": 9, "max_connections": options.connections}
        self.started = time.monotonic()
        self.previous_cpu = None

    def baseline(self):
        routes = json.loads(run("ip", "-j", "-4", "route", "show", "table", "all").stdout)
        return {"routes": sorted(routes, key=lambda value: json.dumps(value, sort_keys=True)),
                "rules": run("nft", "--stateless", "list", "ruleset").stdout,
                "resolver": Path("/etc/resolv.conf").read_text(),
                "forwarding": Path("/proc/sys/net/ipv4/ip_forward").read_text()}

    def owned(self, kind, name):
        value = run("docker", kind, "inspect", name, check=False)
        if value.returncode:
            return False
        value = json.loads(value.stdout)[0]
        labels = value.get("Config", {}).get("Labels", {}) if kind == "container" else value.get("Labels", {})
        return labels.get(LABEL) == self.token

    def docker_start(self, name, args, image, command):
        self.containers.append(name)
        run("docker", "run", "-d", "--name", name, "--label", f"{LABEL}={self.token}",
            "--network", self.network, *args, image, *command)

    def prepare(self):
        self.files.joinpath("credentials.json").write_text(json.dumps(self.credentials))
        self.files.joinpath("credentials.json").chmod(0o600)
        if self.options.deployment == "native":
            require(sys.platform == "linux" and os.geteuid() == 0 and os.environ.get("VAP_NETWORK_TEST") == "1",
                    "原生容量验收需要显式授权的专用 Linux 管理员环境")
            # 降权后的控制进程需要穿过测试父目录；秘密文件仍单独保持 0600。
            self.files.chmod(0o755)
            self.binary = Path(self.options.binary or REPO / "target/release/vap").resolve()
            require(self.binary.is_file(), "缺少本机 Linux 可执行文件，请先发布构建或指定 --binary")
            self.network_baseline = self.baseline()
            self.runtime_description = {"system": platform.system(), "architecture": platform.machine(),
                                        "kernel": platform.release(), "binary_sha256": hashlib.sha256(self.binary.read_bytes()).hexdigest(),
                                        "binary_path": str(self.binary)}
            require(run("ip", "netns", "list").stdout.find("vap_fixture") == -1, "受控夹具网络空间已存在，拒绝覆盖")
            pool = ipaddress.ip_network("11.51.0.0/24")
            for entry in json.loads(run("ip", "-j", "-4", "route", "show", "table", "all").stdout):
                destination = entry.get("dst", "default")
                if destination != "default":
                    require(not pool.overlaps(ipaddress.ip_network(destination, strict=False)), "客户端地址池与既有路由冲突")
            run(str(REPO / "tests/fixtures/setup.sh"), str(self.files / "fixture"))
            self.fixture_ready = True
            self.state({"source_count": 3, "delay": 2})
            bridge = "vs" + self.token
            run("ip", "link", "add", bridge, "type", "bridge")
            self.links[bridge] = self.token
            run("ip", "link", "set", bridge, "alias", self.token)
            run("ip", "addr", "add", "11.51.0.1/24", "dev", bridge)
            run("ip", "link", "set", bridge, "up")
            for index in range(self.options.clients):
                name = f"vap-soak-{self.token}-{index}"
                run("ip", "netns", "add", name)
                handle = Path("/run/netns") / name
                self.spaces[name] = (handle.stat().st_dev, handle.stat().st_ino)
                host, peer = "vc" + self.token + str(index), "vp" + self.token + str(index)
                run("ip", "link", "add", host, "type", "veth", "peer", "name", peer)
                self.links[host] = self.token
                run("ip", "link", "set", host, "alias", self.token)
                run("ip", "link", "set", host, "master", bridge)
                run("ip", "link", "set", host, "up")
                run("ip", "link", "set", peer, "netns", name)
                run("ip", "netns", "exec", name, "ip", "addr", "add", f"11.51.0.{index + 2}/24", "dev", peer)
                run("ip", "netns", "exec", name, "ip", "link", "set", peer, "up")
                run("ip", "netns", "exec", name, "ip", "link", "set", "lo", "up")
            self.files.joinpath("config.json").write_text(json.dumps(self.config))
            self.log = self.files.joinpath("events.log").open("w")
            self.service = subprocess.Popen([str(self.binary), "run", "--config", str(self.files / "config.json")],
                                            stdout=subprocess.DEVNULL, stderr=self.log, start_new_session=True)
            self.proxy_host = "11.51.0.1"
        else:
            run("docker", "info")
            for image in [self.options.image, self.options.fixture_image]:
                run("docker", "image", "inspect", image)
            security = run("docker", "info", "--format", "{{json .SecurityOptions}}").stdout
            require_profiles(json.loads(security), [(self.options.image, "vpngate-auto-proxy"),
                                                    (self.options.fixture_image, "vpngate-auto-proxy-fixture")])
            self.network = f"vap-soak-{self.token}"
            run("docker", "network", "create", "--label", f"{LABEL}={self.token}", "--subnet", "11.52.0.0/24", self.network)
            self.fixture = self.network + "-fixture"
            caps = [argument for cap in CAPS for argument in ["--cap-add", cap]]
            fixture_args = ["--ip", "11.52.0.2", "--cap-drop", "ALL", *caps, "--device", "/dev/net/tun", "--security-opt", "no-new-privileges",
                 "--sysctl", "net.ipv4.ip_forward=1", "-v", f"{REPO}:/workspace:ro", "-e", "VAP_NETWORK_TEST=1", "-e", "VAP_FIXTURE_DIR=/tmp/vap-docker-fixture"]
            if "name=apparmor" in security:
                fixture_args += ["--security-opt", "apparmor=vpngate-auto-proxy-fixture"]
            self.docker_start(self.fixture, fixture_args,
                self.options.fixture_image, ["tests/fixtures/setup-docker.sh"])
            for _ in range(150):
                if run("docker", "exec", self.fixture, "test", "-f", "/tmp/vap-docker-fixture/docker-ready", check=False).returncode == 0:
                    break
                time.sleep(0.2)
            else:
                raise RuntimeError("容量夹具未在三十秒内启动")
            self.state({"source_count": 3, "delay": 2})
            self.config.update({"listen": "0.0.0.0:1080", "credentials_file": "/validation/credentials.json",
                                "runtime_dir": "/run/vap", "data_dir": "/var/lib/vap", "source_url": "http://11.52.0.2:18080/"})
            self.files.joinpath("config.json").write_text(json.dumps(self.config))
            self.product = self.network + "-product"
            volume = self.product + "-data"
            run("docker", "volume", "create", "--label", f"{LABEL}={self.token}", volume)
            self.volumes.append(volume)
            args = ["--ip", "11.52.0.3", "--cap-drop", "ALL", *caps, "--device", "/dev/net/tun", "--security-opt", "no-new-privileges",
                    "--sysctl", "net.ipv4.ip_forward=1", "--read-only", "--tmpfs", "/run:rw,nosuid,nodev", "--tmpfs", "/tmp:rw,nosuid,nodev",
                    "-v", f"{self.files}:/validation:ro", "-v", f"{volume}:/var/lib/vap"]
            if "name=apparmor" in security:
                args += ["--security-opt", "apparmor=vpngate-auto-proxy"]
            self.docker_start(self.product, args, self.options.image, ["run", "--config", "/validation/config.json"])
            image = json.loads(run("docker", "image", "inspect", self.options.image).stdout)[0]
            self.runtime_description = {"system": "Linux", "architecture": image["Architecture"], "image_id": image["Id"],
                                        "security_options": json.loads(security)}
            self.proxy_host = "11.52.0.3"

    def state(self, value):
        if self.options.deployment == "native":
            file = self.files / "fixture/state.json"
            temporary = file.with_suffix(".next")
            temporary.write_text(json.dumps(value))
            temporary.replace(file)
        else:
            code = "import json,sys;from pathlib import Path;p=Path('/tmp/vap-docker-fixture/state.json');t=p.with_suffix('.next');t.write_text(json.dumps(json.loads(sys.argv[1])));t.replace(p)"
            run("docker", "exec", self.fixture, "python3", "-c", code, json.dumps({"source_ip": "11.52.0.2", **value}))

    def status(self):
        if self.options.deployment == "native":
            if self.service.poll() is not None:
                raise RuntimeError("容量试验中服务进程提前退出：" + self.files.joinpath("events.log").read_text()[-2000:])
            args = [str(self.binary), "status", "--runtime-dir", str(self.files / "run"), "--json"]
        else:
            require(run("docker", "inspect", "--format", "{{.State.Running}}", self.product).stdout.strip() == "true", "容量试验中服务容器提前退出")
            args = ["docker", "exec", self.product, "vap", "status", "--runtime-dir", "/run/vap", "--json"]
        result = run(*args, check=False)
        return json.loads(result.stdout) if result.returncode == 0 else None

    def client(self, index, rejection=False):
        script = REPO / "scripts/soak_client.py"
        if self.options.deployment == "native":
            args = ["ip", "netns", "exec", f"vap-soak-{self.token}-{index % self.options.clients}", "python3", str(script)]
        else:
            name = f"{self.network}-client-{index}"
            self.containers.append(name)
            args = ["docker", "run", "--rm", "-i", "--name", name, "--label", f"{LABEL}={self.token}", "--network", self.network,
                    "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only", "--user", "10001:10001",
                    "-v", f"{REPO}:/workspace:ro", self.options.fixture_image, "python3", "/workspace/scripts/soak_client.py"]
        process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   text=True, bufsize=1, start_new_session=True)
        self.children.append(process)
        value = {"host": self.proxy_host, "port": 1080, **self.credentials,
                 "connections": self.options.connections // self.options.clients, "expect_rejection": rejection}
        process.stdin.write(json.dumps(value) + "\n")
        process.stdin.flush()
        return process

    def resources(self):
        if self.options.deployment == "native":
            entries = {}
            for file in Path("/proc").glob("[0-9]*/stat"):
                try:
                    fields = file.read_text().rsplit(")", 1)[1].split()
                    entries[int(file.parent.name)] = (int(fields[1]), int(fields[11]) + int(fields[12]), fields[19])
                except (OSError, ValueError, IndexError):
                    continue
            owned = {self.service.pid}
            while True:
                children = {pid for pid, (parent, _, _) in entries.items() if parent in owned}
                if children <= owned:
                    break
                owned |= children
            ticks = os.sysconf("SC_CLK_TCK")
            # 累积已采到的各进程计数，保留已退出子进程的最后计数。
            if not hasattr(self, "cpu_counts"):
                self.cpu_counts = {}
            for pid in owned & entries.keys():
                identity = pid, entries[pid][2]
                self.cpu_counts[identity] = max(self.cpu_counts.get(identity, 0), entries[pid][1])
            cpu_seconds = sum(self.cpu_counts.values()) / ticks
            rss = peak_sum = 0
            for pid in owned:
                try:
                    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
                        if line.startswith("VmRSS:"):
                            rss += int(line.split()[1]) * 1024
                        elif line.startswith("VmHWM:"):
                            peak_sum += int(line.split()[1]) * 1024
                except OSError:
                    continue
            result = {"rss_bytes": rss, "live_process_hwm_sum_bytes": peak_sum, "process_count": len(owned)}
        else:
            command = "set -e\ncat /sys/fs/cgroup/cpu.stat\ncat /sys/fs/cgroup/memory.peak\n" + process_memory_command()
            lines = run("docker", "exec", self.product, "sh", "-c", command).stdout.splitlines()
            cpu_seconds = int(next(line.split()[1] for line in lines if line.startswith("usage_usec "))) / 1_000_000
            rss, peak_sum = map(int, lines[-1].split())
            result = {"rss_bytes": rss, "live_process_hwm_sum_bytes": peak_sum, "cgroup_peak_memory_bytes": int(lines[-2])}
        now = time.monotonic()
        result["elapsed_seconds"] = now - self.started
        result["cpu_percent"] = None
        if self.previous_cpu:
            previous_time, previous_seconds = self.previous_cpu
            result["cpu_interval_seconds"] = now - previous_time
            result["cpu_percent"] = max(0, cpu_seconds - previous_seconds) / (now - previous_time) * 100
        self.previous_cpu = now, cpu_seconds
        return result

    def stop(self):
        started = time.monotonic()
        if self.options.deployment == "native":
            if self.service and self.service.poll() is None:
                self.service.send_signal(signal.SIGTERM)
                code = self.service.wait(timeout=15)
                require(code == 0 and not (self.files / "run").exists(), "原生停止失败或运行资源残留")
        else:
            run("docker", "stop", "--timeout", "15", self.product, timeout=20)
            require(run("docker", "inspect", "--format", "{{.State.ExitCode}}", self.product).stdout.strip() == "0", "容器停止清理失败")
        require(time.monotonic() - started < 15, "停止超过十五秒")

    def close(self):
        errors = []
        for child in self.children:
            try:
                if child.stdin:
                    child.stdin.close()
                child.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
        if self.service and self.service.poll() is None:
            try:
                self.stop()
            except Exception:
                errors.append("服务停止失败")
        for name, identity in reversed(list(self.spaces.items())):
            path = Path("/run/netns") / name
            if path.exists():
                actual = path.stat()
                if (actual.st_dev, actual.st_ino) != identity:
                    errors.append("客户端网络空间归属变化")
                elif run("ip", "netns", "del", name, check=False).returncode:
                    errors.append("客户端网络空间清理失败")
        for name, alias in reversed(list(self.links.items())):
            try:
                delete_owned_link(name, alias)
            except (RuntimeError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
                errors.append(str(error))
        if self.fixture_ready and run(str(REPO / "tests/fixtures/cleanup.sh"), str(self.files / "fixture"), check=False).returncode:
            errors.append("受控夹具清理失败")
        for name in reversed(self.containers):
            if self.owned("container", name) and run("docker", "rm", "-f", name, check=False).returncode:
                errors.append("本次容器清理失败")
        for name in self.volumes:
            if self.owned("volume", name) and run("docker", "volume", "rm", name, check=False).returncode:
                errors.append("本次数据卷清理失败")
        if self.network and self.owned("network", self.network) and run("docker", "network", "rm", self.network, check=False).returncode:
            errors.append("本次测试网络清理失败")
        if hasattr(self, "log"):
            self.log.close()
        if hasattr(self, "network_baseline") and self.baseline() != self.network_baseline:
            errors.append("原生测试前后网络基线不一致")
        require(not errors, "；".join(errors) + f"；保留诊断目录：{self.files}")
        shutil.rmtree(self.files)


def trial(environment):
    options = environment.options
    samples = []
    deadline = time.monotonic() + 60
    while True:
        status = environment.status()
        sample = environment.resources()
        sample["phase"] = "startup"
        samples.append(sample)
        if status and status["ready"]:
            break
        require(time.monotonic() < deadline, "六十秒内出口未就绪")
        time.sleep(0.2)
    active = status["active_node"]
    # 空闲及两个候选共存阶段均采实际资源，不用推算或预置最低预算。
    deadline = time.monotonic() + 30
    seen_idle = seen_two = False
    while not (seen_idle and seen_two):
        status = environment.status()
        require(status and status["ready"] and status["active_node"] == active, "采样期间活动出口失效或轮换")
        sample = environment.resources()
        running = status["candidates"]["running"]
        sample["phase"] = {0: "idle", 1: "active_with_one_candidate", 2: "active_with_two_candidates"}[running]
        samples.append(sample)
        seen_idle |= running == 0
        seen_two |= running == 2
        require(time.monotonic() < deadline, "未观测到空闲及活动加两个候选阶段")
        time.sleep(0.2)
    clients = [environment.client(index) for index in range(options.clients)]
    connected = collect(clients, timeout=20)
    require(all(value["connected"] == options.connections // options.clients for value in connected), "客户端连接数不符")
    require(len({value["source"] for value in connected}) == options.clients, "客户端没有独立网络身份")
    require(collect([environment.client(options.clients, rejection=True)])[0].get("rejected"), "第五十一条连接未拒绝")
    started = time.monotonic()
    deadline = started + options.duration_seconds
    completed_rounds = 0
    in_round = False
    requests = 0
    last_tick = None
    while time.monotonic() < deadline:
        tick = time.monotonic()
        require(last_tick is None or tick - last_tick <= 10, "连接往返间隔超过十秒")
        replies = send(clients, "tick")
        require(sum(value["round_trips"] for value in replies) == options.connections, "满载往返数量不符")
        requests += options.connections
        last_tick = tick
        status = environment.status()
        require(status and status["ready"] and status["active_node"] == active, "满载期间活动出口失效或轮换")
        require(status["connections"]["current"] == options.connections, "满载期间连接额度不符")
        progress = status["candidates"]
        require(progress["running"] <= 2 and progress["round_selected"] <= 20, "候选检测超出数量或并发上限")
        if progress["running"] > 0:
            in_round = True
        if in_round and progress["running"] == 0 and progress["round_completed"] > 0:
            completed_rounds += 1
            in_round = False
        sample = environment.resources()
        sample.update({"phase": "full_load", "candidate_running": progress["running"]})
        samples.append(sample)
        require(time.monotonic() - tick <= 10, "单轮往返及观测超过十秒")
        if time.monotonic() - started >= 30 and int(time.monotonic() - started) % 30 < 2:
            print(f"容量试验进行中：已持续 {int(time.monotonic() - started)} 秒", flush=True)
        time.sleep(min(1, max(0, deadline - time.monotonic())))
    require(completed_rounds >= 2, "满载期间未观测到两轮完整候选检测")
    require(send([clients[0]], "close_one")[0]["connected"] == options.connections // options.clients - 1, "释放连接失败")
    for _ in range(30):
        status = environment.status()
        if status["connections"]["current"] == options.connections - 1:
            break
        time.sleep(0.1)
    else:
        raise RuntimeError("断开后配额未及时释放")
    require(send([clients[0]], "open_one")[0]["connected"] == options.connections // options.clients, "额度释放后新连接失败")
    send(clients, "tick")
    send(clients, "stop")
    elapsed = time.monotonic() - started
    environment.stop()
    summary = {}
    for phase in sorted({sample["phase"] for sample in samples}):
        values = [sample for sample in samples if sample["phase"] == phase]
        cpu = [sample for sample in values if sample.get("cpu_interval_seconds")]
        summary[phase] = {"samples": len(values), "sampled_peak_rss_bytes": max(sample["rss_bytes"] for sample in values),
                          "mean_rss_bytes": sum(sample["rss_bytes"] for sample in values) / len(values),
                          "mean_cpu_percent": sum(sample["cpu_percent"] * sample["cpu_interval_seconds"] for sample in cpu) / sum(sample["cpu_interval_seconds"] for sample in cpu) if cpu else None}
    return {"schema_version": 1, "run_id": environment.token, "status": "passed",
            "time": datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat(),
            "deployment": options.deployment, "environment": environment.runtime_description,
            "driver_host": {"system": platform.system(), "architecture": platform.machine()},
            "clients": options.clients, "connections": options.connections, "duration_seconds": options.duration_seconds,
            "actual_elapsed_seconds": elapsed, "round_trips": requests, "completed_candidate_rounds": completed_rounds,
            "full_duration_passed": options.duration_seconds >= 1800, "resource_summary": summary, "samples": samples}


def save_report(output, report):
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=output.parent, prefix=".soak-", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(output)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()


def interrupted(_signal, _frame):
    raise RuntimeError("容量试验收到中断，已取消本次验收")


def main():
    parser = argparse.ArgumentParser(description="五个隔离客户端容量验收；三十分钟正式试验须显式执行")
    parser.add_argument("--deployment", choices=["native", "docker"], required=True)
    parser.add_argument("--clients", type=int, default=5)
    parser.add_argument("--connections", type=int, default=50)
    parser.add_argument("--duration-seconds", type=int, default=1800)
    parser.add_argument("--binary")
    parser.add_argument("--image", default="vpngate-auto-proxy:local")
    parser.add_argument("--fixture-image", default="vpngate-auto-proxy-fixture:local")
    parser.add_argument("--output", type=Path, default=REPO / "validation-output/soak.json")
    options = parser.parse_args()
    require(options.clients == 5 and options.connections == 50, "本次验收固定五个客户端、五十条连接")
    require(options.duration_seconds >= 15, "短时流程验证至少十五秒；正式验收为一千八百秒")
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    environment = Environment(options)
    report = None
    try:
        try:
            save_report(options.output, {"schema_version": 1, "run_id": environment.token, "status": "running", "full_duration_passed": False})
            environment.prepare()
            report = trial(environment)
        finally:
            environment.close()
    except BaseException as error:
        failed = {"schema_version": 1, "run_id": environment.token, "status": "failed", "full_duration_passed": False,
                  "failure_reason": str(error)[:4096]}
        if report is not None:
            failed["trial_observations"] = {key: value for key, value in report.items() if key not in {"status", "full_duration_passed"}}
        save_report(options.output, failed)
        raise
    report["owned_resources_removed"] = True
    report["network_baseline_restored"] = True if options.deployment == "native" else None
    save_report(options.output, report)
    print("三十分钟容量试验通过" if report["full_duration_passed"] else "短时容量流程通过，不能替代三十分钟正式验收", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"容量验收失败；没有生成本次通过报告：{error}", file=sys.stderr)
        raise SystemExit(1)
