"""仅创建和删除带本次归属标签的受控桥接测试资源，不访问公共节点。"""
import argparse
import datetime
import hashlib
from zoneinfo import ZoneInfo
import json
import os
import re
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import traceback
import time
import uuid

from docker_profiles import require_profiles
from image_program import program_bytes

REPO = Path(__file__).resolve().parents[1]
LABEL = "io.vpngate-auto-proxy.validation"
CAPS = ["NET_ADMIN", "SYS_ADMIN", "SETUID", "SETGID", "SETPCAP", "KILL", "CHOWN", "DAC_OVERRIDE", "FOWNER"]

def validate_event_timezone(events, timezone):
    if not events:
        raise RuntimeError("未取得运行日志时区证据")
    for event in events:
        # Python 3.9 只接受微秒精度；Rust 日志保留纳秒，核对偏移前截断尾数。
        text = re.sub(r'(\.\d{6})\d+', r'\1', event["timestamp"]).replace('Z', '+00:00')
        timestamp = datetime.datetime.fromisoformat(text)
        if timestamp.tzinfo is None or timestamp.utcoffset() != timestamp.astimezone(ZoneInfo(timezone)).utcoffset():
            raise RuntimeError("运行日志的时区偏移与配置不符")


def validate_child_capabilities(snapshot):
    """业务可用之外，还核对降权进程的所有能力集合与禁止新增权限。"""
    found = set()
    for block in snapshot.strip().split("\n\n"):
        values = dict(line.split(":", 1) for line in block.splitlines() if ":" in line)
        uid = values.get("Uid", "").split()
        if len(uid) != 4 or uid[1] not in ("10001", "10002"):
            continue
        identity = int(uid[1])
        # 后台候选可能正在执行 setpriv；只核对已执行目标程序的消费者。
        name = values.get("Name", "").strip()
        if ((identity == 10002 and name != "openvpn")
                or (identity == 10001 and name != "vap")):
            continue
        expected = 0 if identity == 10001 else 1 << 12
        fields = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
        if any(int(values.get(field, "-1"), 16) != expected for field in fields):
            observed = "、".join(field + "=" + values.get(field, "缺失").strip() for field in fields)
            raise RuntimeError(f"降权进程 {identity} 的能力集合未按契约清空或限定：{observed}")
        if values.get("NoNewPrivs", "").strip() != "1":
            raise RuntimeError(f"降权进程 {identity} 缺少禁止新增权限")
        found.add(identity)
    if found != {10001, 10002}:
        raise RuntimeError("未取得控制/业务及隧道两类真实降权进程的能力证据")

def run(*args, check=True, timeout=60):
    result = subprocess.run(args, cwd=REPO, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"受控命令失败，退出码 {result.returncode}：{result.stderr[-2000:]}")
    return result

def validate_denied_capabilities(exit_code, diagnostic):
    if exit_code != "1":
        raise RuntimeError(f"缺少能力的实例退出码应为 1，实际为 {exit_code}：{diagnostic[-2000:]}")
    if "能力" not in diagnostic:
        raise RuntimeError("缺少能力的实例未输出能力诊断：" + diagnostic[-2000:])


def format_failure(error):
    frames = traceback.extract_tb(error.__traceback__)
    location = f"{Path(frames[-1].filename).name}:{frames[-1].lineno}" if frames else "未知位置"
    return f"容器验收失败（{location}，{type(error).__name__}）：{error or '检查未通过'}"


def fixture_startup_failure(name, output, redactions=()):
    """在归属资源回收前保留有限状态及夹具日志，不保存配置或环境变量。"""
    sections = []
    for title, command in [
        ("容器状态", ("docker", "inspect", "--format", "{{json .State}}", name)),
        ("夹具日志", ("docker", "logs", "--tail", "80", name)),
    ]:
        try:
            result = run(*command, check=False, timeout=10)
            value = (result.stdout + result.stderr)[-8000:]
        except (OSError, subprocess.TimeoutExpired) as error:
            value = f"诊断读取失败：{type(error).__name__}"
        sections.append(title + "\n" + value)
    diagnostic = "\n\n".join(sections)
    for value in redactions:
        if value:
            diagnostic = diagnostic.replace(value, "[已隐藏]")
    output.write_text(diagnostic + "\n")
    output.chmod(0o600)
    return RuntimeError(f"受控节点夹具未启动，诊断：{output}\n{diagnostic[-2000:]}")

def main():
    parser = argparse.ArgumentParser(description="验证受控容器；all 另运行指定时长的容量试验")
    parser.add_argument("--image", default="vpngate-auto-proxy:local")
    parser.add_argument("--fixture-image", default="vpngate-auto-proxy-fixture:local")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--require-apparmor", action="store_true")
    parser.add_argument("--environment-config", action="store_true",
                        help="通过环境模式和默认入口验证主实例；回环对照继续验证文件兼容")
    parser.add_argument("--case", choices=["smoke", "all"], default="smoke")
    parser.add_argument("--duration-seconds", type=int, default=1800)
    parser.add_argument("--omit-capability", choices=CAPS, action="append", default=[],
                        help="仅从产品容器移除指定能力，夹具保持既有能力")
    options = parser.parse_args()
    product_caps = [cap for cap in CAPS if cap not in options.omit_capability]
    if options.case == "all" and options.omit_capability:
        raise RuntimeError("能力缩减实验只用于 smoke，不把原能力集的容量结果混入")
    if options.duration_seconds < 15:
        raise RuntimeError("短时聚合验收至少十五秒，正式验收为一千八百秒")
    security = json.loads(run("docker", "info", "--format", "{{json .SecurityOptions}}").stdout)
    apparmor = any("name=apparmor" in value for value in security)
    if (options.require_apparmor or options.case == "all") and not apparmor:
        raise RuntimeError("当前引擎没有强制实施安全模块，不能完成指定验收")
    if not options.skip_build:
        print("正在构建单程序运行镜像", flush=True)
        result = subprocess.run(["docker", "build", "-t", options.image, "."], cwd=REPO)
        if result.returncode:
            raise RuntimeError("运行镜像构建失败")
    if run("docker", "image", "inspect", options.fixture_image, check=False).returncode:
        print("正在构建受控夹具镜像", flush=True)
        result = subprocess.run(["docker", "build", "-f", "tests/fixtures/Dockerfile", "-t", options.fixture_image, "."], cwd=REPO)
        if result.returncode:
            raise RuntimeError("夹具镜像构建失败")

    require_profiles(security, [(options.image, "vpngate-auto-proxy"),
                                (options.fixture_image, "vpngate-auto-proxy-fixture")])
    image_identity = json.loads(run("docker", "image", "inspect", options.image).stdout)[0]

    token = uuid.uuid4().hex[:12]
    network, fixture, product = (f"vap-validation-{token}-{name}" for name in ["network", "fixture", "product"])
    containers, volumes, network_created = [], [], False
    stop_exec_codes = []
    (REPO / "validation-output").mkdir(exist_ok=True)
    directory = tempfile.TemporaryDirectory(prefix="docker-", dir=REPO / "validation-output")
    files = Path(directory.name)
    password = secrets.token_hex(16)
    (files / "credentials.json").write_text(json.dumps({"username": "fixture", "password": password}))
    (files / "credentials.json").chmod(0o600)
    config = {"countries": ["JP"], "timezone": "America/New_York", "listen": "0.0.0.0:1080", "credentials_file": "/validation/credentials.json", "source_url": "http://11.52.0.2:18080/", "exit_check_urls": ["http://fixture.example/generate_204"], "data_dir": "/var/lib/vap", "runtime_dir": "/run/vap", "health_interval_seconds": 2, "health_timeout_seconds": 1, "retry_initial_seconds": 1, "retry_max_seconds": 2}
    (files / "config.json").write_text(json.dumps(config))
    for name, auth in [("valid", f"fixture:{password}"), ("wrong", "fixture:wrong-password"), ("none", None)]:
        text = 'silent\nshow-error\nmax-time = 5\nsocks5-hostname = "11.52.0.3:1080"\nurl = "http://fixture.example/generate_204"\noutput = "/dev/null"\nwrite-out = "%{http_code}"\n'
        if auth:
            text += f'proxy-user = "{auth}"\n'
        (files / f"curl-{name}.conf").write_text(text)
        (files / f"curl-{name}.conf").chmod(0o600)

    def owned(kind, name):
        result = run("docker", kind, "inspect", name, check=False)
        if result.returncode:
            return False
        record = json.loads(result.stdout)[0]
        labels = record.get("Config", {}).get("Labels", {}) if kind == "container" else record.get("Labels", {})
        return labels.get(LABEL) == token

    def status(name):
        result = run("docker", "exec", name, "vap", "status", "--runtime-dir", "/run/vap", "--json", check=False)
        return json.loads(result.stdout) if result.returncode == 0 else None

    def ready(name):
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            value = status(name)
            if value and value["ready"]:
                assert run("docker", "exec", name, "vap", "status", "--runtime-dir", "/run/vap",
                           "--json", "--check-ready", check=False).returncode == 0
                return value
            if run("docker", "inspect", "--format", "{{.State.Running}}", name).stdout.strip() != "true":
                diagnostic = run("docker", "logs", name, check=False)
                raise RuntimeError("实例提前退出：" + (diagnostic.stdout + diagnostic.stderr)[-2000:])
            time.sleep(0.2)
        raise RuntimeError("受控出口六十秒内未就绪")

    def launch(name, address, configuration="config.json", capabilities=True, publish=False):
        volume = name + "-data"
        run("docker", "volume", "create", "--label", f"{LABEL}={token}", volume)
        volumes.append(volume)
        args = ["docker", "run", "-d", "--name", name, "--label", f"{LABEL}={token}", "--network", network, "--ip", address, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--device", "/dev/net/tun", "--sysctl", "net.ipv4.ip_forward=1", "--tmpfs", "/run:rw,nosuid,nodev,mode=0755", "--tmpfs", "/tmp:rw,nosuid,nodev,mode=1777", "-v", f"{volume}:/var/lib/vap"]
        if capabilities:
            for cap in product_caps:
                args += ["--cap-add", cap]
        if apparmor:
            args += ["--security-opt", "apparmor=vpngate-auto-proxy"]
        if publish:
            args += ["-p", "127.0.0.1::1080"]
        containers.append(name)
        settings = json.loads((files / configuration).read_text())
        if options.environment_config and settings["listen"] == "0.0.0.0:1080":
            args += ["-v", f"{files / 'credentials.json'}:/run/secrets/proxy_credentials:ro",
                     "-e", "VAP_CONFIG_MODE=environment"]
            for field, value in settings.items():
                if field in ("listen", "credentials_file", "data_dir", "runtime_dir"):
                    continue
                text = ','.join(value) if isinstance(value, list) else (
                    str(value).lower() if isinstance(value, bool) else str(value))
                args += ["-e", "VAP_" + field.upper() + "=" + text]
            run(*args, options.image)
            mounted = json.loads(run("docker", "inspect", name).stdout)[0]["Mounts"]
            assert not any(item["Destination"] == "/validation" for item in mounted)
            assert any(item["Destination"] == "/run/secrets/proxy_credentials" for item in mounted)
        else:
            if not capabilities:
                # 私有临时目录属于宿主运行器且为 0700；缺少 DAC_OVERRIDE
                # 的根用户无法遍历它。只挂载不含凭据的配置文件，让对照
                # 实例完成配置读取后由生产预检拒绝缺少的能力。
                if settings.get("credentials_file") is not None:
                    raise RuntimeError("缺少能力的对照只允许无凭据配置")
                (files / configuration).chmod(0o644)
                mount = f"{files / configuration}:/validation/{configuration}:ro"
            else:
                mount = f"{files}:/validation:ro"
            run(*args, "-v", mount, options.image,
                "run", "--config", f"/validation/{configuration}")

    def stop(name):
        started = time.monotonic()
        result = run("docker", "exec", name, "vap", "stop", "--runtime-dir", "/run/vap",
                     timeout=15, check=False)
        # 容器 PID 1 正常结束会终止尚在等待目录回收的 exec 进程。
        # 137 只有同时满足主进程正常退出、预算及后续完整资源回收才可接受。
        if result.returncode not in (0, 137):
            raise RuntimeError("容器内停止请求失败：" + result.stderr[-2000:])
        stop_exec_codes.append(result.returncode)
        run("docker", "wait", name, timeout=max(0.1, 15 - (time.monotonic() - started)))
        if run("docker", "inspect", "--format", "{{.State.ExitCode}}", name).stdout.strip() != "0":
            raise RuntimeError("容器停止或资源清理失败")
        if time.monotonic() - started >= 15:
            raise RuntimeError("容器停止超过十五秒")

    def state(value):
        code = "import json,sys;from pathlib import Path;p=Path('/tmp/vap-docker-fixture/state.json');t=p.with_suffix('.next');t.write_text(json.dumps(json.loads(sys.argv[1])));t.replace(p)"
        run("docker", "exec", fixture, "python3", "-c", code, json.dumps({"source_ip": "11.52.0.2", "source_count": 3, "source_countries": ["JP", "JP", "US"], **value}))

    try:
        run("docker", "network", "create", "--label", f"{LABEL}={token}", "--subnet", "11.52.0.0/24", network)
        network_created = True
        args = ["docker", "run", "-d", "--name", fixture, "--label", f"{LABEL}={token}", "--network", network, "--ip", "11.52.0.2", "--cap-drop", "ALL", "--device", "/dev/net/tun", "--security-opt", "no-new-privileges", "--sysctl", "net.ipv4.ip_forward=1", "-e", "VAP_NETWORK_TEST=1", "-e", "VAP_FIXTURE_DIR=/tmp/vap-docker-fixture", "-v", f"{REPO}:/workspace:ro", "-v", f"{files}:/validation:ro"]
        for cap in CAPS:
            args += ["--cap-add", cap]
        if apparmor:
            args += ["--security-opt", "apparmor=vpngate-auto-proxy-fixture"]
        containers.append(fixture)
        run(*args, options.fixture_image, "tests/fixtures/setup-docker.sh")
        for _ in range(150):
            if run("docker", "exec", fixture, "test", "-f", "/tmp/vap-docker-fixture/docker-ready", check=False).returncode == 0:
                break
            if run("docker", "inspect", "--format", "{{.State.Running}}", fixture, check=False).stdout.strip() != "true":
                raise fixture_startup_failure(fixture, REPO / "validation-output" / f"fixture-{token}.log", (password,))
            time.sleep(0.2)
        else:
            raise fixture_startup_failure(fixture, REPO / "validation-output" / f"fixture-{token}.log", (password,))
        state({})
        print("验证认证、状态、地区筛选、时区和只读容器运行", flush=True)
        launch(product, "11.52.0.3")
        initial = ready(product)
        assert initial["active_node"] and initial["last_exit_check"]["success"]
        assert initial["candidates"]["total"] == 2
        assert initial["timezone"] == config["timezone"]
        logs = run("docker", "logs", product, check=False)
        events = [json.loads(line) for line in (logs.stdout + logs.stderr).splitlines() if line.startswith('{')]
        validate_event_timezone(events, "America/New_York")
        snapshot = run("docker", "exec", product, "sh", "-c",
                       "awk '/^(Name|Uid|CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs):/ {print} "
                       "/^voluntary_ctxt_switches:/ {print \"\"}' /proc/[0-9]*/status").stdout
        validate_child_capabilities(snapshot)
        assert run("docker", "exec", fixture, "curl", "--config", "/validation/curl-valid.conf").stdout == "204"
        for name in ["wrong", "none"]:
            assert run("docker", "exec", fixture, "curl", "--config", f"/validation/curl-{name}.conf", check=False).returncode != 0
        cache = run("docker", "exec", product, "cat", "/var/lib/vap/nodes.json").stdout
        assert len(json.loads(cache)["nodes"]) == 3
        state({"source_code": 503})
        stop(product)
        run("docker", "rm", product)
        launch(product, "11.52.0.3")
        restored = ready(product)
        assert initial["instance_id"] != restored["instance_id"]
        assert cache == run("docker", "exec", product, "cat", "/var/lib/vap/nodes.json").stdout
        assert run("docker", "exec", fixture, "curl", "--config", "/validation/curl-valid.conf").stdout == "204"
        print("缓存原时间保留、来源失败时替换容器重新验证通过", flush=True)
        state({"code": 503})
        for _ in range(50):
            value = status(product)
            if value and not value["ready"]:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("出口故障后未撤销就绪状态")
        assert run("docker", "exec", fixture, "curl", "--config", "/validation/curl-valid.conf", check=False).returncode != 0
        state({})
        ready(product)
        assert run("docker", "exec", fixture, "curl", "--config", "/validation/curl-valid.conf").stdout == "204"
        stop(product)

        print("验证无匹配地区时等待且不回退", flush=True)
        (files / "excluded.json").write_text(json.dumps({**config, "countries": ["SG"]}))
        state({"source_code": 503})
        run("docker", "rm", product)
        launch(product, "11.52.0.3", "excluded.json")
        excluded = product
        for _ in range(100):
            value = status(excluded)
            if value and value["source"]["fetched_at"]:
                break
            time.sleep(0.2)
        assert value and value["source"]["fetched_at"] and not value["ready"]
        excluded_instance = value["instance_id"]
        assert run("docker", "exec", excluded, "vap", "status", "--runtime-dir", "/run/vap",
                   "--json", "--check-ready", check=False).returncode == 3
        assert value["candidates"]["total"] == 0
        assert value["last_exit_check"] is None
        assert value["candidates"]["round_selected"] == 0
        diagnostic = run("docker", "logs", excluded, check=False)
        events = [json.loads(line) for line in (diagnostic.stdout + diagnostic.stderr).splitlines() if line.startswith('{')]
        assert any(event["event_type"] == "cache_loaded" for event in events)
        assert not any(event["event_type"] == "candidate_started" for event in events)
        assert len(json.loads(run("docker", "exec", excluded, "cat", "/var/lib/vap/nodes.json").stdout)["nodes"]) == 3
        stop(excluded)
        print("验证默认回环、存活检查和缺少能力的诊断", flush=True)
        loop = product + "-loop"
        config.update({"listen": "127.0.0.1:1080", "credentials_file": None})
        (files / "loop.json").write_text(json.dumps(config))
        state({"source_count": 0})
        launch(loop, "11.52.0.4", "loop.json", publish=True)
        for _ in range(50):
            value = status(loop)
            if value:
                break
            time.sleep(0.2)
        if not value or value["ready"]:
            diagnostic = run("docker", "logs", loop, check=False)
            raise RuntimeError("回环实例未进入等待状态：" + (diagnostic.stdout + diagnostic.stderr)[-2000:].replace(password, "[已隐藏]"))
        port = run("docker", "port", loop, "1080/tcp").stdout.strip().rsplit(":", 1)[1]
        if run("curl", "--max-time", "3", "--socks5-hostname", f"127.0.0.1:{port}", "http://fixture.example/", check=False).returncode == 0:
            raise RuntimeError("回环监听实例意外接受了宿主代理请求")
        stop(loop)
        denied = product + "-denied"
        launch(denied, "11.52.0.5", "loop.json", capabilities=False)
        exit_code = run("docker", "wait", denied, timeout=10).stdout.strip()
        diagnostic = run("docker", "logs", denied, check=False)
        validate_denied_capabilities(exit_code, (diagnostic.stdout + diagnostic.stderr).replace(password, "[已隐藏]"))
        print("受控镜像短时验收通过：认证、状态、停止、缓存重启、故障阻断与恢复、回环及权限诊断", flush=True)
        if not apparmor:
            print("当前引擎未启用强制实施安全模块；专用策略只做解析校验，原生强制实施及目标架构仍待验收", flush=True)
    finally:
        errors = []
        for name in reversed(containers):
            if owned("container", name) and run("docker", "rm", "-f", name, check=False).returncode:
                errors.append(name)
        for name in volumes:
            if owned("volume", name) and run("docker", "volume", "rm", name, check=False).returncode:
                errors.append(name)
        if network_created and owned("network", network) and run("docker", "network", "rm", network, check=False).returncode:
            errors.append(network)
        directory.cleanup()
        if errors:
            raise RuntimeError("受控资源清理失败：" + "、".join(errors))
    final_identity = json.loads(run("docker", "image", "inspect", options.image).stdout)[0]
    if final_identity['Id'] != image_identity['Id']:
        raise RuntimeError("验收期间镜像标签身份发生变化")
    print(json.dumps({
        "status": "passed", "image_id": image_identity['Id'],
        "binary_sha256": hashlib.sha256(program_bytes(image_identity['Id'],
            'linux/' + image_identity['Architecture'])).hexdigest(),
        "config_mode": "environment" if options.environment_config else "json",
        "instances": {"initial": initial['instance_id'], "restored": restored['instance_id'],
                      "excluded": excluded_instance},
        "apparmor_enforced": apparmor, "cleanup_passed": True,
        "vap_status_ready_codes": [0, 3], "vap_stop_validated": True,
        "container_stop_exec_codes": stop_exec_codes,
        "authentication_cache_regions_timezone_faults_validated": True,
    }, ensure_ascii=False), flush=True)
    if options.case == "all":
        result = subprocess.run([sys.executable, str(REPO / "scripts/validate_soak.py"), "--deployment", "docker", "--clients", "5", "--connections", "50",
            "--duration-seconds", str(options.duration_seconds), "--image", options.image, "--fixture-image", options.fixture_image,
            "--output", str(REPO / "validation-output/soak-docker-all.json")], cwd=REPO, timeout=options.duration_seconds + 180)
        if result.returncode:
            raise RuntimeError("聚合验收中的容量试验失败")

if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, AssertionError, subprocess.TimeoutExpired) as error:
        print(format_failure(error), flush=True)
        raise SystemExit(1)
