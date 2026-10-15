"""逐项且累计移除产品容器能力，运行完整受控短试并保存实际结果。"""
import argparse
import datetime
import json
from pathlib import Path
import subprocess
import sys

from validate_docker import CAPS, REPO


def main():
    parser = argparse.ArgumentParser(description="验证产品容器能力缩减，不修改正在运行的服务")
    parser.add_argument("--image", required=True)
    parser.add_argument("--fixture-image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-apparmor", action="store_true")
    options = parser.parse_args()
    options.output.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "schema_version": 1,
        "recorded_at": datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat(),
        "status": "running", "original_capabilities": CAPS, "experiments": [],
        "scope": "当前引擎、指定镜像与受控短试；不替代目标安全模块、长期运行和全部故障矩阵",
    }

    def save():
        options.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")

    save()
    try:
        report["engine"] = json.loads(subprocess.check_output(
            ["docker", "info", "--format", "{{json .}}"], text=True))
        # 仅保留验收需要的环境字段，避免记录引擎标签、代理设置及注册表信息。
        report["engine"] = {key: report["engine"].get(key) for key in
                            ("OSType", "Architecture", "ServerVersion", "SecurityOptions", "KernelVersion")}
        report["images"] = [json.loads(subprocess.check_output(
            ["docker", "image", "inspect", tag], text=True))[0]["Id"]
                            for tag in (options.image, options.fixture_image)]

        def experiment(label, omitted):
            log = options.output.with_name(options.output.stem + "-" + label + ".log")
            command = [sys.executable, str(REPO / "scripts/validate_docker.py"),
                       "--skip-build", "--case", "smoke", "--image", options.image,
                       "--fixture-image", options.fixture_image]
            if options.require_apparmor:
                command.append("--require-apparmor")
            for cap in omitted:
                command += ["--omit-capability", cap]
            print("能力实验：" + label, flush=True)
            with log.open("w") as stream:
                log.chmod(0o600)
                # 内层每条 Docker 命令和等待均有截止，由其 finally 回收归属资源；
                # 不从外层强杀 Python，避免跳过该清理路径。
                result = subprocess.run(command, cwd=REPO, stdout=stream,
                                        stderr=subprocess.STDOUT)
            item = {"label": label, "omitted": list(omitted), "exit_code": result.returncode,
                    "passed": result.returncode == 0, "log": log.name}
            item["evidence"] = ("完整短试通过" if item["passed"] else
                                "能力预检拒绝，未覆盖实际操作" if "缺少必要能力" in log.read_text()
                                else "短试失败，具体阶段见日志")
            report["experiments"].append(item)
            save()
            return item["passed"]

        if not experiment("baseline", []):
            raise RuntimeError("原能力集短试未通过，不能继续判断哪些能力可删除")
        omitted = []
        for cap in CAPS:
            if experiment("without-" + cap.lower(), omitted + [cap]):
                omitted.append(cap)
        report["removable_in_current_environment"] = omitted
        report["remaining_capabilities"] = [cap for cap in CAPS if cap not in omitted]
        if not experiment("final", omitted):
            raise RuntimeError("最终累计缩减能力集未通过独立短试")
        report["status"] = "passed"
        save()
        print("当前环境能力实验完成；可移除：" + ("、".join(omitted) or "无"))
    except BaseException as error:
        report["status"] = "failed"
        report["error"] = str(error)
        save()
        raise


if __name__ == "__main__":
    main()
