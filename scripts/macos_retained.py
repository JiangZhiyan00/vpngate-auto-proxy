"""保留既有套接字后销毁受控接口；只验证响应阻断，不证明零直连。"""
import json
import select
import secrets
import subprocess

from macos_tunnel import REPO, TARGET, interfaces, run


def read_record(process, timeout=8):
    if not select.select([process.stdout], [], [], timeout)[0]:
        raise RuntimeError("保留套接字探针未按时输出阶段结果")
    line = process.stdout.readline(4097)
    if not line.endswith("\n") or len(line) > 4096:
        raise RuntimeError("保留套接字阶段记录缺失或超限")
    return json.loads(line)


def exercise_retained(options, nodes, activity, runtime, endpoints, uid, gid, evidence):
    process, checks = None, {}
    evidence.update(checks=checks, scope="原套接字在接口销毁后两秒内无响应；不证明零直连、索引复用或生产故障恢复")
    try:
        with (runtime / "retained-error.log").open("w") as err:
            process = subprocess.Popen(
                [options.probe, nodes[0].index, TARGET, "19090", secrets.token_hex(24),
                 endpoints[0]["identity"], "1", "retained"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err, text=True,
                cwd=REPO, user=uid, group=gid, extra_groups=[],
            )
        ready = read_record(process)
        if not (ready.get("tcp") is True and ready.get("udp") is True
                and ready.get("interface_index") == int(nodes[0].index)
                and ready.get("identity") == endpoints[0]["identity"]):
            raise RuntimeError("原套接字的故障前正向验证未通过")
        checks["original_tcp_udp_verified"] = True
        # 独立活动长连接已完成候选共存验证。只取消它，保留本实验的两种套接字。
        if activity.poll() is not None or process.poll() is not None:
            raise RuntimeError("删除接口前业务探针已提前退出")
        activity.terminate()
        activity.wait(timeout=3)
        nodes[0].close()
        checks["interface_removed_with_probe_alive"] = nodes[0].interface not in interfaces() and process.poll() is None
        if not checks["interface_removed_with_probe_alive"]:
            raise RuntimeError("未能在保留套接字进程存活时确认接口消失")
        process.stdin.write("c")
        process.stdin.flush()
        result = read_record(process)
        evidence["retained_socket_observation"] = result
        if result.get("identity") != endpoints[0]["identity"] or result.get("interface_index") != int(nodes[0].index):
            raise RuntimeError("原套接字观察记录归属不符")
        for key in ("retained_tcp_response", "retained_udp_response", "retained_tcp_write_succeeded", "retained_udp_send_succeeded"):
            if type(result.get(key)) is not bool:
                raise RuntimeError("原套接字观察记录缺少结果")
        checks["retained_tcp_no_response_in_2_seconds"] = not result["retained_tcp_response"]
        checks["retained_udp_no_response_in_2_seconds"] = not result["retained_udp_response"]
        process.wait(timeout=3)
        checks["retained_probe_exited_normally"] = process.returncode == 0
        for index in (1, 2):
            for command in (
                [options.probe, nodes[index].index, TARGET, "19090", secrets.token_hex(24), endpoints[index]["identity"], "1"],
                [options.dns_probe, nodes[index].index, TARGET, "53", endpoints[index]["identity"]],
            ):
                value = json.loads(run(command, timeout=8, cwd=REPO, user=uid, group=gid, extra_groups=[]).stdout)
                if value.get("identity") != endpoints[index]["identity"] or value.get("interface_index") != int(nodes[index].index):
                    raise RuntimeError("接口销毁后候选归属不符")
            checks[f"candidate_{index}_business_dns_survived"] = True
        if not all(checks.values()):
            raise RuntimeError("保留套接字实验未通过：" + "、".join(k for k, v in checks.items() if not v))
    except BaseException as error:
        evidence["error"] = str(error) or type(error).__name__
        raise
    finally:
        if process is not None:
            try:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2)
            finally:
                evidence["probe_reaped"] = process.poll() is not None
                for pipe in (process.stdin, process.stdout):
                    if pipe is not None:
                        pipe.close()
