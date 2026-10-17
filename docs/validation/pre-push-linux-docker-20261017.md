# Linux／Docker 提交前检查

日期：2026-10-17，上海时区。用户授权检查通过后提交并推送 main；苹果端明确暂缓。

## 最新候选

镜像身份：`sha256:b14105e79596453e4ecb7237aa08ae20a2fd44121245d1c0a3e80f1912f9228a`，linux/amd64。

程序摘要：`cd2b826dd42205a78386b4d27bd798cd6f94e19f8663e900493eb412ad10d58d`。

最新源码构建成功，受控 smoke 通过：认证、状态、地区、时区、只读运行、缓存原获取时间保留和重启重验、来源失败、故障阻断恢复、默认回环、缺少能力诊断、停止及本次资源清理。实际 Linux 镜像无网络运行配置转换，核对旧算法默认 true、出口检查默认 60 秒／总超时 5 秒、日志默认 info／摘要间隔 60 秒均通过。镜像保留 30 秒本地存活 HEALTHCHECK。

本机引擎未启用强制 AppArmor，仅有策略解析证据，不替代目标主机强制实施或宿主初始化／重启矩阵。最新镜像未重跑十分钟日志矩阵；之前十分钟证据属于默认值修订前候选。公开发布工作流仍要求最终来源冻结后的 smoke、logging 及强制策略验收。

## 普通检查

- 排除暂缓苹果模块的共用库测试：22 项通过、1 项忽略、290 项按过滤范围未执行。
- 配置环境、日志、地区时区与适用契约：89 项通过、3 项忽略；11 项苹果契约按范围过滤，不计通过。
- Python 全套发现 271 项，251 项通过、20 项按适用条件跳过。
- 格式、全目标 clippy 警告门禁、actionlint 工作流检查、差异空白检查通过。
- 提交候选未包含本地凭据、实际私钥或临时验收输出；远端 main 在检查时与本地基线一致。

先前完整本机 Rust 回归有两项苹果子进程测试失败：failed_start_and_forced_retirement_still_prove_direct_child_reaping 的 PID 证据缺失，以及 coupled_already_stopping_never_publishes_connection_material 的启动确认超时。按用户最新指示不修复、不隐藏这两项失败，也不把过滤后的结果称为完整回归通过。此轮没有修改 supervisor.rs；既有苹果实现接入和未完成范围继续按功能 003 任务记录保留。

原始临时记录：validation-output/pre-push-rust-tests.log、pre-push-python-tests.log、pre-push-shared-tests.log、pre-push-contract-tests.log、pre-push-docker-build.log、pre-push-docker-smoke.log。临时文件不提交。本轮仅提交与推送分支，不创建标签或发布镜像。
