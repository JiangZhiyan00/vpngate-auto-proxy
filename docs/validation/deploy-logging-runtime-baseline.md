# 运行日志与监听实现基线

日期：2026-10-16，上海时区。仅检查源码，不代表新功能已验收。

service::emit 与 emit_summary 当前直接向标准错误输出逐行 JSON；runtime_summary 每秒输出。Bootstrap 已携带 AppConfig。事件既有字段为 timestamp、event_type、node_id、worker_id、state、reason、elapsed_ms。公开状态 schema_version=1，运行控制退出码须保持原契约。
service::run 的临时 TcpListener 绑定后释放只是端口预检；实际持久绑定位于 socks::run_gateway，苹果控制进程的 Ready 也不能替代真实监听。
苹果 process::Receipt::child_stderr 调用 ConsumerLease::child_stdio，stderr 是资源锁租约；不能改为普通日志管道。新增诊断必须使用独立描述符。
现有集成启动、候选、切换、生命周期测试读取 events.log；依赖 candidate_started、round_started、cache_loaded 的场景须显式启用 debug，默认安静另验。Docker 验收需使用状态与持久材料作为正向行为证据。
受管理隧道原始输出不得公开透传。日志过滤不得包围调度或清理。当前未执行网络或苹果原生验证。
