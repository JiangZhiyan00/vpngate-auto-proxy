# 启动配置摘要契约

对应需-013—需-018、成-005、成-006。

## 输出时机

一条 `event_type=startup_summary`、`level=info` 的结构化日志，发送到运行日志目标，不能写入控制命令标准输出。

时序：配置校验 → 既有必要预检和安全启动配置交接 → 真正绑定监听对象 → 取得实际地址 → 输出一次摘要 → 服务循环和候选出口验证。服务循环必须接管同一监听对象，不重新 bind。预检时临时绑定后释放、内部工作进程 Ready 或容器健康检查都不能代替这一步。

每个实例最多一次；接收端及输出目标可用时，监听成功后五秒内可观察。使用独立保留的 1 帧诊断槽位，普通事件满队列不能淘汰它；父方优先处理真实监听事实并用已有可信配置重建摘要，完整配置不作为诊断帧传输。warn／error 按信息等级过滤，此时不是输出失败。摘要无法格式化或日志输出受限不能跳过实例回收；不把打印成功作为运行就绪门槛。端口占用和监听前失败无成功摘要，后续出口提升／撤销／恢复不重发摘要。

## 结构示例

下面是设计样例，不是当前程序实测日志；字段值不包含真实凭据。

```json
{
  "timestamp": "2026-10-16T14:00:00+09:00",
  "level": "info",
  "event_type": "startup_summary",
  "node_id": null,
  "worker_id": null,
  "state": "waiting",
  "reason": "服务已开始监听，等待已验证出口",
  "elapsed_ms": 0,
  "instance_id": "12b47214-6e5d-4c7b-b861-50a315ff7ca2",
  "ready": false,
  "config": {
    "listen_address": "0.0.0.0",
    "port": 1080,
    "protocol": "socks5",
    "listen_scope": "container_internal",
    "countries": ["JP"],
    "timezone": "Asia/Tokyo",
    "max_connections": 20,
    "log_level": "info",
    "log_summary_interval_seconds": 60,
    "data_dir": "/var/lib/vap",
    "runtime_dir": "/run/vap",
    "authentication_enabled": true
  }
}
```

- 外层原事件字段保留，新增 level；StartupSummary 独立附加实例、ready 和 config。
- 地址和端口来自真正持有的 listener.local_addr，地区代码使用有效配置的规范化值；空数组表示全部地区。
- 日志时间偏移遵循配置时区，示例为东京，不使用宿主默认时区覆盖配置。
- 初次监听完成后尚未验证出口，因此 ready=false。只有原出口验证流程能推进 ready=true，状态查询保持原结构。
- `listen_scope` 为 `container_internal` 或 `process_local`，来自可信启动上下文。容器专用入口明确传递显示上下文，文件模式容器入口也要覆盖；该标记只用于描述监听范围，不能授权网络或绕过认证。
- 不输出 host_port、public_ip 或“公网可访问”；容器无法确认宿主映射与防火墙，不读取 Docker socket。
- 密码、用户名、令牌、私钥、凭据文件内容及路径、来源 URL、出口检测 URL 均不进入 config 白名单，不通过整个 AppConfig 序列化获得摘要。

## 验收

对照默认及非默认配置逐字段核对；端口占用、权限预检失败和非法配置为失败正例，不产生摘要。无出口时摘要明确等待，出口提升后只产生原有就绪事件；warn／error 不产生信息摘要，但 status 仍独立可用。

容器文件配置与环境配置、原生支持路径都要测试绑定时机；苹果测试还须证明诊断输出不改租约持有、控制失联退休和资源回收。敏感标记在正常启动、配置错误和四等级日志中均不可出现。机器状态查询不得混入上述摘要。
