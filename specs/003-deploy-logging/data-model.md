# 数据模型：部署准备与运行日志

依据 [规格](spec.md) 和 [计划](plan.md)，本阶段仅定义数据与行为，不创建运行材料。

## 一、日志等级与策略

### LogLevel

枚举 `error`、`warn`、`info`、`debug`，严重程度按此前后顺序递减；默认 info。只接受精确小写值，不提供 off／trace，不把非法值自动修正。

### LogPolicy

| 字段 | 类型 | 默认与约束 |
| --- | --- | --- |
| log_level | LogLevel | info |
| log_summary_interval_seconds | 无符号整数 | 60；范围 1—86400 |

属于 AppConfig，经可信启动配置传到每个参与进程；容器空环境值视为省略。策略在一次实例运行中不变，修改需重新启动。派生的单调 `next_summary` 不是持久数据，也不与健康检查的截止时间共用。

## 二、运行事件与诊断消息

### Event

保留 `timestamp`、`event_type`、`node_id`、`worker_id`、`state`、`reason`、`elapsed_ms`，增加 `level`。时间采用配置时区及明确偏移；敏感原因只用安全分类和固定阶段，不保存原始凭据、URL 或外部输出。公开机器状态结构独立，不加入 level 字段。

### DiagnosticFrame

苹果内部诊断通道版本为 1；包含事件类型、等级、可选节点／工作标识、状态、安全原因码及有限安全参数。传输帧最大 4096 字节，队列最多 64 帧，其中 1 帧为不可被普通事件占用的 startup_summary 槽位，63 帧为普通事件队列。父方按启动时登记的实例、直属消费者和预期事件白名单验证，重建可信时间和归属；不接受子进程指定文件、系统命令、任意配置正文或父方权限。

通道只传递观察事件，无启动、停止或资源退休权限；提交非阻塞，满队列按 [日志契约](contracts/logging.md) 的等级淘汰／合并规则处理，四个固定等级饱和计数器记录交付损失，不扩展为任意键缓存。startup_summary 仅交付真实绑定事实，由父方可信配置重建，避免将完整配置装入有限帧。

关键退出阶段及原因在独立于日志队列的可信失败结果中保存；只有回收布尔量的收据不足以承载它，必须增加类型化安全原因结果。队列损失计数不作为运行成功依据。诊断 EOF 和输出故障不改变资源归属或业务停止规则；结束排空至多 1 秒且不超过原十五秒总停止预算。原 stderr 锁租约不属于本模型，保持原用途。

## 三、启动配置摘要

### StartupSummary

为 `event_type=startup_summary` 的信息事件；包含可信实例 ID、`ready` 和独立 config 白名单。

| 字段 | 类型 | 约束 |
| --- | --- | --- |
| instance_id | UUID | 来自本实例可信启动上下文 |
| ready | 布尔 | 初次绑定后为 false；出口就绪由原检查独立推进 |
| config.listen_address | IPv4 文本 | 来自 listener.local_addr 的实际值 |
| config.port | 整数 | 实际监听端口，不是宿主映射端口 |
| config.protocol | 固定文本 | socks5 |
| config.listen_scope | 枚举 | container_internal 或 process_local |
| config.countries | 字符串数组 | 规范化国家代码；空数组表示全部 |
| config.timezone | 文本 | 有效时区名称 |
| config.max_connections | 正整数 | 实际上限 |
| config.log_level | LogLevel | 实际生效等级 |
| config.log_summary_interval_seconds | 整数 | 实际生效摘要间隔 |
| config.data_dir、config.runtime_dir | 绝对路径 | 经校验的配置路径；不拼接凭据正文 |
| config.authentication_enabled | 布尔 | 不携带用户名、密码或凭据内容 |

状态顺序：配置校验 → 必要预检 → 实际监听对象建立 → 允许等级时输出一次摘要 → 服务处理与候选验证 → 原有出口状态推进。任何监听前失败都没有成功摘要，出口恢复不返回摘要阶段。

## 四、宿主材料与登记

### HostSetupManifest（公开附件）

| 字段 | 内容 |
| --- | --- |
| schema_version | 1 |
| project | vpngate-auto-proxy |
| release_tag、source_commit | 严格版本与完整对应提交 |
| installer_filename、installer_sha256 | 单文件版本安装器名称及 64 位小写摘要 |
| policy_name、policy_sha256 | 唯一策略名及内嵌字节摘要 |
| policy_target | 固定 /etc/apparmor.d/vpngate-auto-proxy |
| image_id | 最终验收镜像身份；与 validation.json 一致 |
| supported_hosts | Debian12／Ubuntu24.04、x86_64、systemd、rootful local Docker、AppArmor |

安装器包含相同版本和策略信息；不把自己的字节摘要嵌入自身产生递归。安装器摘要位于外部清单和引导说明；清单摘要由发布 SHA256SUMS 登记。

### HostSetupRecord（宿主受保护登记）

版本 1；记录 project、release_tag、source_commit、installer_sha256、policy_name、policy_sha256、固定目标路径、目标 dev／ino、installed_at（带偏移）、最后本次核对的 boot_id 和 enforce 状态。属主 root:root、普通独立文件、0600，父目录 root:root、0700。它是项目材料归属凭据，不含代理密码，不等同于真实重启验收报告。

### HostSetupTransaction（宿主受保护事务）

事务 ID、当前阶段、本次版本与摘要、旧文件及登记的快照身份、原内核同名策略是否存在及模式、备份位置、本次创建的节点身份、检查与恢复结果。阶段为 prepared → file_committed → kernel_verified → record_committed → complete；任一中断转为 rollback_required，确认恢复则 rolled_back，否则 recovery_required。

不能假定磁盘提交与内核替换原子。恢复只操作事务证明属于本项目的节点和策略，不卸载未知同名策略，不删除未知文件。下次写入前必须核对未完成事务，不能忽略它重新初始化。

### HostSetupResult

仅输出当前检查事实：status、action、release_tag、policy_sha256、disk_verified、kernel_enforced、persistence_configured、changed、stage、safe_reason、recovery_required、recovery_path。真实 `reboot_validated` 只允许由另行目标宿主验收报告记录，普通初始化不自行设置为 true。

## 五、宿主准备状态转换

| 起始状态 | 操作 | 结果 |
| --- | --- | --- |
| 文件、登记、内核同名策略均不存在 | 默认准备 | 校验、安装、加载、登记，通过后 ready |
| 已管理且同版本同摘要、enforce 正确 | 默认或 check | 只核对，不 reload；check 不写文件 |
| 已管理且文件正确但内核缺失 | 默认准备 | 无活跃使用者时按原版本重新加载并复核 |
| 无登记但文件与所选官方策略完全相同 | adopt | 无活跃使用者时验证并明确接管；默认拒绝 |
| 不同受管版本 | update-from | 核对预期旧版本、摘要、无活跃使用者后事务更新 |
| 未知内容、登记不符、只有未知内核策略 | 任意写操作 | 冲突拒绝；check 报告不一致 |
| 未完成事务 | 任意写操作 | 先核对和恢复，不确定时拒绝并说明恢复材料 |
| 依赖、权限或持久条件缺失 | 任意准备 | 失败，不改变原有效状态或其他服务 |
