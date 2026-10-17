# 任务清单：简化部署准备与运行日志

**功能目录**：`specs/003-deploy-logging`
**日期**：2026-10-16，上海时区。
**输入**：[规格](spec.md)、[计划](plan.md)、[研究](research.md)、[数据模型](data-model.md)、[接口契约](contracts/host-setup.md)、[验证指南](quickstart.md)。
**前提**：已完成 42／58 项；Linux／Docker 本地增量及十分钟容器验收通过。剩余 16 项包括苹果专用 8 项、真实宿主与强制策略验收及最终材料冻结／汇总 8 项。T054 的普通检查已通过，但依赖 T053 的最终冻结未完成，保留未勾选。实际分支仍为 main。
**测试依据**：规格明确要求四等级、频率、敏感标记、真实监听、宿主事务与重启等验证，因此包含相应测试任务；不为纯文案编写镜像实现的无效测试。
**组织**：按三个用户故事交付独立增量；每项完成须有对应实现或实测证据，文件生成不代表运行验收完成。

## 格式与执行约定

任务格式为 `- [ ] T编号 [P可选] [US故事可选] 描述及文件路径`。`[P]` 只表示所列前提完成后可与同组不同文件任务并行，不授权自动派发子代理。阶段一、二和最终阶段无故事标签；故事阶段必须标 US1／US2／US3。

故事阶段编号用于组织内容，不构成跨平台的完成屏障；以明确依赖图推进，目标环境缺失的苹果任务保留未完成，不能阻塞没有依赖它们的 Linux／Docker 后续任务。

路径相对仓库根目录。测试先写并确认针对缺失行为失败，再实现；不得用零匹配、平台跳过或已知依赖缺失当作行为通过。需要真实宿主、明确管理员操作、维护者重启或公开发布才能完成的任务单独保留；不自动操作用户现有 Stack、不提交、不推送、不创建或移动标签、不发布镜像。

## 阶段一：准备与基线

**目标**：确认现有行为和证据范围，避免把已发布旧版本或本机模拟结果冒充本功能验证。

- [X] T001 [P] 在 `docs/validation/deploy-logging-host-baseline.md` 记录现有 `scripts/install-vap.py`、`deploy/apparmor/vpngate-auto-proxy`、`scripts/prepare_docker_publish.py` 的身份校验、策略摘要和发布顺序，列出 Debian 12／Ubuntu 24.04 所需工具及真实宿主验证前提；只做只读检查，不修改宿主策略或其他服务。
- [X] T002 [P] 在 `docs/validation/deploy-logging-runtime-baseline.md` 记录 `src/service.rs`、`src/socks.rs`、`src/platform/controller.rs`、`src/platform/process.rs`、`src/platform/lease.rs` 的实际绑定点、全部日志事件、stderr 租约用途及依赖调试事件的现有测试，保留当前状态 JSON 和退出码基线，不记录凭据或完整环境。

## 阶段二：受控验证基础

**目标**：提供不会误操作真实宿主或堵塞子进程的验证基础，不提前实现故事业务。

- [X] T003 在 `scripts/test_host_init.py` 建立临时 root 目录、可注入宿主探测／命令执行和故障点的测试夹具；默认测试不得触及真实 `/etc/apparmor.d`、securityfs、系统服务或用户容器，真实 root 权限用例明确平台门槛；准备命令调用记录供事务和不操作其他服务断言使用。依赖 T001。
- [X] T004 [P] 在 `tests/integration/support.rs` 增加有界且持续排空的 JSON 日志捕获、监听时刻记录和可配置实例启动辅助，确保关闭捕获任务后回收子进程；为后续独立单调时间测试提供可注入时钟接口约定，不改变现有夹具默认网络行为。依赖 T002，与 T003 不共享文件。

**检查点**：基线和隔离夹具已就绪，US1 与 US2 核心可分别启动；US3 等待 US2 日志接口。

## 阶段三：用户故事一——一次完成宿主首次准备（优先级一，最小可交付增量）

**目标**：提供无需源码仓库的受校验单次准备入口，幂等安装项目唯一策略，保留未知材料和其他服务。

**独立验收**：受控事务测试及两个目标发行版上，验证首次准备、三次重复、三次代理操作、失败恢复和一次正常重启后的 enforce；其他服务和策略不因准备操作变化。

### 契约与失败测试

- [X] T005 [P] [US1] 在 `scripts/test_host_init.py` 添加契约及失败用例：默认／`--check`／`--adopt`／`--update-from`／中文帮助、互斥参数、无权限、未支持宿主、远端或无根引擎、缺失工具／设备、链接和危险权限、未知策略、登记损坏、并发、活跃及不可确认消费者、只读检查零写入、各事务阶段失败和中断恢复；断言退出码 0／1／2／4 与安全结果，不接受假成功。依赖 T003。
- [X] T006 [P] [US1] 在 `scripts/test_host_init_package.py` 新建版本安装器打包契约测试，覆盖“单文件版本安装器名称及 64 位小写摘要”、严格版本与完整对应提交、内嵌唯一策略、清单绑定实际镜像、无源码目录也可解析帮助、拒绝已存在输出和不可信来源；用受控下载／执行替身证明校验失败绝不运行安装器。依赖 T003，与 T005 分文件。

### 实现与集成

- [X] T007 [US1] 在 `scripts/host-init.py` 实现安装器参数与 HostSetupManifest／HostSetupRecord／HostSetupResult，固定 `schema_version=1`、`project=vpngate-auto-proxy` 和项目路径，严格校验版本、完整 source_commit、64 位小写摘要及未知字段；结果包含 status、action、release_tag、policy_sha256、disk_verified、kernel_enforced、persistence_configured、changed、stage、safe_reason、recovery_required、recovery_path，不自动声称 reboot_validated。对应需-001、需-002、需-004；依赖 T005。
- [X] T008 [US1] 在 `scripts/host-init.py` 实现 Debian 12／Ubuntu 24.04、x86_64、Python ≥3.10、实际及有效 root、真实宿主命名空间、本机有根 Docker、systemd、AppArmor、标准 include 和 `/dev/net/tun` 的前提检查；受保护系统工具与明确参数执行、清理危险环境；不安装依赖，不 enable／restart／reload 系统服务，不操作其他策略或 Stack。对应需-002、需-003、需-005；依赖 T007。
- [X] T009 [US1] 在 `scripts/host-init.py` 实现固定策略路径、逐段父目录和独立文件身份校验、项目独占锁及登记持久化；遵守“属主 root:root、普通独立文件、0600，父目录 root:root、0700”，策略固定 root:root 0644；提交前复核 dev／ino、摘要和旧登记，`--check` 不创建锁或任何文件。对应需-003、需-004；依赖 T008。
- [X] T010 [US1] 在 `scripts/host-init.py` 实现初装、同版本幂等、显式 adopt 和绑定旧版本的 update-from 状态判断：无登记的完全相同官方文件默认拒绝、显式接管才可接受；未知字节、未知内核同名策略和本地修改拒绝；需真实替换时完整扫描同名策略消费者，无活跃或不可确认消费者才允许，安装器不停止它们。对应需-003—需-005；依赖 T009。
- [X] T011 [US1] 在 `scripts/host-init.py` 实现只解析且唯一名称验证、策略磁盘提交、跳过旧缓存读取加载、精确名称及 enforce 复核、持久启动条件检查与事务恢复；阶段严格为“prepared → file_committed → kernel_verified → record_committed → complete”，中断进入 rollback_required，恢复确认 rolled_back，否则 recovery_required／退出 4；只恢复本事务归属材料，不卸载未知或在用策略，后续写入先处理未完成事务。对应需-002—需-005；依赖 T010。
- [X] T012 [US1] 在 `scripts/package_host_init.py` 生成内嵌策略、版本、提交和许可的自包含 `vap-host-init-vX.Y.Z.py`、`host-setup.json`、`host-setup-command.txt`；不自嵌安装器摘要形成递归，清单绑定最终验收 image_id；一条引导命令仅从固定官方 HTTPS 版本 URL 下载到 root 私有目录，限制时间和大小，核对预期摘要后执行并清理临时材料，执行阶段不联网、不导入仓库其他模块。对应需-001、需-004、需-006；依赖 T006、T011。
- [X] T013 [US1] 在 `scripts/prepare_docker_publish.py`、`deploy/Dockerfile.release` 将安装器源、打包器和生产策略加入冻结输入，最终镜像增加 `io.vpngate-auto-proxy.apparmor-sha256`，与公开清单、内嵌策略一致；在既有最终镜像验收及来源核验通过后生成宿主材料，避免用旧镜像或旧来源记录绑定新材料。依赖 T012。
- [X] T014 [US1] 在 `scripts/package-docker-release.py`、`scripts/test_release_package.py`、`scripts/test_docker_publish.py` 纳入宿主部署材料及本功能契约源码白名单，核对生成材料仅依赖标准库、保留项目许可、完整来源归档和对应摘要；不引入宿主代理二进制、凭据、日志或第二产品命令。依赖 T013。
- [X] T015 [US1] 在 `.github/workflows/docker-publish.yml` 上传同版本宿主安装器、清单及一条命令说明，扩展 `SHA256SUMS` 而不丢弃源码归档摘要；保持先前置验收、再公开附件、最后推送同一镜像的版本和 latest 标签，不覆盖已公开附件或移动标签；核对现有动作引用和语法，无须新动作时不新增依赖。依赖 T014。
- [X] T016 [US1] 在 `scripts/validate_host_init.py` 实现只读 before-reboot／after-reboot 证据采集，记录版本、策略及登记摘要、boot_id、加载模式、持久条件和其他服务基线；after 必须在任何初始化重新加载之前检查并核对 boot_id 已变化；工具不执行 reboot、不保存凭据或整个 inspect 配置。依赖 T011。
- [X] T017 [US1] 在 `docs/deployment.md`、`docs/dockerhub-release.md` 更新首次准备、重复检查、显式接管、版本更新、支持矩阵和 Portainer 已有 Stack 的说明；只给官方版本引导入口，不要求完整源码、不把安装器当作另一个产品 CLI，不暗示生产容器能自行管理宿主策略。依赖 T012、T016。

### 独立验收与证据

- [X] T018 [US1] 执行 `scripts/test_host_init.py`、`scripts/test_host_init_package.py`、`scripts/test_release_package.py`、`scripts/test_docker_publish.py` 的定向回归及隔离 root 文件测试，在 `docs/validation/deploy-logging-host-local.md` 记录具体用例、计数、材料摘要和限制；确认无源码目录运行生成安装器、只读检查无写入、失败引导不执行、恢复不确定状态不被算作成功。依赖 T015、T016。
- [ ] T019 [US1] 在明确提供的 Debian 12 x86_64 测试宿主使用本次材料验证真实 enforce、首次及三次重复、三次代理启停或更新、活跃消费者拒绝替换、合法更新和失败恢复，核对其他容器标识／启动时间／状态及其他策略未被初始化操作改变；结果写入 `docs/validation/deploy-logging-host-debian12.md`，没有目标环境则保持未完成，不操作用户已有生产 Stack。依赖 T018。
- [ ] T020 [US1] 在明确提供的 Ubuntu 24.04 x86_64 测试宿主执行与 T019 相同的真实加载、重复、代理操作、更新及失败矩阵，将平台独立结果写入 `docs/validation/deploy-logging-host-ubuntu2404.md`；不得用 Debian、Docker 容器内文件测试或本机模拟替代。依赖 T018，与 T019 可在不同已授权测试宿主独立执行。
- [ ] T021 [US1] 由维护者在允许中断的两种目标测试宿主各进行一次正常重启，按 `scripts/validate_host_init.py` 的 before／after 契约先核对内核再运行任何初始化，确认无需手工加载即可启动代理；将 boot_id、首次检查顺序和结果补入 `docs/validation/deploy-logging-host-debian12.md`、`docs/validation/deploy-logging-host-ubuntu2404.md`，缺少真实重启证据不勾选。依赖 T019、T020。

**检查点**：T018 形成宿主准备的本地实现增量；T019—T021 齐备才满足故事的完整支持矩阵与成-001，不把本地完成冒充完整故事完成。

## 阶段四：用户故事二——按需要控制日志量（优先级一）

**目标**：默认安静且重要事件可见，四种等级与摘要间隔明确，多进程和外部程序不绕过策略，不改变网络行为及退出。

**独立验收**：受控相同事件序列四等级矩阵、1／60／300 秒摘要、十分钟默认安静、来源失败及活动阻断恢复、状态与退出契约；苹果只在适用环境另验租约和诊断通道。

### 契约与边界测试

- [X] T022 [P] [US2] 在 `tests/contracts/config.rs`、`tests/container_environment.rs` 添加文件／环境等价、旧配置与空环境默认、四种精确小写等级，以及间隔“60；范围 1—86400”的边界用例；拒绝 null、浮点、布尔、零、负数、越界、未知等级和原始值泄漏，确认在创建运行资源前失败。依赖 T004。
- [X] T023 [P] [US2] 在 `tests/logging_contract.rs` 新建独立日志契约测试：枚举“error、warn、info、debug”过滤、每一现有事件分类、保留既有事件字段并增加 level、序列化前过滤、单调时间间隔及延迟不补发、四等级敏感标记零泄漏；不得把探测、状态更新或清理移入日志条件。依赖 T004，与 T022 分文件。
- [ ] T024 [P] [US2] 在 `src/platform/diagnostics.rs` 的测试模块定义苹果诊断反例：版本 1、4096 字节帧、总 64 帧中的 1 帧启动保留槽与 63 帧普通队列；按 `contracts/logging.md` 验证四等级满队列淘汰／合并、固定饱和计数、摘要不被淘汰、输出恢复后的限频汇总及关键失败独立保留；覆盖未知帧、错误归属、超限、拥塞、不可写、EOF、父方退出及最多一秒排空且计入原十五秒预算，不得改接 stderr 租约。依赖 T004，与 T022、T023 分文件。

### 实现与集成

- [X] T025 [US2] 在 `src/logging.rs`、`src/lib.rs` 定义 LogLevel／LogPolicy，并在 `src/config.rs` 增加文件和容器环境转换；约束为“只接受精确小写值，不提供 off／trace，不把非法值自动修正”，默认 info、60，间隔 1—86400，容器空值省略，单次实例策略不可热改，原生文件模式不消费宿主日志环境。对应需-007、需-008、需-010；依赖 T022、T023。
- [X] T026 [US2] 在 `src/logging.rs`、`src/domain.rs` 实现类型化事件等级、统一安全 JSON 输出和现有 Event 构造迁移；保留 timestamp、event_type、node_id、worker_id、state、reason、elapsed_ms 并新增 level，序列化前过滤，按 `contracts/logging.md` 审计全部事件，未知新增事件不能默默采用默认等级，不整体切换 tracing 输出格式或改 StatusSnapshot。对应需-009、需-012、需-017、需-018；依赖 T025。
- [X] T027 [US2] 在 `src/main.rs`、`src/config.rs` 统一参数、配置、隐蔽辅助进程及致命错误的安全出口，所有允许等级保留错误，改用字段和固定安全原因而不输出未知原始值、完整 JSON、URL、凭据或错误链；保持帮助无副作用、机器输出及原退出码。对应需-007、需-017、需-018；依赖 T026。
- [X] T028 [US2] 在 `src/service.rs` 将 Linux 监督／控制事件接入显式策略，Bootstrap 携带同一有效配置；runtime_summary 仅为 debug，第一次可立即输出，随后独立单调截止时间按 now 加间隔，等待或无变化来源刷新不重复信息日志；不改 100 毫秒循环、结构检查、健康周期和退避。对应需-009—需-012；依赖 T026、T027。
- [X] T029 [US2] 在 `src/netd/workers.rs` 核对并整合受管理隧道／工作进程安全诊断，原始外部输出不公开透传，普通候选失败不逐个作为警告，关键失败按阶段可定位；若改为采集管道则持续排空、限制保留字节、纳入停止回收，不让日志读者持有额外控制或隧道句柄。对应需-009、需-011、需-012、需-017；依赖 T028。
- [ ] T030 [US2] 在 `src/platform/diagnostics.rs` 实现版本 1、4096 字节帧、总 64 帧中 1 帧启动事实保留槽和 63 帧普通队列的诊断通道；生产者非阻塞，严格按 `contracts/logging.md` 的 debug／info／warn／error 淘汰合并表执行，以四个固定等级饱和计数器记录损失、恢复后至多每 60 秒按最高损失等级汇总；启动事实只传实际监听信息，父方用可信配置重建，不能传完整配置。关键退出阶段／原因独立进入可信失败结果，诊断 EOF 无控制权限。对应需-011、需-012、需-017；依赖 T024、T026。
- [ ] T031 [US2] 在 `src/platform/controller.rs`、`src/platform/launcher.rs`、`src/platform/process.rs` 显式传递实例策略及诊断 FD，仅继承到预定消费者，保持 `src/platform/lease.rs` 的 stderr 锁租约用途和关闭顺序，不用环境变量自动继承策略，不让日志读者延长控制端寿命。对应需-011、需-012；依赖 T030。
- [ ] T032 [US2] 在 `src/platform/supervisor.rs`、`src/platform/coordinator.rs`、`src/platform/controller.rs`、`src/platform/process.rs` 接入父方白名单重建、优先启动槽位及统一过滤，可信时间／实例归属由父方补充；为仅含回收布尔量的退出收据补充类型化安全阶段／原因结果，不能只靠日志队列保留关键错误。停止排空最多 1 秒且计入原十五秒总预算，最终输出不可写也不得无限阻塞回收或改变业务状态，协调错误不写入租约文件。对应需-009、需-011、需-012、需-017、需-018；依赖 T031。
- [X] T033 [US2] 在 `.env.example`、`config.example.json`、`deploy/config.container.example.json`、`deploy/compose.registry.yaml` 补齐 VAP_LOG_LEVEL、VAP_LOG_SUMMARY_INTERVAL_SECONDS 及文件字段的默认与显式转发，保留原凭据、镜像能力和只读挂载；仅提供日志轮转说明，不新增日志管理服务。对应需-008、需-019；依赖 T025。
- [X] T034 [US2] 在 `tests/integration/startup.rs`、`tests/integration/candidates.rs`、`tests/integration/lifecycle.rs`、`tests/integration/failover.rs` 将依赖调试事件的现有测试显式配置 debug，并保持原行为断言；另设默认安静场景，不删除事件正对照或把平台跳过算作通过。对应需-012、需-018；依赖 T028、T029。
- [X] T035 [US2] 在 `scripts/validate_docker.py`、`scripts/test_docker_publish.py` 将缓存恢复及候选否定判断改用状态、持久材料和独立 debug 正对照，不把 info 日志缺失当作没有候选行为；保持认证、地区、时区、故障阻断恢复和停止资源回收要求。对应需-012、需-018；依赖 T028、T033、T034。
- [X] T036 [US2] 在 `scripts/validate_docker.py` 增加 `--case logging`，保留 smoke／all 语义，按本次归属标签创建与清理受控资源；实现四等级、1／60／300 秒摘要和十分钟默认安静场景，比较同一事件序列，记录实际镜像身份、计数、周期和结果而不保存凭据正文。对应成-003、成-004、成-006；依赖 T035。
- [ ] T037 [US2] 在 `src/platform/lease.rs`、`src/platform/process.rs`、`tests/contracts/platform.rs` 添加租约、错误帧、四等级满队列优先级、启动独立槽位、饱和损失计数、父方强退、输出不可写、控制失联退休及读者回收回归；验证排空至多 1 秒且包含在原十五秒停止预算中，关键退出原因不因队列合并丢失；真实部分仅在适用平台执行，不新增完整苹果生产支持承诺。对应需-011、需-012、需-018；依赖 T032。
- [X] T038 [US2] 在 `docs/deployment.md`、`docs/dockerhub-release.md`、`src/main.rs` 的中文帮助说明中同步四等级、默认 60 秒、范围 1—86400、容器空值与原生文件差异、重建后生效及日志轮转的不同作用；未知等级不能声称支持，RUST_LOG 不覆盖显式策略。对应需-019；依赖 T033、T036。

### 独立验收与证据

- [X] T039 [US2] 执行 `tests/container_environment.rs`、`tests/logging_contract.rs`、原契约／集成回归及 `scripts/validate_docker.py --case logging`，确认十分钟默认安静、四等级和频率、敏感标记以及降低日志后故障阻断与退出相同；结果写入 `docs/validation/deploy-logging-runtime.md`，没有强制 AppArmor 的本机结果单独注明限制。依赖 T029、T036、T038。
- [ ] T040 [US2] 在适用苹果环境执行 `src/platform/diagnostics.rs`、`src/platform/lease.rs`、`src/platform/process.rs` 及对应真实控制子进程回归，将失联、拥塞、原租约持有和全部描述符回收证据写入 `docs/validation/deploy-logging-macos.md`；无环境或未执行的用例保持未完成，不由 Linux 结果替代。依赖 T037。

**检查点**：T039 形成 Linux／Docker 日志增量，T040 单独覆盖涉及苹果资源模型的回归。US2 不依赖 US1 的宿主重启证明，可用既有已加载策略的受控环境独立验证。

## 阶段五：用户故事三——启动后立即了解有效配置（优先级二）

**目标**：监听成功后输出一次安全摘要，包含真实内部端口和主要设置，明确服务已启动与出口就绪的区别。

**独立验收**：非默认配置、有／无出口、端口占用及预检失败、四等级与敏感标记；真实监听后五秒内一次摘要，失败零条，后续出口变化不重发。

### 契约与时机测试

- [X] T041 [P] [US3] 在 `tests/logging_contract.rs`、`tests/contracts/cli.rs` 先添加启动白名单、实际字段值、信息等级过滤、敏感标记及状态仍为单一 JSON 的契约测试；不允许凭据路径、用户名、URL、host_port 或 public_ip 混入摘要。依赖 T026、T027。
- [X] T042 [P] [US3] 在 `tests/integration/startup.rs` 添加真正绑定后五秒内一次摘要、端口占用／预检／非法配置零成功摘要、无出口 ready=false、后续提升／恢复不重发以及停止清理的用例；不能使用临时 bind 后 drop 或内部 Ready 当作启动成功。依赖 T004、T034，与 T041 分文件。

### 实现与集成

- [X] T043 [US3] 在 `src/logging.rs` 实现独立 StartupSummary 白名单：instance_id 为“来自本实例可信启动上下文”的 UUID，ready 为“初次绑定后为 false”；listen_address 为 IPv4、port 为“实际监听端口，不是宿主映射端口”、protocol 固定 socks5、listen_scope 只为“container_internal 或 process_local”；countries 为“规范化国家代码；空数组表示全部”，timezone 为有效名称，max_connections 为正整数实际值，日志字段为实际策略，data_dir／runtime_dir 为经校验绝对路径，authentication_enabled 为“不携带用户名、密码或凭据内容”的布尔；禁止整体序列化 AppConfig。对应需-013、需-015、需-017；依赖 T041。
- [X] T044 [US3] 在 `src/socks.rs` 分离网关一次真实绑定和持有同一 TcpListener 的服务循环，使用 local_addr 提供实际地址；保留非回环认证、连接上限、活动出口故障阻断和取消清理，不能二次 bind 或用日志是否成功控制服务生命周期。对应需-014、需-016；依赖 T042。
- [X] T045 [US3] 在 `src/main.rs`、`deploy/entrypoint.sh`、`src/service.rs`、`src/platform/controller.rs` 的可信启动配置交接中显式区分容器内部与原生进程监听上下文，覆盖容器环境和文件两种模式；标记仅用于显示，不改变授权或网络行为，不从任意环境猜测宿主端口、不引入 Docker socket。对应需-015；依赖 T043、T044。
- [X] T046 [US3] 在 `src/service.rs` 的 Linux 控制启动中接管真实绑定结果后、进入出口验证前生成一次 startup_summary 信息事件，ready=false、state=waiting，执行相同 LogPolicy 过滤；确保监听前失败无成功事件，退出／恢复不重发，打印异常不妨碍原取消和回收。对应需-013、需-014、需-016；依赖 T045、T028。
- [ ] T047 [US3] 在 `src/platform/controller.rs`、`src/platform/supervisor.rs`、`src/platform/diagnostics.rs` 接入苹果真实监听后的摘要事实，使用独立 1 帧保留槽，父方按实际监听信息和已有可信配置重建完整摘要，不把完整配置装入 4096 字节帧；不能用提前 Ready 代替 bind，保留 stderr 租约和关键失败收据，摘要字段不扩大诊断权限。对应需-013—需-017；依赖 T032、T044、T045。
- [X] T048 [US3] 在 `scripts/validate_docker.py` 的 logging 场景和 `tests/container_environment.rs` 补充容器两种配置模式、未发布端口／不同宿主映射、非默认地区／时区／连接数的摘要对照，逐字段核对与实际配置一致；info 有摘要、warn／error 无摘要，出口及缓存恢复行为保持原正证据。对应成-005、成-006；依赖 T036、T046。
- [X] T049 [US3] 在 `docs/deployment.md`、`docs/dockerhub-release.md` 更新 startup_summary 样例和解释，明确内部监听端口、认证仅布尔、默认信息等级显示、严格等级隐藏、未就绪时 status 返回原语义；示例不得包含真实账号、密码、令牌、宿主公网可达承诺。对应需-019；依赖 T046、T048。

### 独立验收与证据

- [X] T050 [US3] 执行 `tests/integration/startup.rs`、`tests/logging_contract.rs`、`tests/contracts/cli.rs` 及 Linux／Docker 容器摘要场景，将成功一次、失败零条、接收及输出可用时五秒时机、非默认字段、四等级、敏感标记和旧状态契约写入 `docs/validation/deploy-logging-startup-linux.md`；只声明实际 Linux／Docker 结果，不等待苹果环境或据此宣称苹果通过。依赖 T048、T049。

- [ ] T051 [US3] 在适用苹果环境执行 `src/platform/controller.rs`、`src/platform/diagnostics.rs` 及对应 `tests/contracts/cli.rs` 的真实绑定、启动保留槽和租约回归，核对摘要一次、监听前失败零条、可用输出时五秒、拥塞不淘汰摘要、关键失败独立保留及资源回收，将证据写入 `docs/validation/deploy-logging-startup-macos.md`；无环境则保持未完成，不能阻塞独立的 T050 或最终 Docker 验收。依赖 T040、T047。

**检查点**：T050 为 Linux／Docker 启动摘要验收，T051 为苹果验收，各自独立标记。Linux 分支只依赖共享日志接口和 Linux 实现，不依赖 T024、T030—T032、T037、T040、T047、T051 等苹果专用任务；苹果尚未验证不得被 Linux 结果冒充。

## 阶段六：收尾与跨故事核验

**目标**：使新配置、部署材料、源码归档、既有契约和验证结论一致；不自动公开发布。

- [X] T052 在 `README.md`、`docs/deployment.md`、`docs/dockerhub-release.md`、`specs/001-vpngate-auto-proxy/contracts/config.md`、`specs/002-rename-cli-vap/contracts/deployment.md` 同步新增配置与一次宿主准备定位，核对全部示例仅调用实际支持的入口、Portainer 不操作其他服务、日志及摘要含义一致；保留历史证据原文和既有仅 vap 产品入口约束。依赖 T017、T038、T049。
- [ ] T053 在 `scripts/package-docker-release.py`、`scripts/prepare_docker_publish.py`、`scripts/test_release_package.py` 复核最终新增源码、契约、部署材料和许可的完整白名单及冻结输入；生成材料与实际 image_id／策略 SHA／程序 SHA 相符，不让文档更新后归档遗漏相关说明，不把本地生成候选当作远端发布。依赖 T014、T048、T052。
- [ ] T054 运行 `Cargo.toml` 对应的 fmt、clippy、Rust／Python 完整适用测试及 `.github/workflows/docker-publish.yml` 语法核验，将数量、忽略原因和结果记入 `docs/validation/deploy-logging-summary.md`；Linux 平台专用测试按原适用门槛执行，苹果原生未验独立保留，不以平台跳过算通过；本任务不依赖 T040、T047、T051。依赖 T050、T053。
- [ ] T055 对最终冻结的新镜像执行 `scripts/validate_docker.py` 的受控 smoke 和 logging 场景，在可用强制 AppArmor 目标引擎核对认证、缓存、地区、时区、故障阻断恢复、十分钟日志量、摘要和十五秒停止回收；报告绑定到 `docs/validation/deploy-logging-summary.md`，无目标引擎保留该范围未完成。此为独立 Linux／Docker 交付门禁，不依赖苹果专用任务或全平台汇总。依赖 T039、T050、T054。
- [ ] T056 使用 `scripts/package_host_init.py`、`scripts/validate_host_init.py` 复核最终宿主材料、单条引导说明与已完成的 T019—T021 证据绑定；最终宿主代码或策略若较受测材料改变则在对应目标重验，否则明确记录未变化的受测输入摘要；把两发行版 enforce／重启、其他服务对照和剩余限制汇入 `docs/validation/deploy-logging-summary.md`。依赖 T021、T053、T054。
- [ ] T057 按 `specs/003-deploy-logging/quickstart.md` 进行全平台汇总，核对 `docs/validation/deploy-logging-macos.md`、`docs/validation/deploy-logging-startup-macos.md` 和宿主矩阵，确认无源码部署、日志和所有平台证据一致；未获授权只记录待发布，不创建标签、上传或推送。依赖 T051、T055、T056；本项只决定全平台完成结论，不是 T055 或仅 Linux 镜像发布的前置。
- [X] T058 在 `specs/003-deploy-logging/tasks.md`、`specs/003-deploy-logging/spec.md`、`docs/validation/remaining-work.md` 更新实际完成及剩余验证范围，逐项复核需-001—需-019、成-001—成-006和章程；未提供目标宿主、维护者重启或苹果环境的任务保留未勾选，明确区分代码实现、本地交付、平台验收及公开发布。依赖可用证据，不以任务末尾为由绕过未完成前项。

## 依赖与执行顺序

### 阶段和故事依赖

```text
T001／T002 基线
       ↓
T003／T004 安全验证基础
       ├── US1：T005—T018 本地宿主增量 → T019／T020 目标宿主 → T021 重启
       └── US2：T022—T039 Linux／Docker 日志；T030—T032 → T037 → T040 苹果回归
                    ↓ 统一日志、诊断与配置已就绪
             US3：T041—T046、T048—T050 Linux 真实监听及摘要；T047／T051 苹果分支
                    ↓
             T052—T058 收尾与证据核验
```

US1 的纯安装器与 US2 的 Rust 核心没有实现依赖。US3 的 Linux 分支依赖 US2 共享配置及 Linux 输出，不依赖苹果诊断通道；苹果分支另外依赖该通道及租约回归。独立验收不要求初始化流程同步执行。US1 的真实宿主重启不阻塞本地 US2／US3 开发，但会阻塞“宿主支持矩阵全部完成”的结论。

### 关键任务链

| 增量 | 依赖链 |
| --- | --- |
| 宿主本地最小交付 | T001 → T003 → T005 → T007 → T008 → T009 → T010 → T011 → T012 → T013 → T014 → T015 → T018；T006 支持打包，T016 支持证据，T017 支持使用说明 |
| Linux 日志 | T002 → T004 → T022／T023 → T025 → T026 → T027 → T028 → T029 → T034 → T035 → T036 → T039；T033／T038 提供环境与说明 |
| 苹果日志 | T024 → T030 → T031 → T032 → T037 → T040；依赖共享 LogPolicy 和安全事件接口 |
| Linux 启动摘要 | T041 → T043、T042 → T044，汇入 T045 → T046 → T048 → T049 → T050；不依赖苹果任务 |
| 苹果启动摘要 | T032／T040 及共享 T043—T045 → T047 → T051，独立保留验收状态 |
| Linux／Docker 交付 | T050 → T052 → T053 → T054 → T055；不存在苹果专用任务的传递依赖 |
| 全平台支持结论 | 各平台证据及最终材料分别绑定，经 T057 汇总，T058 按实际证据更新状态 |

同一故事内按任务依赖执行：先失败测试，再模型和校验，再状态服务及接口，最后独立验收。跨故事复用文件 `src/main.rs`、`src/service.rs`、`scripts/validate_docker.py`、`docs/deployment.md` 等必须串行编辑，不能因故事不同视为无冲突。

## 可并行机会与示例

标 `[P]` 的 10 项是可在其明确前提完成后并行的候选；此外不同已授权目标宿主可各自验证，但不自动派发或取得操作权限。

| 故事 | 可并行示例 | 必须等到的前提 |
| --- | --- | --- |
| US1 | T005 安装器事务测试与 T006 独立打包测试 | T003 已完成；分别编辑 test_host_init.py 和 test_host_init_package.py |
| US2 | T022 配置测试、T023 独立日志契约、T024 诊断反例 | T004 已完成；三个任务不编辑相同文件 |
| US3 | T041 摘要／CLI 契约与 T042 真实启动用例 | 共享日志核心、T034 旧调试测试迁移完成；两任务不编辑相同测试文件 |

T001 和 T002 可并行只读建立各自基线；T004 可与 T003 分文件完成。不得将写同一 host-init.py 的状态、路径和事务任务或共享的 service.rs 改动并行执行。

## 实施策略

### 最小可交付范围

先完成阶段一、二及 US1 的 T005—T018，得到版本化安装器、单次引导入口、隔离事务证明和交付说明；它是本地实现最小增量。只有 T019—T021 真实矩阵通过后才能将相应宿主范围标为完整支持。最小增量不要求改动网络运行架构或完整苹果后端。

### 增量交付

随后完成 US2 的 Linux／Docker 日志、US3 的 Linux 摘要及 T055 最终镜像门禁，可形成仅 Linux／Docker 范围的交付，不等待苹果环境。苹果日志和摘要任务独立实现与验收，未通过不得声明苹果支持；T057 只汇总全平台完成状态，不作为 Linux 交付前置。

最后冻结实际材料、绑定平台证据、核对快速指南和剩余工作；目标环境不足时继续完成不依赖环境的代码与本地验证，将具体目标操作留给维护者，不重启现有业务、不默默放宽验收、不自动提交或发布。

## 需求与任务追踪

| 需求 | 主要任务 | 成功标准 |
| --- | --- | --- |
| 需-001、需-002 | T005—T008、T011、T012、T016、T018—T021 | 成-001、成-002 |
| 需-003、需-004、需-005 | T008—T016、T018—T021、T056 | 成-001、成-002 |
| 需-006 | T012、T015、T017、T052、T057 | 成-001 |
| 需-007、需-008 | T022、T025、T027、T033、T038、T039 | 成-003、成-004、成-006 |
| 需-009、需-010 | T023、T026、T028、T036、T039 | 成-003、成-004 |
| 需-011、需-012 | T024、T028—T032、T034—T037、T039、T040、T055 | 成-003、成-004、成-006 |
| 需-013、需-014、需-015、需-016 | T041—T051 | 成-005 |
| 需-017、需-018 | T023、T026、T027、T029—T032、T035、T037、T041、T043、T048、T050、T055 | 成-006 |
| 需-019 | T017、T033、T038、T049、T052、T057 | 成-001、成-005 |

**任务统计**：共 58 项；准备 2 项、基础 2 项、US1 17 项、US2 19 项、US3 11 项、收尾 7 项。已完成项见各任务勾选；真实目标验收独立保留。格式检查、故事标签、路径及依赖必须在任务生成时核对；本清单不代表实现或验收已经执行。

## 本次分析修订记录

2026-10-16：修订 I1（拆分平台依赖）、U1（诊断满队列规则）、I2（发布范围）、I3（首次与重复验证顺序）。新增独立苹果摘要验收 T051，原 T051—T057 顺移为 T052—T058；全部任务、图、表及内部引用同步，保留所有未完成状态。Linux／Docker 最终门禁 T055 不依赖苹果专用任务；全平台汇总 T057 仍须真实苹果证据。


2026-10-16 用户最新指示：苹果端暂时不处理，本轮提交与推送以 Linux／Docker 为范围。苹果专用实现、原生验收及当前苹果测试失败均保留，不据 Linux／Docker 结果标为完成。
