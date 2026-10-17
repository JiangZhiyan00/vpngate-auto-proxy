# 快速验证：简化部署准备与运行日志

本指南列出完整验收步骤。宿主安装器及只读验证工具、Linux／Docker 日志和启动摘要已实现并完成本地验证；苹果独立诊断通道尚未实现，目标宿主与正式冻结验收仍待执行。命令清单不等同于全部执行结果，实际范围见[验证汇总](../../docs/validation/deploy-logging-summary.md)。首次用户部署使用同版本 Release 生成的一条准备命令，不要求下载完整源码；源码目录仅用于开发验收。

契约：[宿主准备](contracts/host-setup.md)、[日志](contracts/logging.md)、[启动摘要](contracts/startup-summary.md)。

## 一、前提及普通回归

开发环境具备 Rust 1.90.0 及现有构建依赖；Python ≥3.10。宿主真实验证需独立或明确允许中断的 Debian 12／Ubuntu 24.04 x86_64 测试服务器、有根本机 Docker、systemd、AppArmor、隧道设备及已安装工具。不要为本指南重启用户正在运行其他业务的服务器。

在仓库目录执行：

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
python3 -B -m unittest discover -s scripts -p 'test_*.py'
```

预期新增配置、等级、摘要频率、敏感字段、真实监听及安装器事务测试确实被执行且通过；检查测试数量和跳过理由，不能接受零匹配测试作为成功。苹果原生测试只在适用平台执行。普通测试不得自动修改实际宿主策略或重启服务。

## 二、无完整源码的首次准备

先在开发准备阶段为实际版本生成受校验材料；以下变量必须填写实际已验收版本和镜像，不能填移动标签或假摘要：

```sh
RELEASE_TAG=vX.Y.Z
VAP_IMAGE=你的账号/vpngate-auto-proxy:$RELEASE_TAG
python3 scripts/package_host_init.py \
  --tag "$RELEASE_TAG" --image "$VAP_IMAGE" \
  --output "validation-output/host-setup-$RELEASE_TAG"
```

生成接口已实现，正式部署附件尚未发布。打包器要求本地镜像已通过原发布材料校验，拒绝复用旧输出目录，清单绑定实际 image_id 和策略摘要。完整发布器会在其正常准备阶段调用，不要求普通用户自行运行。

用户在同版本官方 Release 中取得 `host-setup-command.txt` 的一条命令，在目标宿主复制执行；命令在 root 私有目录获取安装器，先核对固定预期 SHA256 再执行，不从 main／latest 运行下载内容。文档无需让用户拼接下载、安装、加载三条命令。

以下是独立的干净宿主验收顺序：只下载并校验安装器，不先执行已包含初始化的发布引导命令。将 root 管理目录中安装器的绝对路径记为 HOST_INSTALLER，依次执行一次首次初始化、三次重复初始化，最后只读检查：

```sh
sudo python3 "$HOST_INSTALLER"
sudo python3 "$HOST_INSTALLER"
sudo python3 "$HOST_INSTALLER"
sudo python3 "$HOST_INSTALLER"
sudo python3 "$HOST_INSTALLER" --check
```

预期首次准备完成磁盘、enforce 和持久配置三项；后三次重复不 reload、不改变正确内容；最后 check 不写文件、不加载策略。另行测试干净宿主的只读负例时，--check 应返回 1，不能将它算作初始化成功或混入上述成功顺序。首次无登记但已有完全相同官方策略，应默认拒绝并说明显式 adopt；未知内容不得被 adopt 接管。

## 三、失败与更新边界

在隔离文件测试和专用测试宿主分别验证：

- 普通用户、未知发行版、无根或远端引擎、模块／工具／设备缺失均明确拒绝，原状态不变。
- 错误摘要、截断材料、目标链接、危险目录权限、登记损坏、未知同名文件及内核策略不被覆盖或加载。
- 无副作用解析失败、真实加载失败、加载后核对失败、中断事务、恢复失败均有明确阶段和结果，恢复不确定返回 4。
- 并发准备中只有一个写入者，另一个明确报告锁冲突，不产生两份互相矛盾的完成登记。
- 已有旧版登记但未声明 update-from 时拒绝；匹配旧版本、摘要及无活跃使用者时才允许更新。活跃或无法确认的策略消费者使替换操作失败，安装器不停止它们。

只在专用测试宿主、停止测试代理后使用下列接口验证合法更新：

```sh
sudo python3 "$NEW_HOST_INSTALLER" --update-from "$OLD_RELEASE_TAG"
sudo python3 "$NEW_HOST_INSTALLER" --check
```

宿主其他容器的标识、启动时间、状态和其他策略在准备操作前后一致；不以“后来又启动了”掩盖曾被重启。

## 四、正常重启持久性

已实现的证据工具只读取并记录，不自动执行 reboot、restart 或整个 Stack 更新：

```sh
sudo python3 scripts/validate_host_init.py \
  --phase before-reboot --output validation-output/host-before.json
```

维护者在明确允许中断的专用测试宿主上进行一次正常重启。重连后，**先检查内核和启动配置，不能先运行初始化命令重新加载**：

```sh
sudo python3 scripts/validate_host_init.py \
  --phase after-reboot --before validation-output/host-before.json \
  --output validation-output/host-after.json
```

预期 boot_id 不同，项目策略在调用初始化前已处于 enforce，磁盘与登记摘要对应原版本；随后代理无需手工加载即可启动。Debian 12、Ubuntu 24.04 各自记录结果。准备操作的“持久配置通过”不能代替本步骤。

## 五、Portainer／Compose 的启动与配置

在已有代理服务的 environment 中添加以下配置，其他服务不变：

```yaml
environment:
  VAP_CONFIG_MODE: environment
  VAP_COUNTRIES: JP
  VAP_TIMEZONE: Asia/Tokyo
  VAP_MAX_CONNECTIONS: "20"
  VAP_LOG_LEVEL: info
  VAP_LOG_SUMMARY_INTERVAL_SECONDS: "60"
```

凭据仍须只读挂载到 `/run/secrets/proxy_credentials`，保持项目既有能力、只读文件系统、设备及专用策略，不使用 privileged。已有完整部署示例在实现阶段同步，不在本指南重复整份多服务配置。

项目标准 Compose 示例的服务名为 proxy；用户现有 Stack 中可能为 vap-proxy。终端只操作所选代理，以下以 proxy 为例：

```sh
docker compose up -d --no-deps proxy
docker compose logs --tail 100 proxy
docker compose exec -T proxy vap status --runtime-dir /run/vap --json --check-ready
```

预期启动摘要显示真实内部地址、1080、socks5、JP、Asia/Tokyo、20、info、60 和认证布尔值。未发布端口时不能宣称宿主可访问；状态命令按原 0／3 就绪语义返回，服务监听成功不保证已有出口。不得用整个 Stack 的 down／restart 代替单服务操作。

## 六、四等级、摘要与失败验证

完整受控工具拟增加 `--case logging`，保留 smoke／all 的既有含义，使用项目夹具而非公网节点：

```sh
python3 scripts/validate_docker.py \
  --image "$VAP_IMAGE" --fixture-image "$FIXTURE_IMAGE" \
  --skip-build --environment-config --case logging
```

受控场景预期：

1. 默认 info 持续十分钟，没有 runtime_summary、普通候选详情或成功健康检查刷屏；启动摘要一次，状态查询可用。
2. 四个等级对同一事件序列全部符合等级表；warn／error 不打印信息摘要，仍打印对应警告和错误。
3. debug 摘要 1、60、300 秒分别按频率输出；单调时钟的暂停测试证明延迟不补发、墙上时钟与时区不改变预算。
4. 每个合法启动在真正监听后五秒内一次摘要；端口占用、权限预检失败、非法等级或间隔没有成功摘要。
5. 缓存恢复、地区排除、无节点、来源失败、活动出口阻断及恢复、停止与资源回收保持原行为；状态与持久材料是行为正证据，debug 事件是另外的正对照。
6. 对所有允许日志等级注入受控密码、令牌、私钥和 URL 敏感标记，公开输出零泄漏；公开状态命令仍是单个原格式 JSON。

原生配置文件使用对应 log_level 和 log_summary_interval_seconds，核对与容器一致。修改等级后重新创建或启动实例，不能通过普通 restart 假定编排已读取新的环境设置。

## 七、苹果资源回归与报告

Linux／Docker 验证按 T050、T054、T055 独立完成，不等待苹果专用任务；可交付范围只声明已验证 Linux／Docker 能力。T051 和 T057 分别承担苹果启动验收与全平台总结，不是 Linux 门禁。

在适用的苹果测试环境额外验证：独立诊断通道的错误帧、超限帧、拥塞、父方退出、消费者强退，原租约描述符仍持有正确身份，控制失联仍按原门槛退休。强制填满普通 63 帧队列，分别提交 debug／info／warn／error 与独立启动事实，验证淘汰、合并、固定损失计数和关键失败结果；输出不可写后恢复只限频汇总，启动槽不被普通事件淘汰，停止排空至多一秒且计入原十五秒总预算，所有日志读者和本次描述符按预算回收。普通 Linux 测试不得冒称这些结果。

每份报告分别记录版本、提交、平台、镜像身份／策略摘要、case、实际执行与跳过项、结果和限制。不保存用户配置正文、凭据或整个环境。不把本地文件事务、非强制 AppArmor 引擎、历史云端成功或旧发布材料当作本功能全部通过。
