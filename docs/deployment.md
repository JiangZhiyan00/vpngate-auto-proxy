# 部署与排查

2026-10-15 增量状态：地区筛选、实例时区及标签发布准备已实现；发布目标现会在构建前拒绝其他注册表地址。地区及时区的新版本本地容器验证与历史云端容量属于不同产物证据。首次真实 GitHub 与 Docker Hub 发布仍待执行，见[发布指南](dockerhub-release.md)及[当前验收状态](validation/summary.md)。Docker 按已验范围独立交付，苹果未完成项继续后置。

更新：2026-10-14，中国标准时间。当前优先交付 Linux 容器：Debian 12 x86_64 已通过专用安全策略强制模式下的短试与三十分钟容量。Linux 原生目标矩阵、苹果系统完整原生后端仍未完成验收；苹果后端已有部分实现和受控原生实验，当前暂缓其完整验收。容器验证不能代替原生支持。

## 原生准备

安装 Rust 1.90 及编译工具链、TLS 开发库后执行 `cargo build --locked --release`。运行需要 OpenVPN 2.6、iproute2、nftables、util-linux（含 setpriv、nsenter、unshare、mount、umount）、CA 证书和 TLS 运行库。Debian 系构建通常需要 `build-essential pkg-config libssl-dev`，运行通常需要 `openvpn iproute2 nftables util-linux ca-certificates`；实际版本须在目标系统验收。

本项目交付一个程序；控制、网络辅助和工作子进程调用同一文件的内部命令。外部工具仍须预装。启动需要管理员权限，控制进程随后降至用户 10001，工作进程使用用户 10002；两者清空能力。避免与系统已有这两个身份的其他服务共用专用环境。

部署者须事先准备 `net.ipv4.ip_forward=1`，并允许工作地址池 `10.231.0.0/16` 到节点端点的必要转发；程序不修改全局转发参数，不清空宿主防火墙，不改变默认路由或系统解析。已有路由与工作池重叠时启动拒绝。使用专用 Linux 环境建立网络基线后再测试；不要照抄宽泛的允许全部转发规则。

复制根目录 `config.example.json` 到 `config.local.json`，首次保留 `127.0.0.1:1080`。如需其他设备连接，改成显式局域网地址或 `0.0.0.0:1080`，并设置 `credentials_file`；缺少认证时拒绝启动非回环监听。

凭据文件示例结构如下。请自行设置用户名和足够长的随机密码，文件权限设为 `0600`，不要提交或写入镜像。

```json
{"username":"自定义用户名","password":"自行生成的随机密码"}
```

```sh
chmod 600 credentials.local.json
sudo ./target/release/vpngate-auto-proxy run --config ./config.local.json
sudo ./target/release/vpngate-auto-proxy status --runtime-dir /run/vap --json
sudo ./target/release/vpngate-auto-proxy stop --runtime-dir /run/vap
```

示例运行目录 `/run/vap` 与数据目录 `/var/lib/vap` 不同于配置省略字段时的默认路径；管理命令始终使用实际配置路径。配置相对路径以配置文件所在目录解析。

## 容器部署

使用包含环境适配功能的 Docker Hub 镜像时，按[拉取与启动说明](dockerhub-release.md#发布镜像的使用与启动)首次配置 `.env` 并初始化凭据，随后直接执行 `docker compose up -d`；不需要用户 JSON。`deploy/compose.registry.yaml` 清除本地构建和 JSON 挂载，启动时将显式传入的参数转换为容器临时配置。下列源码构建命令继续采用旧文件模式。两种方式复用同一份能力、凭据、缓存和回环发布配置。

准备根目录 `credentials.local.json` 并设为 `0600`。默认容器配置 `deploy/config.container.example.json` 在容器内部监听 `0.0.0.0:1080`，强制使用只读秘密 `/run/secrets/proxy_credentials`；宿主发布地址默认仍是 `127.0.0.1`。

```sh
docker compose config --quiet
docker compose build
docker compose up -d
docker compose exec proxy vpngate-auto-proxy status --runtime-dir /run/vap --json
docker compose stop
```

局域网发布须显式设置 `VAP_BIND_ADDRESS` 为宿主局域网地址，再执行启动命令。需要自定义来源或检测参数时复制容器示例到 `config.local.json`，设置 `VAP_CONFIG_FILE=./config.local.json`。保持容器监听与只读秘密路径一致。凭据、数据卷和临时目录不得打进镜像。

镜像使用 Alpine 3.22、OpenVPN 2.6、必要网络工具、TLS/CA 和信号转发程序。健康检查查询本地控制通道存活，不检查出口就绪，等待节点不会触发应用退出。根文件系统只读，`/run` 和 `/tmp` 使用临时目录，数据写入独立卷。

部署先移除全部能力，仅添加以下九项：

| 能力 | 用途 |
| --- | --- |
| `NET_ADMIN` | 创建工作接口、路由和限定防火墙规则 |
| `SYS_ADMIN` | 创建独立网络/挂载空间及挂载私有进程视图 |
| `SETUID`、`SETGID`、`SETPCAP` | 降低子进程身份并清空能力 |
| `KILL` | 终止本实例已核对身份的不同用户子进程 |
| `CHOWN`、`DAC_OVERRIDE`、`FOWNER` | 初始化和清理不同用户所属的私有目录、套接字及网络空间文件 |

已在受控 ARM64 容器和 Debian 12 x86_64 云端容器运行这套能力集；后者通过专用安全策略强制模式下的短试与正式容量。2026-10-15 在本机 Linux 虚拟机的隔离实验中逐项移除能力，并核对真实子进程的继承、许可、有效、边界和环境能力集合；当前受控矩阵没有可删除项，九项保持不变，见[发布准备](release/docker-amd64-20261015.md)。该实验不替代目标原生矩阵。保留默认系统调用过滤及禁止新增权限，不使用全特权、宿主网络、宿主空间或容器引擎套接字。原生环境不得通过关闭系统安全机制修复启动失败。

启用应用安全模块的 Linux 宿主须加载专用策略后再使用覆盖文件：

```sh
sudo apparmor_parser -r -W deploy/apparmor/vpngate-auto-proxy
docker compose -f compose.yaml -f deploy/compose.apparmor.yaml up -d
scripts/validate-docker.sh --require-apparmor
```

专用策略已按 Debian 12 x86_64 云端实际内核审计修复，强制实施下短试和三十分钟容量通过。验证记录见[云端验收](validation/cloud-amd64.md)。装载方法参照[容器官方文档](https://docs.docker.com/engine/security/apparmor/)，系统调用过滤保留[引擎默认策略](https://docs.docker.com/engine/security/seccomp/)。策略只授权所需实例路径与挂载操作，不修改全局默认策略；其他目标内核仍需独立验证。

## x86_64 离线容器部署

优先使用已整合修复及来源算法兼容开关的第三版离线包，按[包内说明](../deploy/cloud/README.md)加载镜像和专用策略，再运行 `bash manage.sh init`、`bash manage.sh check`、`bash manage.sh up`。管理入口自动选择安全策略覆盖文件，使用固定项目名，避免换包目录后意外创建另一个缓存卷。初始化不覆盖有效凭据，不在终端输出密码。运行配置允许编辑，程序、镜像与策略仍核对交付摘要。当前公开来源的旧算法需由部署者显式在配置中开启，默认仍拒绝。

`bash manage.sh status` 查询状态，`bash manage.sh ready` 验证出口就绪；等待节点时普通查询可成功，而就绪查询返回 3。`bash manage.sh stop` 使用十五秒停止宽限并保留卷，`bash manage.sh logs` 查看最后一百行日志。状态、停止与日志不依赖镜像归档是否还存在。编排启动与停止行为依据[官方启动说明](https://docs.docker.com/reference/cli/docker/compose/up/)及[停止说明](https://docs.docker.com/reference/cli/docker/compose/stop/)。

| 部署方式 | 当前证据 |
| --- | --- |
| Debian 12 x86_64 云端容器 | 专用安全策略强制模式下短试及三十分钟容量通过；第三版公开出口就绪，服务器本机带认证 SOCKS5 的 HTTPS 请求通过 |
| 本机隔离 Linux ARM64 容器 | 受控代理、候选、恢复、生命周期与长测通过 |
| Linux 直接运行进程 | 有隔离容器内直接运行证据，目标原生系统完整矩阵待验收 |
| 苹果原生 | 继续保留已实现代码与实验，完整恢复和验收暂后 |

云端第三版的公开出口与服务器本机客户端结果见[实际部署记录](validation/cloud-amd64.md)；个人设备经 SSH 转发的带认证 HTTPS 请求也已通过，见[设备结果](validation/cloud-amd64-r3-device-user-result.json)。原生或其他系统版本不由容器结果推定通过。

## 认证设备与状态排查

客户端使用 SOCKS5，填写宿主局域网地址、发布端口、用户名和密码，并启用代理端域名解析。命令行验证可使用 `curl --socks5-hostname 地址:端口 --proxy-user 用户名:密码 检测地址`；避免在共享终端历史记录中留下真实密码，可改用权限为 `0600` 的客户端配置文件。

`status --json` 标准输出只有一个状态对象，不含凭据、证书或业务目标。`ready=false` 时业务拒绝转发；普通查询仍可成功。`--check-ready` 未就绪返回 3；通信失败返回 1，配置错误返回 2，停止超时或清理失败返回 4。退出正常返回 0。

来源获取与节点恢复有各自退避。数据卷内保存节点来源、配置摘要、分层检测结果及有界诊断；缓存过期或损坏会拒绝复用，历史成功不会直接恢复为当前可用，重启必须重新验证。停止保留数据卷；不要使用删除卷的命令当作普通停止。

检测地址默认多个候选随机选择，每轮最多三次；可在 `exit_check_urls` 配置多个普通地址。活动 HTTP 检测默认每十秒一次、总预算五秒；独立结构检查每秒执行。任一轮失败先撤销活动、关闭旧连接，重新验证后恢复，旧连接不会迁移。

收到中断或终止信号等同正常停止，默认内部清理预算十二秒、总时限十五秒。异常退出后仅在进程启动身份、进程组、网络空间及归属记录全部匹配时回收；发现不明进程或资源会拒绝启动并报告，不按任意进程号强制清理。

公共节点试用与受控验收分开记录。公共节点不可用时先看来源错误、端口/隧道/出口失败分类及下一次调度时间；不要把端口可达或隧道握手成功当作代理出口正常。


## 地区筛选和时区

在部署配置中设置 `"countries": ["JP", "SG"]` 即仅选择日本、新加坡节点，省略或 `[]` 接受全部。筛选会重新应用到缓存恢复，不匹配且无健康活动出口时等待，不回退到其他地区；此前合规选出的健康活动出口沿用原维持规则，断开后不从范围外恢复；修改后重启。设置 `"timezone": "Asia/Tokyo"` 可调整日志时区，默认上海；支持夏令时，状态及缓存保持 UTC，容器环境变量 TZ 不覆盖配置。示例文件保持默认全部地区。

通过 GitHub 版本标签发布 Docker Hub 镜像见[操作说明](dockerhub-release.md)。公开发布目前固定为 Linux x86_64。
