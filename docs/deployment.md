# 部署与排查

2026-10-15 增量状态：地区筛选、实例时区及标签发布准备已实现；发布目标现会在构建前拒绝其他注册表地址。地区及时区的新版本本地容器验证与历史云端容量属于不同产物证据。首次真实 GitHub 与 Docker Hub 发布仍待执行，见[发布指南](dockerhub-release.md)及[当前验收状态](validation/summary.md)。Docker 按已验范围独立交付，苹果未完成项继续后置。

更新：2026-10-14，中国标准时间。当前优先交付 Linux 容器：Debian 12 x86_64 已通过专用安全策略强制模式下的短试与三十分钟容量。Linux 原生目标矩阵、苹果系统完整原生后端仍未完成验收；苹果后端已有部分实现和受控原生实验，当前暂缓其完整验收。容器验证不能代替原生支持。

## 原生准备

新交付只提供 `vap`，旧命令没有兼容别名。先使用 `vap help` 或 `vap help status` 查看中文操作说明；产品包/库、镜像、策略、数据目录身份保持原值。

### Linux 无覆盖安装

先从明确选定的发布/构建材料获得程序 SHA256，在管理员终端执行以下命令，替换源的绝对路径及预期摘要：

```sh
sudo python3 scripts/install-vap.py install \
  --source /绝对路径/vap --sha256 选定材料中的64位小写摘要 \
  --install-dir /usr/local/bin
vap help
```

实际和有效用户都须为管理员。目标目录须已存在、root:root、0755；祖先链由管理员管理，不可被组或其他用户写入，没有链接或特殊权限。源须为 1 字节至 64 MiB 的独立普通文件，不能有链接、危险权限或组/其他用户写权限；属主只允许 root，或管理员调用环境明确的非零 SUDO_UID。安装从同一描述符核验快照及摘要，不执行候选，不复制扩展属性、访问控制列表或能力。安装目录及 PATH 任一同名节点均拒绝，包括重复安装；不自动创建或修正目录，不提供强制覆盖参数。PATH 空项、相对项、不可信链接及无法核验目录也拒绝。

管理员通过 sudo 调用时，`SUDO_UID=0` 是有效值，仍只允许 root 源文件；只有合法非零值才扩展允许的源属主。此字段不改变目标目录权限、摘要或禁止覆盖的检查。

旧入口退休必须作为单独明确操作，先用原管理流程正常停止所有所属实例。只有可信历史安装记录、对应发布材料和可复核正常停止/回收证明齐备，才可执行：

```sh
sudo python3 scripts/install-vap.py retire \
  --entry /usr/local/bin/vpngate-auto-proxy \
  --installation-record /受保护目录/installation.json \
  --artifact /受保护目录/release.json --stopped-proof /受保护目录/stopped.json
```

证据格式及消费者核对范围见[退休证据契约](../specs/002-rename-cli-vap/contracts/deployment.md#实现的退休证据格式)。手工旧部署没有可信记录时拒绝自动退休，不补造历史、不按文件名删除。退休只移除已证明归属的指定公开节点；记录、来源、备份及历史受保护程序保持原状。退休成功后再无覆盖安装新程序，才可报告升级完成。现有旧部署没有被本轮测试自动认定为可退休。

退休路径仅支持 `/usr/local/bin`、`/usr/bin` 或 `/opt/<应用>/bin` 中的旧公开文件；实际父目录必须匹配，不扫描或进入其中的备份、数据和历史子目录。`<应用>` 不能是 backup、backups、data、history、versions（不区分大小写）。目录位置符合约束也必须继续通过完整归属及停止证明核验。

### 苹果受保护安装

苹果继续采用既有受保护程序安装及依赖部署流程。构建产物为 `target/release/vap`，内部受保护安装生成的记录和返回路径 basename 为 `vap`；固定父目录及版本摘要目录不变。核验返回路径后，将其所在目录加入 PATH，再运行 `vap help`；不创建旧名链接或包装器。普通 `cargo install` 仅供开发验证，不能替代管理员安装及真实后端验收。苹果完整验收仍后置。

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
sudo vap run --config ./config.local.json
sudo vap status --runtime-dir /run/vap --json
sudo vap stop --runtime-dir /run/vap
```

示例运行目录 `/run/vap` 与数据目录 `/var/lib/vap` 不同于配置省略字段时的默认路径；管理命令始终使用实际配置路径。配置相对路径以配置文件所在目录解析。

## 容器部署

### 一次宿主策略准备

包含宿主准备附件的新版本提供独立安装器，不需要为了准备策略克隆源码仓库。旧版本附件没有此入口，不能把未发布功能当作 `latest` 已有能力。

在所选版本的官方 GitHub 发布中查看 `host-setup-command.txt`，复制其中完整的一条命令到宿主终端。它在管理员私有目录下载固定版本的 `vap-host-init-vX.Y.Z.py`，先核对预期摘要，再执行；校验失败不会执行下载内容。信任起点是官方发布说明，摘要不是独立签名。安装器只准备 `/etc/apparmor.d/vpngate-auto-proxy`，不安装代理、不启动容器、不修改或重启其他服务。

目标矩阵为 Debian 12／Ubuntu 24.04 x86_64、真实 systemd 宿主、本机有根 Docker、已启用 AppArmor 及 `/dev/net/tun`，需要 Python 3.10 以上及标准系统工具。缺少依赖或启动链不完整时明确拒绝，由管理员补齐；不通过关闭防护或使用全特权容器回退。两种发行版的真实加载与重启验收独立记录，当前本地文件测试不能替代它们。

准备通过后，在 Portainer 仅部署或更新代理服务，保留已有秘密、设备、只读目录、能力和 `apparmor=vpngate-auto-proxy` 配置。日常同版本启动无需重新加载策略；服务开始监听与出口就绪不同，仍须运行 `vap status --runtime-dir /run/vap --json --check-ready`。

保留已校验安装器用于重复核对，以下路径须替换为该文件的绝对路径：

```sh
sudo python3 /受保护目录/vap-host-init-vX.Y.Z.py --check
```

`--check` 完全只读，不创建锁、登记或加载策略。重复默认初始化在版本、摘要和 enforce 一致时跳过加载。无登记但已有完全相同官方策略时默认拒绝；停止仅使用此策略的代理后，管理员可明确执行 `--adopt`。未知字节和本地修改不能接管。升级时使用已校验的新版本安装器及 `--update-from v旧版本`，绑定原登记；需要替换策略时存在活动或无法确认的消费者均拒绝，工具不自行停止它们。策略字节完全相同的受管版本更新无需重新加载。

退出码为 0 检查通过、1 已明确失败、2 参数无效、4 恢复不确定。退出 4 时保留 `/var/lib/vap-host/transaction.json`，按安全失败阶段处理，不能删除登记后强行重新初始化。正常宿主重启后的持久性须在专用目标宿主独立验证；安装器不执行重启。

使用包含环境适配功能的 Docker Hub 镜像时，按[拉取与启动说明](dockerhub-release.md#发布镜像的使用与启动)首次配置 `.env` 并初始化凭据，随后直接执行 `docker compose up -d`；不需要用户 JSON。`deploy/compose.registry.yaml` 清除本地构建和 JSON 挂载，启动时将显式传入的参数转换为容器临时配置。下列源码构建命令继续采用旧文件模式。两种方式复用同一份能力、凭据、缓存和回环发布配置。

准备根目录 `credentials.local.json` 并设为 `0600`。默认容器配置 `deploy/config.container.example.json` 在容器内部监听 `0.0.0.0:1080`，强制使用只读秘密 `/run/secrets/proxy_credentials`；宿主发布地址默认仍是 `127.0.0.1`。

```sh
docker compose config --quiet
docker compose build
docker compose up -d
docker compose exec proxy vap status --runtime-dir /run/vap --json
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

优先使用已整合修复及来源算法兼容开关的第三版离线包，按[包内说明](../deploy/cloud/README.md)加载镜像和专用策略，再运行 `bash manage.sh init`、`bash manage.sh check`、`bash manage.sh up`。管理入口自动选择安全策略覆盖文件，使用固定项目名，避免换包目录后意外创建另一个缓存卷。初始化不覆盖有效凭据，不在终端输出密码。运行配置允许编辑，程序、镜像与策略仍核对交付摘要。该旧版离线包的默认值仍为 false；2026-10-16 后新增的 Linux／Docker 默认兼容行为见下节，不改变已发布包。

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

## 日志等级与启动摘要

本功能需要包含日志配置的新镜像；修改配置后重新创建或启动实例，旧公开镜像不会自动获得新字段。

原生文件可设置 `log_level` 和 `log_summary_interval_seconds`；容器环境模式对应以下参数：

```yaml
environment:
  VAP_CONFIG_MODE: environment
  VAP_LOG_LEVEL: info
  VAP_LOG_SUMMARY_INTERVAL_SECONDS: "60"
```

等级只接受精确小写 `error`、`warn`、`info`、`debug`，默认 `info`，显示所选等级及更严重事件。默认保留启动、停止、出口提升和恢复等生命周期，以及来源失败、活动出口失效等警告；普通候选详情、成功健康检查和周期摘要属于 `debug`。摘要间隔默认 60 秒，范围为 1—86400 秒整数；调试首条可以立即输出，随后不补发错过的周期。日志设置不改变实际健康检查、调度、退避或出口状态。

容器空值采用默认；原生文件不读取宿主 `RUST_LOG` 或同名环境变量。未知等级、空白拼接、非整数或越界间隔会在创建运行网络资源前拒绝。没有关闭错误输出的静默等级，也不支持热更新。编排环境变更后执行 `docker compose up -d --no-deps proxy`，普通 `restart` 不重新读取编排变量。已有 Portainer Stack 中仅更新代理服务，保留其他服务。

默认信息等级下，实际监听成功后输出一次 `startup_summary`，例如：

```json
{"event_type":"startup_summary","level":"info","state":"waiting","ready":false,"config":{"listen_address":"0.0.0.0","port":1080,"protocol":"socks5","listen_scope":"container_internal","countries":["JP"],"timezone":"Asia/Tokyo","max_connections":20,"log_level":"info","log_summary_interval_seconds":60,"data_dir":"/var/lib/vap","runtime_dir":"/run/vap","authentication_enabled":true}}
```

这是省略通用时间和实例字段的展示样例。完整日志保留时间、实例及事件上下文；地区空数组表示全部。摘要不包含用户名、凭据路径、密码、来源或检测地址。地址和端口是容器内部实际监听，宿主映射端口由编排决定；没有发布端口时不能据此判断宿主或公网可访问。`ready=false` 表示仍在等待已验证出口，须独立查询状态。出口提升、切换和恢复不重发启动摘要，失败启动没有成功摘要。

`warn`／`error` 会隐藏信息等级摘要，状态查询仍独立有效；不能把无摘要或无候选调试日志当作实例死亡或没有检测。日志输出受限时可能丢失诊断，业务仍按原安全规则阻断、退休和回收，不因等待日志延长停止预算。

日志轮转限制保存量，日志等级控制产生量，两者不同。可在代理服务单独配置轮转，勿为此修改整个 Stack：

```yaml
logging:
  driver: json-file
  options:
    max-size: "10m"
    max-file: "3"
```


## VPN Gate 算法兼容默认值（2026-10-16 源码修订）

新版 Linux／Docker 在配置省略时默认 allow_legacy_vpngate_crypto=true；容器环境未设置或设为空字符串也采用 true。只接受已实现的完整 AES-128-CBC／SHA1 组合，不扩大算法列表，不放宽脚本、外部文件、压缩、证书及端点校验。

需要严格模式时，在环境模式设置 VAP_ALLOW_LEGACY_VPNGATE_CRYPTO="false"，或在文件模式设置 allow_legacy_vpngate_crypto=false。显式 false 始终优先，不会被默认值覆盖；更新镜像不会修改用户已有配置。苹果原生默认仍为 false，兼容算法尚未支持，不因本次改动增加支持承诺。

本修订尚未发布，旧镜像仍需显式设置 true 并重新创建服务才能启用兼容。


## 活动出口检查频率

新版默认每 60 秒对活动出口做一次网络可用性检查，单次总超时仍为 5 秒；检查不重叠。容器环境模式可设置 VAP_HEALTH_INTERVAL_SECONDS="60" 和 VAP_HEALTH_TIMEOUT_SECONDS="5"，文件模式使用 health_interval_seconds 和 health_timeout_seconds。间隔必须为可表示的正整数秒且严格大于超时；省略或容器空值采用默认，显式旧值 10 仍保持 10。修改环境后重新创建服务生效。

默认 60 秒将正常运行中的检查频率降低为旧默认的六分之一，代价是仅表现为出口不可达的故障可能等待约一个周期再开始确认，之后还需检测耗时与调度。隧道／工作进程结构检查仍按原有每秒周期执行，首次出口验证也不等待此周期。此参数与 Dockerfile 的 30 秒本地实例健康检查、日志摘要间隔相互独立，不延迟已发现故障后的阻断。

已发布镜像也支持此配置项，可先在 Portainer 服务环境中设置 VAP_HEALTH_INTERVAL_SECONDS="60" 并重新创建服务；新的默认值尚未发布。
