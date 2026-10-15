# 快速启动与验收指南

## 容器单一环境配置增量（US8、成-014）

首次复制 `.env.example` 为 `.env`，填写发布镜像、地区、时区等，执行 `python3 scripts/cloud_deploy.py init` 初始化独立凭据，完成宿主所需的生产策略加载后，直接 `docker compose up -d`。无需用户 JSON。修改 `.env` 后仍执行 `docker compose up -d`，通过重新创建容器应用变化；旧 JSON 部署保持原方式。具体命令及版本前提见[发布镜像使用说明](../../docs/dockerhub-release.md#发布镜像的使用与启动)。

独立验证：`cargo test --locked --test container_environment` 检查转换、默认、非法参数及真实无网络命令行。使用临时环境文件执行 `docker compose --env-file 文件 config --format json`，核对没有 build 或 JSON 绑定，只有持久缓存卷、独立凭据及受限能力；分别核对有/无专用策略。真实镜像在无网络、无能力及只读根目录下运行 `container-config`，非法环境的默认入口须返回 2，不能启动服务；正向配置仍须经既有容器和正式发布门槛。完整网络、容量及远端发布不由本增量转换测试替代。

2026-10-15 收敛实施：T117 已限制实际发布目标只能解析至 Docker Hub，并覆盖构建前拒绝；首次真实标签发布仍按第六节执行 T111、T112。本地增量结果、历史云端结果及各平台未完成矩阵分别见[当前验收汇总](../../docs/validation/summary.md)，不能互相替代。Linux 原生矩阵及苹果恢复仍待收口，不增加 Docker 独立交付的范围。

2026-10-15 当前优先级：先完成 Linux 容器部署，苹果原生完整验收暂后。Debian 12 x86_64 云端容器已通过专用安全策略强制模式下的短试与三十分钟容量；第三版实际部署已从公开来源建立活动出口，服务器本机带认证 SOCKS5 的 HTTPS 请求返回 HTTP 204、客户端退出码为零。离线包的加载、凭据初始化、预检及生命周期命令见[包内说明](../../deploy/cloud/README.md)，实测证据见[云端记录](../../docs/validation/cloud-amd64.md)。个人设备经 SSH 转发的带认证请求也已通过，见[设备结果](../../docs/validation/cloud-amd64-r3-device-user-result.json)；Linux 原生及苹果完整原生任务仍未收口；下文保留原生验收契约。

云端第二版实际启动后，公开来源获取成功但候选数为零。本机实时来源样本的 96 条配置全部使用 `AES-128-CBC` 与 `SHA1`，原严格白名单全部拒绝。第三版提供默认关闭的 Linux 兼容开关，部署者明确启用后才接受完整旧算法组合；脚本、外部文件及端点限制不放宽。第三版云端实际出口与服务器本机客户端请求已验证，节点持续可用性仍不作保证。

## 平台范围变更（2026-10-10）

用户已确认：苹果系统与 Linux 均须原生运行；每个目标系统分别交付一个可执行文件，提供启动、状态查看和停止命令。Linux 验证先使用本机 ARM64 容器，不将其结果等同于 x86_64 验收。

本节优先于本文原有的“首版仅 Linux”范围描述。既有 Linux 实现与验证记录继续保留；苹果系统正式启动路径已接入，但持久崩溃恢复、管理员完整原生运行和故障隔离矩阵尚未验收，不能用在苹果系统中运行 Linux 容器替代。

用户已确认允许预先安装外部隧道程序及必要系统工具；本项目本身只交付一个可执行文件。苹果系统的网络后端仍须通过原生可行性验证，不降低故障阻断、候选隔离和宿主网络保护要求。

2026-10-11，用户确认苹果系统首个原生验收目标为当前电脑：系统 27.0.1（26A434）、ARM64。首轮范围不包含其他系统版本或处理器架构；此决定确定验收范围，不代表完整原生后端已通过验收。2026-10-13 隔离 Linux ARM64 容器内四组三十分钟长测已完成；这不替代目标 Linux 原生、安全模块或苹果原生验收。

本指南是运行与验证契约。程序、配置、容器和安全策略文件已经实现，ARM64 受控容器短试、四组三十分钟长测、真实局域网认证及 x86_64 云端强制安全策略容器验收已有证据；第三版云端公开出口与服务器本机客户端请求也已通过。目标 Linux 原生矩阵和苹果完整原生验收仍缺，不能表述为全部交付通过。当前实际操作说明见根目录 `README.md` 及 `docs/deployment.md`，证据见 `docs/validation/summary.md`。
字段定义见[配置契约](contracts/config.md)，退出与状态见[命令行契约](contracts/cli.md)，
流量边界见[网络契约](contracts/network.md)。

## 一、受支持的验收环境

Linux x86_64，原生基线为 Debian 12 或 Ubuntu 24.04；容器为有根 Docker 和桥接网络。
需要 TUN、网络空间、nftables、OpenVPN 2.6、iproute2、util-linux/setpriv；
构建需要 Rust 1.90 和编译工具链；HTTPS 还需要 CA 证书包及 TLS 运行库。
容器构建会提供对应工具，不依赖宿主安装 Rust。
真实节点试用需要能获取来源并直接连接节点，不要求已有上游代理。

先在受控环境验证，不把公共节点是否在线当作自动测试成功条件。
实现必须提供一个受控 VPN 来源、TCP/UDP 测试服务器、DNS 与检测响应服务，
通过测试服务器内部映射提供符合公网目标校验的测试地址，不把允许任意私网作为测试后门。

原生宿主还须预先允许 IPv4 转发及实例工作网段到外联网卡的转发路径。
先查看 `sysctl net.ipv4.ip_forward`，需要的值为 1；由部署者显式完成宿主准备，
程序不得自动写入全局转发参数。宿主有转发过滤时按实例网段、接口与节点端点设置窄范围允许，
不清空防火墙或修改其默认策略。受控验收使用满足这些前提的专用 Linux 环境，
将准备完成后的网络配置作为前后对照基线。
容器使用下面单独指定的容器内转发参数，不要求应用去更改宿主设置。

## 二、构建与原生启动

在仓库根目录执行，实施后相应文件必须存在：

```sh
cargo build --locked --release
cargo test --locked
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cp config.example.json config.local.json
```

编辑配置，首次本机试用保留 `127.0.0.1:1080`。
局域网使用则设置显式监听地址，例如 `0.0.0.0:1080`，并指定私有凭据文件。
检测链接可替换成多个普通网页，最大次数默认 3；无需配置连续多轮失败阈值。

凭据文件只写测试用或自己的凭据，权限设为 `0600`，不提交仓库。
启动程序初始读取配置/秘密并初始化所需权限，之后主控制和工作进程降权。

```sh
sudo ./target/release/vpngate-auto-proxy run --config ./config.local.json
```

另一终端查看，默认目录如下；如配置改变须同步命令：

```sh
sudo ./target/release/vpngate-auto-proxy status --runtime-dir /run/vap
sudo ./target/release/vpngate-auto-proxy status --runtime-dir /run/vap --json
sudo ./target/release/vpngate-auto-proxy status --runtime-dir /run/vap --check-ready
```

未连接时显示验证中或等待节点，ready 为 false；建立并验证出口后才为 true。
默认监听只允许本机连接；局域网认证必须启用后才能放开监听。

本机无认证回环模式测试：

```sh
curl --socks5-hostname 127.0.0.1:1080 --max-time 15 https://www.gstatic.com/generate_204 -o /dev/null -w '%{http_code}\n'
```

授权局域网客户端将宿主局域网地址与端口填入支持 SOCKS5 的应用，并填写凭据、启用代理端域名解析。
不要求浏览器所有业务可达；检测成功仅表示普通连通性地址可用。

停止：

```sh
sudo ./target/release/vpngate-auto-proxy stop --runtime-dir /run/vap
```

预期 15 秒内退出，无本服务监听或网络资源残留，宿主原有路由与解析设置不变。

## 三、Docker 构建与部署

第三版 x86_64 离线包的实际操作入口为[云端包说明](../../deploy/cloud/README.md)：进入解压目录，依次执行 `bash run.sh load`、`bash manage.sh init`、`bash manage.sh check`、`bash manage.sh up`、`bash manage.sh ready`。当前公开来源使用的旧算法需要部署者在包内 `config.json` 明确启用 `allow_legacy_vpngate_crypto`；默认严格模式继续拒绝。这一路径已在 Debian 12 x86_64 云端取得就绪、出口及服务器本机认证请求结果，见[云端记录](../../docs/validation/cloud-amd64.md)。下面的 `docker build` 和 `docker run` 是源码直接构建部署的另一条操作路径，不能将离线包结果自动视为其独立验收。

```sh
docker build -t vpngate-auto-proxy:local .
```

容器使用配置契约中的固定目录。准备本地配置与凭据，并显式配置局域网监听和认证。
缓存目录由服务在数据卷内初始化，不将秘密写入镜像。

启用 AppArmor 的宿主先加载实施阶段交付的专用 profile：

```sh
sudo apparmor_parser -r -W deploy/apparmor/vpngate-auto-proxy
```

以下示例用于已加载该 profile 的主机；未启用 AppArmor 的主机省略对应选项，
不能靠关闭宿主防护来绕过所需操作检查。

```sh
docker run -d --name vpngate-auto-proxy \
  --cap-drop ALL \
  --cap-add NET_ADMIN --cap-add SYS_ADMIN \
  --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
  --cap-add KILL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
  --device /dev/net/tun \
  --security-opt no-new-privileges \
  --security-opt apparmor=vpngate-auto-proxy \
  --read-only --tmpfs /run --tmpfs /tmp \
  --sysctl net.ipv4.ip_forward=1 \
  --stop-timeout 15 \
  -p 127.0.0.1:1080:1080 \
  -v vpngate-auto-proxy-data:/var/lib/vap \
  -v "$PWD/config.local.json:/etc/vap/config.json:ro" \
  -v "$PWD/credentials.local.json:/run/secrets/proxy_credentials:ro" \
  vpngate-auto-proxy:local run --config /etc/vap/config.json
```

配置以 `deploy/config.container.example.json` 为起点，凭据路径使用 `/run/secrets/proxy_credentials`，数据目录 `/var/lib/vap`、运行目录 `/run/vap`；`listen` 显式设为 `0.0.0.0:1080` 并启用认证。宿主端口默认只发布到回环地址，局域网开放须由部署者显式选择宿主地址。
该命令不需要网页端口、不挂 Docker 套接字、不用宿主网络或全特权模式。
默认配置的回环监听在容器内不能通过普通映射访问，这是默认安全行为；不得自动改成无认证开放。
实施同时提供 `compose.yaml`，与上述权限、配置、数据卷及 15 秒停止宽限一致。

```sh
docker exec vpngate-auto-proxy vpngate-auto-proxy status --runtime-dir /run/vap --json
docker exec vpngate-auto-proxy vpngate-auto-proxy status --runtime-dir /run/vap --check-ready
docker logs vpngate-auto-proxy
docker stop -t 15 vpngate-auto-proxy
```

替换容器复用同一数据卷。来源不可用时未过期缓存仍可恢复，但必须重新验证隧道与出口。
没有可用节点时容器保持运行并退避，状态显示等待，不通过自动重启掩盖问题。

## 四、确定性验收脚本契约

实施阶段交付下列脚本，启动受控服务、保存证据并在失败时返回非零状态。
脚本不得改变宿主无关网络资源，清理自己的测试资源；特权测试只能在专用 Linux 测试环境执行。

```sh
sudo env VAP_NETWORK_TEST=1 scripts/validate-linux.sh --case all
sudo scripts/validate-docker.sh --case all
sudo env VAP_NETWORK_TEST=1 scripts/validate-soak.sh --deployment native --clients 5 --connections 50 --duration-seconds 1800
sudo scripts/validate-soak.sh --deployment docker --clients 5 --connections 50 --duration-seconds 1800
```

5 个受控客户端网络空间代表 5 台设备；每个 10 条连接、每 10 秒至少一次小数据往返。
同时补做一台真实局域网设备访问，确认端口映射和凭据配置。
持续性验收使用真实 30 分钟，不用虚拟时钟代替；调度顺序与退避单元测试可以用受控时钟。

| 场景 | 操作与期望 | 规格依据 |
| --- | --- | --- |
| 启动 | 来源 5 秒内、握手 30 秒内、出口 10 秒内，60 秒内完成首请求，待启用隧道验证后直接提升，不重复连接 | 成-001 |
| 分层与轮转 | 45 候选覆盖不同结果，前三轮覆盖全部且每轮不超过 20、并发默认 2 | 成-002 |
| 隧道与 HTTP 故障 | 停活动隧道或使所有检测响应失败；立即阻断并启动切换，符合条件下 120 秒恢复 | 成-003 |
| 候选隔离 | 持续请求并进行两轮检测，活动出口不变，主机原路由/DNS 不变 | 成-004 |
| 缓存 | 来源故障后重启/替换容器，原获取时间保留，未过期可重新验证，过期/损坏不可使用 | 成-005 |
| 清理 | 端口冲突、权限缺失、危险配置启动失败；正常停止 15 秒内清理；异常终止后核查归属 | 成-006 |
| 命令行 | 无网页完成启动、状态与停止，错误可定位且凭据不出现在输出 | 成-007 |
| 全不可用 | 连续 30 分钟等待，退避 30 至 300 秒，不退出；下一批出现可用节点后恢复 | 成-008 |
| 容量 | 50 连接稳定，第 51 个拒绝，释放一条后可重建，默认两部署分别验证 | 成-009 |
| 检测判定 | 200、空体 204、跳转后 2xx 通过；第 1/2 次成功立即停止；3 次全失败立即切换 | 成-010 |

出口判定另测最大次数 1 和 5、单地址重复抽取、多地址随机选择、非 2xx、TLS 失败、跳转环及总超时。
诊断缓存另测 8 MiB、2,048 条及 512 字节失败说明边界、重复结果覆盖、旧节点淘汰；
损坏、超限或未知版本诊断只被忽略，不影响有效来源恢复或当前节点可用性。
随机测试使用可控种子验证序列和早停，不要求偶然抽样中每个地址必须出现。
TCP 和 UDP 隧道均验证；UDP 不执行 TCP 快速端口检测。

## 五、证据与资源占用

保存脱敏的配置摘要、构建/依赖版本、用例结果、事件、命名空间/接口/规则前后快照，
以及业务网卡和管理网卡的受控抓包。核对业务数据和业务 DNS 未从管理路径直接发出。
公共节点试验另记节点、时间和结果，不用随机公网故障判断受控测试失败。

资源报告分别记录启动、空闲、一个活动加两候选、50 连接下的处理器、常驻内存及峰值。
不预设 1 核或 1 GB 最低预算，也不将无实测数据的资源目标作为已达成结论。
发布前核查 MIT 归属、第三方清单、系统包许可及镜像分发材料，再更新已验证支持矩阵。


## 苹果专用依赖与下一步验收

苹果普通 `run` 已接入原生后端，但需要安装包含 T099 的受保护程序，并在配置中增加以下对象；编号必须来自明确选定的现有非管理员账户，路径须替换为本机已安装依赖与受保护父目录：

```json
{
  "macos": {
    "dependency_manifest": "/Library/Application Support/vpngate-auto-proxy/dependencies/固定版本/dependency.json",
    "runtime_parent": "/private/var/vap/generations",
    "worker_uid": 501,
    "worker_gid": 20
  }
}
```

`runtime_dir` 应位于另一个受保护父目录下并在启动前不存在；`data_dir` 可由首次启动创建，之后必须持续保持所选账户及主组拥有、权限 0700。当前安全重启尚未实现，遇到既有运行目录会拒绝接管；管理员正向运行步骤与证据仍见[待执行事项](../../docs/validation/pending-user-actions.md)。

2026-10-12，用户已接受苹果首版预装带本项目补丁的固定版本外部隧道程序；标准安装版本不能静默替代。当前构建仍位于私有验证目录，尚未形成正式安装产物。真实句柄身份交接的工具、操作和门槛见 [交接身份验证](../../docs/validation/macos-utun-handoff.md)。苹果后端仍未完成；2026-10-13 的隔离 Linux 容器三十分钟验证见[长测记录](../../docs/validation/long-tests-20261013.md)，不代表苹果原生验收。

## 六、地区筛选、时区与版本发布增量验收

对应 US5—US7、成-011—成-013。使用包含本次新增能力的镜像及当前受控脚本，旧 r3 的结果不能替代以下验收。配置详细约束见[配置契约](contracts/config.md)，版本发布见[发布契约](contracts/release.md)。

### 地区与时间的独立验证

在仓库根目录执行：

```sh
cargo test --locked --test region_timezone
cargo test --locked --test contracts region_changes_filter_full_cache_and_refresh_before_scheduling
cargo test --locked --test contracts human_status_uses_instance_timezone_and_old_payload_defaults_to_shanghai
python3 -m unittest discover -s scripts -p test_docker_publish.py
```

预期：省略配置接受全部地区并默认上海；`["JP", "sg"]` 接受日本、新加坡且不接受美国或空国家码；非法代码及非法时区拒绝。含日本、新加坡、美国的完整缓存改变白名单后重新筛选，不修改原缓存。日本、新加坡、纽约、悉尼各冬夏两组样本偏移正确且对应同一时刻；旧状态缺字段按上海显示。纳秒日志的偏移核对兼容本机旧 Python。上述不要求连接真实公网节点。

在现有配置中合并 `"countries": ["JP", "SG"]` 和 `"timezone": "Asia/Tokyo"`，重启后生效；候选数量只代表筛选后的目录，机器时间仍为 UTC。未知但格式合法的地区代码可能导致等待，不会被自动替换为全部地区。

### 受控容器验收

需要有根 Linux amd64 Docker、TUN、项目规定的能力及默认 seccomp。启用 AppArmor 的宿主先加载两个专用策略：

```sh
sudo apparmor_parser -r -W deploy/apparmor/vpngate-auto-proxy
sudo apparmor_parser -r -W deploy/apparmor/vpngate-auto-proxy-fixture
python3 scripts/validate_docker.py \
  --image "${VAP_VALIDATION_IMAGE:?请指定包含新增功能的产品镜像}" \
  --fixture-image "${VAP_FIXTURE_IMAGE:?请指定受控夹具镜像}" \
  --skip-build --require-apparmor
```

预期：完整来源含两个日本节点和一个美国节点，允许日本时只出现两个候选；缓存仍含三个节点。来源失败时保留原获取时间重启并重新验证；随后将白名单改为新加坡，在来源不可用时重启原数据卷，读取到完整缓存但无匹配候选、无新检测和可用出口，不回退。日志偏移符合配置的纽约规则，状态 `timezone` 一致；认证、故障阻断恢复、回环与权限诊断继续通过；临时资源按归属清理。日本、新加坡并列允许及其他时区样本由前述独立测试覆盖，不把本短试表述为实际连接过所有地区。

未启用 AppArmor 的本地引擎可省略强制选项作辅助试验，但必须注明限制，不能替代远端强制策略门槛。此次本地记录见[功能验证](../../docs/validation/docker-features-20261015.json)，新版本三十分钟容量试验未重跑。

### 远端发布验收（T111，待执行）

维护者按[发布说明](../../docs/dockerhub-release.md)在两个公开仓库配置两项密钥和目标仓库变量，先提交并推送本次修订，再选择一个尚未公开的稳定版本标签进行首次真实触发。实际发布具有外部影响，由维护者明确触发；文档校验不会自动推送标签或镜像。

成功后核对：

1. 记录标签、对应提交及 GitHub 工作流运行地址，确认检查、强制策略容器验收、源码附件上传和镜像推送全部通过。
2. 公开下载该版本的源码归档和 `SHA256SUMS`，运行 `sha256sum -c SHA256SUMS`；核对 `validation.json` 明确的环境与验收范围。
3. 用实际仓库及标签执行 `docker pull --platform linux/amd64 账号/仓库:v1.0.0`，通过 `docker image inspect` 核对系统、架构与记录的配置摘要；另行记录仓库清单摘要，不将两类摘要混淆。
4. 普通分支不发布、非法标签在严格校验拒绝、前置失败不推送等负例，与已有自动化合同测试及实际工作流条件对应；注明哪些场景实际在远端执行，未验证的范围保持未完成。
5. 将脱敏结果登记到 `docs/validation/dockerhub-release.json` 后才能将 T111 标为完成。任何失败保持未完成，不覆盖已公开版本，后续修复使用新版本。

历史本地归档保持原内容和摘要。本次只补文档，真实标签发布需从修订后的提交重新冻结材料，不能声称旧归档已自动包含本次补审内容。
