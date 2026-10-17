# 自动节点代理

自动获取节点列表，在隔离隧道内验证实际出口，通过本机的 SOCKS5 入口服务授权设备。出口故障时先阻断旧连接，再重新验证替代节点；无节点时保持运行并退避。

当前优先交付容器部署。Debian 12 x86_64 云服务器已在专用安全策略强制模式下通过容器短试及三十分钟、五客户端、五十连接容量验收；第三版实际部署已通过公开出口检测和服务器本机带认证的代理请求。Linux ARM64 隔离容器另有代理、候选调度、故障恢复和长测证据。个人设备经 SSH 转发的带认证请求也已通过；原生进程部署的完整目标矩阵仍待验收；苹果原生后端正在实现，本阶段优先级降低。

新交付的唯一程序名称为 `vap`，不提供旧命令兼容入口。目标交付为苹果系统和 Linux 各自的一个可执行文件，允许预装外部隧道程序与系统依赖。Rust 可跨平台编译，但路由、隔离和权限需要各平台独立实现。

## 构建与命令

构建需要 Rust 1.90、系统编译工具链和 TLS 开发库。Linux 服务需要 OpenVPN 2.6、iproute2、nftables、util-linux、CA 证书及管理员权限。运行目录应位于本机文件系统。

```sh
cargo build --locked --release --bin vap
# Linux：按部署说明核验摘要后无覆盖安装；苹果使用受保护安装流程。
vap help
cp config.example.json config.local.json
sudo vap run --config ./config.local.json
```

示例配置使用回环监听，运行目录为 `/run/vap`。原生运行前先按[部署说明](docs/deployment.md)准备转发和防火墙。

```sh
sudo vap status --runtime-dir /run/vap --json
sudo vap status --runtime-dir /run/vap --check-ready
sudo vap stop --runtime-dir /run/vap
```

普通状态查询在等待节点时仍成功；就绪检查返回 3，只有真实出口验证成功才返回 0。停止默认十五秒以内完成。帮助、版本和本地状态查询不发起额外外网检测。

## 容器与设备连接

容器部署见[部署说明](docs/deployment.md)，使用独立桥接、只读根文件系统和受限能力。配置与凭据只读挂载，缓存使用数据卷。

从 Docker Hub 拉取已发布版本、初始化凭据及启动的完整命令见[发布镜像使用说明](docs/dockerhub-release.md#发布镜像的使用与启动)，无需在服务器编译 Rust。

首次将 `.env.example` 复制为 `.env`，在其中配置镜像版本、国家筛选、时区和检测参数；初始化凭据并加载宿主所需策略后，日常启动仅需 `docker compose up -d`，停止用 `docker compose stop`。无需维护用户 JSON 或每次设置环境变量；修改 `.env` 后再次执行 `docker compose up -d` 生效。原生及既有文件部署仍支持 JSON。

x86_64 第三版离线包已整合云端验证期间的修复。实际部署发现当前公开来源的配置均使用旧算法，程序原有严格白名单会使候选数为零；该历史第三版提供默认关闭、仅 Linux 可用的显式兼容开关。当前源码已将 Linux／Docker 省略配置时的默认值调整为 true，显式 false 仍启用严格模式；此变更尚未发布，不改变旧包。是否启用及旧版升级步骤见[离线包说明](deploy/cloud/README.md)。解压后先加载镜像及主机所需的专用策略，再使用以下入口：

```sh
bash manage.sh init
bash manage.sh check
bash manage.sh up
bash manage.sh status
bash manage.sh ready
bash manage.sh stop
```

初始化不覆盖已有凭据，启动前自动选择专用策略并校验镜像、配置和权限；停止保留缓存卷。就绪查询未通过出口验证时返回 3。完整操作见[离线包说明](deploy/cloud/README.md)。

仅支持 SOCKS5 CONNECT 和 IPv4；域名须由代理端解析。不支持业务 UDP、IPv6、BIND 或私网目标。面向局域网必须显式监听并配置用户名密码；客户端填写宿主地址、发布端口和凭据。

```sh
curl --socks5-hostname 127.0.0.1:1080 --max-time 15 https://www.gstatic.com/generate_204
```

公共节点由第三方运营，普通检测地址成功不代表任意网站持续可用，也不承诺匿名性或端到端保密性。

## 验证与当前边界

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
scripts/validate-docker.sh --case smoke
```

普通测试不会代替显式授权的特权网络测试。短时 Linux 验证使用 `VAP_NETWORK_TEST=1 scripts/validate-linux.sh --case us3 --duration-seconds 15`，须在专用环境执行。省略持续参数会默认一千八百秒。

详细证据与缺口见[验收汇总](docs/validation/summary.md)、[任务清单](specs/001-vpngate-auto-proxy/tasks.md)。许可证见 [LICENSE](LICENSE)。本次 Docker x86_64 测试版的[第三方声明](THIRD_PARTY_NOTICES.md)及完整来源材料已按具体镜像核验；分发应使用同时包含产品镜像和来源归档的完整发布包。其他平台二进制须另行核验。

容量验收工具提供五个独立客户端、五十连接、配额与资源采样；目标 x86_64 云端容器三十分钟报告已核验归档，详见[资源记录](docs/validation/resources.md)。以下命令仅用于短时流程复核，不替代完整容量试验。

```sh
scripts/validate-soak.sh --deployment docker --clients 5 --connections 50 --duration-seconds 15 --output validation-output/soak-docker.json
```

## 国家/地区与时区

在现有配置文件中加入：

```json
{
  "countries": ["JP", "SG"],
  "timezone": "Asia/Tokyo"
}
```

`countries` 使用 VPNGate 来源中的两字母国家/地区代码，大小写不敏感。上例只从日本和新加坡节点中选取；省略或设置为空数组表示全部地区。筛选也应用于重启恢复的缓存；没有匹配节点且无健康活动出口时等待，不回退到其他地区；此前按当前配置选出的健康活动出口仍遵循原维持规则，断开后才重新选择范围内节点。地区信息来自 VPNGate 的声明，不等同于独立地理位置核验。

`timezone` 使用地区时区名称，例如 `Asia/Tokyo`、`Asia/Singapore`、`America/New_York`、`Australia/Sydney`；默认 `Asia/Shanghai`，自动应用夏令时。运行日志采用配置时区，状态接口时间、缓存和检测记录仍使用统一世界时，状态命令的人类可读时间遵循实例时区，调度与有效期不受显示时区影响。无需修改服务器时区或安装时区数据包；容器的 `TZ` 环境变量不覆盖此配置。修改后重启实例生效，旧配置可以继续使用。

版本标签自动构建与 Docker Hub 发布的配置步骤见[发布说明](docs/dockerhub-release.md)。

## 宿主准备与日志配置增量

包含本功能的新版本发布会提供 `host-setup-command.txt`：首次在宿主执行其中一条固定版本、先校验后运行的命令，准备项目唯一 AppArmor 策略，随后可在 Portainer 直接启动镜像。安装器不要求完整源码、不安装系统依赖、不重启其他容器；仅针对已验证的宿主矩阵声明支持。旧版本没有这些附件，具体边界见[一次宿主准备](docs/deployment.md#一次宿主策略准备)。

新镜像新增 `VAP_LOG_LEVEL`（默认 info，只允许 error／warn／info／debug）及 `VAP_LOG_SUMMARY_INTERVAL_SECONDS`（默认 60，范围 1—86400）。周期摘要只在 debug 输出，不改变健康检查频率。实际监听成功后默认显示一次安全配置摘要；容器内部端口与宿主映射、出口就绪分别判断。修改环境后重新创建代理容器；文件配置使用对应的小写字段。详见[日志和摘要说明](docs/deployment.md#日志等级与启动摘要)。


活动出口检查间隔可通过 VAP_HEALTH_INTERVAL_SECONDS 配置，新版默认 60 秒；检测总超时默认 5 秒，间隔必须大于超时。已发布镜像可显式设置该变量使用 60 秒，无须等待新默认值发布。详见[部署说明](docs/deployment.md#活动出口检查频率)。
