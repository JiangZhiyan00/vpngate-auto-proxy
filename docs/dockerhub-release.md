# 版本标签自动发布

推送严格的三段版本标签（如 `v1.0.0`）时，`.github/workflows/docker-publish.yml` 构建并发布 Linux x86_64 镜像。普通提交、分支推送和预发布标签不会发布镜像。每次正式发布都推送版本标签及 `latest`，两者指向同一份已验收镜像。`latest` 随发布更新，补发旧版本也会更新它；需要固定版本时使用明确的版本标签。

在 GitHub 仓库的“设置 → 密钥和变量 → 操作”中配置：

| 类型 | 名称 | 内容 |
| --- | --- | --- |
| 密钥 | `DOCKERHUB_USERNAME` | Docker Hub 登录账号 |
| 密钥 | `DOCKERHUB_TOKEN` | 有目标镜像仓库写权限的访问令牌 |
| 变量 | `DOCKERHUB_IMAGE` | 完整仓库名，如 `你的账号/vpngate-auto-proxy`，使用小写 |

先在 Docker Hub 创建目标仓库，并将项目源码仓库设为公开。工作流需要仓库允许工作流写入发布附件；任务声明了相应的内容写权限。首次执行前确认这些配置已保存。

目标变量只接受小写的“命名空间/仓库”，不填写域名、端口、标签或摘要。命名空间不能含点，也不能为 `localhost`，避免被容器引擎解析成其他注册表；仓库名可以含点。`ghcr.io/proxy`、`localhost/proxy` 和显式的 `docker.io/example/proxy` 均会在构建前拒绝。构建、验收及最终推送使用同一已校验目标，登录固定使用 Docker Hub。

代码提交并推送后，执行：

```sh
git tag -a v1.0.0 -m '发布 v1.0.0'
git push origin v1.0.0
```

成功后可拉取 `你的账号/vpngate-auto-proxy:v1.0.0` 或 `你的账号/vpngate-auto-proxy:latest`；省略标签也使用 `latest`。部署时继续使用项目提供的能力、只读文件系统、凭据及专用安全策略配置，不能仅凭镜像拉取成功判断代理已就绪。

工作流先执行格式、静态检查、普通测试及工具回归，再构建固定架构镜像，收集并核验完整依赖来源、系统包源码及原始声明。随后在专用 AppArmor 策略下运行受控容器短试，冻结源码归档，将对应归档、摘要和验收记录上传至同名 GitHub 版本发布，最后登录 Docker Hub，先推送版本标签，成功后为同一镜像添加并推送 `latest`。版本标签推送失败时不更新 `latest`；若仅 `latest` 推送失败，版本镜像可能已公开，应核对两种标签的状态。任何前置步骤失败均不推送镜像。这里的短试不等同于每个版本重新执行三十分钟容量验收。

工作流动作须采用核验时的官方最新稳定版，并固定到对应完整提交摘要。2026-10-15 已核对并更新代码检出至 [v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1)、镜像登录至 [v4.6.0](https://github.com/docker/login-action/releases/tag/v4.6.0)；现用输入兼容，均使用第 24 版运行环境。每次发布前重新核对官方最新稳定版，升级后检查参数兼容性和工作流语法。

GitHub 版本发布中的 `vpngate-source-v1.0.0.tar.gz` 包含项目源码、锁定的完整依赖原包、系统包来源、配方及声明。按附件 `SHA256SUMS` 核验；离线恢复依赖的步骤见归档内说明。公开源码附件必须持续可用。

工作流不会自动覆盖已存在的发布附件。若发布在上传附件之后失败，应先核对失败原因、已存在的源码附件及镜像状态；同一版本已公开时不要移动标签或用不同代码覆盖镜像，修复应使用新版本。首次云端工作流尚需在配置密钥后触发，仓库本地测试不能替代 GitHub 与 Docker Hub 的真实发布验证。

## 发布镜像的使用与启动

以下以已经成功发布的 `v1.0.0` 为例，适用于 Linux x86_64、有根 Docker 及编排插件，宿主需要 `/dev/net/tun`。把目标镜像名替换为实际 Docker Hub 仓库。只下载部署文件并拉取镜像，无需安装 Rust 或在服务器构建。

```sh
git clone --branch v1.0.0 --depth 1 https://github.com/JiangZhiyan00/vpngate-auto-proxy.git
cd vpngate-auto-proxy
cp .env.example .env
python3 scripts/cloud_deploy.py init
```

以上复制与初始化只做一次，不要在后续启动时覆盖自己的配置。编辑 `.env`，填写镜像仓库、版本和运行参数；不需要创建 `config.local.json`。部署参数持久保存在 `.env`，新终端无需重新设置环境变量。需要 Docker 编排插件 2.24.4 或更新版本；覆盖文件清除构建及用户 JSON 挂载，只拉取镜像。

初始化生成独立随机凭据，保存在权限为 `0600` 的 `credentials.local.json`，已有有效凭据不会被覆盖。自行查看和保管该文件，客户端使用其中的用户名和密码。镜像版本应与下载的部署文件版本一致。`manage.sh` 是离线包入口，不适用于此镜像仓库部署方式。

`.env` 常用配置示例：

```dotenv
VAP_IMAGE=你的账号/vpngate-auto-proxy:v1.0.0
VAP_BIND_ADDRESS=127.0.0.1
VAP_PORT=1080
VAP_COUNTRIES=JP,SG
VAP_TIMEZONE=Asia/Shanghai
VAP_MAX_CONNECTIONS=50
VAP_ALLOW_LEGACY_VPNGATE_CRYPTO=false
```

`VAP_COUNTRIES` 留空表示全部；国家及检测地址列表用逗号分隔。`VAP_SOURCE_URL`、`VAP_EXIT_CHECK_URLS` 留空采用程序默认。现有数字配置字段使用大写 `VAP_` 名称，例如 `VAP_CANDIDATE_CONCURRENCY=2`、`VAP_HEALTH_INTERVAL_SECONDS=10`；默认值及约束见[配置契约](../specs/001-vpngate-auto-proxy/contracts/config.md)。布尔仅接受 `true`、`false`，非法参数在创建网络资源前拒绝。启动时自动生成临时 JSON，不在宿主维护此文件，不读取宿主代理环境。

默认严格算法模式可能拒绝来源中的旧算法节点；若明确接受兼容方案，可将 `.env` 中的 `VAP_ALLOW_LEGACY_VPNGATE_CRYPTO` 改为 `true`，详见[部署说明](deployment.md)。代理密码仍由独立凭据文件挂载，不放进环境变量。

在启用 AppArmor 的 Debian 宿主，首次加载生产专用策略：

```sh
sudo apparmor_parser -r -W deploy/apparmor/vpngate-auto-proxy
```

首次配置完成后，每次启动只需：

```sh
docker compose up -d
```

本地缺少指定版本时自动拉取。未启用 AppArmor 的宿主在 `.env` 中将 `COMPOSE_FILE` 改为 `compose.yaml:deploy/compose.registry.yaml`；这不构成强制安全策略验收。启动保留现有能力约束、只读根目录、凭据秘密挂载和缓存数据卷。

检查出口就绪及日志：

```sh
docker compose exec -T proxy vap status --runtime-dir /run/vap --json --check-ready
docker compose logs --tail 100 proxy
```

就绪命令返回 `0` 且 `ready=true` 才表示出口验证成功；等待节点返回 `3`，容器启动或健康检查通过不等于出口就绪。默认只向宿主回环地址发布 `127.0.0.1:1080`。本机带认证测试如下，按提示输入凭据文件中的密码，预期返回 `HTTP 204`：

```sh
curl --socks5-hostname 127.0.0.1:1080 --proxy-user proxy \
  --max-time 20 --silent --show-error --output /dev/null \
  --write-out 'HTTP %{http_code}\n' https://www.gstatic.com/generate_204
```

其他电脑可通过 SSH 本地转发访问，或在 `.env` 中设置 `VAP_BIND_ADDRESS` 为宿主局域网地址后执行 `docker compose up -d`；客户端仍须填写上述代理凭据并使用代理端域名解析。停止和重新启动使用以下命令，保留缓存卷：

```sh
docker compose stop
docker compose up -d
```

修改 `.env` 的地区、时区等参数后执行 `docker compose up -d`，编排会根据环境变更重新创建容器；`restart` 不重新读取 `.env`，不能用于应用这些变更。升级时使用新版本对应部署文件，在 `.env` 更新镜像版本，执行 `docker compose pull proxy` 及 `docker compose up -d`；不要同时运行两个实例管理同一数据卷。旧镜像尚不识别环境配置模式，应升级到包含该功能的发布版本，或继续使用旧 JSON 方式。
