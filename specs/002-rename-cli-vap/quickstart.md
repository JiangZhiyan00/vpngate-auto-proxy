# vap 命令快速验收

本指南用于新命令复核；2026-10-16 已完成本地 Docker 范围验证，实际结果见[实施记录](../../docs/validation/vap-cli.md)。实现遵循[命令契约](contracts/cli.md)与[部署契约](contracts/deployment.md)。

## 一、前提与普通回归

使用 Rust 1.90.0 和既有构建依赖；Docker 验证优先 Linux amd64、有根引擎及 TUN。仅帮助实验不需要 TUN、特权或外网。原生网络与安装验证须在明确选择的专用目标环境执行；普通组件不能替代目标平台证据。

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
python3 -m unittest discover -s scripts -p 'test_*.py'
```

记录通过、忽略和未执行的实际数量；忽略项不计为平台验收通过。

## 二、干净构建与帮助

在仓库根目录为本轮选取一个尚不存在的专用产物目录，避免现有 target 中旧程序残留：

```sh
export CARGO_TARGET_DIR="$PWD/validation-output/vap-cli-build"
cargo build --locked --release --bin vap
test -x "$CARGO_TARGET_DIR/release/vap"
test ! -e "$CARGO_TARGET_DIR/release/vpngate-auto-proxy"
"$CARGO_TARGET_DIR/release/vap" help
"$CARGO_TARGET_DIR/release/vap" --help
"$CARGO_TARGET_DIR/release/vap" help run
"$CARGO_TARGET_DIR/release/vap" help status
"$CARGO_TARGET_DIR/release/vap" help stop
"$CARGO_TARGET_DIR/release/vap" --version
```

预期全部帮助/版本操作返回 0、中文参数说明完整、用法名称为 vap；总览和详情不展示隐藏内部操作。无子命令、未知操作及隐藏帮助目标返回 2，提示 vap help，不启动服务。`cargo metadata --no-deps --format-version 1` 的产品 bin 目标应只有 vap，库身份保持原值。构建可访问依赖缓存，但帮助阶段必须单独证明无网络和无实例/缓存创建，不能把构建联网误记为帮助行为。

## 三、原生安装与管理

在无同名命令的受控 Linux 安装目录，可使用指定产品的无强制覆盖安装流程，并按文档配置该目录的 PATH：

```sh
cargo install --path . --locked --bin vap --root ./validation-output/vap-cli-install
export PATH="$PWD/validation-output/vap-cli-install/bin:$PATH"
vap help
vap --version
```

生产安装还必须检查已有 PATH 中的同名命令；上述独立目录仅用于受控验证。另准备无关 vap 文件和链接，分别验证安装拒绝且文件内容/链接目标不变；禁止用 --force 获得通过。苹果采用既有受保护安装入口安装新的 vap，使用返回的受保护目录配置 PATH，并核对安装记录、正式派生及权限；普通用户 cargo install 不作为苹果正式后端通过证据。

Linux 生产成功/拒绝应另外通过 `scripts/install-vap.py` 及其 `scripts/test_install_vap.py` 验证，不能由上面的 Cargo 开发安装代替。实施后分别运行普通用户组件回归，以及无网络独立 Linux root 测试容器内的真实安装回归：

```sh
python3 -m unittest discover -s scripts -p test_install_vap.py -v
```

测试的生产目标只使用容器内部独立 root:root/0755 目录（例如本轮专用的 `/opt` 子目录），不能用含可写 `/tmp` 祖先的路径伪装生产目标，也不绑定宿主系统安装目录。root 成功路径和普通用户纯组件/拒绝路径分别记数；测试不得向生产入口传递跳过权限参数。

| 核查情况 | 必须结果 |
| --- | --- |
| 实际或有效用户非 UID 0 | 拒绝，目标不变 |
| 目标 UID/GID、0755、祖先链或源文件约束不满足 | 拒绝，不修正现有节点 |
| 选定源、同一描述符快照及可信摘要匹配，目标空且链受保护 | 安装 vap 为 root:root/0755；不复制额外权限、能力或属性 |
| PATH 含安全 root 链接目录 | 规范化后检查冲突；不得直接执行目录中程序 |
| 同名文件、链接、目录或并发安装 | 原有节点保留；同一新目标至多一个提交成功 |
| 可信旧安装记录、对应发布材料、停止回收证明及节点复核齐备 | 明确退休步骤仅移除选定旧公开入口，再允许无覆盖新安装 |
| 旧记录缺失/伪造/可写，材料不符，节点替换或消费者存活/未知 | 拒绝退休，旧节点不变，不补造历史记录 |
| 用户备份、无关程序和历史受保护版本 | 全部保留 |

旧入口正例只能使用明确标记的受控安装夹具记录；真实旧部署没有可信记录时，结果必须是拒绝或未完成，不能把测试构造记录当作其生产归属证明。

在已准备好的专用原生网络环境运行：

```sh
vap run --config ./config.local.json
```

在第二个终端用相同 PATH 查询及停止：

```sh
vap status --runtime-dir /run/vap --json
vap status --runtime-dir /run/vap --json --check-ready
vap stop --runtime-dir /run/vap
```

运行目录始终按实际配置填写，苹果不能照抄 Linux 路径。等待节点时普通状态成功、就绪查询返回 3；真实验证出口后为 0。无实例的通信失败、重复停止和故障清理沿用旧契约。安装阶段不得自行启动实例；原生矩阵缺少目标环境时单独记为未执行。

以上安装和本地控制验证仅构成 US1 核心实现增量。US1 的实际代理启动、状态、就绪、停止四场景须在下方两模式受控短试完成并登记后才算验收齐备；不以 T009 的本地契约通过声明完整故事交付。

## 四、无网络容器帮助与入口检查

实现后先构建本轮镜像，再设置 VAP_IMAGE 为该实际本地镜像或已验收发布镜像。以下 VAP_IMAGE 由执行者填写，不使用未经确认的随机公开镜像：

```sh
docker run --rm --network none --cap-drop ALL --read-only --user 65534:65534 "$VAP_IMAGE" help
docker run --rm --network none --cap-drop ALL --read-only --user 65534:65534 "$VAP_IMAGE" help status
docker run --rm --network none --cap-drop ALL --read-only --user 65534:65534 "$VAP_IMAGE" --version
docker run --rm --network none --cap-drop ALL --read-only --entrypoint /bin/sh "$VAP_IMAGE" \
  -c 'test -x /usr/local/bin/vap && test ! -e /usr/local/bin/vpngate-auto-proxy && test ! -L /usr/local/bin/vpngate-auto-proxy'
```

预期全部返回 0，不挂载配置/凭据、不创建网络或数据卷。分别运行其余公开帮助与参数错误用例，核对隐藏操作不外泄及退出状态 2。

## 五、实际受控代理与分发核验

使用已准备的受控夹具镜像，在专用 Docker 环境分别验证旧文件模式及环境模式：

```sh
python3 scripts/validate_docker.py --image "$VAP_IMAGE" --fixture-image "$VAP_FIXTURE_IMAGE" --skip-build
python3 scripts/validate_docker.py --image "$VAP_IMAGE" --fixture-image "$VAP_FIXTURE_IMAGE" --skip-build --environment-config
```

强制策略目标宿主增加 --require-apparmor。两模式短试同时补验 US1 的实际启动、状态、就绪、停止四场景，并验证认证拒绝、缓存重启、地区/时区、无匹配等待、出口故障阻断及恢复、停止清理和存活检查。结果按 US1/US3 分别登记，齐备后才认定相应实际交付范围完成。使用环境配置的部署内，`docker compose exec -T proxy vap status --runtime-dir /run/vap --json --check-ready` 必须可用；普通存活检查仍不以 ready=false 判死。

按既有发布流程核对 `/usr/local/bin/vap` 的程序摘要、动态库原文、完整来源和离线包。公开发布需维护者单独触发并取得远端证据，不因本地短试成功而推送。将新提交、程序/镜像摘要、命令、环境、结果和未执行项记录到独立的新验证文件；不得覆盖既有报告或写入秘密。

## 六、追溯与完成条件

| 需求 | 验证范围 | 成功标准 |
| --- | --- | --- |
| 需-001、需-002 | 唯一产物、原生管理及容器真实操作，参数含义保持 | 成-001、成-004 |
| 需-003、需-009 | 新镜像旧路径缺失、安装无兼容入口、当前示例和迁移说明；历史标识例外逐项归类 | 成-003 |
| 需-004、需-005、需-006 | 总览/详情/版本、无网络无配置非管理员、内部命令隐藏及无资源创建 | 成-002 |
| 需-007 | 真实命令行及既有契约中的 0/1/2/3/4 行为，缺参数和未知帮助目标拒绝 | 成-004 |
| 需-008 | 默认入口、健康检查、两配置模式、认证、故障及回收 | 成-001、成-004 |
| 需-010 | 版本身份、安装同名文件/链接/并发冲突和无覆盖证据 | 成-002、成-003 |

本次改名完成不代表旧功能所有平台完成。已完成范围、未执行目标和真实远端发布须分别报告，不以纯帮助测试替代正式生命周期或网络验收。

2026-10-16 已执行范围：干净构建、格式/严格静态、Rust/Python 回归、Linux 独立管理员安装、无网络非管理员镜像帮助、同一程序的 JSON/环境模式短试、完整本地分发准备及来源逐文件核对。未执行范围：苹果管理员完整部署、目标 Linux 原生矩阵、新镜像强制策略及真实发布。本地候选标签 v1.0.1 不代表已创建 Git 标签或公开推送。

收敛修复后的本地候选为 `local-validation/vap:v1.0.2`，详细新摘要及包核对见[收敛验证](../../docs/validation/vap-convergence-20261016.md)。该标签同样仅在本地使用；`vap` 无参数应返回 2，并在标准错误显示中文用法。退休负例须增加 bin 下的备份/数据/历史路径以及嵌套 bin，拒绝时节点和证据均不变。

代码审查修复后的本地候选为 `local-validation/vap:v1.0.3`，结果见[审查修复记录](../../docs/validation/vap-review-fixes-20261016.md)。额外复核 `vap run -- --help` 等分隔符场景返回 2，并在独立管理员环境确认 SUDO_UID=0 安装 root 源成功、其他属主及权限/摘要/覆盖仍拒绝。标签仅用于本地候选，尚未公开发布。
