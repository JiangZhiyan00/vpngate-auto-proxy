# Repository Guidelines

## 项目结构

本项目自动获取并验证 VPNGate 节点，通过 `vap` 提供 SOCKS5 代理。

- `src/`：配置、节点评分、调度、代理及存储；`src/platform/` 实现平台隧道与网络控制，`src/netd/` 实现网络守护进程。
- `tests/contracts/`、`tests/integration/`：契约与集成测试；`tests/fixtures/` 存放受控测试环境，`examples/` 存放平台探针。
- `scripts/`：部署、验收与打包工具；`deploy/`：容器入口、部署配置和安全策略。
- `specs/`：功能规格与任务；`docs/`：部署说明、验收证据及第三方材料。

## 构建、测试与开发

使用 `rust-toolchain.toml` 固定的 Rust 1.90.0；构建需系统编译工具链及 TLS 开发库。

```sh
cargo build --locked --release --bin vap
cargo run --locked --bin vap -- help
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
python3 -m unittest discover -s scripts -p 'test_*.py'
```

以上依次用于发布构建、查看命令、格式检查、静态检查、Rust 测试和脚本测试。原生启动前复制 `config.example.json` 为 `config.local.json`，按 `docs/deployment.md` 准备依赖和网络权限，再运行 `sudo target/release/vap run --config ./config.local.json`。

## 编码风格与命名

遵循 Rust 2024 版及现有模块边界，使用四空格缩进，由 `rustfmt` 统一格式。函数与模块采用 `snake_case`，类型采用 `PascalCase`，常量采用 `SCREAMING_SNAKE_CASE`。静态检查不得产生警告；项目默认禁止不安全代码，平台底层例外须有明确的安全依据。

## 测试规范

使用 Rust 内置测试框架、`proptest` 和 Python `unittest`。测试名称应描述触发条件及预期行为；脚本测试采用 `test_*.py`。新增契约或集成子模块须在对应入口文件显式注册，并保留平台条件编译。

提交前运行上述检查，为行为变更补充回归测试；当前未设置覆盖率百分比门槛。特权网络测试须另获明确授权并在专用环境运行，例如 `VAP_NETWORK_TEST=1 scripts/validate-linux.sh --case us3 --duration-seconds 15`；短时验证不能替代三十分钟稳定性验收。

## 提交与合并请求

近期提交使用简短中文动宾描述，例如“实现节点综合优选、故障恢复与后台探索”。每次提交聚焦一个可审查的变更。

合并请求应说明问题、行为变化、关联任务或问题，以及验证命令和结果；涉及平台网络或部署时注明平台、权限条件和未验证范围。配置或命令变化应同步更新示例与文档，验收证据归档到 `docs/validation/`。

## 配置与安全

不得提交凭据、`.env`、本机配置、运行缓存或日志；参考 `.gitignore`。面向局域网开放代理时必须配置认证。修改隧道、路由或故障恢复逻辑时，维持出口验证和故障阻断约束。
