# 第三方来源声明

本项目按 MIT 许可提供。已移植的网络、代理、节点和配置解析模块来自 `Uber-Eins/vpngate2socks`，固定提交为 `a4ba00b3bb081dd3b192c0ea8a1dce56a19886ad`；原 MIT 版权与许可声明完整保存在 `LICENSE`。移植范围和修改记录见 `docs/reuse-map.md`。本项目的许可不替代第三方组件各自的许可。

## Rust 依赖与标准库

实际程序及构建依赖的版本、来源、声明表达式和原文摘要见 `docs/third-party/inventory.json`，对应原始许可文件保存在 `docs/third-party/rust/`。完整发布源码材料还包含 Cargo.lock 中的全部依赖原包及其原始许可、版权、作者或通知文件；这些原文及嵌套归属同时保存在 `docs/third-party/nested/`。少数原包遗漏的工作区许可按其包内固定 VCS 提交补齐，来源地址和提交记录在源码清单中，不使用上游主分支代替。

Rust 1.90.0 标准库的原始 `COPYRIGHT-library.html` 和配套许可文本保存在 `docs/third-party/runtime/rust-1.90.0/`；官方标准库源码组件、摘要和实际构建工具链身份随源码材料提供。标准库包含的第三方组件继续遵循各自声明，不把整个标准库简化为本项目 MIT 许可。

苹果接口适配所使用的固定 `socket2` 0.6.5、`unix-ancillary` 0.6.1、`nix` 0.31.3、`rustix` 1.1.5 及其声明均保留在上述锁文件来源材料中；对应代码存在不表示苹果原生服务已经通过完整验收。

## 容器系统组件与原生链接库

Docker x86_64 产品镜像实际包含的系统包及版本登记在清单中，按各自的上游来源归档。发布源码材料保留固定 Alpine aports 提交中的完整配方目录、安装脚本和触发器，以及 SHA512 核验通过的上游源码或补丁。系统原始声明和动态链接关系保存在 `docs/third-party/runtime/alpine/` 与 `alpine-distribution.json`。

本次程序实际动态链接 OpenSSL 的 `libssl`、`libcrypto`，GCC 的 `libgcc_s` 及 musl；它们分别保留自己的声明和来源，GCC 运行库例外文本也随材料保留。容器中的 OpenVPN、网络工具及其他系统程序继续遵循各自许可。发布完整包时应同时提供其中的 `source-materials.tar.gz`，不要把它替换成只有上游首页地址的说明。

## 外部实验补丁

项目源码中的 `scripts/patches/openvpn-2.6.23-utun-fd.patch` 基于官方 OpenVPN 2.6.23，补丁及其上游上下文遵循该程序原有的第二版通用公共许可证及链接例外，原声明不由本项目 MIT 许可覆盖。固定上游完整归档、摘要和补丁摘要随源码材料的 `extras/` 提供，具体修改边界见 `scripts/patches/README.md`。本次产品镜像不包含该补丁后的苹果实验二进制。

## 本次分发范围

本次发布候选仅为 Linux amd64 的 Docker 产品镜像和完整配套源码材料，不包含受控夹具镜像、能力实验镜像或其他平台的原生二进制。具体镜像与材料核验状态见 `docs/third-party/docker-review.json` 和发布包中的 `release-validation.json`；必须在检查通过后生成发布包。后续改变目标、构建产物或依赖时，应重新核验实际分发内容。
