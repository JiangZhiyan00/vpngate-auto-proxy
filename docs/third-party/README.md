# 第三方材料

本目录保存锁定依赖的原始许可/归属文本和实际运行镜像的系统包清单。原文逐字保留，不翻译或替换版权声明。

`inventory.json` 记录锁文件摘要、目标平台、依赖版本、声明表达式、来源地址、原始文本摘要，以及实际镜像标识、架构、系统包版本、上游地址和打包来源提交。清单范围为程序及构建依赖的保守集合，排除只从项目开发依赖可达的包；不等同于最终二进制链接审计，也不能证明未经运行的平台已支持。

复现命令：

```sh
python3 scripts/collect-license-inventory.py --image vpngate-auto-proxy:local
```

需要本地锁定的包元数据及实际运行镜像。工具从包缓存复制现有声明文件，不改写原文，不重新调查参考项目。缺少声明或原始文本时失败，不能静默忽略。

本目录存在本身不表示分发检查已通过。采集工具先将 `distribution_review_complete` 与 `system_package_sources_bundled` 设为假；`finalize_distribution_review.py` 在逐项检查完整来源、原文、锁文件和实际镜像后，才登记带镜像身份及目标范围的通过结论。当前产物应以 `inventory.json` 的 `distribution_review_scope` 和 `docker-review.json` 为准，不能据此推定其他平台二进制也通过。

2026-10-14，运行镜像现随项目声明一起携带本目录 `rust/` 下的原始许可文本。镜像构建后运行 `python3 scripts/collect-license-inventory.py --image vpngate-auto-proxy:local` 重建清单，再运行 `python3 scripts/verify-license-image.py --image vpngate-auto-proxy:local`，核对镜像标识、锁文件摘要、每份依赖原文的路径与内容摘要，以及项目声明。当前 ARM64 本地镜像的 304 份依赖原文和两份项目声明通过核对；这仅证明材料在该镜像中一致，不覆盖上述分发缺口。

2026-10-15 Docker x86_64 发布材料增加了标准库原始版权、全部锁定原包与嵌套声明、实际原生链接库登记和完整系统包来源。来源采集及断网恢复命令如下；输出目录必须在仓库的私有验证目录中，完整来源按发布打包器的白名单进入 `source-materials.tar.gz`：

```sh
python3 scripts/collect_alpine_sources.py --output validation-output/docker-release-sources/alpine
python3 scripts/collect_rust_distribution.py --builder-image vap-cloud-builder-amd64:20261014 --output validation-output/docker-release-sources/rust
python3 scripts/collect_patch_source.py --output validation-output/docker-release-sources/extras
python3 scripts/collect_runtime_notices.py --sources validation-output/docker-release-sources/alpine --image 实际运行镜像
python3 scripts/restore_vendor.py --sources validation-output/docker-release-sources/rust --output validation-output/docker-release-vendor
```

系统来源保留固定提交的完整配方目录，避免遗漏不在 `source` 摘要表中的安装脚本和触发器。原包逐项核对固定 SHA512，crate 原包逐项核对 Cargo.lock 的 SHA256；缺失或摘要不符时失败。公共目录接口限流时使用同一固定提交的完整快照，记录快照摘要，不改用最新版本。

最终镜像构建并重建清单后，再为同一镜像刷新系统来源清单，执行 `python3 scripts/finalize_distribution_review.py --image 实际发布镜像 --sources validation-output/docker-release-sources`。发布打包器会再次核对来源和镜像材料；不把收集到文件等同于检查完成。记录见[Docker 发布准备](../release/docker-amd64-20261015.md)。
