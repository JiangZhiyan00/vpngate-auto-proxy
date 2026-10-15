# 苹果正式代际调用链验证工具

日期：2026-10-13，中国标准时间。T092 是既有 T057 的验证工具细分，原生实际执行尚未完成。

隐藏入口 `mac-validate` 串联受保护程序和专用依赖核验、正式代际启动、低权限出口检测、活动提升、最多两个并存候选及逆序退休。全部节点先核验公网端点、再生配置摘要与来源时效，之后才允许创建首个接口。活动与候选检测均使用正式工作端；每个候选建立、退休后复核活动代际及其出口检测结果。

输入必须是明确选定的一至三个不同节点及明确提供的检测网址，并携带该输入文件的小写摘要。读取有一兆字节上限，拒绝符号链接、硬链接、摘要变化、未知字段及无效配置。退出报告不包含隧道配置、证书或私钥。来源过期直接拒绝；工具不下载节点、不刷新来源时间、不自动选择公共节点，也不接受旧回环夹具替代公网规则。

无论正常结束、检测失败或收到中断/终止信号，均先撤销再等待所属代际回收。只读比较运行前后的接口名称与索引；不删除未知接口。失败检测保留阶段报告，未确认回收保持失败。整个进程被强制终止及异常重启仍待后续恢复协议验证。

## 用户执行步骤

先按[部署验证](macos-deployment-check.md)构建并安装本次新版主程序，明确选定已有低权限账户，准备受保护短路径父目录，并通过实际降权部署检查。旧安装及专用依赖保留，专用依赖无需重复安装。本次构建摘要与历史安装不同，须使用本次受保护安装路径。

下面的来源快照是现有缓存格式 `nodes.json`，节点内包含已净化再生配置；请在本机选择，不发送配置内容。节点标识为快照内 `id`，所选顺序中首个作为活动出口，其余作为候选。要覆盖活动加两个候选，须明确选定三个不同节点。来源有效期为一小时，使用过期快照不会通过；不要手工改时间。验证一至两个节点时，报告只证明所选数量。

在普通权限终端准备材料，替换全部占位值；每个额外节点重复 `--node-id`，每个检测网址重复 `--check-url`：

```sh
cd /Users/jiangzhiyan/VsCodeProjects/vpngate-auto-proxy
mkdir -p validation-output/macos-native-pipeline-native
python3 scripts/prepare-macos-native-input.py \
  --source '/替换为明确选定的来源缓存目录/nodes.json' \
  --node-id '替换为活动节点标识' \
  --node-id '替换为候选一标识' \
  --node-id '替换为候选二标识' \
  --check-url 'https://替换为明确选定的检测网址/' \
  --output validation-output/macos-native-pipeline-native/input.json
```

工具保留原节点时间与配置，创建权限 0600 的新文件，拒绝覆盖已有文件，只输出输入路径、摘要和节点标识。来源快照整体三十二兆字节上限；正式入口仍会独立完整核验所选材料及检测设置。

在同一终端使用已确认的 `installed_program`、`worker_uid`、`worker_gid` 和 `dependency_manifest`（见部署步骤），实际启动隧道：

```sh
input_file="$PWD/validation-output/macos-native-pipeline-native/input.json"
input_sha256=$(/usr/bin/shasum -a 256 "$input_file" | /usr/bin/awk '{print $1}')
sudo "$installed_program" mac-validate \
  --input "$input_file" --sha256 "$input_sha256" \
  --dependency-manifest "$dependency_manifest" \
  --runtime-parent /private/var/vap \
  --worker-uid "$worker_uid" --worker-gid "$worker_gid" \
  > validation-output/macos-native-pipeline-native/report.json
cat validation-output/macos-native-pipeline-native/report.json
```

每一步成功后再执行下一步。失败保留报告与所属材料，不自动递归删除或按裸进程号杀进程。重复试验使用新的输出目录，不覆盖原始证据。

## 成功范围与证据

成功要求 `status=passed`、`native_generation_pipeline_validated=true`、全部 `checks` 为真、`cleanup_errors` 为空，并核对 `maximum_simultaneous_generations` 等于所选数量。各阶段检测报告须成功；接口名称与索引清单须恢复。

本工具未启动公共代理，未检测持续既有连接，未独立验证外部出口身份，未抓包证明零直连，也未比较宿主全部路由与解析基线。`full_macos_backend_validated`、`public_service_validated`、`exit_identity_validated`、`continuous_connection_validated`、`fault_injection_performed` 始终为假。网页成功状态只属于出口检测证据，不代替这些独立结论；两种承载、同地址并存、完整故障与主服务仍需各自证据。

普通权限新增五项单元、一项真实命令行契约及四项材料工具回归，覆盖输入摘要、严格选择、预算与网址拒绝、后续无效节点阻止首个启动、只读接口清单、管理员身份先行拒绝、私有输出及保持来源时间、拒绝覆盖和链接。完整结果为 210 项单元、67 项契约通过，35 项特权或目标用例保持忽略；格式、严格静态检查与锁定构建通过。正向原生编排尚未执行，普通测试不代替它。

日志：`validation-output/macos-native-pipeline-20261013/`；[机器记录](macos-native-pipeline-tools.json)。未新增依赖版本或本项目不安全代码。T057、T058 及九项主任务保持未完成；三十分钟测试继续暂缓。
