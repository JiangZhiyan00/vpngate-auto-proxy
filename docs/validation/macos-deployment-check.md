# 苹果安装与实际降权部署验证入口

日期：2026-10-13，中国标准时间。T091 是既有 T057 的工具细分，管理员实际验证尚未执行。

此前用户已安装专用依赖和主程序，主程序安装已只读核验，见[安装记录](macos-installation-user-result.json)。本次增加隐藏的 `mac-deployment` 入口，需要使用包含此入口的新构建，并从其管理员保护安装路径执行。旧安装保持不变，专用依赖无需重复安装。

## 检查范围

正式入口先核验真实及有效管理员身份、明确选定的已有非零账户及其主组、当前程序受保护安装记录，以及专用依赖记录、摘要和加载库。全部通过后才在指定短路径父目录下创建本次独立代际目录。

同一受保护程序派生独立身份检查子进程，设置指定用户和主组、清空继承环境，并使用专属进程组。子进程报告真实及有效用户和组、实际组清单、当前目录和本次授权标识；确认额外附属组为空，并验证无法读取管理员私有配置、可以写入指定账户所属的验证文件。父方再次核对身份与授权，在明确观察本次直属子进程回收后，按文件节点归属清理本次目录。

本轮核对苹果[内核组清单实现](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_prot.c)确认：有效主组也包含在组清单中。因此允许所选主组本身，拒绝所有额外组，不把主组误判为继承的附属权限。实际运行仍须同时核对真实与有效组；本轮尚未从管理员进程验证当前工具链的降权结果。

输出有界为 8192 字节，固定授权及严格字段核验；输出读取与正常退出共用三秒截止，异常或取消后最多等待两秒强制回收。丢弃外层等待会取消检查，任务仍持有资源并继续回收；外层运行时必须保持存活。交互中断同样先取消，再等待报告。进程整体崩溃及安全重启不在本入口已验证范围。

验证文件由管理员先创建并登记实际节点，再转交指定账户。子进程不跟随链接，父方复核同一文件节点并有界读取。替代文件、未知内容及未确认回收均不会成为递归删除或杀任意进程的理由。现有归属清单仍不是完整异常重启恢复清单。

**本入口不创建网络接口、不启动加密隧道、不配置地址或路由、不请求网页、不启动公共代理。** 成功只能证明这次安装与实际降权部署检查通过，不能证明完整苹果后端、业务出口归属或零直连。

## 2026-10-13 描述符交付修复

部署验证文件位于已交付普通账户的工作目录，创建后按路径变更归属存在被替换的竞争。本次改为保持原文件描述符打开，通过描述符变更归属，并从描述符元数据登记原设备、节点及归属；创建使用排他创建且不跟随链接。交付前要求路径仍指向原文件、权限为 0600 且只有一个硬链接，缺失、替代或额外链接均失败。失败时仍保留原节点的清理责任，不收养替代文件。

新增三项普通权限回归，通过受控插入点确定性覆盖符号链接替换、普通文件替换、路径缺失、多重硬链接和正常交付。替换后清理拒绝未知节点，外部文件内容、权限及归属保持不变；恢复原节点后精确清理成功。这些回归验证描述符操作和归属登记，不替代管理员向不同账户交付的实际验证。

完整检查通过：257 项单元、68 项契约、格式检查、严格静态检查和锁定构建；36 项目标环境或特权用例保持忽略。工具证据见[机器记录](macos-marker-handoff-tools.json)，详细本地日志位于 `validation-output/macos-marker-handoff-20261013/`。锁文件与依赖版本未变。真实控制子进程、公开网关、实例管理和原生整体验收仍待完成。

## 用户执行步骤

先明确选定一个已存在的本地账户，填入下方 `worker_user`。当前账户可用于验证身份切换；正式服务是否采用独立账户仍需部署决定。入口不创建账户，也不默认猜测身份。

在仓库中普通权限构建并查看新程序材料：

```sh
cd /Users/jiangzhiyan/VsCodeProjects/vpngate-auto-proxy
cargo build --locked
./target/debug/vpngate-auto-proxy mac-program --program "$PWD/target/debug/vpngate-auto-proxy"
```

明确采用本次构建后安装新版；已有旧摘要版本不覆盖：

```sh
program_sha256=$(/usr/bin/shasum -a 256 ./target/debug/vpngate-auto-proxy | /usr/bin/awk '{print $1}')
sudo ./target/debug/vpngate-auto-proxy mac-program \
  --program "$PWD/target/debug/vpngate-auto-proxy" \
  --install --sha256 "$program_sha256"
installed_program="/Library/Application Support/vpngate-auto-proxy-programs/0.1.0-$program_sha256/vpngate-auto-proxy"
```

若该摘要已经安装，安装器会拒绝覆盖；核对对应已安装版本后使用其路径，无需重新安装。

下面只创建一次受保护短路径父目录。先确认该路径尚不存在；若已存在，不覆盖或调整其权限，由验证入口核验既有目录：

```sh
sudo /bin/mkdir -m 0711 /private/var/vap
```

本机 `/private/var/run` 实际权限为 0775，不符合祖先路径不可被普通用户修改的要求；不要使用此前位于其下的示例，也不要改动系统目录权限。

在同一终端明确填入选定账户并执行验证：

```sh
worker_user='替换为选定的已有本地账户名'
worker_uid=$(/usr/bin/id -u "$worker_user")
worker_gid=$(/usr/bin/id -g "$worker_user")
dependency_manifest='/Library/Application Support/vpngate-auto-proxy/dependencies/openvpn-2.6.23-7619ae9d2fd7592bb834ce8bb54b790aeb2a7e7af7417caab8c08b5353d23a45/dependency.json'
mkdir -p validation-output/macos-deployment-native
sudo "$installed_program" mac-deployment \
  --dependency-manifest "$dependency_manifest" \
  --runtime-parent /private/var/vap \
  --worker-uid "$worker_uid" --worker-gid "$worker_gid" \
  > validation-output/macos-deployment-native/report.json
cat validation-output/macos-deployment-native/report.json
```

每一步成功后再执行下一步。失败时保留报告；未确认清理会在报告中给出材料目录，不据裸进程号自动杀进程或递归删除。成功要求 `status=passed` 且全部 `checks` 为真，`cleanup_errors` 为空；`native_tunnel_validated`、`full_macos_backend_validated` 和 `service_activated` 仍为假。

## 普通权限验证证据

新增七项单元回归，覆盖身份、授权、组与环境拒绝、真实子进程成功和回收、错误/超限/异常退出/超时回收、取消回收，以及验证文件有界复核、替代保护与所属目录清理。新增两项真实命令行契约，覆盖普通用户在任何部署材料读取前拒绝，以及真实身份子进程观察当前身份并拒绝继承环境。子进程成功报告的单元测试采用注入夹具，不代替管理员实际降权。

205 项单元、66 项契约、格式、严格静态检查和锁定构建通过；35 项目标或特权用例保持忽略。未增加依赖版本或本项目不安全代码；启用已固定 `rustix` 的进程功能，用其安全接口读取实际组清单，锁文件摘要不变。

日志位于 `validation-output/macos-deployment-20261013/`，机器证据见[工具记录](macos-deployment-check-tools.json)。初次编译发现原安全库未在苹果平台提供组清单接口，改用既有固定安全依赖；测试编译期间修正了调试派生和归属函数的模块路径。未在本会话运行管理员验证、真实隧道或三十分钟测试，T057、T058 及九项主任务保持未完成。
