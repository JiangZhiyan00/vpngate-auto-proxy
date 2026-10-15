# 云服务器离线包

本包适用于 x86_64 Linux、有根 Docker；服务器需具备 `/dev/net/tun`、网络空间与所需容器能力。包内包含运行镜像、轻量受控测试夹具、验收脚本和部署配置，无个人密码、私钥或节点缓存。夹具仅用于测试，不是生产服务。

新版包已整合云端验证期间的镜像摘要、夹具与生产安全策略修复，不需要逐个应用历史补丁。Debian 12 x86_64 云端受控短试与三十分钟容量已通过。第二版实际部署发现，当前公开来源全部使用旧算法，安全白名单因而没有候选；第三版增加默认关闭的显式兼容开关。第三版云端公开节点出口及服务器本机带认证的代理请求已通过；个人设备经 SSH 转发的带认证 HTTPS 请求也已通过；原生进程部署及其他系统仍须分别验证。

容量资源采样还需要控制组第二版及内核提供的 `/sys/fs/cgroup/memory.peak`；环境不满足时会报告失败，不能把缺失资源数据当作验收通过。

## 加载镜像

上传整个压缩包到服务器，解压并进入包目录。宿主需要 Bash、Python 3、Docker；实际部署需要容器编排插件，受控验收还需要 curl。以下命令须能操作 Docker。目录路径不要包含冒号。

```sh
tar -xzf vpngate-cloud-amd64-20261014-r3.tar.gz
cd vpngate-cloud-amd64-20261014-r3
bash run.sh load
```

`load` 先核对程序、策略、镜像及交付文件摘要，再离线加载两个镜像，不拉取远端镜像。不需要在服务器安装 Rust。`config.json` 是允许用户修改的运行配置，其修改不会关闭其他文件的完整性核验；凭据另行创建，不在离线包中。

## 先执行受控验收

使用独立测试服务器或维护窗口，不与正在运行的本项目实例同时测试。受控验收创建带本次归属标签的容器、网络和卷，正常结束会回收。测试不访问随机公共节点，也不发布公网代理端口。

若 Docker 启用了 AppArmor，先加载本包的两份专用策略：

```sh
sudo apparmor_parser -r -W deploy/apparmor/vpngate-auto-proxy
sudo apparmor_parser -r -W deploy/apparmor/vpngate-auto-proxy-fixture
```

再执行短试，验证认证、状态、停止、缓存恢复、故障阻断与恢复、默认回环、权限拒绝：

```sh
bash run.sh smoke
```

验收会先用无网络、无能力的临时探针确认策略能够应用；缺少策略时在创建测试网络之前给出加载命令。夹具启动失败时，退出状态和有限日志保存在 `validation-output/fixture-*.log`，随后仍回收本次资源。

启用 AppArmor 的主机可继续执行短试加三十分钟容量的聚合验收：

```sh
bash run.sh all
```

未启用 AppArmor 的主机仍可单独执行三十分钟容量验收；该结果不涵盖安全模块强制实施：

```sh
bash run.sh capacity
```

结果保存在 `validation-output/`。请保留全部日志与报告，再提供这些结果。失败时不要执行全局清理命令；若需中断使用 Ctrl+C 并等待回收。`all` 会在缺少安全模块时明确失败，不会静默跳过。

## 启动实际代理

若从第二版升级，先在第二版目录执行 `bash manage.sh stop`。第三版仍使用固定项目名和原数据卷，启动时沿用缓存；停机后再加载新镜像，避免两个版本同时管理一个实例。第三版 `config.json` 默认保持严格算法白名单。当前 VPN Gate 公共接口提供的配置均使用 `AES-128-CBC` 和 `SHA1`；如果决定使用这些节点，请在第三版包内将 `config.json` 的 `allow_legacy_vpngate_crypto` 从 `false` 改为 `true`，再执行下面的预检与启动。该开关仅对 Linux 后端有效，只接受完整的旧算法组合，其他脚本、外部文件、压缩与端点限制保持原有拒绝规则。旧算法的安全强度低于默认要求；不接受此取舍则保留 `false` 并使用符合白名单的来源。

受控测试结束后，使用统一管理入口。首次初始化独立代理凭据，随后执行预检并启动：

```sh
bash manage.sh init
bash manage.sh check
bash manage.sh up
bash manage.sh status
bash manage.sh ready
```

初始化只在凭据文件不存在时生成随机密码，权限为 0600，不打印密码；已有有效文件保持原内容，符号链接、多重链接或权限过宽的文件会被拒绝。请自行查看并保管凭据，不复用服务器登录密码。

管理入口使用固定编排项目名 `vpngate-auto-proxy`，自动按主机选择专用安全策略覆盖文件，禁止构建和拉取镜像，并在启动前核对镜像身份、配置映射、只读根目录、能力和回环端口。启用安全模块时仍需先加载生产策略；管理入口不修改宿主策略。检查结果为 `validation-output/deployment-check.json`，其中 `legacy_crypto_opt_in` 可核对是否已经显式启用；报告只证明部署条件，不证明公共出口已就绪。

`status` 在等待节点时仍可成功，`ready` 未就绪返回 3、出口验证成功返回 0，通信或执行失败返回非零。启动不会等待公共节点一定可用。

`ready=true` 后，可在包含 `manage.sh` 和 `credentials.local.json` 的第三版包目录执行一次服务器本机业务请求。以下命令使用 `init` 生成的独立凭据，通过标准输入交给 `curl`；不会把密码打印出来或放入命令参数。预期结果为 `HTTP 204；curl 退出码 0`：

```sh
python3 - <<'PY'
import json
import subprocess
from pathlib import Path

credentials = json.loads(Path('credentials.local.json').read_text())
authentication = credentials['username'] + ':' + credentials['password']
if any(character in authentication for character in ('"', '\\', '\r', '\n')):
    raise SystemExit('凭据包含当前检测命令不支持的字符')
result = subprocess.run(
    ['curl', '--config', '-', '--socks5-hostname', '127.0.0.1:1080',
     '--max-time', '20', '--silent', '--show-error', '--output', '/dev/null',
     '--write-out', '%{http_code}', 'https://www.gstatic.com/generate_204'],
    input=f'proxy-user = "{authentication}"\n', text=True, capture_output=True,
)
print(f"HTTP {result.stdout.strip() or '无响应'}；curl 退出码 {result.returncode}")
raise SystemExit(0 if result.returncode == 0 and result.stdout.strip() == '204' else 1)
PY
```

从旧版手工编排切换时，请先在旧目录执行原启动命令对应的 `stop`，再决定是否迁移原数据卷；旧版默认项目名和新版固定项目名不同，新管理入口不会自动接管其他项目的卷。

配置文件为 `config.json`，默认从公共 VPN 来源取节点；公共节点能否连通须在服务器上实际确认。`ready=true` 才表示当前出口已验证，等待节点时业务拒绝转发。

宿主端口固定仅绑定 `127.0.0.1:1080`。在自己的电脑另开终端执行 SSH 转发，填写实际服务器登录信息：

```sh
ssh -N -L 1080:127.0.0.1:1080 用户名@服务器地址
```

客户端使用本机 `127.0.0.1:1080`、上述独立凭据与代理端域名解析。停止时保留缓存卷：

```sh
bash manage.sh stop
bash manage.sh logs
```

停止宽限为十五秒，保留数据卷；状态、停止和有限日志不依赖镜像归档仍然可读或出口已经就绪。不要用删除数据卷的命令替代普通停止。

这些镜像是本次私有验收候选。构建与本机模拟执行不能替代云服务器实测；包内没有 Linux 原生部署的完成证明，苹果原生验收按当前安排暂缓。
