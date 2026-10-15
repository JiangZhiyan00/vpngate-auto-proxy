# Docker x86_64 测试版

本发布范围为 Debian 12 x86_64、有根 Docker、独立桥接网络。云端受控短试和三十分钟五客户端五十连接容量已有报告，第三版运行代码通过公开出口及服务器本机、个人设备带认证请求。当前发布镜像在该运行镜像上补齐来源声明，程序文件保持相同摘要。苹果原生服务和 Linux 原生部署完整矩阵仍待验收。

本包只含产品镜像，受控夹具和跳过能力预检的实验镜像不随公开包分发。`source-materials.tar.gz` 提供项目源码、全部锁定 crate 原包、Rust 标准库来源和声明，以及镜像实际系统包的固定构建配方、补丁、源码与索引。各组件保留原始许可，项目 MIT 许可不覆盖第三方组件。发布本包时应一并提供其中的源码材料。

## 初次部署

在解压后的包目录执行。主机需具备 Docker 编排插件、Python 3 和 `/dev/net/tun`：

```sh
sha256sum -c SHA256SUMS
bash run.sh load
sudo apparmor_parser -r -W deploy/apparmor/vpngate-auto-proxy
bash manage.sh init
```

安全策略加载命令用于启用 AppArmor 的主机。配置为 `config.json`，凭据由初始化入口写入 `credentials.local.json`，权限 0600。当前公开来源若仍使用 `AES-128-CBC` 与 `SHA1`，部署者须自行决定是否将配置的 `allow_legacy_vpngate_crypto` 设为 `true`；默认严格模式保持拒绝。兼容只接受固定的完整组合，其余节点配置限制不变。

```sh
bash manage.sh check
bash manage.sh up
bash manage.sh status
bash manage.sh ready
```

普通状态查询在等待节点时仍能成功；就绪查询未通过返回 3。宿主仅发布 `127.0.0.1:1080`，容器存活不等于出口就绪。

## 从第三版升级

先解压新包并加载镜像、加载生产安全策略。将旧目录的 `config.json` 和 `credentials.local.json` 复制到新目录，保持凭据权限 0600。在旧目录执行 `bash manage.sh stop` 后，再在新目录执行 `bash manage.sh check` 和 `bash manage.sh up`。固定编排项目名沿用同一缓存卷，重启会重新验证出口。独立镜像标签保留旧镜像，回退也按先停当前服务、再从旧目录启动的顺序操作。

## 个人设备使用

在自己的电脑建立 SSH 本地转发，填写实际端口、私钥路径及服务器地址，保持终端打开：

```sh
ssh -p SSH端口 -i /私钥路径 -o IdentitiesOnly=yes \
  -o ExitOnForwardFailure=yes -N \
  -L 127.0.0.1:11080:127.0.0.1:1080 登录用户@服务器地址
```

客户端设置 SOCKS5 `127.0.0.1:11080`，使用独立代理用户名和密码，并启用代理端域名解析。命令行可交互输入密码，以下用户名 `proxy` 对应默认初始化结果：

```sh
curl --socks5-hostname 127.0.0.1:11080 --proxy-user proxy \
  --max-time 20 --silent --show-error --output /dev/null \
  --write-out 'HTTP %{http_code}\n' https://www.gstatic.com/generate_204
```

只支持 SOCKS5 CONNECT、IPv4 和公网目标，不支持业务 UDP、IPv6 或 BIND。检测成功不代表任意目标长期可达。停止服务执行 `bash manage.sh stop`，查看有限日志执行 `bash manage.sh logs`；停止保留数据卷。

## 来源重建

将 `source-materials.tar.gz` 解压到独立目录，先阅读其中 `source/README.md`。来源索引逐项记录版本、提交及摘要；修改第三方来源时应继续保留其声明。部署包中的 `release-validation.json` 记录具体镜像、程序摘要及验证范围。
