# 参考项目源码核查与复用方向

核查日期：2026-10-10。核查范围为官方仓库固定提交的文档和关键源码，未实际部署验证。
本记录用于后续技术规划，不表示已选定基础项目、引入第三方代码或完成许可兼容性判断。

## 已确认的复用原则

项目优先采用满足需求的现成实现，允许裁剪已有项目或组合复用模块，避免全量重写。
复用方式必须服从精简命令行、Linux 与 Docker、周期验证、故障重试和局域网认证要求。
不能把项目说明中的宣称当作源码已实现或本项目验收通过。

## 节点代理网关

仓库：<https://github.com/zhaxg/vpngate2proxy>
核查提交：`4cd29bc139d19c04bb025684a5cbf1937e05040b`。

- 可参考节点获取、活动隧道生命周期、源地址策略路由、代理健康检查、自动重连及容器部署。
- [连接管理源码](https://github.com/zhaxg/vpngate2proxy/blob/4cd29bc139d19c04bb025684a5cbf1937e05040b/app/vpn_manager.py)
  中的候选测试直接返回成功，后台扫描只预热列表，不能用作完整候选验证。
- 同文件的活动出口检查要求成功状态且响应体非空，会拒绝空响应的 204 检测；
  复用时必须按检测目标的预期响应判据改造。
- [代理源码](https://github.com/zhaxg/vpngate2proxy/blob/4cd29bc139d19c04bb025684a5cbf1937e05040b/app/socks_server.py)
  当前仅接受无认证方式，必须补齐局域网认证；容器入口与网页管理需要解耦。
- 项目说明标注 MIT，但核查提交的文件树未发现许可证文件；直接复制前须补齐许可依据。

## 节点检测与调度项目

仓库：<https://github.com/illria/gatevpn>
核查提交：`05f8853826179e8c13990453f598e0172d7f5fbd`。

- 可参考节点获取、候选握手测试、故障调度、活动代理出口检测及隧道内域名解析。
- [连接管理源码](https://github.com/illria/gatevpn/blob/05f8853826179e8c13990453f598e0172d7f5fbd/vpngate_manager.py)
  的候选测试使用独立虚拟网卡并禁止拉取路由，主要验证握手，不能等同于独立网络空间
  或候选出口验证。需要补齐与本规格相符的候选出口检测和隔离验收。
- [代理源码](https://github.com/illria/gatevpn/blob/05f8853826179e8c13990453f598e0172d7f5fbd/proxy_server.py)
  当前只选择无认证方式；多来源、网页与风险评分超出首版范围，核查版本未见现成容器部署文件。
- [许可证文件](https://github.com/illria/gatevpn/blob/05f8853826179e8c13990453f598e0172d7f5fbd/LICENSE)
  声明 GPL 第三版或后续版本，正文包含省略内容；复用前须明确相应分发义务。

## 隔离隧道代理项目

仓库：<https://github.com/Uber-Eins/vpngate2socks>
核查提交：`a4ba00b3bb081dd3b192c0ea8a1dce56a19886ad`。

- [节点模块](https://github.com/Uber-Eins/vpngate2socks/blob/a4ba00b3bb081dd3b192c0ea8a1dce56a19886ad/src/vpngate.rs)
  包含获取、限额解析与稳定节点标识，模块边界相对独立。
- [网络模块](https://github.com/Uber-Eins/vpngate2socks/blob/a4ba00b3bb081dd3b192c0ea8a1dce56a19886ad/src/netd/system.rs)
  包含网络空间与防直连规则；
  [代理模块](https://github.com/Uber-Eins/vpngate2socks/blob/a4ba00b3bb081dd3b192c0ea8a1dce56a19886ad/src/socks.rs)
  有用户名密码认证。已有容器构建和部署配置。
- 当前采用 Rust，要求已有上游代理，并包含网页与特权网络守护进程；
  整仓采用会引入本项目未要求的依赖，必须评估裁剪成本，不能原样照搬。
- [许可证文件](https://github.com/Uber-Eins/vpngate2socks/blob/a4ba00b3bb081dd3b192c0ea8a1dce56a19886ad/LICENSE)
  提供完整 MIT 文本及版权声明。

## 轻量代理网关

仓库：<https://github.com/wanchangkongyi/vpngate-gateway>
核查提交：`793219490d8897ea0f76895824bdbcc17489d598`。

- [命令行工具](https://github.com/wanchangkongyi/vpngate-gateway/blob/793219490d8897ea0f76895824bdbcc17489d598/vpngw)
  和后台管理适合作为精简运行方式的参考；已有节点缓存、探测和故障轮换流程。
- [节点工具](https://github.com/wanchangkongyi/vpngate-gateway/blob/793219490d8897ea0f76895824bdbcc17489d598/vpn_utils.py)
  通过随机虚拟网卡测试握手，尚不是候选完整出口验证。
- [代理源码](https://github.com/wanchangkongyi/vpngate-gateway/blob/793219490d8897ea0f76895824bdbcc17489d598/proxy_server.py)
  绑定隧道接口，但目前无认证，域名使用系统解析器；需适配容器、认证与业务域名解析策略。
- 核查提交未见许可证文件，项目说明未检索到明确许可声明；直接复制前须补齐许可依据。

## 技术规划必须回答的问题

优先评估裁剪一个现有核心与组合少量现成模块的成本，再决定基础项目和语言。
对获取节点、隧道管理、代理服务、验证调度和容器部署，逐项记录采用来源、
所需改造及必须自行补齐的缺口。不得仅因新建仓库而重新实现已有能力。

实现前固定所采用的源码版本、记录归属及许可条件；
实现后验证分批候选出口检测、204 响应判定、隔离、防直连、认证与容器退出清理。
已存在的实现可以减少开发量，但不能替代这些验收。
