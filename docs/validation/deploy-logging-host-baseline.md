# 宿主准备实现基线

日期：2026-10-16，上海时区。仅只读仓库检查，未操作宿主策略。

现有 scripts/install-vap.py 安装原生产品，使用逐段目录描述符、普通独立文件及身份复核；新宿主准备安装器独立交付，不创建产品包装命令。
生产策略仅定义 vpngate-auto-proxy，文件摘要：`3662c71ea9dd45164c9f04a48d3d4a988a4e01070fdd52e77c234c003ad6d3e5`。
现有 prepare_docker_publish.py 固定 linux/amd64，冻结构建输入，完成镜像与来源核验、受控验收后准备源码归档；工作流先公开附件，再推送版本与 latest。

目标环境为 Debian 12 或 Ubuntu 24.04 x86_64、真实 systemd 宿主、本机有根 Docker、Python 3.10 以上。需要 apparmor_parser、systemctl、docker、标准 AppArmor 包含文件、可读 securityfs、已启用的 AppArmor 启动链及 /dev/net/tun。普通测试只操作临时目录。
真实 enforce、其他服务不受影响及两种发行版的重启证明均未执行。本机不能替代该矩阵；禁止自动重启现有服务器。
