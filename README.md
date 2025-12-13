# ⚡️ sk5： Sing-box 节点快速部署管理工具

**sk5** 是一个专为 **Linux** 设计的 **Sing-box** 节点增强管理工具。它提供一键安装、多用户管理、IPv6 支持、UDP 转发，并通过 `sk` / `ck` 快捷命令实现快速菜单操作。

---


## ✅ 一键安装命令
在支持的 Linux 发行版上，运行以下命令即可开始安装和初始化：
```bash
bash <(curl -Ls https://raw.githubusercontent.com/chinahch/sk5/refs/heads/main/install.sh)
```

---
✨ 核心功能亮点
✅ 全栈网络支持： 支持 IPv4 和 IPv6 地址同时监听。

👤 灵活用户管理： 支持 SOCKS 节点的添加、删除、查看，以及多用户和密码认证。

⚡️ 高性能转发： 支持 UDP 转发（要求新版 Sing-box 核心）。

🚀 核心自动更新： 支持自动更新 Sing-box 内核。

⚙️ 轻量级运行： 支持静默后台启动（兼容 OpenRC）。
---


## 🧰 快捷命令说明

| 命令 | 说明 |
|------|------|
| `sk` | 初始化安装 + 菜单 |
| `ck` | 快速进入管理菜单 |

---

📘 使用环境建议
操作系统： 推荐 Alpine / Debian / Ubuntu / CentOS 等通用 Linux 发行版。

Sing-box 版本： 推荐 Sing-box >= v1.10.0（建议使用最新版）。
