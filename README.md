
# sk5 - Sing-box 管理增强工具

这是一个用于 Linux 的一键安装 Sing-box 节点管理工具，支持多用户、IPv6、UDP 转发、自定义菜单和快捷命令（sk / ck）。

---

## ✅ 一键安装命令

```bash
bash <(curl -Ls https://raw.githubusercontent.com/chinahch/sk5/refs/heads/main/install.sh)
```

---

## ✨ 功能特性

- 支持 IPv4 + IPv6 同时监听
- 支持 SOCKS 节点添加、删除、查看
- 支持多用户 + 密码认证
- 支持 UDP 转发（新版 Sing-box 才能用）
- 支持自动更新 Sing-box 内核
- 支持静默后台启动（OpenRC 支持）
- 支持快捷命令：`sk`（初始化）、`ck`（进入菜单）

---

## 📂 文件结构

| 文件名 | 功能 |
|--------|------|
| `sing_box_manage_geo_v2rayn.sh` | 主程序脚本 |
| `install.sh` | 一键入口脚本 |
| `README.md` | 项目说明文档 |

---

## 🧰 快捷命令说明

| 命令 | 说明 |
|------|------|
| `sk` | 初始化安装 + 菜单 |
| `ck` | 快速进入管理菜单 |

---

## 📘 使用环境建议

- Alpine / Debian / Ubuntu / CentOS 等通用 Linux 发行版
- Sing-box >= v1.10.0（推荐最新版）
