#!/usr/bin/env bash
# sk5.sh - 嘻嘻哈哈 节点管理工具 (入口脚本)
# Open Source: https://github.com/chinahch/sk5

# ================= 配置区 =================
INSTALL_DIR="/etc/sk5_tools"
CORE_LOCAL="$INSTALL_DIR/core.sh"
# ⚠️ 注意：这里必须是你 GitHub 的 raw 地址
CORE_URL="https://raw.githubusercontent.com/chinahch/sk5/main/core.sh"
# =========================================

mkdir -p "$INSTALL_DIR"

# 1. 核心库加载逻辑
load_core() {
    # 如果本地没有 core.sh，或者文件为空，则下载
    if [[ ! -s "$CORE_LOCAL" ]]; then
        echo "正在下载脚本核心组件..."
        if command -v curl >/dev/null 2>&1; then
            curl -sL -o "$CORE_LOCAL" "$CORE_URL"
        elif command -v wget >/dev/null 2>&1; then
            wget -qO "$CORE_LOCAL" "$CORE_URL"
        else
            echo "错误：未找到 curl 或 wget，无法下载核心组件。"
            exit 1
        fi
        chmod +x "$CORE_LOCAL"
    fi

    if [[ ! -s "$CORE_LOCAL" ]]; then
        echo "错误：核心组件下载失败，请检查网络或 GitHub 地址。"
        echo "尝试访问: $CORE_URL"
        exit 1
    fi

    source "$CORE_LOCAL"
}

# 2. 执行加载与初始化
load_core
initialize_core

# ================= 界面逻辑 =================

show_version_info() {
  local OS OS_NAME BIN OUT VER
  OS=$(detect_os)
  OS_NAME="${OS^}"
  if is_docker; then OS_NAME="${OS_NAME}（docker）"; fi
  
  BIN=$(_sb_bin)
  if [[ -n "$BIN" && -x "$BIN" ]]; then
    OUT=$("$BIN" version 2>/dev/null)
    VER=$(echo "$OUT" | grep -oE 'version [0-9.]+' | awk '{print $2}')
    say "Sing-box 版本: ${VER:-未知}  | 系统: ${OS_NAME}"
  else
    say "Sing-box 版本: 未安装  | 系统: ${OS_NAME}"
  fi
}

script_services_menu() {
  while true; do
    say "====== 脚本服务 ======"
    say "1) 检测并修复环境"
    say "2) 重启 Sing-box 服务"
    say "3) 更新 Sing-box 内核"
    say "4) 强制更新脚本 (重新拉取 core.sh)"
    say "5) 完全卸载"
    say "0) 返回"
    read -rp "请选择: " op
    case "$op" in
      1) check_and_repair_menu ;;
      2) restart_singbox ;;
      3) update_singbox ;;
      4) 
         rm -f "$CORE_LOCAL"
         say "已清除本地缓存，正在重新下载..."
         load_core
         say "更新完成！"
         ;;
      5) reinstall_menu ;;
      0) break ;;
      *) warn "无效输入" ;;
  esac
  done
}

main_menu() {
  say ""
  show_version_info
  say "============= 嘻嘻哈哈 节点管理工具 ============="
  say "1) 添加节点 (Socks5 / VLESS / Hy2 / Argo)"
  say "2) 查看节点"
  say "3) 删除节点"
  say "4) 脚本服务 & 更新"
  say "5) NAT 模式设置"
  say "0) 退出"
  say "================================================="
  
  # 快捷指令
  if [[ ! -f /usr/local/bin/sk5 ]]; then
      ln -sf "$0" /usr/local/bin/sk5
      chmod +x /usr/local/bin/sk5
      say "💡 提示: 已设置快捷指令，下次输入 sk5 即可启动菜单"
  fi

  if ! read -t 60 -rp "请选择 (60s自动退出): " choice; then exit 0; fi
  [[ -z "$choice" ]] && exit 0

  case "$choice" in
    1) add_node ;;
    2) view_nodes "normal" ;;
    3) delete_node ;;
    4) script_services_menu ;;
    5) nat_mode_menu ;;
    0) exit 0 ;;
    *) warn "无效输入" ;;
  esac
}

# 入口
trap on_int_menu_quit_only INT
while true; do main_menu || break; done
disown_temp_tunnel