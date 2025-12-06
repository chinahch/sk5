#!/usr/bin/env bash
# sk5.sh 融合 Misaka-blog Hysteria2 一键逻辑版 (性能优化版)
# 🚀 代码大师修改：模块化拆分版

export LC_ALL=C # 优化 grep/sed/awk 处理速度

# --- 核心路径与变量定义 ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"

ARGO_TEMP_CACHE="/root/agsbx/jh.txt"
ARGO_FIXED_CACHE="/root/agsbx/gd.txt"
ARGO_META_TAG_PREFIX="Argo-"
CONFIG="/etc/sing-box/config.json"
META="/etc/sing-box/nodes_meta.json"
NAT_FILE="/etc/sing-box/nat_ports.json"
LOG_FILE="/var/log/sing-box.log"

# --- 缓存系统信息，避免重复检测 ---
_OS_CACHE=""
_INIT_SYS_CACHE=""
DEPS_CHECKED=0  # 全局标志
GLOBAL_IPV4=""  # 占位符，会在初始化时填充
GLOBAL_IPV6=""  # 占位符，会在初始化时填充

# ============= 基础工具与变量定义 =============
umask 022
C_RESET='\033[0m'
C_GREEN='\033[32m'
C_YELLOW='\033[33m'
C_CYAN='\033[36m'
C_RED='\033[31m'

say()  { printf "%b\n" "$*"; }
err()  { printf " ${C_RED}%b${C_RESET}\n" "$*" >&2; }
ok()   { printf " ${C_GREEN}%b${C_RESET}\n" "$*" >&2; }
warn() { printf " ${C_YELLOW}%b${C_RESET}\n" "$*" >&2; }
log_msg() {
  local level="$1" msg="$2"
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $msg" >> "$LOG_FILE"
}

print_card() {
  local title="$1"
  local name="$2"
  local info="$3"
  local link="$4"

  echo ""
  echo -e "${C_GREEN}=========================================================${C_RESET}"
  echo -e "${C_GREEN}                 ${title}                         ${C_RESET}"
  echo -e "${C_GREEN}=========================================================${C_RESET}"
  echo ""
  echo -e "节点名称: ${C_CYAN}${name}${C_RESET}"
  echo -e "${info}"
  echo ""
  echo -e "【 节点链接 】"
  echo -e "${C_YELLOW}${link}${C_RESET}"
  echo ""
}

# ============= 基础检测函数（保留在主文件） =============
detect_os() {
  if [[ -n "$_OS_CACHE" ]]; then echo "$_OS_CACHE"; return; fi
  if [[ -f /etc/os-release ]]; then . /etc/os-release; _OS_CACHE="$ID"; else _OS_CACHE="unknown"; fi
  echo "$_OS_CACHE"
}

detect_init_system() {
  if [[ -n "$_INIT_SYS_CACHE" ]]; then echo "$_INIT_SYS_CACHE"; return; fi
  if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    _INIT_SYS_CACHE="systemd"
  elif command -v rc-service >/dev/null 2>&1 && [[ -d /run/openrc ]]; then
    _INIT_SYS_CACHE="openrc"
  else
    _INIT_SYS_CACHE="unknown"
  fi
  echo "$_INIT_SYS_CACHE"
}

daemonize() { setsid "$@" </dev/null >/dev/null 2>&1 & }

# ============= 退出与清理逻辑（保留在主文件） =============
# A. on_int_menu_quit_only 函数
on_int_menu_quit_only() {
  # 1. 临时 Argo 进程清理和分离
  disown_temp_tunnel 
  
  # 2. 尝试重启 Sing-box 服务 (执行配置更新)
  restart_singbox >/dev/null 2>&1
  
  # 3. 确保退出时不再执行 EXIT 陷阱
  trap - EXIT
  
  # 4. 安全退出脚本进程
  exit 0
}

# B. 退出陷阱设置
trap 'disown_temp_tunnel >/dev/null 2>&1; echo; exit 0' INT
trap '' SIGHUP 2>/dev/null || true

if [ -z "$BASH_VERSION" ]; then
  echo "本脚本需要 Bash 解释器，请使用 Bash 运行。"
  exit 1
fi

# ============= 引入功能模块 =============
# 检查 lib 目录和文件是否存在
if [ ! -d "$LIB_DIR" ]; then
    err "错误：未找到 lib 目录 ($LIB_DIR)。请确保所有文件已正确放置。"
    exit 1
fi

source "$LIB_DIR/deps_and_util.sh"
source "$LIB_DIR/service_control.sh"
source "$LIB_DIR/nat_control.sh"
source "$LIB_DIR/add_node.sh"
source "$LIB_DIR/view_and_del_node.sh"

# ============= 快捷指令设置 =============
setup_shortcuts() {
  local SCRIPT_PATH
  SCRIPT_PATH="$(readlink -f "$0" 2>/dev/null || echo '/root/main.sh')" # 假设入口脚本为 /root/main.sh

  if [[ ! -f /root/.bashrc ]]; then
    touch /root/.bashrc
    ok "已创建 /root/.bashrc 文件。"
  fi

  if grep -q "# SK5_QUICKSTART_ALIAS" /root/.bashrc; then
    sed -i '/# SK5_QUICKSTART_ALIAS/,+2d' /root/.bashrc
  fi

  local ALIAS_TEXT="# SK5_QUICKSTART_ALIAS
alias my=\"bash $SCRIPT_PATH --menu\"
alias MY=\"bash $SCRIPT_PATH --menu\"
"
  echo -e "$ALIAS_TEXT" >> /root/.bashrc
  
  ok "✅ 快捷指令 'my' 和 'MY' 已设置成功！"

  if [[ $- =~ i ]]; then 
     say "尝试在当前会话中加载快捷指令..."
     source /root/.bashrc 2>/dev/null || {
         warn "自动加载失败。请手动运行: source /root/.bashrc"
     }
  fi
  
  say "（下次您只需输入 my 或 MY 即可直接启动菜单）"
}

# ============= 主菜单逻辑 =============
main_menu() {
  say ""
  show_version_info
  say "============= 嘻嘻哈哈 节点管理工具（IPv4 + IPv6） ============="
  say "1) 添加节点"
  say "2) 查看节点 (分类查看)"
  say "3) 删除节点"
  say "4) 脚本服务"
  say "5) NAT 模式设置"
  say "0) 退出"
  say "==============================================================="
  say "（提示：脚本将在 20 秒无操作后自动退出）"

  if ! read -t 20 -rp "请输入操作编号: " choice; then
      local rc=$?
      if [ $rc -eq 1 ]; then
          echo "无法读取输入（非交互式模式），脚本退出。"
          exit 1
      elif [ $rc -eq 128 ]; then
          echo ""
          say "超过 20 秒未操作，自动退出。"
          exit 0
      fi
  fi

  if [[ -z "$choice" ]]; then
      echo ""
      say "输入为空或超时，自动退出。"
      exit 0
  fi

  case "$choice" in
    1) add_node ;;
    2) view_nodes_menu ;;
    3) delete_node ;;
    4) script_services_menu ;;
    5) nat_mode_menu ;;
    0) exit 0 ;;
    *) warn "无效输入" ;;
  esac
}

# ==========================================
# 脚本主执行流程 (位于文件末尾)
# ==========================================

# 1. 如果检测到 --menu 参数，直接进入菜单并跳过初始化
if [[ "$1" == "--menu" ]]; then
    load_nat_data
    auto_optimize_cpu
    trap on_int_menu_quit_only INT
    while true; do main_menu || break; done
    disown_temp_tunnel
    exit 0
fi

# 2. 完整初始化流程 (只运行一次)
say "🚀 正在进行首次/完整启动初始化..."
ensure_dirs
install_dependencies
if ! command -v sing-box >/dev/null 2>&1; then
  install_singbox_if_needed || true
fi

# 获取 IP 地址 (必须在初始化阶段完成)
GLOBAL_IPV4=$(get_public_ipv4)

if [[ -z "$GLOBAL_IPV4" && -t 0 ]]; then
  echo ""
  echo -e "\033[33m⚠️  警告：无法自动获取公网 IPv4，这会导致节点链接无法连接！\033[0m"
  local_guess=$(ip -4 addr | grep -v '127.0.0.1' | grep -v 'docker' | awk '{print $2}' | cut -d/ -f1 | head -n1)
  read -rp "请输入公网 IPv4 地址 (参考: $local_guess): " manual_ip
  GLOBAL_IPV4=${manual_ip:-$local_guess}
elif [[ -z "$GLOBAL_IPV4" ]]; then
  GLOBAL_IPV4="127.0.0.1" # 非交互式下给个默认值防止报错
fi

GLOBAL_IPV6=$(get_public_ipv6)

INIT_SYS=$(detect_init_system)
case "$INIT_SYS" in
  systemd)
    install_systemd_service
    install_logrotate
    ;;
  openrc)
    ensure_service_openrc
    install_logrotate
    ;;
  *)
    install_singleton_wrapper
    install_autostart_fallback
    install_logrotate
    install_watchdog_cron
    start_singbox_legacy_nohup &
    ;;
esac

load_nat_data
auto_optimize_cpu
trap on_int_menu_quit_only INT

if command -v crond >/dev/null 2>&1; then
    pgrep crond >/dev/null || nohup crond start >/dev/null 2>&1 || crond >/dev/null 2>&1 || true
fi

# 3. 设置快捷指令
setup_shortcuts

# 4. 决定是进入菜单还是自动退出
if [ ! -t 0 ]; then
    if is_docker || [ "$AUTO_DAEMON" = "1" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Docker 容器环境检测到，强制拉起 sing-box 守护进程"
        /usr/local/bin/sb-singleton --force >/dev/null 2>&1
        
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] sing-box 已启动，实时日志如下（容器不会退出）"
        tail -f /var/log/sing-box.log
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] 非交互环境检测到，启动 sing-box 服务后退出脚本界面"
        /usr/local/bin/sb-singleton --force >/dev/null 2>&1
        disown_temp_tunnel 
        exit 0
    fi
else
    # 交互式终端：进入主菜单循环
    while true; do main_menu || break; done
fi
disown_temp_tunnel
exit 0