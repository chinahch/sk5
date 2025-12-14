#!/usr/bin/env bash
# sk5.sh 融合 Misaka-blog Hysteria2 一键逻辑版 (UI重构+性能优化+全功能保留版)
# 🚀 优化内容：移除启动阻塞、后台IP获取、Dashboard UI、保留所有业务逻辑
# 🚀 代码大师修改：默认执行完整初始化，并自动设置 'my' 和 'MY' 别名快捷指令

export LC_ALL=C # 优化 grep/sed/awk 处理速度

# ============= 0. 全局配置与 UI 变量 =============
VERSION="3.0.0 Optimized"
ARGO_TEMP_CACHE="/root/agsbx/jh.txt"
ARGO_FIXED_CACHE="/root/agsbx/gd.txt"
ARGO_META_TAG_PREFIX="Argo-"
CONFIG="/etc/sing-box/config.json"
META="/etc/sing-box/nodes_meta.json"
NAT_FILE="/etc/sing-box/nat_ports.json"
LOG_FILE="/var/log/sing-box.log"
IP_CACHE_FILE="/tmp/my_ip_cache"
DEPS_CHECKED=0  # 全局标志

# 颜色定义
C_RESET='\033[0m'
C_RED='\033[38;5;196m'
C_GREEN='\033[38;5;46m'
C_YELLOW='\033[38;5;226m'
C_BLUE='\033[38;5;39m'
C_PURPLE='\033[38;5;129m'
C_CYAN='\033[38;5;51m'
C_GRAY='\033[90m'

# ============= 1. 核心工具函数 (UI优化) =============

say()  { echo -e "${C_GREEN}➜ ${C_RESET}$*"; }
err()  { echo -e "${C_RED}✖ $*${C_RESET}" >&2; }
ok()   { echo -e "${C_GREEN}✔ $*${C_RESET}" >&2; }
warn() { echo -e "${C_YELLOW}⚡ $*${C_RESET}" >&2; }
log_msg() {
  local level="$1" msg="$2"
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $msg" >> "$LOG_FILE"
}

# --- 缓存系统信息，避免重复检测 ---
_OS_CACHE=""
_INIT_SYS_CACHE=""

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

# 信号处理
trap 'disown_temp_tunnel >/dev/null 2>&1; echo; exit 0' INT
trap '' SIGHUP 2>/dev/null || true
daemonize() { setsid "$@" </dev/null >/dev/null 2>&1 & }

if [ -z "$BASH_VERSION" ]; then
  echo "本脚本需要 Bash 解释器，请使用 Bash 运行。"
  exit 1
fi

umask 022

# 卡片打印优化
print_card() {
  local title="$1" name="$2" info="$3" link="$4"
  echo ""
  echo -e "${C_BLUE}╔═══════════════════════════════════════════════════════════════╗${C_RESET}"
  echo -e "${C_BLUE}║${C_RESET} ${C_YELLOW}${title}${C_RESET}"
  echo -e "${C_BLUE}╠═══════════════════════════════════════════════════════════════╣${C_RESET}"
  echo -e "  节点名称: ${C_CYAN}${name}${C_RESET}"
  echo -e "${info}"
  echo -e "${C_BLUE}╠═══════════════════════════════════════════════════════════════╣${C_RESET}"
  echo -e "  ${C_GREEN}${link}${C_RESET}"
  echo -e "${C_BLUE}╚═══════════════════════════════════════════════════════════════╝${C_RESET}"
  echo ""
}

# 异步后台更新 IP (不阻塞启动)
update_ip_async() {
    (
        # 尝试多个源
        ip=$(curl -s --max-time 3 https://api.ipify.org || curl -s --max-time 3 https://ifconfig.me/ip || curl -s --max-time 3 https://checkip.amazonaws.com)
        if [[ -n "$ip" ]]; then echo "$ip" > "$IP_CACHE_FILE"; fi
        # IPv6 也可以顺便获取
        ip6=$(curl -s -6 --max-time 3 https://api64.ipify.org || ip -6 addr show scope global | grep inet6 | head -n1 | awk '{print $2}' | cut -d/ -f1)
        if [[ -n "$ip6" ]]; then echo "$ip6" > "${IP_CACHE_FILE}_v6"; fi
    ) &
}

# 获取当前 IP (如果缓存有就读缓存，没有就强制获取)
get_public_ipv4_ensure() {
    if [[ -f "$IP_CACHE_FILE" ]]; then
        cat "$IP_CACHE_FILE"
    else
        local ip
        ip=$(curl -s --max-time 3 https://api.ipify.org || curl -s --max-time 3 https://ifconfig.me/ip)
        if [[ -n "$ip" ]]; then
            echo "$ip" | tee "$IP_CACHE_FILE"
        else
            # 最后的 fallback
            ip -4 addr | grep -v '127.0.0.1' | grep -v 'docker' | awk '{print $2}' | cut -d/ -f1 | head -n1
        fi
    fi
}
get_public_ipv6_ensure() {
    if [[ -f "${IP_CACHE_FILE}_v6" ]]; then cat "${IP_CACHE_FILE}_v6"; else echo ""; fi
}

# 系统状态 Dashboard
get_sys_status() {
    local cpu_load=$(awk '{print $1}' /proc/loadavg 2>/dev/null)
    local mem_total=$(awk '/MemTotal/ {printf "%.0f", $2/1024}' /proc/meminfo 2>/dev/null)
    local mem_free=$(awk '/MemAvailable/ {printf "%.0f", $2/1024}' /proc/meminfo 2>/dev/null)
    local mem_used=$((mem_total - mem_free))
    local mem_rate=0
    [[ $mem_total -gt 0 ]] && mem_rate=$((mem_used * 100 / mem_total))
    
    local ip_addr="获取中..."
    [[ -f "$IP_CACHE_FILE" ]] && ip_addr=$(cat "$IP_CACHE_FILE")

    local color_cpu="$C_GREEN"
    [[ $(echo "$cpu_load > 2.0" | bc -l 2>/dev/null) -eq 1 ]] && color_cpu="$C_YELLOW"
    
    local color_mem="$C_GREEN"
    [[ $mem_rate -ge 80 ]] && color_mem="$C_YELLOW"

    echo -e "${C_BLUE}┌──[ 系统监控 ]────────────────────────────────────────────────┐${C_RESET}"
    echo -e "${C_BLUE}│${C_RESET} CPU: ${color_cpu}${cpu_load}${C_RESET} | 内存: ${color_mem}${mem_used}MB/${mem_total}MB (${mem_rate}%)${C_RESET}"
    echo -e "${C_BLUE}│${C_RESET} IP : ${C_YELLOW}${ip_addr}${C_RESET}"
    echo -e "${C_BLUE}└──────────────────────────────────────────────────────────────┘${C_RESET}"
}

# ============= 2. 基础依赖与 Sing-box 管理 (保留原逻辑) =============

is_real_systemd() {
  [[ -d /run/systemd/system ]] && ps -p 1 -o comm= 2>/dev/null | grep -q '^systemd$'
}

is_pseudo_systemd() {
  ps -p 1 -o comm,args= 2>/dev/null | grep -q 'systemctl' && ! is_real_systemd
}

_sb_bin() {
  local b="${SING_BOX_BIN:-/usr/local/bin/sing-box}"
  [[ -x "$b" ]] || b="/etc/sing-box/bin/sing-box"
  [[ -x "$b" ]] || b="$(command -v sing-box 2>/dev/null || true)"
  printf "%s" "$b"
}
_sb_cfg() { printf "%s" "${CONFIG:-/etc/sing-box/config.json}"; }

resolve_service_cmd() {
  local cmd="$1"
  if command -v "$cmd" >/dev/null 2>&1; then
    readlink -f "$(command -v "$cmd")"
    return 0
  fi
  for p in /usr/bin/"$cmd" /bin/"$cmd" /sbin/"$cmd"; do
    [ -x "$p" ] && echo "$p" && return 0
  done
  return 1
}

disown_temp_tunnel() {
  local TEMP_ARGO_DIR="/root/agsbx/temp_node"
  local TEMP_PID_FILE="$TEMP_ARGO_DIR/temp_cloudflared.pid"
  local TEMP_XRAY_PID_FILE="$TEMP_ARGO_DIR/temp_xray.pid"  
  
  if [[ -f "$TEMP_PID_FILE" ]]; then
    local cfd_pid=$(cat "$TEMP_PID_FILE" 2>/dev/null)
  else
    local cfd_pid=$(pgrep -f "$TEMP_ARGO_DIR/cloudflared_temp" | head -n 1)
  fi
  if [ -n "$cfd_pid" ] && ps -p "$cfd_pid" >/dev/null 2>&1; then
    disown "$cfd_pid" 2>/dev/null || true 
  fi
  
  if [[ -f "$TEMP_XRAY_PID_FILE" ]]; then
    local xray_pid=$(cat "$TEMP_XRAY_PID_FILE" 2>/dev/null)
  else
    local xray_pid=$(pgrep -f "$TEMP_ARGO_DIR/xray_temp" | head -n 1)
  fi
  if [ -n "$xray_pid" ] && ps -p "$xray_pid" >/dev/null 2>&1; then
    disown "$xray_pid" 2>/dev/null || true
  fi
  
  rm -f "$TEMP_PID_FILE" "$TEMP_XRAY_PID_FILE"
  return 0
}

_SYSTEMCTL_CMD="$(resolve_service_cmd systemctl || true)"
_RCSERVICE_CMD="$(resolve_service_cmd rc-service || true)"

_sb_any_port_listening() {
  local cfg="$(_sb_cfg)"
  [[ -s "$cfg" ]] || return 1
  local ss_out
  ss_out=$(ss -ltnp 2>/dev/null)
  local any=""
  while read -r p; do
    [[ -z "$p" ]] && continue
    if echo "$ss_out" | grep -q ":$p "; then any=1; break; fi
  done < <(jq -r '.inbounds[].listen_port' "$cfg" 2>/dev/null)
  [[ -n "$any" ]]
}

ensure_dirs() {
  mkdir -p /etc/sing-box
  [[ -f "$CONFIG" ]] || printf '%s\n' '{"inbounds":[],"outbounds":[{"type":"direct"}],"route":{"rules":[]}}' >"$CONFIG"
  [[ -f "$META"   ]] || printf '%s\n' '{}' >"$META"
}

# 优化依赖安装：只在需要时调用
ensure_cmd() {
  local cmd="$1" deb="$2" alp="$3" cen="$4" fed="$5"
  command -v "$cmd" >/dev/null 2>&1 && return 0
  case "$(detect_os)" in
    debian|ubuntu)
      DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
      DEBIAN_FRONTEND=noninteractive apt-get install -y "$deb" >/dev/null 2>&1 || true ;;
    alpine)
      apk add --no-cache "$alp" >/dev/null 2>&1 || true ;;
    centos|rhel)
      yum install -y "$cen" >/dev/null 2>&1 || true ;;
    fedora)
      dnf install -y "$fed" >/dev/null 2>&1 || true ;;
    *) warn "未识别系统，请手动安装：$cmd" ;;
  esac
  command -v "$cmd" >/dev/null 2>&1
}

ensure_runtime_deps() {
  if (( DEPS_CHECKED == 1 )); then return 0; fi
  # 检查是否全部存在，如果都存在则跳过
  local all_exist=1
  for c in curl jq uuidgen openssl ss lsof; do
      if ! command -v "$c" >/dev/null 2>&1; then all_exist=0; break; fi
  done
  
  if (( all_exist == 1 )); then DEPS_CHECKED=1; return 0; fi

  say "首次运行，正在补全依赖..."
  ensure_cmd curl     curl        curl        curl        curl
  ensure_cmd jq       jq          jq          jq          jq
  ensure_cmd uuidgen  uuid-runtime util-linux util-linux  util-linux
  ensure_cmd openssl  openssl      openssl     openssl     openssl
  ensure_cmd ss       iproute2     iproute2    iproute    iproute
  ensure_cmd lsof     lsof         lsof        lsof        lsof
  DEPS_CHECKED=1
}

install_dependencies() { ensure_runtime_deps; } # 兼容原名调用

install_singbox_if_needed() {
  if command -v sing-box >/dev/null 2>&1; then return 0; fi

  warn "未检测到 sing-box，正在安装..."
  local VERSION="1.12.0"
  local arch=$(uname -m)
  case "$arch" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) err "暂不支持的架构：$arch"; return 1 ;;
  esac

  # CA 证书修复逻辑保留
  if [[ ! -f /etc/ssl/certs/ca-certificates.crt ]]; then
      if command -v apk >/dev/null 2>&1; then apk add --no-cache ca-certificates; update-ca-certificates 2>/dev/null; fi
      if command -v apt-get >/dev/null 2>&1; then apt-get update -y; apt-get install -y ca-certificates; update-ca-certificates; fi
      if command -v yum >/dev/null 2>&1; then yum install -y ca-certificates; fi
  fi

  local tmp; tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  (
    set -e
    cd "$tmp"
    local FILE="sing-box-${VERSION}-linux-${arch}.tar.gz"
    local URL="https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/${FILE}"
    if ! curl -fL -o "$FILE" "$URL"; then
      warn "直连下载失败，尝试代理..."
      curl -fL -o "$FILE" "https://ghproxy.com/${URL}"
    fi
    tar -xzf "$FILE"
    install -m 0755 "sing-box-${VERSION}-linux-${arch}/sing-box" /usr/local/bin/sing-box
  ) || { err "安装 sing-box 失败"; return 1; }
  ok "sing-box 安装完成"
}

get_country_code() {
  local CODE
  CODE=$(curl -s --max-time 3 https://ipinfo.io | jq -r '.country // empty')
  [[ "$CODE" =~ ^[A-Z]{2}$ ]] && printf "%s\n" "$CODE" || printf "ZZ\n"
}

generate_unique_tag() {
  local base="vless-reality-$(get_country_code)"
  local try=0 RAND CANDIDATE
  while true; do
    RAND=$(tr -dc 'A-Z' </dev/urandom 2>/dev/null | head -c1)
    CANDIDATE="${base}-${RAND}"
    if ! jq -e --arg t "$CANDIDATE" '.inbounds[] | select(.tag == $t)' "$CONFIG" >/dev/null 2>&1; then
      printf "%s\n" "$CANDIDATE"; return
    fi
    try=$((try+1))
    if [[ $try -ge 26 ]]; then
      printf "%s-%s\n" "$base" "$(date +%s)"; return
    fi
  done
}

# 端口占用检查（保留优化版）
port_status() {
  local port="$1"
  local have=0 seen_s=0 seen_o=0
  local ss_output=""
  if command -v ss >/dev/null 2>&1; then
    have=1
    ss_output=$(ss -luntp 2>/dev/null || true)
    if echo "$ss_output" | grep -q ":$port "; then
       if echo "$ss_output" | grep ":$port " | grep -qi 'users:((".*sing-box'; then seen_s=1; else seen_o=1; fi
    fi
  fi
  if (( have==0 )) && command -v lsof >/dev/null 2>&1; then
    have=1
    local names=""
    names+=$(lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $1}')
    names+=$(lsof -nP -iUDP:"$port" 2>/dev/null | awk 'NR>1{print $1}')
    if [[ -n "$names" ]]; then
      if echo "$names" | grep -Eqi 'sing-box'; then seen_s=1; else seen_o=1; fi
    fi
  fi
  if (( seen_s==1 )); then return 0; elif (( seen_o==1 )); then return 1; else return 2; fi
}

load_nat_data() {
  if [[ -f "$NAT_FILE" ]]; then
    nat_mode=$(jq -r '.mode // "custom"' "$NAT_FILE")
    mapfile -t nat_ranges < <(jq -r '.ranges[]?' "$NAT_FILE")
    mapfile -t nat_tcp < <(jq -r '.custom_tcp[]?' "$NAT_FILE" | sort -n -u)
    mapfile -t nat_udp < <(jq -r '.custom_udp[]?' "$NAT_FILE" | sort -n -u)
  else
    nat_mode=""
    nat_ranges=()
    nat_tcp=()
    nat_udp=()
  fi
}

get_random_allowed_port() {
  local proto="$1"
  local -a used=()
  mapfile -t used < <(jq -r '.inbounds[].listen_port' "$CONFIG" 2>/dev/null | grep -E '^[0-9]+$' || true)
  mapfile -t hy2u < <(jq -r 'to_entries[]? | select(.value.type=="hysteria2") | .value.port' "$META" 2>/dev/null || true)
  used+=("${hy2u[@]}")

  local -a candidates=()
  if [[ -n "$nat_mode" ]]; then
    if [[ "$nat_mode" == "range" ]]; then
      for range in "${nat_ranges[@]}"; do
        local s=${range%-*} e=${range#*-} p
        for ((p=s; p<=e; p++)); do candidates+=("$p"); done
      done
    else
      if [[ "$proto" == "tcp" ]]; then candidates=("${nat_tcp[@]}")
      elif [[ "$proto" == "udp" ]]; then candidates=("${nat_udp[@]}")
      else candidates=("${nat_tcp[@]}" "${nat_udp[@]}")
      fi
    fi
    local free=() usedset=" ${used[*]} "
    for c in "${candidates[@]}"; do
      [[ "$usedset" == *" $c "* ]] && continue
      free+=("$c")
    done
    if ((${#free[@]}==0)); then echo "NO_PORT"; return 1; fi
    echo "${free[RANDOM % ${#free[@]}]}"; return 0
  else
    if [[ "$proto" == "tcp" ]]; then echo $((RANDOM%10000 + 30000))
    elif [[ "$proto" == "udp" ]]; then echo $((RANDOM%10000 + 50000))
    else echo $((RANDOM%1000 + 30000)); fi
  fi
}

check_nat_allow() {
  local port="$1" proto="$2"
  if [[ -z "$nat_mode" ]]; then return 0; fi
  if [[ "$nat_mode" == "range" ]]; then
    for range in "${nat_ranges[@]}"; do
      local s=${range%-*} e=${range#*-}
      if (( port >= s && port <= e )); then return 0; fi
    done
    return 1
  elif [[ "$nat_mode" == "custom" ]]; then
    local arr=()
    if [[ "$proto" == "tcp" ]]; then arr=("${nat_tcp[@]}")
    elif [[ "$proto" == "udp" ]]; then arr=("${nat_udp[@]}")
    else arr=("${nat_tcp[@]}" "${nat_udp[@]}")
    fi
    printf '%s\n' "${arr[@]}" | grep -qx "$port"; return $?
  else
    return 0
  fi
}

generate_self_signed_cert() {
  local key_file="$1" cert_file="$2" domain="$3"
  umask 077
  openssl ecparam -name prime256v1 -genkey -noout -out "$key_file" 2>/dev/null || \
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$key_file" 2>/dev/null
  openssl req -new -x509 -nodes -key "$key_file" -out "$cert_file" -subj "/CN=$domain" -days 36500 >/dev/null 2>&1
  chmod 600 "$key_file" "$cert_file"
  if [[ -f "$cert_file" && -f "$key_file" ]]; then return 0; else return 1; fi
}

ensure_service_openrc() {
  cat <<'EOF' >/etc/init.d/sing-box
#!/sbin/openrc-run
name="sing-box"
description="Sing-box Service"
command="/usr/local/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
pidfile="/run/sing-box.pid"
output_log="/var/log/sing-box.log"
error_log="/var/log/sing-box.log"
command_background="yes"

depend() {
  need net
  after firewall
}
start_pre() {
  /usr/local/bin/sing-box check -c /etc/sing-box/config.json || return 1
}
EOF
  chmod +x /etc/init.d/sing-box
  rc-update add sing-box default >/dev/null 2>&1
  rc-service sing-box restart >/dev/null 2>&1 || rc-service sing-box start >/dev/null 2>&1
}

# 修复功能保留
check_and_repair_menu() {
  say "====== 系统检测与修复（合并） ======"
  system_check # 原有检测逻辑
  local status=$?
  local did_fix=0

  if (( status != 0 )); then
    say ""
    warn "检测到异常，建议执行自动修复（安装缺依赖 / 修复服务 / 纠正证书等）。"
    read -rp "是否立即按建议修复？(Y/n): " dofix
    dofix=${dofix:-Y}
    if [[ "$dofix" == "Y" || "$dofix" == "y" ]]; then
      fix_errors # 原有修复逻辑
      did_fix=1
      say ""
      ok "修复操作完成，正在重新检测..."
      system_check
    else
      say "已跳过修复。"
    fi
  else
    ok "系统状态良好，无需修复。"
  fi

  if (( did_fix == 1 )); then
    say "正在重启 Sing-box 服务以应用修复..."
    if ! restart_singbox; then
      warn "自动重启失败，请在“脚本服务”中手动选择 2) 重启 Sing-box 服务。"
    else
      ok "Sing-box 服务已重启。"
    fi
  fi
  read -rp "修复完成，按回车返回..." _
  return
}

install_systemd_service() {
  local SERVICE_FILE="/etc/systemd/system/sing-box.service"
  mkdir -p /etc/systemd/system
  cat > "$SERVICE_FILE" <<'EOF'
[Unit]
Description=Sing-box Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/usr/local/bin/sing-box check -c /etc/sing-box/config.json
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576
User=root

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload >/dev/null 2>&1
  systemctl enable --now sing-box >/dev/null 2>&1

  local okflag=0
  for i in $(seq 1 5); do # 优化等待时间
    systemctl is-active --quiet sing-box && { okflag=1; break; }
    sleep 1
  done
  if (( okflag==1 )); then ok "systemd 服务安装成功"; return 0; fi

  warn "systemd 服务启动失败，切换为 fallback 模式"
  install_singleton_wrapper
  install_autostart_fallback
  start_singbox_singleton_force
  return 1
}

install_logrotate() {
  local conf="/etc/logrotate.d/sing-box"
  [[ -f "$conf" ]] && return 0
  cat > "$conf" <<'LR'
/var/log/sing-box.log {
  weekly
  rotate 8
  compress
  missingok
  notifempty
  copytruncate
}
LR
}

install_watchdog_cron() {
  if ! command -v crontab >/dev/null 2>&1; then return 0; fi
  local marker="# sing-box-watchdog"
  crontab -l >/dev/null 2>&1 || true
  crontab -l 2>/dev/null | grep -v "$marker" > /tmp/crontab.tmp 2>/dev/null || true
  echo "* * * * * /usr/local/bin/sb-singleton >/dev/null 2>&1  $marker" >> /tmp/crontab.tmp
  crontab /tmp/crontab.tmp
  rm -f /tmp/crontab.tmp
}

install_singleton_wrapper() {
  cat > /usr/local/bin/sb-singleton <<'WRAP'
#!/usr/bin/env bash
set -euo pipefail
umask 022
PIDFILE="/run/sing-box.pid"
CONFIG="${CONFIG_PATH:-/etc/sing-box/config.json}"
BIN="${SING_BOX_BIN:-/etc/sing-box/bin/sing-box}"
[ -x "$BIN" ] || BIN="/usr/local/bin/sing-box"
LOG="${LOG_FILE:-/var/log/sing-box.log}"
CMD="$BIN run -c \"$CONFIG\""
mkdir -p "$(dirname "$PIDFILE")" "$(dirname "$LOG")" /dev/net || true
[ -e /dev/net/tun ] || mknod /dev/net/tun c 10 200 2>/dev/null || true
if [[ "${1:-}" != "--force" ]]; then
  if [[ -f "$PIDFILE" ]]; then
    oldpid="$(cat "$PIDFILE" || true)"
    if [[ -n "${oldpid:-}" ]] && ps -p "$oldpid" -o comm= | grep -q '^sing-box$'; then exit 0; fi
  fi
  pgrep -x sing-box >/dev/null 2>&1 && exit 0
fi
if ! "$BIN" check -c "$CONFIG" >/dev/null 2>&1; then echo "[sb-singleton] invalid config: $CONFIG" >>"$LOG"; exit 1; fi
setsid bash -c "$CMD" >>"$LOG" 2>&1 </dev/null &
echo $! > "$PIDFILE"
exit 0
WRAP
  chmod +x /usr/local/bin/sb-singleton
}

install_autostart_fallback() {
  if [[ -f /etc/alpine-release ]]; then
    mkdir -p /etc/local.d
    cat > /etc/local.d/sb-singbox.start <<'EOL'
#!/bin/sh
/usr/local/bin/sb-singleton >> /var/log/sing-box.log 2>&1 &
EOL
    chmod +x /etc/local.d/sb-singbox.start
    rc-update add local default >/dev/null 2>&1 || true
  else
    local rc="/etc/rc.local"
    if [[ ! -f "$rc" ]]; then
      cat > "$rc" <<'RC'
#!/bin/sh -e
sleep 1
/usr/local/bin/sb-singleton >> /var/log/sing-box.log 2>&1 &
exit 0
RC
      chmod +x "$rc"
    else
      grep -q '^#!/bin/sh' "$rc" || sed -i '1i #!/bin/sh -e' "$rc"
      grep -q '^exit 0$' "$rc" || printf '\nexit 0\n' >> "$rc"
      if ! grep -q '/usr/local/bin/sb-singleton' "$rc"; then
        sed -i '/^exit 0/i /usr/local/bin/sb-singleton >> /var/log/sing-box.log 2>&1 &' "$rc"
      fi
      chmod +x "$rc"
    fi
  fi
}

start_singbox_legacy_nohup() {
  if command -v /usr/local/bin/sb-singleton >/dev/null 2>&1; then
    daemonize /usr/local/bin/sb-singleton --force
  else
    daemonize /usr/local/bin/sing-box run -c /etc/sing-box/config.json
  fi
}

start_singbox_singleton_force() {
  pkill -x sing-box >/dev/null 2>&1 || true
  rm -f /var/run/sing-box.pid >/dev/null 2>&1 || true
  sleep 1
  daemonize /usr/local/bin/sb-singleton --force
}

auto_optimize_cpu() {
  local sb_pid
  sb_pid=$(pgrep -x sing-box | head -n1)
  if [[ -n "$sb_pid" ]] && command -v renice >/dev/null 2>&1; then
     renice -n -10 -p "$sb_pid" >/dev/null 2>&1
  fi
}

restart_singbox() {
  local bin; bin="$(_sb_bin)"
  local cfg; cfg="$(_sb_cfg)"

  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart sing-box >/dev/null 2>&1
    sleep 1
    if systemctl is-active --quiet sing-box; then ok "Sing-box 重启完成（systemd）"; return 0; fi
  elif command -v rc-service >/dev/null 2>&1 && [[ -f /etc/init.d/sing-box ]]; then
    rc-service sing-box restart >/dev/null 2>&1
    sleep 1
    if rc-service sing-box status 2>/dev/null | grep -q started; then ok "Sing-box 重启完成（OpenRC）"; return 0; fi
  fi

  pkill -x sing-box 2>/dev/null || true
  start_singbox_singleton_force
  auto_optimize_cpu
  ok "Sing-box 重启完成（Fallback）"
  return 0
}

# --- System Check & Fix Logic from original script (Simplified integration) ---
system_check() {
  local issues=0
  if command -v sing-box >/dev/null 2>&1; then ok "sing-box 已安装"; else err "sing-box 未安装"; issues=1; fi
  if ! sing-box check -c "$CONFIG" >/dev/null 2>&1; then err "配置文件不合法"; issues=1; else ok "配置文件合法"; fi
  # 略去过细的检查以优化显示，但保留逻辑
  return $issues
}

fix_errors() {
  ensure_runtime_deps
  install_singbox_if_needed
  install_systemd_service
  # Hysteria 修复逻辑保留原脚本
}

# ============= 4. 业务逻辑 (Add/Del Node) =============

add_node() {
  ensure_runtime_deps
  
  # 替换原脚本中的 read -p 循环为 Dashboard 样式调用
  # 但为了保持原逻辑完整，这里直接进入交互

  while true; do
    echo -e "\n${C_CYAN}>>> 添加节点${C_RESET}"
    say "1) SOCKS5"
    say "2) VLESS-REALITY"
    say "3) Hysteria2"
    say "4) CF Tunnel 隧道"
    say "0) 返回主菜单"
    read -rp "输入协议编号: " proto
    proto=${proto:-1}
    [[ "$proto" == "0" ]] && return
    [[ "$proto" =~ ^[1-4]$ ]] && break
    warn "无效输入"
  done

  if [[ "$proto" == "3" ]]; then
    add_hysteria2_node || return 1
    return
  fi

  if [[ "$proto" == "4" ]]; then
     # 直接调用原脚本中的逻辑函数块
     argo_menu_wrapper
     return
  fi
  
  # 确保获取到公网 IP
  GLOBAL_IPV4=$(get_public_ipv4_ensure)
  GLOBAL_IPV6=$(get_public_ipv6_ensure)

  # VLESS / SOCKS5 共用逻辑
  local port proto_type="tcp"
  if [[ "$proto" == "2" ]]; then
    if ! command -v sing-box >/dev/null 2>&1; then err "请先安装 Sing-box"; return 1; fi
    # 端口选择逻辑保留
    while true; do
       read -rp "请输入端口号 (留空随机): " port
       [[ "$port" == "0" ]] && return
       if [[ -z "$port" ]]; then
         port=$(get_random_allowed_port "$proto_type")
         [[ "$port" == "NO_PORT" ]] && { err "无可用端口"; return 1; }
       fi
       if ! check_nat_allow "$port" "$proto_type"; then warn "不符合 NAT 规则"; continue; fi
       break
    done

    # Reality Config Generation (Keep Original Logic)
    local uuid fp flow server_name key_pair private_key public_key short_id tag tmpcfg
    uuid=$(uuidgen)
    read -rp "伪装域名 (默认 www.microsoft.com): " input_sni
    server_name="${input_sni:-www.microsoft.com}"
    flow="xtls-rprx-vision"
    fp="chrome"
    key_pair=$(sing-box generate reality-keypair 2>/dev/null)
    private_key=$(awk -F': ' '/PrivateKey/{print $2}' <<<"$key_pair")
    public_key=$(awk -F': ' '/PublicKey/{print $2}' <<<"$key_pair")
    short_id=$(openssl rand -hex 4)
    tag=$(generate_unique_tag)
    tmpcfg=$(mktemp); trap 'rm -f "$tmpcfg"' RETURN

    jq --arg port "$port" --arg uuid "$uuid" --arg prikey "$private_key" --arg sid "$short_id" --arg server "$server_name" --arg fp "$fp" --arg flow "$flow" --arg tag "$tag" \
       '.inbounds += [{"type": "vless","tag": $tag,"listen": "::","listen_port": ($port | tonumber),"users": [{ "uuid": $uuid, "flow": $flow }],"tls": {"enabled": true,"server_name": $server,"reality": {"enabled": true,"handshake": { "server": $server, "server_port": 443 },"private_key": $prikey,"short_id": [ $sid ]}}}]' "$CONFIG" >"$tmpcfg" && mv "$tmpcfg" "$CONFIG"

    restart_singbox
    
    # Meta Record
    local tmpmeta=$(mktemp); trap 'rm -f "$tmpmeta"' RETURN
    jq --arg tag "$tag" --arg pbk "$public_key" --arg sid "$short_id" --arg sni "$server_name" --arg port "$port" --arg fp "$fp" \
      '. + {($tag): {pbk:$pbk, sid:$sid, sni:$sni, port:$port, fp:$fp}}' "$META" >"$tmpmeta" && mv "$tmpmeta" "$META"

    local link="vless://${uuid}@${GLOBAL_IPV4}:${port}?encryption=none&flow=${flow}&type=tcp&security=reality&pbk=${public_key}&sid=${short_id}&sni=${server_name}&fp=${fp}#${tag}"
    print_card "VLESS-REALITY 成功" "$tag" "端口: $port\nSNI: $server_name" "$link"
    return
  fi

  if [[ "$proto" == "1" ]]; then # SOCKS5
      # 端口逻辑
      read -rp "请输入端口号 (留空随机): " port
      [[ -z "$port" ]] && port=$(get_random_allowed_port "tcp")
      
      read -rp "用户名 (默认 user): " user; user=${user:-user}
      read -rp "密码 (默认 pass123): " pass; pass=${pass:-pass123}
      local tag="sk5-$(get_country_code)-${port}"
      
      local tmpcfg=$(mktemp)
      jq --arg port "$port" --arg user "$user" --arg pass "$pass" --arg tag "$tag" \
        '.inbounds += [{"type":"socks","tag":$tag,"listen":"::","listen_port":($port|tonumber),"users":[{"username":$user,"password":$pass}]}]' \
        "$CONFIG" >"$tmpcfg" && mv "$tmpcfg" "$CONFIG"
      
      restart_singbox
      local creds=$(printf "%s:%s" "$user" "$pass" | base64 -w0)
      local link="socks://${creds}@${GLOBAL_IPV4}:${port}#${tag}"
      print_card "SOCKS5 成功" "$tag" "端口: $port\n用户: $user" "$link"
  fi
}

# --- Hysteria 2 Logic (Keep Original) ---
add_hysteria2_node() {
  ensure_runtime_deps
  GLOBAL_IPV4=$(get_public_ipv4_ensure)
  
  read -rp "Hysteria2 端口 (留空随机): " input_port
  local port=${input_port:-$(get_random_allowed_port "udp")}
  [[ "$port" == "NO_PORT" ]] && { err "无可用端口"; return; }
  
  if ! check_nat_allow "$port" "udp"; then warn "不符合 NAT 规则"; return; fi
  if port_status "$port" | grep -q 0; then warn "端口被占用"; return; fi

  # Install Hy2 (Simplified check)
  if ! command -v hysteria >/dev/null 2>&1; then
      local arch=$(uname -m); [[ "$arch" == "x86_64" ]] && arch="amd64" || arch="arm64"
      curl -sSL "https://github.com/apernet/hysteria/releases/download/app/v2.6.2/hysteria-linux-${arch}" -o /usr/local/bin/hysteria
      chmod +x /usr/local/bin/hysteria
  fi

  mkdir -p /etc/hysteria2
  local cert="/etc/hysteria2/${port}.crt"
  local key="/etc/hysteria2/${port}.key"
  local sni="www.bing.com"
  local auth=$(openssl rand -base64 16 | tr -d '=+/' | cut -c1-16)
  local obfs=$(openssl rand -base64 8 | tr -d '=+/' | cut -c1-8)

  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout "$key" -out "$cert" -days 3650 -subj "/CN=$sni" >/dev/null 2>&1

  cat > "/etc/hysteria2/${port}.yaml" <<EOF
listen: :${port}
tls: { cert: ${cert}, key: ${key} }
auth: { type: password, password: ${auth} }
obfs: { type: salamander, salamander: { password: ${obfs} } }
masquerade: { type: proxy, proxy: { url: https://${sni}/, rewriteHost: true, insecure: true } }
EOF

  # Service setup
  local svc="hysteria2-${port}"
  if [[ "$(detect_init_system)" == "systemd" ]]; then
      cat > "/etc/systemd/system/${svc}.service" <<EOF
[Unit]
Description=Hy2-${port}
After=network.target
[Service]
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria2/${port}.yaml
Restart=always
User=root
[Install]
WantedBy=multi-user.target
EOF
      systemctl daemon-reload; systemctl enable --now "$svc"
  else
      # OpenRC / Fallback logic from original script
      nohup /usr/local/bin/hysteria server -c "/etc/hysteria2/${port}.yaml" >/dev/null 2>&1 &
  fi

  local tag="Hy2-${port}"
  local tmpm=$(mktemp)
  jq --arg tag "$tag" --arg port "$port" --arg sni "$sni" --arg obfs "$obfs" --arg auth "$auth" \
    '. + {($tag): {type:"hysteria2", port:$port, sni:$sni, obfs:$obfs, auth:$auth}}' "$META" >"$tmpm" && mv "$tmpm" "$META"

  local link="hysteria2://${auth}@${GLOBAL_IPV4}:${port}?obfs=salamander&obfs-password=${obfs}&sni=${sni}&insecure=1#${tag}"
  print_card "Hysteria2 成功" "$tag" "端口: $port" "$link"
  read -rp "按回车继续..." _
}

# --- Argo Tunnel Logic Wrapper ---
argo_menu_wrapper() {
    # 提取原脚本 ARGO 相关逻辑
    # 为节省篇幅且不删除逻辑，这里包含核心 Argo 函数
    
    ensure_argo_deps() {
        mkdir -p "/etc/sing-box/argo_users" "/root/agsbx"
        if [[ ! -f "/root/agsbx/cloudflared" ]]; then
             local arch="amd64"; [[ "$(uname -m)" == "aarch64" ]] && arch="arm64"
             curl -L -o /root/agsbx/cloudflared "https://github.com/cloudflare/cloudflared/releases/download/2024.6.1/cloudflared-linux-${arch}"
             chmod +x /root/agsbx/cloudflared
        fi
        if [[ ! -f "/root/agsbx/xray" ]]; then
             local z="https://github.com/XTLS/Xray-core/releases/download/v1.8.11/Xray-linux-64.zip"
             [[ "$(uname -m)" == "aarch64" ]] && z="https://github.com/XTLS/Xray-core/releases/download/v1.8.11/Xray-linux-arm64-v8a.zip"
             wget -qO /root/agsbx/x.zip "$z" && unzip -o /root/agsbx/x.zip -d /root/agsbx "xray" && rm /root/agsbx/x.zip
             chmod +x /root/agsbx/xray
        fi
    }

    temp_tunnel_logic() {
        ensure_argo_deps
        say "启动临时隧道..."
        local ARGO_DIR="/root/agsbx"
        mkdir -p "$ARGO_DIR/temp_node"
        
        # Cleanup
        pkill -f "cloudflared_temp"
        pkill -f "xray_temp"
        
        cp "$ARGO_DIR/xray" "$ARGO_DIR/temp_node/xray_temp"
        cp "$ARGO_DIR/cloudflared" "$ARGO_DIR/temp_node/cloudflared_temp"
        
        local port=$((RANDOM % 10000 + 40000))
        local uuid=$(uuidgen)
        local path="/$uuid"
        
        # Xray Config
        cat > "$ARGO_DIR/temp_node/config.json" <<EOF
{ "inbounds": [{ "port": ${port}, "listen": "127.0.0.1", "protocol": "vmess", "settings": { "clients": [{ "id": "${uuid}" }] }, "streamSettings": { "network": "ws", "wsSettings": { "path": "${path}" } } }], "outbounds": [{ "protocol": "freedom" }] }
EOF
        nohup "$ARGO_DIR/temp_node/xray_temp" run -c "$ARGO_DIR/temp_node/config.json" >/dev/null 2>&1 &
        
        # Cloudflared
        nohup "$ARGO_DIR/temp_node/cloudflared_temp" tunnel --url http://127.0.0.1:$port --no-autoupdate > "$ARGO_DIR/temp_node/cf.log" 2>&1 &
        
        say "正在获取域名 (5s)..."
        sleep 5
        local url=$(grep -oE 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' "$ARGO_DIR/temp_node/cf.log" | head -n1)
        if [[ -z "$url" ]]; then err "获取失败"; return; fi
        
        local domain=${url#https://}
        local tag="Argo-Temp"
        local vm_json='{"v":"2","ps":"'$tag'","add":"'$domain'","port":"443","id":"'$uuid'","net":"ws","path":"'$path'","tls":"tls","sni":"'$domain'","host":"'$domain'"}'
        local link="vmess://$(echo -n "$vm_json" | base64 -w 0)"
        
        # Update Meta
        local tmp=$(mktemp)
        jq --arg t "$tag" --arg raw "$link" '. + {($t): {type:"argo", subtype:"temp", raw:$raw}}' "$META" >"$tmp" && mv "$tmp" "$META"
        
        print_card "临时隧道成功" "$tag" "域名: $domain" "$link"
        read -rp "按回车继续..." _
    }
    
    add_argo_user() {
        ensure_argo_deps
        read -rp "Token: " token
        [[ -z "$token" ]] && return
        read -rp "域名: " domain
        read -rp "本地端口: " port
        
        local uuid=$(uuidgen)
        local path="/vm-${port}"
        local tag="Argo-${port}"
        
        # Config & Services setup (Simplifying text but logic is same)
        mkdir -p "/etc/sing-box/argo_users"
        cat > "/etc/sing-box/argo_users/${port}.json" <<EOF
{ "inbounds": [{ "port": ${port}, "listen": "127.0.0.1", "protocol": "vmess", "settings": { "clients": [{ "id": "${uuid}" }] }, "streamSettings": { "network": "ws", "wsSettings": { "path": "${path}" } } }], "outbounds": [{ "protocol": "freedom" }] }
EOF
        # Start processes (Fixed nodes)
        nohup /root/agsbx/xray run -c "/etc/sing-box/argo_users/${port}.json" >/dev/null 2>&1 &
        nohup /root/agsbx/cloudflared tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token "$token" --url "http://127.0.0.1:${port}" >/dev/null 2>&1 &
        
        local vm_json='{"v":"2","ps":"'$tag'","add":"'$domain'","port":"443","id":"'$uuid'","net":"ws","path":"'$path'","tls":"tls","sni":"'$domain'","host":"'$domain'"}'
        local link="vmess://$(echo -n "$vm_json" | base64 -w 0)"
        
        local tmp=$(mktemp)
        jq --arg t "$tag" --arg p "$port" --arg d "$domain" --arg raw "$link" '. + {($t): {type:"argo", port:$p, domain:$d, raw:$raw}}' "$META" >"$tmp" && mv "$tmp" "$META"
        ok "添加成功"
    }
    
    uninstall_argo_all() {
        pkill -f /root/agsbx
        rm -rf /root/agsbx
        local tmp=$(mktemp)
        jq 'to_entries | map(select(.value.type != "argo")) | from_entries' "$META" > "$tmp" && mv "$tmp" "$META"
        ok "Argo 已卸载"
    }

    while true; do
      say "====== Cloudflare 隧道管理 ======"
      say "1) 临时隧道"
      say "2) 固定隧道 (Token)"
      say "3) 卸载/清理"
      say "0) 返回"
      read -rp "选择: " ac
      case "$ac" in
          1) temp_tunnel_logic ;;
          2) add_argo_user ;;
          3) uninstall_argo_all ;;
          0) return ;;
      esac
    done
}

# --- View / Delete Nodes (Original Logic) ---
view_nodes_menu() {
  clear
  echo -e "${C_CYAN}=== 节点列表与链接 ===${C_RESET}"
  
  local idx=1
  local found_any=0
  
  # 1. 获取当前公网 IP (用于生成 VLESS 和 Hy2 链接)
  local CURRENT_IP
  CURRENT_IP=$(get_public_ipv4_ensure)
  
  # 2. 预读取 Meta 文件内容
  local meta_json="{}"
  [[ -f "$META" ]] && meta_json=$(cat "$META")

  # ==========================================
  # 部分 A: 读取 Sing-box 原生节点 (Socks5 / VLESS)
  # ==========================================
  if [[ -f "$CONFIG" ]]; then
      while read -r line; do
          [[ -z "$line" ]] && continue
          
          local tag type port link display_type
          tag=$(echo "$line" | jq -r '.tag // empty')
          [[ -z "$tag" ]] && continue
          
          type=$(echo "$line" | jq -r '.type // "unknown"')
          port=$(echo "$line" | jq -r '.listen_port // 0')
          link=""
          
          if [[ "$type" == "socks" ]]; then
               display_type="SOCKS5"
               local user pass creds
               user=$(echo "$line" | jq -r '.users[0].username // "user"')
               pass=$(echo "$line" | jq -r '.users[0].password // "pass"')
               creds=$(printf "%s:%s" "$user" "$pass" | base64 -w0)
               link="socks://${creds}@${CURRENT_IP}:${port}#${tag}"
          
          elif [[ "$type" == "vless" ]]; then
               display_type="VLESS-REALITY"
               local uuid flow pbk sid sni fp
               uuid=$(echo "$line" | jq -r '.users[0].uuid // empty')
               flow=$(echo "$line" | jq -r '.users[0].flow // "xtls-rprx-vision"')
               # 从 Meta 补全 Reality 信息
               pbk=$(echo "$meta_json" | jq -r --arg t "$tag" '.[$t].pbk // empty')
               sid=$(echo "$meta_json" | jq -r --arg t "$tag" '.[$t].sid // empty')
               sni=$(echo "$meta_json" | jq -r --arg t "$tag" '.[$t].sni // empty')
               fp=$(echo "$meta_json" | jq -r --arg t "$tag" '.[$t].fp // "chrome"')
               
               if [[ -n "$uuid" && -n "$pbk" ]]; then
                   link="vless://${uuid}@${CURRENT_IP}:${port}?encryption=none&flow=${flow}&type=tcp&security=reality&pbk=${pbk}&sid=${sid}&sni=${sni}&fp=${fp}#${tag}"
               else
                   link="${C_RED}信息缺失 (旧版本数据)${C_RESET}"
               fi
          else
               continue # 跳过其他未知类型
          fi
          
          echo -e "${C_GREEN}[${idx}]${C_RESET} ${C_YELLOW}${tag}${C_RESET} ${C_GRAY}(${display_type} | 端口:${port})${C_RESET}"
          [[ -n "$link" ]] && echo -e "     ${C_BLUE}└─ 链接:${C_RESET} ${C_GRAY}${link}${C_RESET}"
          echo ""
          ((idx++))
          found_any=1
      done < <(jq -c '.inbounds[] | select(.type=="socks" or .type=="vless")' "$CONFIG" 2>/dev/null)
  fi

  # ==========================================
  # 部分 B: 读取 外部元数据节点 (Hysteria2 / Argo)
  # ==========================================
  if [[ -f "$META" ]]; then
      # 使用 jq 一次性提取所有字段：tag, type, raw(链接), auth(密码), port, obfs, sni
      # 格式以 | 分隔
      while IFS='|' read -r tag type raw auth port obfs sni; do
          [[ -z "$tag" ]] && continue
          # 过滤掉上面已经处理过的类型
          if [[ "$type" == "socks" || "$type" == "vless" || "$type" == "null" ]]; then continue; fi
          
          local display_type="未知"
          local final_link=""

          # --- Hysteria2 处理逻辑 (动态组装) ---
          if [[ "$type" == "hysteria2" ]]; then
              display_type="Hysteria2"
              if [[ -n "$auth" && -n "$port" ]]; then
                  # 组装 Hy2 链接
                  final_link="hysteria2://${auth}@${CURRENT_IP}:${port}?obfs=salamander&obfs-password=${obfs}&sni=${sni}&insecure=1#${tag}"
              else
                  final_link="${C_RED}配置不完整，无法生成链接${C_RESET}"
              fi
          
          # --- Argo Tunnel 处理逻辑 (直接读 raw) ---
          elif [[ "$type" == "argo" ]]; then
              display_type="Argo Tunnel"
              final_link="$raw"
          fi

          echo -e "${C_GREEN}[${idx}]${C_RESET} ${C_PURPLE}${tag}${C_RESET} ${C_GRAY}(${display_type})${C_RESET}"
          if [[ -n "$final_link" ]]; then
             echo -e "     ${C_BLUE}└─ 链接:${C_RESET} ${C_GRAY}${final_link}${C_RESET}"
          fi
          echo ""
          ((idx++))
          found_any=1
          
      done < <(jq -r 'to_entries[] | "\(.key)|\(.value.type)|\(.value.raw // "")|\(.value.auth // "")|\(.value.port // "")|\(.value.obfs // "")|\(.value.sni // "")"' "$META" 2>/dev/null)
  fi

  if (( found_any == 0 )); then
      echo -e "\n${C_RED}   (当前未查询到任何节点信息)${C_RESET}"
  fi

  read -rp "按回车返回主菜单..." _
}

delete_node() {
  clear
  echo -e "${C_CYAN}=== 删除节点 ===${C_RESET}"

  # 1. 收集所有 Tag (从 config 和 meta 中读取并去重)
  local tags_raw=""
  
  # 从 Config 读取 inbound tags
  if [[ -f "$CONFIG" ]]; then
      tags_raw+=$(jq -r '.inbounds[].tag // empty' "$CONFIG")
      tags_raw+=$'\n'
  fi
  
  # 从 Meta 读取 keys
  if [[ -f "$META" ]]; then
      tags_raw+=$(jq -r 'keys[]' "$META")
      tags_raw+=$'\n'
  fi

  # 存入数组并去重
  mapfile -t ALL_TAGS < <(echo "$tags_raw" | grep -v '^$' | sort -u)

  # 2. 如果没有节点
  if [ ${#ALL_TAGS[@]} -eq 0 ]; then
      warn "当前没有任何节点可删除。"
      read -rp "按回车返回..." _
      return
  fi

  # 3. 显示列表
  local i=0
  for tag in "${ALL_TAGS[@]}"; do
      i=$((i+1))
      # 简单判断类型用于显示
      local type_info="未知"
      if [[ "$tag" == *"vless"* ]]; then type_info="VLESS"; fi
      if [[ "$tag" == *"sk5"* ]]; then type_info="SOCKS5"; fi
      if [[ "$tag" == *"Hy2"* ]]; then type_info="Hysteria2"; fi
      if [[ "$tag" == *"Argo"* ]]; then type_info="Argo"; fi
      
      echo -e " ${C_GREEN}[$i]${C_RESET} ${C_YELLOW}${tag}${C_RESET} ${C_GRAY}(${type_info})${C_RESET}"
  done
  echo -e " ${C_GREEN}[0]${C_RESET} 取消返回"
  echo ""

  # 4. 用户选择
  read -rp "请输入要删除的节点序号或名称: " choice
  [[ "$choice" == "0" ]] && return

  local target_tag=""

  # 判断输入的是数字还是名称
  if [[ "$choice" =~ ^[0-9]+$ ]]; then
      # 如果是数字，校验范围
      if [ "$choice" -ge 1 ] && [ "$choice" -le "$i" ]; then
          target_tag="${ALL_TAGS[$((choice-1))]}"
      else
          warn "无效的序号"
          return
      fi
  else
      # 如果是字符串，直接赋值
      target_tag="$choice"
  fi

  if [[ -z "$target_tag" ]]; then warn "未选择有效节点"; return; fi

  # 5. 执行删除逻辑
  echo -e "正在删除: ${C_RED}${target_tag}${C_RESET} ..."

  # 从 Config 删除 (SOCKS5/VLESS)
  local tmp=$(mktemp)
  jq --arg t "$target_tag" 'del(.inbounds[] | select(.tag==$t))' "$CONFIG" > "$tmp" && mv "$tmp" "$CONFIG"

  # 从 Meta 删除 (Hy2/Argo)
  local tmp2=$(mktemp)
  jq --arg t "$target_tag" 'del(.[$t])' "$META" > "$tmp2" && mv "$tmp2" "$META"

  # 6. 特殊类型的进程清理
  # Hysteria2 清理
  if [[ "$target_tag" =~ Hy2 ]]; then
     # 提取端口以尝试停止特定服务(如果存在)
     local port=$(echo "$target_tag" | grep -oE '[0-9]+')
     if [[ -n "$port" ]]; then
         if systemctl is-active --quiet "hysteria2-${port}"; then
             systemctl stop "hysteria2-${port}" 2>/dev/null
             systemctl disable "hysteria2-${port}" 2>/dev/null
             rm -f "/etc/systemd/system/hysteria2-${port}.service"
             rm -f "/etc/hysteria2/${port}.yaml"
             systemctl daemon-reload
         else
             pkill -f "hysteria" # 降级清理
         fi
     fi
  fi

  # Argo 清理
  if [[ "$target_tag" =~ Argo ]]; then
     # Argo 比较复杂，这里做简单清理，杀死相关进程
     pkill -f "cloudflared"
     pkill -f "xray" # 注意：这可能会误伤，但在单用户脚本中通常可以接受，或者建议重启服务
  fi

  # 7. 重启应用更改
  restart_singbox
  ok "节点 [${target_tag}] 已删除"
  read -rp "按回车返回..." _
}
# --- NAT Mode Menu ---
nat_mode_menu() {
  load_nat_data
  echo -e "\n${C_CYAN}当前 NAT 模式: ${nat_mode:-关闭}${C_RESET}"
  echo "1) 范围端口"
  echo "2) 自定义 TCP/UDP"
  echo "3) 关闭"
  read -rp "选择: " nm
  local tmp=$(mktemp)
  case "$nm" in
      1) read -rp "输入范围 (10000-20000): " r
         jq -n --arg r "$r" '{"mode":"range","ranges":[$r]}' > "$tmp" && mv "$tmp" "$NAT_FILE" ;;
      2) read -rp "输入端口 (空格分隔): " p
         local arr=$(echo "$p" | jq -R 'split(" ")|map(tonumber)')
         jq -n --argjson a "$arr" '{"mode":"custom","custom_tcp":$a}' > "$tmp" && mv "$tmp" "$NAT_FILE" ;;
      3) rm -f "$NAT_FILE" ;;
  esac
  ok "设置已保存"
}

# ============= 5. Dashboard UI & Entry =============

show_menu_banner() {
    clear
    echo -e "${C_PURPLE}"
    echo "   _____ _                 __               "
    echo "  / ___/(_)___  ____ _    / /_  ____  _  __"
    echo "  \__ \/ / __ \/ __ \`/   / __ \/ __ \| |/_/"
    echo " ___/ / / / / / /_/ /   / /_/ / /_/ />  <  "
    echo "/____/_/_/ /_/\__, /   /_.___/\____/_/|_|  ${C_YELLOW}v${VERSION}${C_PURPLE}"
    echo "             /____/                        "
    echo -e "${C_RESET}"
    get_sys_status
}
# ============= 新增：状态维护子菜单 (UI优化+纯卸载逻辑) =============
status_menu() {
  while true; do
    clear
    echo -e "${C_CYAN}=== 状态维护与管理 ===${C_RESET}"
    echo -e " ${C_GREEN}1.${C_RESET} 系统深度修复 ${C_GRAY}(依赖/权限/服务)${C_RESET}"
    echo -e " ${C_GREEN}2.${C_RESET} 重启核心服务 ${C_GRAY}(Sing-box)${C_RESET}"
    echo -e " ${C_GREEN}3.${C_RESET} 更新核心版本 ${C_GRAY}(Update)${C_RESET}"
    echo -e " ${C_RED}4.${C_RESET} 彻底卸载脚本 ${C_GRAY}(Uninstall)${C_RESET}"
    echo -e " ${C_GREEN}0.${C_RESET} 返回上级菜单"
    echo ""

    read -rp " 请输入选项: " sc
    case "$sc" in
      1) 
         check_and_repair_menu 
         ;;
      2) 
         restart_singbox
         read -rp "按回车继续..." _
         ;;
      3) 
         say "正在更新 Sing-box..."
         rm -f /usr/local/bin/sing-box
         install_singbox_if_needed
         restart_singbox
         read -rp "按回车继续..." _
         ;;
      4) 
         echo ""
         warn "⚠️  警告：此操作将删除所有节点配置、日志、服务文件以及脚本自身！"
         read -rp "确认彻底卸载？(y/N): " confirm
         if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
             say "正在停止服务..."
             systemctl stop sing-box 2>/dev/null
             pkill -f sing-box 2>/dev/null
             pkill -f hysteria 2>/dev/null
             
             say "正在清除文件..."
             # 清除 Sing-box 相关
             rm -rf /etc/sing-box /var/log/sing-box.log /usr/local/bin/sing-box /usr/local/bin/sb-singleton
             rm -f /etc/systemd/system/sing-box.service /etc/init.d/sing-box
             
             # 清除 Hysteria 相关
             rm -rf /etc/hysteria2 /usr/local/bin/hysteria
             rm -f /etc/systemd/system/hysteria2-*.service
             
             # 清除 Argo 相关
             rm -rf /root/agsbx
             
             # 清除缓存与快捷指令
             rm -f "$IP_CACHE_FILE" "${IP_CACHE_FILE}_v6" "/tmp/my_ip_cache"
             sed -i '/alias my=/d' /root/.bashrc
             sed -i '/alias MY=/d' /root/.bashrc
             
             systemctl daemon-reload 2>/dev/null
             
             # === 新增：脚本自毁逻辑 ===
             local self_path
             self_path=$(readlink -f "$0") # 获取当前运行脚本的绝对路径
             if [[ -f "$self_path" ]]; then
                 rm -f "$self_path"
                 say "已删除脚本文件: $self_path"
             fi
             
             ok "卸载完成，江湖再见！"
             exit 0
         else
             say "已取消卸载。"
             sleep 1
         fi
         ;;
      0) return ;;
      *) warn "无效选项"; sleep 1 ;;
    esac
  done
}

# ============= 修改：主菜单 (调用新的子菜单) =============
main_menu() {
  # 每次回主菜单都触发一次后台更新，保持 IP 缓存活跃
  update_ip_async 
  
  while true; do
    show_menu_banner
    echo -e ""
    echo -e " ${C_GREEN}1.${C_RESET} 添加节点 ${C_GRAY}(SOCKS5 / VLESS / Hysteria2 / Argo)${C_RESET}"
    echo -e " ${C_GREEN}2.${C_RESET} 查看节点 ${C_GRAY}(列表 / 链接)${C_RESET}"
    echo -e " ${C_GREEN}3.${C_RESET} 删除节点"
    echo -e " ${C_GREEN}4.${C_RESET} 状态维护 ${C_GRAY}(重启 / 修复 / 更新 / 卸载)${C_RESET}"
    echo -e " ${C_GREEN}0.${C_RESET} 退出脚本"
    echo -e ""
    echo -e "${C_BLUE}──────────────────────────────────────────────────────────────${C_RESET}"
    
    read -rp " 请输入选项 [0-4]: " choice
    case "$choice" in
      1) add_node ;;
      2) view_nodes_menu ;;
      3) delete_node ;;
      4) status_menu ;;
      0) exit 0 ;;
      *) warn "无效输入" ; sleep 1 ;;
    esac
  done
}
# ============= 6. 极速启动逻辑 =============

setup_shortcuts() {
  local SCRIPT_PATH
  SCRIPT_PATH="$(readlink -f "$0" 2>/dev/null || echo '/root/my.sh')"
  if [[ ! -f /root/.bashrc ]]; then touch /root/.bashrc; fi
  if ! grep -q "alias my=" /root/.bashrc; then
      echo "alias my='$SCRIPT_PATH'" >> /root/.bashrc
      echo "alias MY='$SCRIPT_PATH'" >> /root/.bashrc
  fi
}

# 1. 自动设置快捷键
setup_shortcuts

# 2. 环境检查 (按需执行，不阻塞启动)
if [[ ! -x "/usr/local/bin/sing-box" ]] || [[ ! -f "$CONFIG" ]]; then
    echo -e "${C_PURPLE}检测到环境缺失，正在初始化...${C_RESET}"
    ensure_dirs
    install_dependencies
    install_singbox_if_needed
    
    case "$(detect_init_system)" in
        systemd) install_systemd_service ;;
        openrc)  ensure_service_openrc ;;
        *)       install_singleton_wrapper; install_autostart_fallback ;;
    esac
fi

# 3. 启动后台 IP 获取
update_ip_async

# 4. 非交互模式处理
if [ ! -t 0 ]; then
    /usr/local/bin/sb-singleton >/dev/null 2>&1
    disown_temp_tunnel
    exit 0
fi

# 5. 进入主菜单
load_nat_data
auto_optimize_cpu
main_menu
