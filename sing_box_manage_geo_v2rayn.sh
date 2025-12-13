#!/usr/bin/env bash
# sk5.sh 融合 Misaka-blog Hysteria2 一键逻辑版 (性能优化版)
# 优化内容：减少外部进程调用、缓存系统检测结果、降低轮询频率、内存手动回收
# 🚀 代码大师修改：默认执行完整初始化，并自动设置 'my' 和 'MY' 别名快捷指令

export LC_ALL=C # 优化 grep/sed/awk 处理速度

ARGO_TEMP_CACHE="/root/agsbx/jh.txt"
ARGO_FIXED_CACHE="/root/agsbx/gd.txt"
ARGO_META_TAG_PREFIX="Argo-"

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
# A. 恢复 on_int_menu_quit_only 函数
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
# A. 修改 on_int_menu_quit_only 函数
# 替换为：
# 目的：执行清理函数，然后立即退出（不重启 Sing-box 服务）
trap 'disown_temp_tunnel >/dev/null 2>&1; echo; exit 0' INT
trap '' SIGHUP 2>/dev/null || true
daemonize() { setsid "$@" </dev/null >/dev/null 2>&1 & }
if [ -z "$BASH_VERSION" ]; then
  echo "本脚本需要 Bash 解释器，请使用 Bash 运行。"
  exit 1
fi

# ============= 基础工具与变量定义 =============
umask 022
C_RESET='\033[0m'
C_GREEN='\033[32m'
C_YELLOW='\033[33m'
C_CYAN='\033[36m'
C_RED='\033[31m'

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

CONFIG="/etc/sing-box/config.json"
META="/etc/sing-box/nodes_meta.json"
NAT_FILE="/etc/sing-box/nat_ports.json"
LOG_FILE="/var/log/sing-box.log"
DEPS_CHECKED=0  # 全局标志

say()  { printf "%s\n" "$*"; }
err()  { printf " %s\n" "$*" >&2; }
ok()   { printf " %s\n" "$*" >&2; }
warn() { printf " %s\n" "$*" >&2; }
log_msg() {
  local level="$1" msg="$2"
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $msg" >> "$LOG_FILE"
}

# ============= 基础工具 =============
# detect_os 已移至头部
# detect_init_system 已移至头部

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
    # 优先使用 PATH 找到的命令
    readlink -f "$(command -v "$cmd")"
    return 0
  fi
  # 其次查找常见绝对路径 (针对精简环境)
  for p in /usr/bin/"$cmd" /bin/"$cmd" /sbin/"$cmd"; do
    [ -x "$p" ] && echo "$p" && return 0
  done
  return 1
}
disown_temp_tunnel() {
  local TEMP_ARGO_DIR="/root/agsbx/temp_node"
  local TEMP_PID_FILE="$TEMP_ARGO_DIR/temp_cloudflared.pid"
  local TEMP_XRAY_PID_FILE="$TEMP_ARGO_DIR/temp_xray.pid"  
  
  # 尝试 disown Cloudflared 进程（优先用 PID 文件，fallback pgrep）
  if [[ -f "$TEMP_PID_FILE" ]]; then
    local cfd_pid=$(cat "$TEMP_PID_FILE" 2>/dev/null)
  else
    local cfd_pid=$(pgrep -f "$TEMP_ARGO_DIR/cloudflared_temp" | head -n 1)
  fi
  if [ -n "$cfd_pid" ] && ps -p "$cfd_pid" >/dev/null 2>&1; then
    disown "$cfd_pid" 2>/dev/null || true 
  fi
  
  # 尝试 disown Xray 进程（类似）
  if [[ -f "$TEMP_XRAY_PID_FILE" ]]; then
    local xray_pid=$(cat "$TEMP_XRAY_PID_FILE" 2>/dev/null)
  else
    local xray_pid=$(pgrep -f "$TEMP_ARGO_DIR/xray_temp" | head -n 1)
  fi
  if [ -n "$xray_pid" ] && ps -p "$xray_pid" >/dev/null 2>&1; then
    disown "$xray_pid" 2>/dev/null || true
  fi
  
  # 清理 PID 文件
  rm -f "$TEMP_PID_FILE" "$TEMP_XRAY_PID_FILE"
  
  return 0
}
# 缓存 systemctl 和 rc-service 的绝对路径
_SYSTEMCTL_CMD="$(resolve_service_cmd systemctl || true)"
_RCSERVICE_CMD="$(resolve_service_cmd rc-service || true)"
_sb_any_port_listening() {
  local cfg="$(_sb_cfg)"
  [[ -s "$cfg" ]] || return 1
  # 优化：一次性获取 ss 输出
  local ss_out
  ss_out=$(ss -ltnp 2>/dev/null)
  
  local any=""
  while read -r p; do
    [[ -z "$p" ]] && continue
    if echo "$ss_out" | grep -q ":$p "; then any=1; break; fi
    # 减少 timeout bash 调用，仅作为 fallback
    # timeout 1 bash -lc "echo >/dev/tcp/127.0.0.1/$p" >/dev/null 2>&1 && { any=1; break; }
  done < <(jq -r '.inbounds[].listen_port' "$cfg" 2>/dev/null)
  [[ -n "$any" ]]
}

ensure_dirs() {
  mkdir -p /etc/sing-box
  [[ -f "$CONFIG" ]] || printf '%s\n' '{"inbounds":[],"outbounds":[{"type":"direct"}],"route":{"rules":[]}}' >"$CONFIG"
  [[ -f "$META"   ]] || printf '%s\n' '{}' >"$META"
}

# 合并依赖安装
install_deps() {
  local deps=("$@")
  local os="$(detect_os)"
  local installed=0
  for cmd in "${deps[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      case "$os" in
        debian|ubuntu)
          DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || log_msg "WARN" "apt update failed"
          DEBIAN_FRONTEND=noninteractive apt-get install -y "$cmd" >/dev/null 2>&1 || log_msg "WARN" "Failed to install $cmd on $os"
          ;;
        alpine)
          apk add --no-cache "$cmd" >/dev/null 2>&1 || log_msg "WARN" "Failed to install $cmd on $os"
          ;;
        centos|rhel)
          yum install -y "$cmd" >/dev/null 2>&1 || log_msg "WARN" "Failed to install $cmd on $os"
          ;;
        fedora)
          dnf install -y "$cmd" >/dev/null 2>&1 || log_msg "WARN" "Failed to install $cmd on $os"
          ;;
        *) log_msg "WARN" "Unknown OS, cannot install $cmd" ;;
      esac
      installed=1
    fi
  done
  if (( installed == 1 )); then
    ok "Dependencies installed/checked: ${deps[*]}"
  else
    ok "All dependencies satisfied"
  fi
}
install_dependencies() {
  if (( DEPS_CHECKED == 1 )); then return 0; fi # 避免重复检查

  local need=()
  command -v curl >/dev/null 2>&1    || need+=("curl")
  command -v jq >/dev/null 2>&1      || need+=("jq")
  command -v uuidgen >/dev/null 2>&1 || need+=("uuid-runtime")
  command -v openssl >/dev/null 2>&1 || need+=("openssl")
  command -v ss >/dev/null 2>&1      || need+=("iproute2")
  command -v lsof >/dev/null 2>&1    || need+=("lsof")
  command -v bash >/dev/null 2>&1    || need+=("bash")
  
  # --- 针对 Alpine 系统的 openssl/jq 依赖修复 ---
  # 尽管上面的逻辑已经将 openssl/jq 加入 need 数组，
  # 但这里的 case 语句确保了 Alpine 系统使用 apk 命令来安装。
  # -----------------------------------------------
  
  if ((${#need[@]})); then
    case "$(detect_os)" in
      debian|ubuntu)
        printf "\n[等待] 正在更新软件源，请稍候...\n"
        DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
        printf "[等待] 正在安装运行所需依赖，请稍候...\n"
        # iproute2 在 Debian/Ubuntu 上是 iproute2
        DEBIAN_FRONTEND=noninteractive apt-get install -y "${need[@]/iproute2/iproute2}" >/dev/null 2>&1 || true ;;
      alpine)
        printf "[等待] 正在安装运行所需依赖（Alpine）...\n"
        # 确保使用 Alpine 对应的包名 (iproute2 对应 iproute2, uuid-runtime 对应 util-linux 或 uuid-runtime)
        local alpine_need=()
        for cmd in "${need[@]}"; do
          case "$cmd" in
            uuid-runtime) alpine_need+=("util-linux");; # Alpine 的 uuidgen 来源于 util-linux
            iproute2)     alpine_need+=("iproute2");;
            *)            alpine_need+=("$cmd");;
          esac
        done
        apk add --no-cache "${alpine_need[@]}" >/dev/null 2>&1 || true ;;
      centos|rhel)
        printf "[等待] 正在安装运行所需依赖（CentOS/RHEL）...\n"
        # iproute2 在 RHEL 上是 iproute
        yum install -y "${need[@]/iproute2/iproute}" >/dev/null 2>&1 || true ;;
      fedora)
        printf "[等待] 正在安装运行所需依赖（Fedora）...\n"
        # iproute2 在 Fedora 上是 iproute
        dnf install -y "${need[@]/iproute2/iproute}" >/dev/null 2>&1 || true ;;
      *) warn "未识别系统，请确保安装：${need[*]}" ;;
    esac
  fi
  DEPS_CHECKED=1
  ok "依赖已满足（curl/jq/uuidgen/openssl/iproute2/lsof）"
}
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
  ensure_cmd curl     curl        curl        curl        curl
  ensure_cmd jq       jq          jq          jq          jq
  ensure_cmd uuidgen  uuid-runtime util-linux util-linux  util-linux
  ensure_cmd openssl  openssl      openssl     openssl     openssl
  ensure_cmd ss       iproute2     iproute2    iproute    iproute
  ensure_cmd lsof     lsof         lsof        lsof        lsof
  DEPS_CHECKED=1
}

install_singbox_if_needed() {
  if command -v sing-box >/dev/null 2>&1; then return 0; fi

  fix_ca_certificates() {
    if [[ ! -f /etc/ssl/certs/ca-certificates.crt ]]; then
      warn "检测到 CA 证书缺失，正在安装 ca-certificates..."
      if command -v apk >/dev/null 2>&1; then
        apk update 2>/dev/null || true
        apk add --no-cache ca-certificates
        update-ca-certificates 2>/dev/null || log_msg "WARN" "update-ca-certificates failed"
      elif command -v apt-get >/dev/null 2>&1; then
        apt-get update -y
        apt-get install --reinstall -y ca-certificates
        update-ca-certificates
      elif command -v dnf >/dev/null 2>&1; then
        dnf install -y ca-certificates
      elif command -v yum >/dev/null 2>&1; then
        yum install -y ca-certificates
      else
        warn "无法自动安装 CA 证书，请手动安装 ca-certificates 包"
      fi
      ok "CA 证书已修复"
    fi
  }

  warn "未检测到 sing-box，正在安装..."
  local VERSION="1.12.0"
  local arch=$(uname -m)
  case "$arch" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) err "暂不支持的架构：$arch"; return 1 ;;
  esac

  fix_ca_certificates

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

get_ipv6_address() {
  ip -6 addr show scope global 2>/dev/null | awk '/inet6/{print $2}' | cut -d/ -f1 | head -n1
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

# ============= 端口占用检查（TCP监听）优化版 =============
port_status() {
  local port="$1"
  local have=0 seen_s=0 seen_o=0
  
  # 优化：一次性获取所有监听端口，减少进程创建
  local ss_output=""
  if command -v ss >/dev/null 2>&1; then
    have=1
    ss_output=$(ss -luntp 2>/dev/null || true)
    
    # Check TCP
    if echo "$ss_output" | grep -q ":$port "; then
       # 检查是否是 sing-box
       if echo "$ss_output" | grep ":$port " | grep -qi 'users:((".*sing-box'; then
          seen_s=1
       else
          seen_o=1
       fi
    fi
  fi
  
  # Fallback to lsof if ss not available or failed (unlikely)
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
      if [[ "$proto" == "tcp" ]]; then
        candidates=("${nat_tcp[@]}")
      elif [[ "$proto" == "udp" ]]; then
        candidates=("${nat_udp[@]}")
      else
        candidates=("${nat_tcp[@]}" "${nat_udp[@]}")
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
    if [[ "$proto" == "tcp" ]]; then
      echo $((RANDOM%10000 + 30000))
    elif [[ "$proto" == "udp" ]]; then
      echo $((RANDOM%10000 + 50000))
    else
      echo $((RANDOM%1000 + 30000))
    fi
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
  rc-update add sing-box default >/dev/null 2>&1 || log_msg "WARN" "rc-update failed"
  rc-service sing-box restart >/dev/null 2>&1 || rc-service sing-box start >/dev/null 2>&1 || log_msg "WARN" "rc-service start failed"
}

kill_rogue_singbox() {
  local sysd_pid pids
  sysd_pid=$(systemctl show -p MainPID --value sing-box 2>/dev/null || echo "")
  pids=$(pgrep -f "/usr/local/bin/sing-box run -c /etc/sing-box/config.json" || true)
  for p in $pids; do
    if [[ -n "$sysd_pid" && "$p" == "$sysd_pid" ]]; then continue; fi
    kill -9 "$p" 2>/dev/null || true
  done
}

check_and_repair_menu() {
  say "====== 系统检测与修复（合并） ======"
  system_check
  local status=$?
  local did_fix=0

  if (( status != 0 )); then
    say ""
    warn "检测到异常，建议执行自动修复（安装缺依赖 / 修复服务 / 纠正证书等）。"
    read -rp "是否立即按建议修复？(Y/n): " dofix
    dofix=${dofix:-Y}
    if [[ "$dofix" == "Y" || "$dofix" == "y" ]]; then
      fix_errors
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

  read -rp "修复完成，按回车返回脚本服务菜单..." _
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

  systemctl daemon-reload >/dev/null 2>&1 || log_msg "WARN" "daemon-reload failed"
  systemctl enable --now sing-box >/dev/null 2>&1 || log_msg "WARN" "enable sing-box failed"

  local okflag=0
  for i in $(seq 1 20); do
    systemctl is-active --quiet sing-box && { okflag=1; break; }
    _sb_any_port_listening && { okflag=1; break; }
    sleep 1 # 优化：降低轮询频率
  done
  if (( okflag==1 )); then ok "已安装并启用 systemd 自启动服务：sing-box"; return 0; fi

  warn "systemd 服务启动失败，切换为容器友好后台运行（fallback）"
  install_singleton_wrapper
  install_autostart_fallback
  start_singbox_singleton_force

  for i in $(seq 1 20); do
    _sb_any_port_listening && { ok "fallback 已启动 sing-box（后台）"; return 0; }
    sleep 1
  done
  err "fallback 启动失败，请检查 $LOG_FILE"
  return 1
}

choose_start_mode() {
  if [[ -n "${START_MODE:-}" ]]; then echo "$START_MODE"; return; fi 
  if is_pseudo_systemd; then echo "legacy"; else echo "singleton"; fi
}

ensure_rc_local_template() {
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
    grep -q '^sleep 1$' "$rc" || sed -i '1a sleep 1' "$rc"
    chmod +x "$rc"
  fi
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
    if [[ -n "${oldpid:-}" ]] && ps -p "$oldpid" -o comm= | grep -q '^sing-box$'; then
      exit 0
    fi
  fi
  pgrep -x sing-box >/dev/null 2>&1 && exit 0
fi

if ! "$BIN" check -c "$CONFIG" >/dev/null 2>&1; then
  echo "[sb-singleton] invalid config: $CONFIG" >>"$LOG"
  exit 1
fi

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
    ensure_rc_local_template
  fi

  if is_docker || [[ -f /.dockerenv ]]; then
    local start_cmd="/usr/local/bin/sb-singleton >> /var/log/sing-box.log 2>&1 &"
    for profile in /etc/profile /root/.profile /root/.bashrc /root/.ashrc; do
      if [[ -f "$profile" ]] && ! grep -q "sb-singleton" "$profile"; then
        echo "" >> "$profile"
        echo "# Sing-box Autostart (Docker Fix)" >> "$profile"
        echo "$start_cmd" >> "$profile"
        log_msg "INFO" "Added autostart to $profile"
      fi
    done
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

view_nat_ports() {
  if [[ ! -f "$NAT_FILE" ]]; then
    warn "当前未设置 NAT 模式规则"
    return
  fi

  local BOLD="" C_END="" C_CYAN="" C_GRN="" C_YLW=""
  if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && [[ $(tput colors 2>/dev/null) -ge 8 ]]; then
    BOLD=$'\033[1m'; C_END=$'\033[0m'
    C_CYAN=$'\033[36m'; C_GRN=$'\033[32m'; C_YLW=$'\033[33m'
  fi

  _print_grid() {
    local cols="$1" cellw="$2"; shift 2
    local i=0 item
    for item in "$@"; do
      printf "%-*s" "$cellw" "$item"
      i=$((i+1))
      if (( i % cols == 0 )); then printf "\n"; else printf " "; fi
    done
    (( i % cols != 0 )) && printf "\n"
  }

  local mode; mode="$nat_mode"
  printf "%s" "$BOLD"; printf "%s" "当前 NAT 模式:"; printf "%s" "$C_END"; printf " %s\n\n" "$mode"

  if ((${#nat_ranges[@]})); then
    printf "%s%s范围端口:%s\n" "$BOLD" "$C_CYAN" "$C_END"
    _print_grid 4 13 "${nat_ranges[@]}"
    printf "\n"
  fi

  if ((${#nat_tcp[@]})); then
    printf "%s%s自定义 TCP 端口:%s\n" "$BOLD" "$C_GRN" "$C_END"
    _print_grid 8 6 "${nat_tcp[@]}"; printf "\n"
  fi

  if ((${#nat_udp[@]})); then
    printf "%s%s自定义 UDP 端口:%s\n" "$BOLD" "$C_YLW" "$C_END"
    _print_grid 8 6 "${nat_udp[@]}"; printf "\n"
  fi

  local w_left=34
  printf '%s\n' "------ 端口规则管理 ------"
  printf "%-*s %s\n" "$w_left" "1) 添加范围端口"                      "2) 删除范围端口"
  printf "%-*s %s\n" "$w_left" "3) 添加自定义TCP端口"                 "4) 删除自定义TCP端口"
  printf "%-*s %s\n" "$w_left" "5) 添加自定义UDP端口"                 "6) 删除自定义UDP端口"
  printf "%s\n" "0) 返回"
  printf "%s\n\n" "提示：空格分隔"

  read -rp "选择: " op
  case "$op" in
    1)
      read -rp "输入范围段: " ranges_in
      [[ -z "$ranges_in" ]] && { warn "未输入"; return; }
      local tmp; tmp=$(mktemp)
      trap 'rm -f "$tmp"' EXIT
      jq --argjson arr "$(printf '%s\n' "$ranges_in" | jq -R 'split(" ")')" \
         '.mode="range"|.ranges=((.ranges//[])+$arr)|.custom_tcp=(.custom_tcp//[])|.custom_udp=(.custom_udp//[])' \
         "$NAT_FILE" >"$tmp" && mv "$tmp" "$NAT_FILE"
      load_nat_data
      ok "已添加范围段"
      ;;
    2)
      read -rp "输入要删除的范围段（完全匹配）: " seg
      [[ -z "$seg" ]] && { warn "未输入"; return; }
      local tmp; tmp=$(mktemp)
      trap 'rm -f "$tmp"' EXIT
      jq --arg seg "$seg" '.ranges=((.ranges//[])|map(select(.!=$seg)))' "$NAT_FILE" >"$tmp" && mv "$tmp" "$NAT_FILE"
      load_nat_data
      ok "已删除范围段"
      ;;
    3)
      read -rp "输入要添加的TCP端口（空格分隔）: " ports
      local tmp; tmp=$(mktemp)
      trap 'rm -f "$tmp"' EXIT
      jq --argjson add "$(printf '%s\n' "$ports" | jq -R 'split(" ")|map(tonumber)')" \
         '.mode="custom"|.custom_tcp=((.custom_tcp//[])+$add)|.custom_udp=(.custom_udp//[])|.ranges=[]' \
         "$NAT_FILE" >"$tmp" && mv "$tmp" "$NAT_FILE"
      load_nat_data
      ok "已添加TCP端口"
      ;;
    4)
      read -rp "输入要删除的TCP端口（空格分隔）: " ports
      local tmp; tmp=$(mktemp)
      trap 'rm -f "$tmp"' EXIT
      jq --argjson del "$(printf '%s\n' "$ports" | jq -R 'split(" ")|map(tonumber)')" \
         '.custom_tcp=((.custom_tcp//[])|map(select(( $del|index(.) )|not )))' \
         "$NAT_FILE" >"$tmp" && mv "$tmp" "$NAT_FILE"
      load_nat_data
      ok "已删除TCP端口"
      ;;
    5)
      read -rp "输入要添加的UDP端口（空格分隔）: " ports
      local tmp; tmp=$(mktemp)
      trap 'rm -f "$tmp"' EXIT
      jq --argjson add "$(printf '%s\n' "$ports" | jq -R 'split(" ")|map(tonumber)')" \
         '.mode="custom"|.custom_udp=((.custom_udp//[])+$add)|.custom_tcp=(.custom_tcp//[])|.ranges=[]' \
         "$NAT_FILE" >"$tmp" && mv "$tmp" "$NAT_FILE"
      load_nat_data
      ok "已添加UDP端口"
      ;;
    6)
      read -rp "输入要删除的UDP端口（空格分隔）: " ports
      local tmp; tmp=$(mktemp)
      trap 'rm -f "$tmp"' EXIT
      jq --argjson del "$(printf '%s\n' "$ports" | jq -R 'split(" ")|map(tonumber)')" \
         '.custom_udp=((.custom_udp//[])|map(select(( $del|index(.) )|not )))' \
         "$NAT_FILE" >"$tmp" && mv "$tmp" "$NAT_FILE"
      load_nat_data
      ok "已删除UDP端口"
      ;;
    0) return ;;
    *) warn "无效输入" ;;
  esac
}

disable_nat_mode() {
  if [[ -f "$NAT_FILE" ]]; then rm -f "$NAT_FILE"; load_nat_data; ok "NAT 模式已关闭（规则已清除）"
  else warn "当前未启用 NAT 模式"; fi
}

set_nat_range() {
  read -rp "请输入范围端口（多个用空格分隔，如 12000-12020 34050-34070）: " ranges
  local tmp; tmp=$(mktemp)
  trap 'rm -f "$tmp"' EXIT
  jq -n --argjson arr "$(printf '%s\n' "$ranges" | jq -R 'split(" ")')" \
    '{"mode":"range","ranges":$arr,"custom_tcp":[],"custom_udp":[]}' > "$tmp"
  mv "$tmp" "$NAT_FILE"
  load_nat_data
  ok "范围端口已保存"
}
set_nat_custom_tcp() {
  read -rp "请输入自定义TCP端口（空格分隔）: " ports
  local tmp; tmp=$(mktemp)
  trap 'rm -f "$tmp"' EXIT
  if [[ -f "$NAT_FILE" ]]; then
    jq --argjson arr "$(printf '%s\n' "$ports" | jq -R 'split(" ") | map(tonumber)')" '.custom_tcp = $arr' "$NAT_FILE" > "$tmp"
  else
    jq -n --argjson arr "$(printf '%s\n' "$ports" | jq -R 'split(" ") | map(tonumber)')" '{"mode":"custom","ranges":[],"custom_tcp":$arr,"custom_udp":[]}' > "$tmp"
  fi
  mv "$tmp" "$NAT_FILE"
  load_nat_data
  ok "自定义TCP端口已保存"
}

set_nat_custom_udp() {
  read -rp "请输入自定义UDP端口（空格分隔）: " ports
  local tmp; tmp=$(mktemp)
  trap 'rm -f "$tmp"' EXIT
  if [[ -f "$NAT_FILE" ]]; then
    jq --argjson arr "$(printf '%s\n' "$ports" | jq -R 'split(" ") | map(tonumber)')" '.custom_udp = $arr' "$NAT_FILE" > "$tmp"
  else
    jq -n --argjson arr "$(printf '%s\n' "$ports" | jq -R 'split(" ") | map(tonumber)')" '{"mode":"custom","ranges":[],"custom_tcp":[],"custom_udp":$arr}' > "$tmp"
  fi
  mv "$tmp" "$NAT_FILE"
  load_nat_data
  ok "自定义UDP端口已保存"
}

nat_mode_menu() {
  say "====== NAT 模式设置 ======"
  say "1) 设置范围端口"
  say "2) 设置自定义TCP端口"
  say "3) 设置自定义UDP端口"
  say "4) 查看当前NAT端口规则"
  say "5) 退出 NAT 模式"
  say "0) 返回主菜单"
  read -rp "请选择: " opt
  case "$opt" in
    1) set_nat_range ;;
    2) set_nat_custom_tcp ;;
    3) set_nat_custom_udp ;;
    4) view_nat_ports ;;
    5) disable_nat_mode ;;
    0) return ;;
    *) warn "无效输入" ;;
  esac
}

update_singbox() {
  say " 正在检查 Sing-box 更新..."
  local CUR LATEST ARCH tmp
  CUR=$(sing-box version 2>/dev/null | awk '/sing-box version/{print $3}')
  say "当前版本: ${CUR:-未知}"
  LATEST=$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest 2>/dev/null | jq -r '.tag_name // empty' | sed 's/^v//')
  if [[ -z "$LATEST" ]]; then warn "获取最新版本失败"; return; fi
  say "最新版本: $LATEST"
  [[ "$CUR" == "$LATEST" ]] && { ok "已是最新版"; return; }
  read -rp "是否更新到 $LATEST？(y/N): " c; [[ "$c" == "y" ]] || { say "已取消"; return; }
  ARCH=$(uname -m); case "$ARCH" in x86_64|amd64) ARCH="amd64";; aarch64|arm64) ARCH="arm64";; *) err "不支持架构 $ARCH"; return 1;; esac
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  (
    set -e
    cd "$tmp"
    local FILE="sing-box-${LATEST}-linux-${ARCH}.tar.gz"
    local URL="https://github.com/SagerNet/sing-box/releases/download/v${LATEST}/${FILE}"
    if ! curl -fL -o "$FILE" "$URL"; then
      warn "直连下载失败，尝试代理..."
      curl -fL -o "$FILE" "https://ghproxy.com/${URL}"
    fi
    tar -xzf "$FILE"
    local init; init=$(detect_init_system)
    [[ "$init" == "systemd" ]] && systemctl stop sing-box || true
    [[ "$init" == "openrc"  ]] && rc-service sing-box stop >/dev/null 2>&1 || true
    install -m 0755 "sing-box-${LATEST}-linux-${ARCH}/sing-box" /usr/local/bin/sing-box
    [[ "$init" == "systemd" ]] && systemctl start sing-box || true
    [[ "$init" == "openrc"  ]] && rc-service sing-box start >/dev/null 2>&1 || true
  ) || { err "升级失败"; return 1; }
  ok "已成功升级为 v${LATEST}"

  say " 正在重启 Sing-box 服务以确保新版本生效..."
  if ! restart_singbox; then
    warn "自动重启失败，请在“脚本服务”中手动选择 2) 重启 Sing-box 服务。"
  fi
}
reinstall_menu() {
  echo "====== 卸载 / 重装 Sing-box ======"
  echo "1) 完全卸载（清空所有服务）"
  echo "2) 保留节点配置并重装 Sing-box"
  echo "0) 返回"
  read -rp "请选择: " choice
  case "$choice" in
    1)
      echo " 即将卸载 Sing-box、Hysteria2 及相关文件（包含本脚本）..."
      read -rp "确认继续 (y/N): " confirm
      [[ "$confirm" != "y" && "$confirm" != "Y" ]] && return

      say "正在停止服务..."
      if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now sing-box >/dev/null 2>&1 || true
        shopt -s nullglob
        for f in /etc/systemd/system/hysteria2*.service; do
          systemctl disable --now "$(basename "$f")" >/dev/null 2>&1 || true
        done
        shopt -u nullglob
      fi
      if command -v rc-service >/dev/null 2>&1; then
        rc-service sing-box stop >/dev/null 2>&1 || true
        rc-update del sing-box default >/dev/null 2>&1 || true
      fi
      
      pkill -9 -x sing-box >/dev/null 2>&1 || true
      pkill -9 -x hysteria >/dev/null 2>&1 || true
      pkill -9 -f "sb-singleton" >/dev/null 2>&1 || true
      pkill -9 -f "cloudflared" >/dev/null 2>&1 || true
      pkill -9 -f "xray" >/dev/null 2>&1 || true

      say "正在清理文件..."
      rm -f /etc/systemd/system/sing-box.service
      rm -f /lib/systemd/system/sing-box.service
      rm -f /etc/systemd/system/hysteria2*.service
      rm -f /lib/systemd/system/hysteria2*.service
      [ -n "$(command -v systemctl)" ] && systemctl daemon-reload >/dev/null 2>&1 || true

      rm -f /etc/init.d/sing-box
      rm -f /etc/local.d/sb-singbox.start

      rm -f /usr/local/bin/sing-box /usr/bin/sing-box
      rm -f /usr/local/bin/hysteria /usr/bin/hysteria
      rm -f /usr/local/bin/sb-singleton
      rm -rf /etc/sing-box /var/lib/sing-box /var/log/sing-box* /tmp/sing-box*
      rm -rf /etc/hysteria2 /var/lib/hysteria2 /var/log/hysteria2* /tmp/hysteria2*
      rm -rf /root/agsbx
      rm -f "$META" "$NAT_FILE"
      
      say "正在清理自启配置..."
      if command -v crontab >/dev/null 2>&1; then
        crontab -l 2>/dev/null | grep -v "sb-singleton" | grep -v "agsbx" | crontab - >/dev/null 2>&1 || true
      fi
      
      if [ -f /etc/rc.local ]; then
        sed -i '/sb-singleton/d' /etc/rc.local
      fi
      
      for profile in /etc/profile /root/.profile /root/.bashrc /root/.ashrc; do
        if [ -f "$profile" ]; then
           sed -i '/sb-singleton/d' "$profile"
           sed -i '/# Sing-box Autostart/d' "$profile"
        fi
      done

      say " Sing-box、Hysteria2 及 Argo 已完全卸载"
      SCRIPT_PATH="$(realpath "$0")"
      rm -f "$SCRIPT_PATH"

      echo "脚本已删除，程序退出。"
      exit 0
      ;;
    2)
      systemctl stop sing-box 2>/dev/null
      echo " 正在重新安装 Sing-box（保留节点配置）..."
      bash <(curl -fsSL https://sing-box.app/install.sh)
      echo " Sing-box 已重新安装完成（节点已保留）"
      case "$(detect_init_system)" in
        systemd) install_systemd_service ;;
        openrc)  ensure_service_openrc ;;
      esac
      echo " 正在重启 Sing-box 服务..."
      if ! restart_singbox; then
        warn "自动重启失败，请在“脚本服务”中手动选择 2) 重启 Sing-box 服务。"
      else
        ok "Sing-box 服务已重启。"
      fi
      ;;
    0) return ;;
    *) echo "无效选择" ;;
  esac
}


system_check() {
  local issues=0
  if command -v sing-box >/dev/null 2>&1; then ok "sing-box 已安装"; else err "sing-box 未安装"; issues=1; fi
  local init; init=$(detect_init_system)
  if [[ "$init" == "systemd" ]]; then
    if systemctl is-active --quiet sing-box; then ok "Sing-box 服务运行中"
    else
      if ! systemctl status sing-box >/dev/null 2>&1; then err "Sing-box 服务未配置 (systemd)"; issues=1
      elif systemctl is-failed --quiet sing-box; then err "Sing-box 服务启动失败"; issues=1
      else err "Sing-box 服务未运行"; issues=1
      fi
    fi
  elif [[ "$init" == "openrc" ]]; then
    if rc-service sing-box status 2>/dev/null | grep -q started; then ok "Sing-box 服务运行中 (OpenRC)"
    else 
      if [[ -f /etc/init.d/sing-box ]]; then err "Sing-box 服务未运行 (OpenRC)"; issues=1; else err "Sing-box 服务未配置 (OpenRC)"; issues=1; fi
    fi
  else
    if pgrep -x sing-box >/dev/null 2>&1; then ok "Sing-box 进程运行中"; else err "Sing-box 进程未运行"; issues=1; fi
  fi

  if command -v sing-box >/dev/null 2>&1; then
    if ! sing-box check -c "$CONFIG" >/dev/null 2>&1; then err "配置文件不合法：$CONFIG"; issues=1
    else ok "配置文件合法"; fi
  fi

  local any_issue=0 port
  for port in $(jq -r '.inbounds[].listen_port' "$CONFIG" 2>/dev/null); do
    [[ -z "$port" ]] && continue
    port_status "$port"
    case $? in
      0) : ;;
      1) warn "端口 $port 被其他进程占用"; any_issue=1 ;;
      2) warn "端口 $port 未监听"; any_issue=1 ;;
    esac
  done
  local dup; dup=$(jq -r '.inbounds[].listen_port' "$CONFIG" 2>/dev/null | sort | uniq -d)
  [[ -n "$dup" ]] && { err "配置文件端口冲突: $(echo "$dup" | xargs)"; any_issue=1; }
  [[ $any_issue -eq 0 ]] && ok "所有入站端口监听正常"
  ((issues+=any_issue))

  local missing=()
  for cmd in curl jq uuidgen openssl lsof ss; do command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd"); done
  if ((${#missing[@]})); then err "缺少依赖: ${missing[*]}"; issues=1; else ok "依赖项齐全"; fi

  return $issues
}

fix_errors() {
  install_dependencies
  if ! command -v sing-box >/dev/null 2>&1; then
    install_singbox_if_needed || true
  fi
  install_systemd_service

  local need_hy_install=0
  shopt -s nullglob
  for f in /etc/systemd/system/hysteria2*.service; do
    if ! command -v hysteria >/dev/null 2>&1; then need_hy_install=1; break; fi
  done
  if [[ $need_hy_install -eq 1 ]]; then
    local H_VERSION="2.6.2" arch=$(uname -m)
    case "$arch" in x86_64|amd64) arch="amd64";; aarch64|arm64) arch="arm64";; *) err "暂不支持的架构：$arch";; esac
    local tmp; tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    (
      set -e
      cd "$tmp"
      curl -sSL "https://github.com/apernet/hysteria/releases/download/app/v${H_VERSION}/hysteria-linux-${arch}" -o hysteria-bin || { err "下载 hysteria 失败"; exit 1; }
      install -m 0755 hysteria-bin /usr/local/bin/hysteria
    ) || true
    command -v hysteria >/dev/null 2>&1 && ok "hysteria 安装完成"
  fi

  for f in /etc/systemd/system/hysteria2*.service; do
    local name=$(basename "$f")
    local port=${name#hysteria2-}; port=${port%.service}
    if ! systemctl is-active --quiet "$name"; then
      if [[ ! -f /etc/hysteria2/${port}.crt || ! -f /etc/hysteria2/${port}.key ]]; then
        generate_self_signed_cert "/etc/hysteria2/${port}.key" "/etc/hysteria2/${port}.crt" "bing.com" && ok "已重新生成端口 $port 证书"
      fi
      systemctl daemon-reload >/dev/null 2>&1 || log_msg "WARN" "daemon-reload failed"
      systemctl enable "$name" >/dev/null 2>&1 || log_msg "WARN" "enable $name failed"
      systemctl restart "$name" >/dev/null 2>&1 || log_msg "WARN" "restart $name failed"
      sleep 1
      systemctl is-active --quiet "$name" && ok "Hysteria2-${port} 服务已启动" || err "Hysteria2-${port} 服务仍无法启动"
    fi
  done
  shopt -u nullglob
}

auto_optimize_cpu() {
  if ! command -v renice >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then 
      export DEBIAN_FRONTEND=noninteractive
      apt-get -yq update >/dev/null 2>&1 && apt-get -yq install bsdutils >/dev/null 2>&1 || apt-get -yq install util-linux >/dev/null 2>&1
    elif command -v apk >/dev/null 2>&1; then 
      apk add --no-cache util-linux >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then 
      yum -y -q install util-linux >/dev/null 2>&1
    fi
  fi

  local sb_pid
  sb_pid=$(pgrep -x sing-box | head -n1)
  
  if [[ -n "$sb_pid" ]] && command -v renice >/dev/null 2>&1; then
     renice -n -10 -p "$sb_pid" >/dev/null 2>&1
     if [ -t 1 ]; then echo " [自动优化] "; fi
  fi
  
  # 额外优化：如果脚本在 Docker 中作为守护进程运行，降低自身优先级
  if is_docker || [[ -f /.dockerenv ]]; then
    renice -n 10 -p $$ >/dev/null 2>&1 || true
  fi
}

restart_singbox() {
  local bin; bin="$(_sb_bin)"
  local cfg; cfg="$(_sb_cfg)"

  if command -v systemctl >/dev/null 2>&1; then
    pkill -9 sing-box >/dev/null 2>&1 || true
    systemctl kill -s SIGKILL sing-box >/dev/null 2>&1 || true
    sleep 0.4
    if ! "$bin" check -c "$cfg" >/dev/null 2>&1; then
      err "配置文件校验失败：$cfg"; "$bin" check -c "$cfg" || true; return 1
    fi
    nohup sing-box run -c /etc/sing-box/config.json > $LOG_FILE 2>&1 &
    local okflag=0
    for i in $(seq 1 30); do
      systemctl is-active --quiet sing-box && { okflag=1; break; }
      _sb_any_port_listening && { okflag=1; break; }
      sleep 1
    done
    if (( okflag==1 )); then ok "Sing-box 重启完成（systemd）"; return 0; fi
    warn "当前环境虽有 systemctl，但重启失败；切换 fallback 后台运行"
  elif command -v rc-service >/dev/null 2>&1 && [[ -f /etc/init.d/sing-box ]]; then
    rc-service sing-box restart >/dev/null 2>&1 || rc-service sing-box start >/dev/null 2>&1 || log_msg "WARN" "rc-service failed"
    local okflag=0
    for i in $(seq 1 30); do
      rc-service sing-box status 2>/dev/null | grep -q started && { okflag=1; break; }
      _sb_any_port_listening && { okflag=1; break; }
      sleep 1
    done
    if (( okflag==1 )); then ok "Sing-box 重启完成（OpenRC）"; return 0; fi
    warn "OpenRC 服务重启失败；切换 fallback 后台运行"
  fi

  pkill -9 -f "$bin run -c $cfg" 2>/dev/null || true
  pkill -9 -x sing-box 2>/dev/null || true
  install_singleton_wrapper
  install_autostart_fallback
  start_singbox_singleton_force
  auto_optimize_cpu
  for i in $(seq 1 30); do
    _sb_any_port_listening && { ok "Sing-box 重启完成（fallback 后台）"; return 0; }
    sleep 1
  done
  err "Sing-box 重启失败（fallback 也未监听），请查看 $LOG_FILE"
  return 1
}

add_node() {
  ensure_runtime_deps

  while true; do
    say "请选择协议类型："
    say "0) 返回主菜单"
    say "1) SOCKS5"
    say "2) VLESS-REALITY"
    say "3) Hysteria2"
    say "4) CF Tunnel 隧道"
    read -rp "输入协议编号（默认 1，输入 0 返回）: " proto
    proto=${proto:-1}
    [[ "$proto" == "0" ]] && return
    [[ "$proto" =~ ^[1-4]$ ]] && break
    warn "无效输入，请重新输入"
  done

  if [[ "$proto" == "3" ]]; then
    add_hysteria2_node || return 1
    return
  fi

  if [[ "$proto" == "2" ]]; then
    if ! command -v sing-box >/dev/null 2>&1; then
      err "未检测到 sing-box，无法生成 Reality 密钥。请先在“脚本服务”里重装/安装。"
      return 1
    fi

    local port proto_type="tcp"
    while true; do
      [[ -n "$nat_mode" ]] && {
        [[ "$nat_mode" == "custom" ]] && say "已启用自定义端口模式：VLESS 仅允许使用 自定义TCP端口集合"
        [[ "$nat_mode" == "range" ]] && say "已启用范围端口模式：VLESS 仅允许使用 范围内端口"
      }
      read -rp "请输入端口号（留空自动挑选允许端口；输入 0 返回）: " port
      [[ "$port" == "0" ]] && return
      if [[ -z "$port" ]]; then
        port=$(get_random_allowed_port "$proto_type")
        [[ "$port" == "NO_PORT" ]] && { err "无可用端口"; return 1; }
        say "（已自动选择随机端口：$port）"
      fi
      [[ "$port" =~ ^[0-9]+$ ]] && ((port>=1 && port<=65535)) || { warn "端口无效"; continue; }
      (( port < 1024 )) && warn "端口<1024可能需root权限"
      if ! check_nat_allow "$port" "$proto_type"; then warn "端口 $port 不符合 NAT 规则（协议: $proto_type）"; continue; fi
      if jq -e --argjson p "$port" '.inbounds[] | select(.listen_port == $p)' "$CONFIG" >/dev/null 2>&1; then
        warn "端口 $port 已存在"; continue
      fi
      if jq -e --argjson p "$port" 'to_entries[]? | select(.value.type=="hysteria2" and .value.port == $p)' "$META" >/dev/null 2>&1; then
        warn "端口 $port 已被 Hysteria2 使用"; continue
      fi
      break
    done

    local uuid fp flow server_name key_pair private_key public_key short_id tag tmpcfg
    if command -v uuidgen >/dev/null 2>&1; then
      uuid=$(uuidgen)
    else
      uuid=$(openssl rand -hex 16 | sed 's/\(..\)/\1/g; s/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
    fi

    read -rp "请输入伪装域名 (默认 www.microsoft.com): " input_sni
    if [[ -z "$input_sni" ]]; then
      server_name="www.microsoft.com"
    else
      server_name="$input_sni"
    fi
    say "已选择伪装域名: $server_name"
    flow="xtls-rprx-vision"
    case $((RANDOM%5)) in 0) fp="chrome";; *) fp="firefox";; esac
    key_pair=$(sing-box generate reality-keypair 2>/dev/null)
    private_key=$(awk -F': ' '/PrivateKey/{print $2}' <<<"$key_pair")
    public_key=$(awk -F': ' '/PublicKey/{print $2}' <<<"$key_pair")
    [[ -z "$private_key" || -z "$public_key" ]] && { err "生成 Reality 密钥失败"; return 1; }
    short_id=$(openssl rand -hex 4)
    tag=$(generate_unique_tag)
    tmpcfg=$(mktemp); trap 'rm -f "$tmpcfg"' RETURN

    jq --arg port "$port" \
       --arg uuid "$uuid" \
       --arg prikey "$private_key" \
       --arg sid "$short_id" \
       --arg server "$server_name" \
       --arg fp "$fp" \
       --arg flow "$flow" \
       --arg tag "$tag" \
       '.inbounds += [{
         "type": "vless",
         "tag": $tag,
         "listen": "::",
         "listen_port": ($port | tonumber),
         "users": [{ "uuid": $uuid, "flow": $flow }],
         "tls": {
           "enabled": true,
           "server_name": $server,
           "reality": {
             "enabled": true,
             "handshake": { "server": $server, "server_port": 443 },
             "private_key": $prikey,
             "short_id": [ $sid ]
           }
         }
       }]' "$CONFIG" >"$tmpcfg" && mv "$tmpcfg" "$CONFIG"

    say " 正在校验配置..."
    if sing-box check -c "$CONFIG" >/dev/null 2>&1; then
      ok "配置通过，正在重启 Sing-box..."
      restart_singbox || { err "重启失败"; return 1; }
    else
      err "配置校验失败"; sing-box check -c "$CONFIG"; return 1
    fi

    local tmpmeta; tmpmeta=$(mktemp); trap 'rm -f "$tmpmeta"' RETURN
    jq --arg tag "$tag" --arg pbk "$public_key" --arg sid "$short_id" --arg sni "$server_name" --arg port "$port" --arg fp "$fp" \
      '. + {($tag): {pbk:$pbk, sid:$sid, sni:$sni, port:$port, fp:$fp}}' "$META" >"$tmpmeta" && mv "$tmpmeta" "$META"

    local link="vless://${uuid}@${GLOBAL_IPV4}:${port}?encryption=none&flow=${flow}&type=tcp&security=reality&pbk=${public_key}&sid=${short_id}&sni=${server_name}&fp=${fp}#${tag}"
    local info="本地端口: ${C_CYAN}${port}${C_RESET}\nSNI域名: ${C_CYAN}${server_name}${C_RESET}\nUUID: ${C_CYAN}${uuid}${C_RESET}"
    print_card "VLESS-REALITY 搭建成功" "$tag" "$info" "$link"
    return
  fi

  if [[ "$proto" == "4" ]]; then

    # --- Cloudflare Tunnel 管理所需的变量 ---
    local ARGO_NODES_DIR="/etc/sing-box/argo_users"
    local ARGO_BIN_DIR="/root/agsbx"
    
    # --- 依赖安装函数 ---
    ensure_argo_deps() {
        mkdir -p "$ARGO_NODES_DIR" "$ARGO_BIN_DIR"
        local c_cpu c_argo
        case "$(uname -m)" in
            aarch64) c_cpu="arm64-v8a"; c_argo="arm64" ;;
            x86_64) c_cpu="64"; c_argo="amd64" ;;
            *) err "不支持的架构: $(uname -m)"; return 1 ;;
        esac
        
        if ! command -v unzip >/dev/null 2>&1; then
             say "正在安装 unzip..."
             if command -v apt-get >/dev/null 2>&1; then
                 apt-get update -y >/dev/null 2>&1 && apt-get install -y unzip >/dev/null 2>&1
             elif command -v yum >/dev/null 2>&1; then
                 yum install -y unzip >/dev/null 2>&1
             elif command -v apk >/dev/null 2>&1; then
                 apk add --no-cache unzip >/dev/null 2>&1
             fi
        fi

        if [ ! -x "$ARGO_BIN_DIR/xray" ]; then
            say "正在下载 Xray 核心..."
            local x_url="https://github.com/XTLS/Xray-core/releases/download/v1.8.11/Xray-linux-${c_cpu}.zip"
            wget -qO "$ARGO_BIN_DIR/xray.zip" "$x_url" || curl -L -s -o "$ARGO_BIN_DIR/xray.zip" "$x_url"
            if [ -f "$ARGO_BIN_DIR/xray.zip" ]; then
                unzip -o "$ARGO_BIN_DIR/xray.zip" -d "$ARGO_BIN_DIR" "xray" >/dev/null 2>&1
                rm -f "$ARGO_BIN_DIR/xray.zip"
                chmod +x "$ARGO_BIN_DIR/xray"
            else
                err "Xray 下载失败。"; return 1
            fi
        fi
        
        if [ ! -x "$ARGO_BIN_DIR/cloudflared" ]; then
            say "正在下载 Cloudflared..."
            local c_url="https://github.com/cloudflare/cloudflared/releases/download/2024.6.1/cloudflared-linux-${c_argo}"
            wget -qO "$ARGO_BIN_DIR/cloudflared" "$c_url" || curl -L -s -o "$ARGO_BIN_DIR/cloudflared" "$c_url"
            if [ ! -f "$ARGO_BIN_DIR/cloudflared" ]; then
                err "Cloudflared 下载失败。"; return 1
            fi
            chmod +x "$ARGO_BIN_DIR/cloudflared"
        fi
        return 0
    }

    # --- 启动/管理函数：add_argo_user ---
 add_argo_user() {
    set +e
    # ARGO_NODES_DIR 和 ARGO_BIN_DIR 依赖于父级作用域的定义
    if ! ensure_argo_deps; then read -rp "按回车返回..." _; return 1; fi

    say "========== 添加新的 CF Tunnel 用户 =========="
    
    local port proto_type="tcp"
    local uuid agn_input agk_input vm_port tag user_tag
    
    # 1. 端口选择 (手动输入)
    while true; do
        read -rp "请输入 Xray 本地监听端口 (10000-65535, 建议): " input_port
        
        if ! [[ "$input_port" =~ ^[0-9]+$ ]] || (( input_port < 10000 || input_port > 65535 )); then
            warn "端口无效，请输入 10000-65535 之间的数字。"
            continue
        fi
        
        vm_port="$input_port"
        
        # 检查端口是否被系统占用（TCP/UDP）
        port_status "$vm_port"
        if [ $? -ne 2 ]; then # 0=被 sing-box 占用, 1=被其他进程占用, 2=未占用
            warn "端口 $vm_port 已被系统占用或正在监听，请更换端口。"
            continue
        fi
        
        # 检查端口是否被 sing-box 其他入站节点占用
        if jq -e --argjson p "$vm_port" '.inbounds[] | select(.listen_port == $p)' "$CONFIG" >/dev/null 2>&1; then
            warn "端口 $vm_port 已被 Sing-box 其他节点占用。"
            continue
        fi

        # 检查端口是否已被其他 Argo/Hysteria2 节点占用（在 META 中）
        if jq -e --argjson p "$vm_port" 'to_entries[]? | select((.value.type=="argo" or .value.type=="hysteria2") and .value.port == $p)' "$META" >/dev/null 2>&1; then
            warn "端口 $vm_port 已被其他 Argo/Hysteria2 节点占用。"
            continue
        fi

        # 检查 NAT 规则 (Argo/Vmess 是 TCP 隧道，但 Xray 监听是本地 TCP)
        if ! check_nat_allow "$vm_port" "tcp"; then 
           warn "端口 $vm_port 不符合当前的 NAT 端口规则 (协议: tcp)"
           continue
        fi

        break
    done
    say "已选择本地监听端口: $vm_port"
    
    # 2. 隧道信息
    read -rp "请输入 隧道域名（例如 vps.mycf.com）: " agn_input
    [[ -z "$agn_input" ]] && { warn "域名不能为空！"; return 1; }
    
    read -rp "请输入 隧道Token (eyJh...): " agk_input
    [[ -z "$agk_input" ]] && { warn "Token 不能为空！"; return 1; }

    read -rp "请输入用户标记 (默认 CF-User): " user_tag
    user_tag=${user_tag:-CF-User}
    
    # 3. 核心配置生成
    uuid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen || openssl rand -hex 16 | sed 's/\(..\)/\1/g; s/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
    local ws_path="/vm-${vm_port}-$(openssl rand -hex 3)"
    tag="Argo-${user_tag}-${vm_port}"
    local config_file="$ARGO_NODES_DIR/${vm_port}.json"
    local log_file="$ARGO_NODES_DIR/${vm_port}.log"

    cat > "$config_file" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "port": ${vm_port},
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": { "clients": [ { "id": "${uuid}", "alterId": 0 } ] },
      "streamSettings": { 
        "network": "ws", 
        "wsSettings": { "path": "${ws_path}" } 
      }
    }
  ],
  "outbounds": [ { "protocol": "freedom", "tag": "direct" } ]
}
EOF
    
    # 4. 停止并杀死旧进程 (防止僵尸进程)
    pkill -9 -f "xray run -c $config_file" >/dev/null 2>&1 || true
    pkill -9 -f "cloudflared.*${vm_port}" >/dev/null 2>&1 || true
    
    # 5. 元数据保存 (写入核心信息，但不包括链接 'raw')
    local tmpmeta; tmpmeta=$(mktemp)
    jq --arg tag "$tag" --arg port "$vm_port" --arg uuid "$uuid" --arg domain "$agn_input" --arg token "$agk_input" --arg path "$ws_path" \
        '. + {($tag): {type:"argo", subtype:"fixed", port:$port, uuid:$uuid, domain:$domain, token:$token, path:$path}}' "$META" >"$tmpmeta" && mv "$tmpmeta" "$META"

    # 6. 自启配置（Systemd -> Alpine local.d -> Crontab）
    local service_name="cf-tunnel-${vm_port}"
    
    install_cf_tunnel_service() {
      
      # 1. 创建 Xray 服务文件
      cat > "/etc/systemd/system/${service_name}-xray.service" <<EOF_XRAY
[Unit]
Description=CF Tunnel Xray Core (Port ${vm_port})
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=${ARGO_BIN_DIR}/xray run -c ${config_file}
Restart=always
RestartSec=3s
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF_XRAY

      # 2. 创建 Cloudflared 服务文件
      cat > "/etc/systemd/system/${service_name}-cfd.service" <<EOF_CFD
[Unit]
Description=CF Tunnel Cloudflared (Port ${vm_port})
After=${service_name}-xray.service
Wants=${service_name}-xray.service
[Service]
Type=simple
ExecStart=${ARGO_BIN_DIR}/cloudflared tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${agk_input} --url http://127.0.0.1:${vm_port}
Restart=always
RestartSec=3s
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF_CFD
    
      # 3. 启用并启动服务
      "$_SYSTEMCTL_CMD" daemon-reload >/dev/null 2>&1
      "$_SYSTEMCTL_CMD" enable "${service_name}-xray.service" >/dev/null 2>&1
      "$_SYSTEMCTL_CMD" enable "${service_name}-cfd.service" >/dev/null 2>&1
      "$_SYSTEMCTL_CMD" start "${service_name}-xray.service" >/dev/null 2>&1
      "$_SYSTEMCTL_CMD" start "${service_name}-cfd.service" >/dev/null 2>&1
    }
    
    if [[ -n "$_SYSTEMCTL_CMD" ]]; then
        install_cf_tunnel_service
        say "已安装 Systemd 服务 ${service_name} 并启动。"
    else
        say "未检测到 Systemd。正在配置原生自启脚本..."
        
        # === 方案 A: Alpine /etc/local.d (最可靠的非Systemd方式) ===
        if [[ -d /etc/local.d ]]; then
            cat > "/etc/local.d/argo_${vm_port}.start" <<EOF
#!/bin/sh
# Auto-generated by sk5.sh for Port ${vm_port}
nohup ${ARGO_BIN_DIR}/xray run -c ${config_file} >/dev/null 2>&1 &
sleep 2
nohup ${ARGO_BIN_DIR}/cloudflared tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${agk_input} --url http://127.0.0.1:${vm_port} > ${log_file} 2>&1 &
EOF
            chmod +x "/etc/local.d/argo_${vm_port}.start"
            if command -v rc-update >/dev/null 2>&1; then
                rc-update add local default >/dev/null 2>&1 || true
            fi
            say "   已添加 Alpine local.d 自启脚本。"
        fi

        # === 方案 B: Crontab (作为补充) ===
        if command -v crontab >/dev/null 2>&1; then
            # 尝试启动 crond 如果没运行
            if ! pgrep crond >/dev/null 2>&1 && command -v crond >/dev/null 2>&1; then
                nohup crond -f >/dev/null 2>&1 &
            fi
            local crontab_entry_xray="@reboot sleep 10 && nohup $ARGO_BIN_DIR/xray run -c $config_file >/dev/null 2>&1  # agsbx-$vm_port-xray"
            local crontab_entry_cfd="@reboot sleep 15 && nohup $ARGO_BIN_DIR/cloudflared tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${agk_input} --url http://127.0.0.1:${vm_port} > $log_file 2>&1  # agsbx-$vm_port-cfd"
            crontab -l 2>/dev/null | grep -v "# agsbx-$vm_port" > /tmp/crontab.tmp || true
            echo "$crontab_entry_xray" >> /tmp/crontab.tmp
            echo "$crontab_entry_cfd" >> /tmp/crontab.tmp
            crontab /tmp/crontab.tmp
            rm -f /tmp/crontab.tmp
        fi
        
        # 立即启动进程 (Alpine 修复版：使用 setsid -f 替代 nohup)
    setsid -f "$ARGO_BIN_DIR/xray" run -c "$config_file"
    sleep 2
    setsid -f "$ARGO_BIN_DIR/cloudflared" tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token "$agk_input" --url "http://127.0.0.1:${vm_port}" > "$log_file" 2>&1

    say "已配置 Fallback 自启并立即启动进程。"
    fi
    
    sleep 3
    
    # 7. 生成链接并写入 META 的 'raw' 字段 (修复链接缺失问题)
    local vm_json='{
      "v": "2", "ps": "'$tag'", "add": "'$agn_input'", "port": "443", 
      "id": "'$uuid'", "aid": "0", "scy": "auto", "net": "ws", "type": "none", 
      "host": "'$agn_input'", "path": "'$ws_path'", "tls": "tls", "sni": "'$agn_input'", 
      "alpn": "http/1.1"
    }'
    local vmess_link="vmess://$(echo -n "$vm_json" | base64 -w 0)"
    
    local tmpmeta_link; tmpmeta_link=$(mktemp)
    jq --arg t "$tag" --arg link "$vmess_link" \
        '.[$t].raw = $link' "$META" > "$tmpmeta_link" && mv "$tmpmeta_link" "$META"

    local info="隧道域名: ${C_CYAN}${agn_input}${C_RESET}\n本地端口: ${C_CYAN}${vm_port}${C_RESET}\nUUID: ${C_CYAN}${uuid}${C_RESET}"
    print_card "CF Tunnel 用户 ${user_tag} 添加成功" "$tag" "$info" "$vmess_link"
    read -rp "按回车继续..." _
    set -e
    return 0
}
    # --- 启动/管理函数：view_argo_users ---
    view_argo_users() {
        set +e
        say "========== Cloudflare Tunnel 节点列表 =========="
        
        local nodes
        nodes=$(jq -r 'to_entries[] | select(.value.type == "argo") | "\(.key) \(.value.port // "null") \(.value.domain // "null") \(.value.uuid // "null") \(.value.path // "null")"' "$META" 2>/dev/null || true)
        
        if [ -z "$nodes" ]; then say "当前无 CF Tunnel 节点。"; read -rp "按回车返回..." _; return 1; fi
        
        local idx=1
        local all_links_file=$(mktemp)
        
        while IFS= read -r line; do
            local tag port domain uuid path status_mark=""
            read -r tag port domain uuid path <<< "$line"
            
            # 进程状态检查：优先检查 Cloudflared 进程
            local service_name="cf-tunnel-${port}"
            
            if [[ -n "$_SYSTEMCTL_CMD" && "$port" != "null" ]]; then
                if "$_SYSTEMCTL_CMD" is-active --quiet "${service_name}-cfd.service"; then
                    status_mark="${C_GREEN}[运行中 (Systemd)]${C_RESET}"
                else
                    status_mark="${C_RED}[停止 (Systemd)]${C_RESET}"
                fi
            elif [[ "$port" == "null" ]]; then
                # 临时节点检查 (仅检查是否有临时进程在运行)
                if pgrep -f "/root/agsbx/temp_node/cloudflared_temp" >/dev/null; then
                    status_mark="${C_GREEN}[运行中 (临时)]${C_RESET}"
                else
                    status_mark="${C_RED}[停止/失效 (临时)]${C_RESET}"
                fi
            elif pgrep -f "cloudflared.*${port}" >/dev/null; then
                status_mark="${C_GREEN}[运行中 (Fallback)]${C_RESET}"
            else
                status_mark="${C_RED}[停止 (Fallback)]${C_RESET}"
            fi

            local vm_json='{
              "v": "2", "ps": "'$tag'", "add": "'$domain'", "port": "443", 
              "id": "'$uuid'", "aid": "0", "scy": "auto", "net": "ws", "type": "none", 
              "host": "'$domain'", "path": "'$path'", "tls": "tls", "sni": "'$domain'", 
              "alpn": "http/1.1"
            }'
            local vmess_link="vmess://$(echo -n "$vm_json" | base64 -w 0)"
            
            echo -e "[${C_GREEN}${idx}${C_RESET}] ${C_CYAN}${tag}${C_RESET} (${status_mark})"
            echo -e "    ${C_YELLOW}域名: ${domain}${C_RESET} | ${C_YELLOW}本地端口: ${port}${C_RESET}"
            echo -e "    ${C_YELLOW}链接: ${vmess_link}${C_RESET}"
            echo "---------------------------------------------------------"
            
            echo "$vmess_link" >> "$all_links_file"
            ((idx++))
        done <<< "$nodes"
        
        say ""
        read -rp "是否将所有节点链接导出到 /root/argo_all_links.txt？(Y/n): " do_export
        do_export=${do_export:-Y}
        if [[ "$do_export" == "Y" || "$do_export" == "y" ]]; then
            mv "$all_links_file" "/root/argo_all_links.txt"
            ok "所有链接已导出到 /root/argo_all_links.txt"
        else
            rm -f "$all_links_file"
            say "已取消导出。"
        fi

        read -rp "按回车返回..." _
        set -e
        return 0
    }
    
    # --- 启动/管理函数：activate_fixed_argo_nodes ---
    activate_fixed_argo_nodes() {
        set +e
        say "========== 激活/重启固定 CF Tunnel 节点 =========="
        
        local ARGO_NODES_DIR="/etc/sing-box/argo_users"
        local ARGO_BIN_DIR="/root/agsbx"
        local nodes_to_restart=()
        
        local nodes
        nodes=$(jq -r 'to_entries[] | select(.value.type == "argo" and .value.port != "null") | "\(.key) \(.value.port) \(.value.domain) \(.value.token) \(.value.uuid)"' "$META" 2>/dev/null || true)
        
        if [ -z "$nodes" ]; then
            say "当前没有已配置的固定 CF Tunnel 用户可供激活。"
            read -rp "按回车返回..." _
            return
        fi
        
        say "检测到以下固定 CF Tunnel 用户："
        local idx=1
        while IFS= read -r line; do
            local tag port domain token uuid
            read -r tag port domain token uuid <<< "$line"
            
            local is_running=0
            local service_name="cf-tunnel-${port}"
            
            if [[ -n "$_SYSTEMCTL_CMD" ]]; then
                if "$_SYSTEMCTL_CMD" is-active --quiet "${service_name}-cfd.service"; then
                    is_running=1
                fi
            else
                if pgrep -f "cloudflared.*${port}" >/dev/null; then
                    is_running=1
                fi
            fi

            if (( is_running == 1 )); then
                say "[${idx}] ${tag} (端口: ${port}) - ${C_GREEN}已运行${C_RESET}，跳过。"
            else
                say "[${idx}] ${tag} (端口: ${port}) - ${C_RED}停止中${C_RESET}，将重启..."
                nodes_to_restart+=("$line")
            fi
            ((idx++))
        done <<< "$nodes"
        
        if ((${#nodes_to_restart[@]} == 0)); then
            ok "所有固定 CF Tunnel 节点均已运行。"
            read -rp "按回车返回..." _
            return
        fi
        
        say ""
        say "正在尝试重启 ${#nodes_to_restart[@]} 个停止中的 CF Tunnel 用户..."
        
        local restart_count=0
        for node_line in "${nodes_to_restart[@]}"; do
            local tag port domain token uuid
            read -r tag port domain token uuid <<< "$node_line"
            
            local config_file="$ARGO_NODES_DIR/${port}.json"
            local log_file="$ARGO_NODES_DIR/${port}.log"
            local service_name="cf-tunnel-${port}"
            
            say "-> 重启用户 ${tag} (端口 ${port})..."

            if [[ -n "$_SYSTEMCTL_CMD" ]]; then
                # Systemd 环境管理
                "$_SYSTEMCTL_CMD" daemon-reload >/dev/null 2>&1 || true
                "$_SYSTEMCTL_CMD" restart "${service_name}-xray.service" >/dev/null 2>&1 || true
                sleep 1
                "$_SYSTEMCTL_CMD" restart "${service_name}-cfd.service" >/dev/null 2>&1 || true
                sleep 2

                if "$_SYSTEMCTL_CMD" is-active --quiet "${service_name}-cfd.service"; then
                    ok "   用户 ${tag} 启动成功 (Systemd)。"
                    ((restart_count++))
                else
                    err "   用户 ${tag} 启动失败，请检查日志: sudo journalctl -u ${service_name}-cfd.service"
                fi
                
            else
                # Fallback 到 nohup 启动（非 Systemd/OpenRC）
                say "   非Systemd环境，使用nohup重启..."
                
                # 1. 强制杀死旧进程 (防止僵尸进程)
                pkill -9 -f "xray run -c $config_file" >/dev/null 2>&1 || true
                pkill -9 -f "cloudflared.*${port}" >/dev/null 2>&1 || true
                sleep 1
                
                # 2. 启动 Xray 核心
                (nohup "$ARGO_BIN_DIR/xray" run -c "$config_file" >/dev/null 2>&1 &)
                sleep 1
                
                # 3. 启动 Cloudflared 隧道
                (nohup "$ARGO_BIN_DIR/cloudflared" tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token "$token" --url "http://127.0.0.1:${port}" > "$log_file" 2>&1 &)
                sleep 2
                
                if pgrep -f "cloudflared.*${port}" >/dev/null; then
                    ok "   用户 ${tag} 启动成功 (Fallback)。"
                    ((restart_count++))
                else
                    err "   用户 ${tag} 启动失败，请检查日志: cat ${log_file}"
                fi
            fi
        done
        
        say ""
        ok "重启操作完成。成功启动 ${restart_count} 个用户。"
        read -rp "按回车返回..." _
        set -e
    }
    
    delete_argo_user() {
    set +e
    say "========== 删除 CF Tunnel 用户 =========="
    local nodes
    nodes=$(jq -r 'to_entries[] | select(.value.type == "argo") | "\(.key) \(.value.port // "null") \(.value.domain // "null")"' "$META" 2>/dev/null || true)
    if [ -z "$nodes" ]; then say "当前无 CF Tunnel 节点可删除。"; read -rp "按回车返回..." _; return; fi

    local idx=1 tags=() ports=()
    while IFS= read -r line; do
        local tag port domain
        read -r tag port domain <<< "$line"
        tags[$idx]="$tag"
        ports[$idx]="$port"
        echo "[${idx}] ${tag} (端口: ${port}, 域名: ${domain})"
        ((idx++))
    done <<< "$nodes"

    say "[0] 返回"
    read -rp "请输入要删除的节点序号（1-$((idx-1))）: " del_idx
    [[ "$del_idx" == "0" || -z "$del_idx" ]] && return
    if ! [[ "$del_idx" =~ ^[0-9]+$ ]] || (( del_idx < 1 || del_idx >= idx )); then warn "无效序号。"; return; fi 

    local tag_to_del="${tags[$del_idx]}"
    local port_to_del="${ports[$del_idx]}"
    read -rp "确认删除节点 ${tag_to_del} ？(y/N): " confirm
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && { say "已取消"; return; }
    
    say "-> 正在处理节点 ${tag_to_del}..."

    if [[ "$port_to_del" == "null" ]]; then
        pkill -f "/root/agsbx/temp_node/xray_temp" >/dev/null 2>&1 || true
        pkill -f "/root/agsbx/temp_node/cloudflared_temp" >/dev/null 2>&1 || true
        rm -f "$ARGO_TEMP_CACHE"
        local tmpmeta; tmpmeta=$(mktemp)
        jq "del(.\"$tag_to_del\")" "$META" > "$tmpmeta" && mv "$tmpmeta" "$META"
        ok "已删除临时节点 ${tag_to_del} 的元数据。"
    elif [[ -n "$port_to_del" ]]; then
        local service_name="cf-tunnel-${port_to_del}"
        if [[ -n "$_SYSTEMCTL_CMD" ]]; then
            "$_SYSTEMCTL_CMD" disable --now "${service_name}-xray.service" >/dev/null 2>&1 || true
            "$_SYSTEMCTL_CMD" disable --now "${service_name}-cfd.service" >/dev/null 2>&1 || true
            rm -f "/etc/systemd/system/${service_name}-xray.service"
            rm -f "/etc/systemd/system/${service_name}-cfd.service"
            "$_SYSTEMCTL_CMD" daemon-reload >/dev/null 2>&1 || true
        else
            pkill -9 -f "xray run -c ${ARGO_NODES_DIR}/${port_to_del}.json" >/dev/null 2>&1 || true
            pkill -9 -f "cloudflared.*${port_to_del}" >/dev/null 2>&1 || true
            # 清理 Alpine local.d 脚本
            rm -f "/etc/local.d/argo_${port_to_del}.start"
            # 清理 Crontab
            crontab -l 2>/dev/null | grep -v "# agsbx-${port_to_del}" > /tmp/crontab.tmp || true
            if [[ -s /tmp/crontab.tmp ]]; then crontab /tmp/crontab.tmp; else crontab -r >/dev/null 2>&1; fi
            rm -f /tmp/crontab.tmp
        fi
        rm -f "${ARGO_NODES_DIR}/${port_to_del}.json" "${ARGO_NODES_DIR}/${port_to_del}.log"
        local tmpmeta; tmpmeta=$(mktemp)
        jq "del(.\"$tag_to_del\")" "$META" > "$tmpmeta" && mv "$tmpmeta" "$META"
        ok "已删除固定 CF Tunnel 用户 ${tag_to_del} (进程已停止)"
    fi
    read -rp "按回车返回..." _
    set -e
}
    # --- 启动/管理函数：uninstall_argo_all (核心卸载逻辑) ---
    uninstall_argo_all() {
    set +e
    say "========== 卸载所有 CF Tunnel 相关组件及进程 =========="
    read -rp "确认卸载所有 CF Tunnel 用户及其核心组件 (Xray/Cloudflared)？(y/N): " confirm
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && { say "已取消"; return; }
    
    say "正在停止所有 CF Tunnel 进程..."
    pkill -9 -f "${ARGO_BIN_DIR}/xray" >/dev/null 2>&1 || true
    pkill -9 -f "${ARGO_BIN_DIR}/cloudflared" >/dev/null 2>&1 || true
    pkill -9 -f "/root/agsbx/temp_node/xray_temp" >/dev/null 2>&1 || true
    pkill -9 -f "/root/agsbx/temp_node/cloudflared_temp" >/dev/null 2>&1 || true
    
    say "正在清理服务文件和自启配置..."
    if [[ -n "$_SYSTEMCTL_CMD" ]]; then
        shopt -s nullglob
        for f in /etc/systemd/system/cf-tunnel-*.service; do
          "$_SYSTEMCTL_CMD" disable --now "$(basename "$f" .service)" >/dev/null 2>&1 || true
          rm -f "$f"
        done
        shopt -u nullglob
        "$_SYSTEMCTL_CMD" daemon-reload >/dev/null 2>&1 || true
    fi

    # 清理 Alpine local.d 脚本
    rm -f /etc/local.d/argo_*.start

    rm -rf "$ARGO_NODES_DIR"
    rm -rf "$ARGO_BIN_DIR"
    rm -rf "/root/agsbx/temp_node"
    rm -f "$ARGO_TEMP_CACHE" "$ARGO_FIXED_CACHE"
    
    if [[ -f "$META" ]]; then
        jq 'to_entries | map(select(.value.type != "argo")) | from_entries' "$META" > "${META}.tmp" && mv "${META}.tmp" "$META"
    fi
    
    crontab -l 2>/dev/null | grep -v "# agsbx-" > /tmp/crontab.tmp || true
    if [[ -s /tmp/crontab.tmp ]]; then crontab /tmp/crontab.tmp; else crontab -r >/dev/null 2>&1; fi
    rm -f /tmp/crontab.tmp
    
    ok "所有 CF Tunnel 组件及用户已彻底卸载。"
    read -rp "按回车返回..." _
    set -e
}
    # --- 启动/管理函数：temp_tunnel_logic (临时隧道独立逻辑) ---
# 原始的临时隧道逻辑 (现在修改为独立进程)
              temp_tunnel_logic() {
      set +e # 临时隧道逻辑使用 set +e
      say "========== 临时隧道 (独立进程) 部署 =========="
      
      local TEMP_ARGO_DIR="/root/agsbx/temp_node" # 临时隧道专用目录
      local ARGO_BIN_DIR="/root/agsbx" # 核心二进制文件目录 (共享)
      local TEMP_PID_FILE="$TEMP_ARGO_DIR/temp_cloudflared.pid"
      local TEMP_XRAY_PID_FILE="$TEMP_ARGO_DIR/temp_xray.pid"  # Xray PID 文件
      local TEMP_XRAY_LOG="$TEMP_ARGO_DIR/xray.log"  # Xray 日志文件，用于诊断
      
      mkdir -p "$TEMP_ARGO_DIR" "$ARGO_BIN_DIR"
      
      # 1. 强制清理旧的临时隧道进程 (增强清理，使用 pkill -9)
      say "-> 强制终止旧的临时隧道进程..."
      pkill -9 -f "$TEMP_ARGO_DIR/xray_temp" >/dev/null 2>&1 || true
      pkill -9 -f "$TEMP_ARGO_DIR/cloudflared_temp" >/dev/null 2>&1 || true
      sleep 1 # 等待系统释放资源

      # 2. 清理临时文件和缓存
      rm -f "$TEMP_ARGO_DIR/argo.log" "$TEMP_XRAY_LOG" "$ARGO_TEMP_CACHE" "$TEMP_PID_FILE" "$TEMP_XRAY_PID_FILE"
      # 尝试删除旧的可执行文件，防止 cp 冲突
      rm -f "$TEMP_ARGO_DIR/xray_temp" "$TEMP_ARGO_DIR/cloudflared_temp"
      
      # 确保 Xray 和 Cloudflared 二进制文件存在
      if ! ensure_argo_deps; then
          read -rp "依赖安装失败，按回车返回..." _; return
      fi
      
      # 3. 复制核心文件到临时目录
      say "-> 复制核心文件到独立目录..."
      cp "$ARGO_BIN_DIR/xray" "$TEMP_ARGO_DIR/xray_temp" || { err "复制 Xray 失败，请检查文件权限和占用。"; return; }
      cp "$ARGO_BIN_DIR/cloudflared" "$TEMP_ARGO_DIR/cloudflared_temp" || { err "复制 Cloudflared 失败，请检查文件权限和占用。"; return; }
      chmod +x "$TEMP_ARGO_DIR/xray_temp" "$TEMP_ARGO_DIR/cloudflared_temp"

      say "正在识别 IP 归属信息..."
      # ... (IP 归属逻辑不变)
      
      local uuid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)
      if [ -z "$uuid" ]; then uuid=$(openssl rand -hex 16 | sed 's/\(..\)/\1/g; s/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/'); fi
      
      local port=$(shuf -i 10000-60000 -n 1)
      local ws_path="/${uuid}-vm"
      local temp_config="$TEMP_ARGO_DIR/config.json"
      local temp_log="$TEMP_ARGO_DIR/argo.log"
      
      # Xray 配置文件 (不变，但日志级别为 info 以记录更多)
      cat > "$temp_config" <<EOF
{
  "log": { "loglevel": "info" },
  "inbounds": [
    {
      "port": ${port},
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": { "clients": [ { "id": "${uuid}", "alterId": 0 } ] },
      "streamSettings": { "network": "ws", "wsSettings": { "path": "${ws_path}" } }
    }
  ],
  "outbounds": [ { "protocol": "freedom", "tag": "direct" } ]
}
EOF
      
  # 4. 启动新的 Xray 进程 (修复 Alpine 下 PID 误判问题)
      # 移除 nohup，仅使用 setsid，并依靠 pgrep 检查存活
      setsid bash -c "trap '' INT HUP; exec \"$TEMP_ARGO_DIR/xray_temp\" run -c \"$temp_config\" > \"$TEMP_XRAY_LOG\" 2>&1" &
      sleep 2
      
      # 使用 pgrep 模糊匹配进程路径，而不是依赖 PID
      if ! pgrep -f "$TEMP_ARGO_DIR/xray_temp" >/dev/null 2>&1; then
          err "Xray 启动失败！请检查日志: cat $TEMP_XRAY_LOG"
          return
      fi
      # 重新获取正确的 PID 写入文件 (给停止脚本用)
      pgrep -f "$TEMP_ARGO_DIR/xray_temp" | head -n 1 > "$TEMP_XRAY_PID_FILE"

      say "正在申请 Argo 临时域名 (请等待约 5 秒)..."
     # 5. 启动新的 Cloudflared 进程 (修复 Alpine 下 PID 误判问题)
      setsid bash -c "trap '' INT HUP; exec \"$TEMP_ARGO_DIR/cloudflared_temp\" tunnel --url \"http://127.0.0.1:${port}\" --edge-ip-version auto --no-autoupdate > \"$temp_log\" 2>&1" &
      sleep 5 
      
      # 使用 pgrep 模糊匹配进程路径
      if ! pgrep -f "$TEMP_ARGO_DIR/cloudflared_temp" >/dev/null 2>&1; then
          err "Cloudflared 启动失败！请检查日志: cat $temp_log"
          return
      fi
      # 重新获取正确的 PID
      pgrep -f "$TEMP_ARGO_DIR/cloudflared_temp" | head -n 1 > "$TEMP_PID_FILE"

      local argo_url=""
      for i in {1..20}; do
          sleep 1
          argo_url=$(grep -oE 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' "$temp_log" | head -n 1 | sed 's/https:\/\///')
          if [ -n "$argo_url" ]; then break; fi
          printf "."
      done
      echo ""

      if [ -z "$argo_url" ]; then
          err "域名获取失败！请查看日志: cat $temp_log"
          read -rp "按回车返回..." _
          return
      fi

      local vm_json='{
        "v": "2",
        "ps": "Argo-Temp-'$port'",
        "add": "www.visa.com.sg",
        "port": "443",
        "id": "'$uuid'",
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": "'$argo_url'",
        "path": "/'$uuid'-vm",
        "tls": "tls",
        "sni": "'$argo_url'",
        "alpn": ""
      }'
      local vmess_link="vmess://$(echo -n "$vm_json" | base64 -w 0)"
      echo "$vmess_link" > "$ARGO_TEMP_CACHE"

      local info="Argo 域名: ${C_CYAN}${argo_url}${C_RESET}"
      print_card "Argo 临时隧道搭建成功" "Argo-Temp-$port" "$info" "$vmess_link"

      # 导入节点并重启 Sing-box (确保覆盖旧的临时节点)
      import_argo_nodes >/dev/null 2>&1 
      read -rp "请复制上方链接，按回车返回..." _
      
      set -e
    }
    # --- 菜单结构：multi_user_menu (二级菜单) ---
    multi_user_menu() {
      while true; do
        say ""
        say "========== Cloudflare Tunnel =========="
        say "1) 添加 CF (独立进程)"
        say "2) 卸载 CF (组件进程)        "
        say "0) 返回上级菜单"
        read -rp "请选择: " cf_user_choice
        case "$cf_user_choice" in
          1) add_argo_user ;;
          2) uninstall_argo_all ;;
          0) return ;;
          *) warn "无效选项" ; read -rp "按回车继续..." _ ;;
        esac
      done
    }

    # --- 菜单结构：uninstall_argo_logic (一级菜单卸载，调用 uninstall_argo_all) ---
    uninstall_argo_logic() {
      set +e
      say "正在停止进程并清理文件..."
pkill -f "/root/agsbx/xray" >/dev/null 2>&1 || true
pkill -f "/root/agsbx/cloudflared" >/dev/null 2>&1 || true

# 额外清理多用户进程
pkill -9 -f "${ARGO_BIN_DIR}/xray" >/dev/null 2>&1 || true
pkill -9 -f "${ARGO_BIN_DIR}/cloudflared" >/dev/null 2>&1 || true

# !!! 临时隧道进程清理 !!!
pkill -f "/root/agsbx/temp_node/xray_temp" >/dev/null 2>&1 || true
pkill -f "/root/agsbx/temp_node/cloudflared_temp" >/dev/null 2>&1 || true
# !!! -------------------- !!!

say "正在清理文件和元数据..."
rm -rf "/root/agsbx"
rm -rf "$ARGO_NODES_DIR" # 清理多用户文件夹
rm -f "$ARGO_TEMP_CACHE" "$ARGO_FIXED_CACHE"

# !!! 临时隧道目录清理 !!!
rm -rf "/root/agsbx/temp_node"
      if [[ -f "$META" ]]; then
          jq 'to_entries | map(select(.value.type != "argo")) | from_entries' "$META" > "${META}.tmp" && mv "${META}.tmp" "$META"
      fi
      
      if command -v crontab >/dev/null 2>&1; then
          crontab -l 2>/dev/null | grep -v "agsbx" | grep -v "# agsbx-" > /tmp/crontab.tmp || true
          if [[ -s /tmp/crontab.tmp ]]; then crontab /tmp/crontab.tmp; else crontab -r >/dev/null 2>&1; fi
          rm -f /tmp/crontab.tmp
      fi
      
      say "正在刷新节点列表..."
      restart_singbox >/dev/null 2>&1 || true
      ok "CF Tunnel 已彻底卸载 (进程/文件/自启/节点记录 已清空)"
      read -rp "按回车继续..." _
      set -e
    }


    # --- 第一层 CF Tunnel 菜单 ---
   # **********************************************
    while true; do
      say "========== Cloudflare 隧道管理 =========="
      say "1) 临时隧道 (trycloudflare.com)"
      say "2) 固定隧道 (添加/管理 CF Token 用户)"
      say "3) 删除 CF 用户 (独立停止进程)"
      say "4) 激活/重启固定隧道"
      say "5) 卸载所有 CF Tunnel 组件 (清空 Xray/Cloudflared/配置)" 
      say "0) 返回上级菜单"
      
      read -rp "请选择: " argo_choice
      case "$argo_choice" in
        1) temp_tunnel_logic ;;
        2) 
          # 2) 固定隧道：直接调用添加用户的函数
          add_argo_user
          ;; 
        3) delete_argo_user ;; 
        4) activate_fixed_argo_nodes ;;
        5) uninstall_argo_all ;; # 使用原有的彻底卸载函数
        0) return ;;
        *) warn "无效选项" ; read -rp "按回车继续..." _ ;;
      esac
    done
    return
  fi
  local port user pass tag tmpcfg proto_type="tcp"
  while true; do
    [[ -n "$nat_mode" ]] && {
      [[ "$nat_mode" == "custom" ]] && say "已启用自定义端口模式：SOCKS5 仅允许使用 自定义TCP端口集合"
      [[ "$nat_mode" == "range" ]] && say "已启用范围端口模式：SOCKS5 仅允许使用 范围内端口"
    }
    read -rp "请输入端口号（留空自动挑选允许端口；输入 0 返回）: " port
    [[ "$port" == "0" ]] && return
    if [[ -z "$port" ]]; then
      port=$(get_random_allowed_port "$proto_type")
      [[ "$port" == "NO_PORT" ]] && { err "无可用端口"; return 1; }
      say "（已自动选择随机端口：$port）"
    fi
    [[ "$port" =~ ^[0-9]+$ ]] && ((port>=1 && port<=65535)) || { warn "端口无效"; continue; }
    (( port < 1024 )) && warn "端口<1024可能需root权限"
    if ! check_nat_allow "$port" "$proto_type"; then warn "端口 $port 不符合 NAT 规则（协议: $proto_type）"; continue; fi
    if jq -e --argjson p "$port" '.inbounds[] | select(.listen_port == $p)' "$CONFIG" >/dev/null 2>&1; then
      warn "端口 $port 已存在"; continue
    fi
    if jq -e --argjson p "$port" 'to_entries[]? | select(.value.type=="hysteria2" and .value.port == $p)' "$META" >/dev/null 2>&1; then
      warn "端口 $port 已被 Hysteria2 使用"; continue
    fi
    break
  done

  read -rp "请输入用户名（默认 user）: " user; user=${user:-user}
  read -rp "请输入密码（默认 pass123）: " pass; pass=${pass:-pass123}
  tag="sk5-$(get_country_code)-$(tr -dc 'A-Z' </dev/urandom | head -c1)"

  tmpcfg=$(mktemp); trap 'rm -f "$tmpcfg"' RETURN
  jq --arg port "$port" --arg user "$user" --arg pass "$pass" --arg tag "$tag" \
    '.inbounds += [{"type":"socks","tag":$tag,"listen":"::","listen_port":($port|tonumber),"users":[{"username":$user,"password":$pass}]}]' \
    "$CONFIG" >"$tmpcfg" && mv "$tmpcfg" "$CONFIG"

  say " 正在校验配置..."
  if sing-box check -c "$CONFIG" >/dev/null 2>&1; then
    ok "配置通过，正在重启 Sing-box..."
    restart_singbox || { err "重启失败"; return 1; }
  else
    err "配置校验失败"; sing-box check -c "$CONFIG"; return 1
  fi

  local creds; creds=$(printf "%s:%s" "$user" "$pass" | base64 -w0)
  local link="socks://${creds}@${GLOBAL_IPV4}:${port}#${tag}"
  local info="本地端口: ${C_CYAN}${port}${C_RESET}\n用户名: ${C_CYAN}${user}${C_RESET}\n密码: ${C_CYAN}${pass}${C_RESET}"
  print_card "SOCKS5 搭建成功" "$tag" "$info" "$link"
  [[ -n "$GLOBAL_IPV6" ]] && echo -e "IPv6 链接: socks://${creds}@[IPv6]:${port}#${tag}"
  echo ""
}
add_hysteria2_node() {
  ensure_runtime_deps
  
  local port proto_type="udp"
  
  while true; do
    read -rp "请输入 Hysteria2 端口 (留空则自动随机): " input_port
    
    if [[ -z "$input_port" ]]; then
      say "正在自动寻找可用 UDP 端口..."
      local found_port=0
      for i in {1..10}; do
          port=$(get_random_allowed_port "$proto_type")
          if [[ "$port" == "NO_PORT" ]]; then
              err "无可用端口，请检查 NAT 规则或端口占用"
              return 1
          fi
          
          if jq -e --argjson p "$port" '.inbounds[] | select(.listen_port == $p)' "$CONFIG" >/dev/null 2>&1; then continue; fi
          if jq -e --argjson p "$port" 'to_entries[]? | select(.value.type=="hysteria2" and .value.port == $p)' "$META" >/dev/null 2>&1; then continue; fi
          if port_status "$port"; then continue; fi
          
          found_port=1
          break
      done
      
      if [[ $found_port -eq 0 ]]; then
          err "自动分配端口失败，请手动检查系统端口占用情况。"
          return 1
      fi
      break
    else
      if ! [[ "$input_port" =~ ^[0-9]+$ ]] || (( input_port < 1 || input_port > 65535 )); then
          warn "端口无效，请输入 1-65535 之间的数字"
          continue
      fi
      
      port="$input_port"
      
      if ! check_nat_allow "$port" "$proto_type"; then 
         warn "该端口不符合当前的 NAT 端口规则 (协议: $proto_type)"
         continue
      fi
      
      if jq -e --argjson p "$port" '.inbounds[] | select(.listen_port == $p)' "$CONFIG" >/dev/null 2>&1; then
          warn "端口 $port 已被 Sing-box 其他节点占用"
          continue
      fi
      if jq -e --argjson p "$port" 'to_entries[]? | select(.value.type=="hysteria2" and .value.port == $p)' "$META" >/dev/null 2>&1; then
          warn "端口 $port 已被其他 Hysteria2 节点占用"
          continue
      fi
      if port_status "$port"; then
          warn "系统端口 $port 已被占用"
          continue
      fi
      
      break
    fi
  done
  
  say "已选定端口: $port"

  if ! command -v hysteria >/dev/null 2>&1; then
    say "正在安装 Hysteria 2 核心..."
    local H_VERSION="2.6.2"
    local arch=$(uname -m)
    case "$arch" in
      x86_64|amd64) arch="amd64" ;;
      aarch64|arm64) arch="arm64" ;;
      *) err "暂不支持的架构：$arch"; return 1 ;;
    esac
    
    local tmp; tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    (
      set -e
      cd "$tmp"
      curl -sSL "https://github.com/apernet/hysteria/releases/download/app/v${H_VERSION}/hysteria-linux-${arch}" -o hysteria-bin || { err "下载 hysteria 失败"; exit 1; }
      install -m 0755 hysteria-bin /usr/local/bin/hysteria
    ) || { return 1; }
    ok "Hysteria 2 安装完成"
  fi

  mkdir -p /etc/hysteria2
  local cert_file="/etc/hysteria2/${port}.crt"
  local key_file="/etc/hysteria2/${port}.key"
  local sni_domain="www.bing.com"

  say "正在生成自签名证书 ($sni_domain)..."
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout "$key_file" -out "$cert_file" -days 3650 -subj "/CN=$sni_domain" >/dev/null 2>&1
  chmod 644 "$cert_file" "$key_file"

  local auth_pwd=$(openssl rand -base64 16 | tr -d '=+/' | cut -c1-16)
  local obfs_pwd=$(openssl rand -base64 8 | tr -d '=+/' | cut -c1-8)

  cat > "/etc/hysteria2/${port}.yaml" <<EOF
listen: :${port}

tls:
  cert: ${cert_file}
  key: ${key_file}

auth:
  type: password
  password: ${auth_pwd}

obfs:
  type: salamander
  salamander:
    password: ${obfs_pwd}

masquerade:
  type: proxy
  proxy:
    url: https://${sni_domain}/
    rewriteHost: true 
    insecure: true

ignoreClientBandwidth: false
EOF

  # ... (Hysteria2 YAML 配置创建完毕)
  local service_name="hysteria2-${port}"
  
  INIT_SYS=$(detect_init_system) # <-- 强制重新检测，确保 INIT_SYS 是最新的
  
  if [[ "$INIT_SYS" == "systemd" ]]; then
      # 写入 Systemd 服务文件
      cat > "/etc/systemd/system/${service_name}.service" <<EOF
[Unit]
Description=Hysteria2 Service (Port ${port})
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria2/${port}.yaml
Restart=always
RestartSec=3
User=root
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
      systemctl daemon-reload >/dev/null 2>&1
      systemctl enable "$service_name" >/dev/null 2>&1
      systemctl restart "$service_name" >/dev/null 2>&1
      
      sleep 2
      if ! systemctl is-active --quiet "$service_name"; then
          err "Hysteria2 服务启动失败，请检查日志: journalctl -u $service_name"
          return 1
      fi
      
  elif [[ "$INIT_SYS" == "openrc" ]]; then
      # 写入 OpenRC 服务文件
      cat > "/etc/init.d/${service_name}" <<EOF
#!/sbin/openrc-run
name="${service_name}"
description="Hysteria2 Service (Port ${port})"
command="/usr/local/bin/hysteria"
command_args="server -c /etc/hysteria2/${port}.yaml"
pidfile="/run/${service_name}.pid"
command_background="yes"

depend() {
  need net
}
EOF
      chmod +x "/etc/init.d/${service_name}"
      rc-update add "${service_name}" default >/dev/null 2>&1
      rc-service "${service_name}" start >/dev/null 2>&1

      sleep 2
      if ! rc-service "${service_name}" status >/dev/null 2>&1; then
          err "Hysteria2 服务启动失败，请检查日志: rc-service ${service_name} status"
          return 1
      fi

  else
      err "未知初始化系统: $INIT_SYS，无法启动 Hysteria2 服务。"
      return 1
  fi
# ... (后续代码)

  local tag="Hy2-Default-$(date +%s)"
  local tmpmeta; tmpmeta=$(mktemp)
  trap 'rm -f "$tmpmeta"' EXIT
  
  if [[ ! -f "$META" ]]; then echo "{}" > "$META"; fi
  jq --arg tag "$tag" --arg port "$port" --arg sni "$sni_domain" --arg obfs "$obfs_pwd" --arg auth "$auth_pwd" \
    '. + {($tag): {type:"hysteria2", port:$port, sni:$sni, obfs:$obfs, auth:$auth}}' "$META" >"$tmpmeta" && mv "$tmpmeta" "$META"

  local link="hysteria2://${auth_pwd}@${GLOBAL_IPV4}:${port}?obfs=salamander&obfs-password=${obfs_pwd}&sni=${sni_domain}&insecure=1#${tag}"
  local info="本地端口: ${C_CYAN}${port}${C_RESET}\nAuth密码: ${C_CYAN}${auth_pwd}${C_RESET}\nObfs密码: ${C_CYAN}${obfs_pwd}${C_RESET}\n模式: ${C_CYAN}自签证书(bing.com)${C_RESET}"
  
  print_card "Hysteria2 部署成功" "$tag" "$info" "$link"
  
  if [[ -n "$GLOBAL_IPV6" ]]; then
      local link_v6="hysteria2://${auth_pwd}@[${GLOBAL_IPV6}]:${port}?obfs=salamander&obfs-password=${obfs_pwd}&sni=${sni_domain}&insecure=1#${tag}"
      echo -e "IPv6 链接: ${C_YELLOW}${link_v6}${C_RESET}"
      echo ""
  fi
  
  read -rp "按回车返回主菜单..." _
}

import_argo_nodes() {
    set +e
    local imported=0
    local ARGO_META_TAG_PREFIX="Argo-"
    local tmpmeta_file=$(mktemp)

    # 1. 预处理：从 $META 中删除所有旧的临时节点 (subtype: temp)
    say "-> 清理旧的临时隧道元数据..."
    # 确保 $META 文件存在，并且只保留非临时节点
    if [[ -f "$META" ]]; then
        jq 'to_entries | map(select(.value.type != "argo" or .value.subtype != "temp")) | from_entries' "$META" > "$tmpmeta_file"
    else
        echo "{}" > "$tmpmeta_file"
    fi
    mv "$tmpmeta_file" "$META"

    # 2. 导入固定隧道节点 (这些是多用户模式，它们应该已经以 type: argo, subtype: fixed, port: PORT 存在于 META 中，
    #    但这里保留对 ARGO_FIXED_CACHE 的旧兼容逻辑，以防万一。)
    if [[ -f "$ARGO_FIXED_CACHE" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
            if [[ "$line" =~ ^(vmess|vless|trojan|ss):// ]]; then
                tag="${ARGO_META_TAG_PREFIX}Fixed-$(date +%s)"
                jq --arg t "$tag" --arg url "$line" \
                   '.[$t] = {type:"argo", subtype:"fixed", raw:$url}' "$META" > "$META.tmp" && mv "$META.tmp" "$META"
                ((imported++))
            fi
        done < "$ARGO_FIXED_CACHE"
    fi

    # 3. 导入新的临时隧道节点 (从 ARGO_TEMP_CACHE)
    if [[ -f "$ARGO_TEMP_CACHE" ]]; then
        say "-> 导入新的临时隧道节点..."
        while IFS= read -r line || [[ -n "$line" ]]; do
          [[ "$line" =~ ^[[:space:]]*# ]] && continue
            if [[ "$line" =~ ^(vmess|vless|trojan|ss):// ]]; then
                # 临时节点的标签是 Temp，但每次导入都会被前面的步骤清除
                tag="${ARGO_META_TAG_PREFIX}Temp-$(date +%s)"
                jq --arg t "$tag" --arg url "$line" \
                   '.[$t] = {type:"argo", subtype:"temp", raw:$url}' "$META" > "$META.tmp" && mv "$META.tmp" "$META"
                ((imported++))
                # 临时节点只处理第一个（确保只有一个活动临时节点）
                break 
            fi
        done < "$ARGO_TEMP_CACHE"
    fi

    rm -f "$tmpmeta_file" "$META.tmp" # 清理临时文件
    
    if (( imported > 0 )); then
        say "导入 $imported 个 CF Tunnel 节点，正在重启 Sing-box..."
        restart_singbox >/dev/null 2>&1
    fi
    set -e
    return 0
}
view_nodes() {
  local filter_mode="$1" 
  set +e

  local total ext_count
  if [[ "$filter_mode" == "normal" ]]; then
    # 正常节点计数（SOCKS5/VLESS）
    total=$(jq '[.inbounds[] | select(.type=="socks" or .type=="vless")] | length' "$CONFIG" 2>/dev/null || echo "0")
    # 外部节点计数（Hysteria2）
    ext_count=$(jq '[to_entries[] | select(.value.type=="hysteria2")] | length' "$META" 2>/dev/null || echo "0")
  fi

  declare -A node_ports node_types node_tags node_raws node_domains node_uuids
  local idx=0

  if [[ "$filter_mode" == "normal" ]]; then
    # 导入 Sing-box 内部节点
    while read -r line; do
      local tag port type
      tag=$(jq -r '.tag' <<<"$line")
      port=$(jq -r '.listen_port // empty' <<<"$line")
      type=$(jq -r '.type' <<<"$line")
      node_tags[$idx]="$tag"; node_ports[$idx]="${port:-未知}"; node_types[$idx]="$type"; node_raws[$idx]=""
      ((idx++))
    done < <(jq -c '.inbounds[] | select(.type=="socks" or .type=="vless")' "$CONFIG" 2>/dev/null)

    # 导入 Hysteria2 节点
    if (( ext_count > 0 )); then
      while read -r key; do
        local tag port
        tag="$key"
        port=$(jq -r --arg t "$tag" '.[$t].port // "未知"' "$META")
        node_tags[$idx]="$tag"; node_ports[$idx]="$port"; node_types[$idx]="hysteria2"; node_raws[$idx]=""
        ((idx++))
      done < <(jq -r 'to_entries[] | select(.value.type=="hysteria2") | .key' "$META")
    fi
  fi

  if [[ "$filter_mode" == "argo" ]]; then
    say "正在从元数据中读取 CF Tunnel 节点..."
    while read -r key; do
        local tag raw port domain uuid subtype path
        tag="$key"
        raw=$(jq -r --arg t "$tag" '.[$t].raw // empty' "$META")
        subtype=$(jq -r --arg t "$tag" '.[$t].subtype // "fixed"' "$META")
        
        if [[ "$subtype" == "temp" ]]; then
            # --- 修复：更鲁棒的 Vmess 解码和信息提取 ---
            local b64_str="${raw#vmess://}"
            # 1. 尝试添加 padding
            local remainder=$(( ${#b64_str} % 4 ))
            if [[ $remainder -gt 0 ]]; then
                b64_str="${b64_str}$(printf '%0.s=' $(seq 1 $((4 - remainder))))"
            fi
            
            # 2. Base64 解码
            local decoded_json=$(echo "$b64_str" | base64 -d 2>/dev/null)
            
            if [[ -n "$decoded_json" ]]; then
                domain=$(jq -r '.host // empty' <<<"$decoded_json")
                uuid=$(jq -r '.id // empty' <<<"$decoded_json")
                port=$(jq -r '.port // "443"' <<<"$decoded_json")
                local ps_name=$(jq -r '.ps // empty' <<<"$decoded_json")
                tag=${ps_name:-$tag}
            else
                domain="解码失败/Base64错误"
                port="443"
            fi
        else
            # 固定节点：从 $META 字段读取信息 (Fixed Nodes are reliable)
            port=$(jq -r --arg t "$tag" '.[$t].port // "443"' "$META")
            domain=$(jq -r --arg t "$tag" '.[$t].domain // empty' "$META")
            uuid=$(jq -r --arg t "$tag" '.[$t].uuid // empty' "$META")
        fi
        
        node_tags[$idx]="${tag}"; 
        node_ports[$idx]="${port}"; 
        node_types[$idx]="ARGO-${subtype^^}"; 
        node_raws[$idx]="$raw";
        node_domains[$idx]="$domain";
        ((idx++))

    done < <(jq -r 'to_entries[] | select(.value.type=="argo") | .key' "$META")
  fi

  if (( idx == 0 )); then
    say "当前分类下暂无节点"
    unset node_tags node_ports node_types node_raws node_domains
    set -e
    return
  fi

  local ss_tcp="" ss_udp=""
  if [[ "$filter_mode" == "normal" ]]; then
      ss_tcp=$(ss -ltnp 2>/dev/null || true)
      ss_udp=$(ss -lunp 2>/dev/null || true)
  fi

  echo ""
  echo -e "${C_GREEN}序号  协议        端口         名称${C_RESET}"
  echo "---------------------------------------------------------"

  local -a sort_map
  local k
  for ((k=0; k<idx; k++)); do
    local p_str="${node_ports[$k]}"
    local p_val
    if [[ "$p_str" =~ [0-9]+ ]]; then p_val="${BASH_REMATCH[0]}"; else p_val=999999; fi
    sort_map+=("$p_val:$k")
  done

  local -a sorted_indices
  IFS=$'\n' sorted_indices=($(sort -n <<<"${sort_map[*]}"))
  unset IFS

  local display_seq=1
  for item in "${sorted_indices[@]}"; do
    local i="${item#*:}" 
    local tag="${node_tags[$i]}"
    local port="${node_ports[$i]}"
    local type="${node_types[$i]}"
    local raw="${node_raws[$i]}"
    local domain="${node_domains[$i]}"
    local display_link="$raw"

    local status_mark=""
    
    if [[ "$type" =~ ARGO ]]; then
      local port_num="${port}"
      if [[ "$type" == "ARGO-TEMP" ]]; then
        if pgrep -f "/root/agsbx/temp_node/cloudflared_temp" >/dev/null; then status_mark="${C_GREEN}[运行中 (临时)]${C_RESET}"; else status_mark="${C_RED}[停止/失效 (临时)]${C_RESET}"; fi
        printf "[%2d] ${C_GREEN}%-10s${C_RESET} | ${C_CYAN}%-10s${C_RESET} | ${C_CYAN}域名: %s${C_RESET} %s\n" "$display_seq" "TEMP" "443" "${domain}" "${status_mark}"
      else
        local s_name="cf-tunnel-${port_num}"
        if [[ -n "$_SYSTEMCTL_CMD" ]] && "$_SYSTEMCTL_CMD" is-active --quiet "${s_name}-cfd.service"; then status_mark="${C_GREEN}[运行中 (Systemd)]${C_RESET}";
        elif pgrep -f "cloudflared.*${port_num}" >/dev/null; then status_mark="${C_GREEN}[运行中 (Fallback)]${C_RESET}";
        else status_mark="${C_RED}[停止 (Fallback)]${C_RESET}"; fi
        printf "[%2d] ${C_GREEN}%-10s${C_RESET} | ${C_CYAN}%-10s${C_RESET} | ${C_CYAN}域名: %s${C_RESET} %s\n" "$display_seq" "FIXED" "443" "${domain}" "${status_mark}"
      fi
    else
      if [[ "$port" =~ ^[0-9]+$ ]] && ! grep -q ":$port " <<<"$ss_tcp$ss_udp" &>/dev/null; then status_mark="${C_RED}[未运行]${C_RESET}"; fi
      
      case "$type" in
        vless)
          local uuid=$(jq -r --arg t "$tag" '.inbounds[] | select(.tag==$t) | .users[0].uuid // empty' "$CONFIG")
          local pbk=$(jq -r --arg t "$tag" '.[$t].pbk // empty' "$META")
          local sid=$(jq -r --arg t "$tag" '.[$t].sid // empty' "$META")
          local sni=$(jq -r --arg t "$tag" '.[$t].sni // "www.cloudflare.com"' "$META")
          local fp=$(jq -r --arg t "$tag" '.[$t].fp // "chrome"' "$META")
          
          [[ -n "$uuid" && -n "$pbk" ]] && display_link="vless://${uuid}@${GLOBAL_IPV4}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&pbk=${pbk}&sid=${sid}&sni=${sni}&fp=${fp}#${tag}"
          ;;
        socks)
          local info=$(jq -r --arg t "$tag" '.inbounds[] | select(.tag==$t) | "\(.users[0].username):\(.users[0].password)"' "$CONFIG")
          local creds=$(printf "%s" "$info" | base64 -w0)
          display_link="socks://${creds}@${GLOBAL_IPV4}:${port}#${tag}"
          ;;
        hysteria2)
          local auth=$(jq -r --arg t "$tag" '.[$t].auth // empty' "$META")
          local obfs=$(jq -r --arg t "$tag" '.[$t].obfs // empty' "$META")
          local sni=$(jq -r --arg t "$tag" '.[$t].sni // "bing.com"' "$META")
          [[ -n "$auth" ]] && display_link="hysteria2://${auth}@${GLOBAL_IPV4}:${port}?obfs=salamander&obfs-password=${obfs}&sni=${sni}&insecure=1#${tag}"
          ;;
        *) display_link="[链接生成失败]";;
      esac

      printf "[%2d] ${C_GREEN}%-10s${C_RESET} | ${C_CYAN}%-10s${C_RESET} | ${C_CYAN}%s${C_RESET} %s\n" \
             "$display_seq" "${type^^}" "${port}" "${tag}" "${status_mark}"
      
    fi

    echo -e "     ${C_YELLOW}${display_link}${C_RESET}"
    echo -e "${C_RESET}---------------------------------------------------------${C_RESET}"
    
    ((display_seq++))
  done
  
  unset node_tags node_ports node_types node_raws sorted_indices sort_map node_domains
  set -e
}

view_nodes_menu() {
  while true; do
    say ""
    say "========== 查看节点 =========="
    say "1) 普通节点 (SOCKS5 / VLESS / Hysteria2)"
    say "2) 隧道节点 (Argo 临时 / 固定)"
    say "0) 返回主菜单"
    read -rp "请选择查看类型: " v_opt
    case "$v_opt" in
      1) 
        say "--- 普通节点列表 ---"
        view_nodes "normal" 
        read -rp "按回车继续..." _
        ;;
      2) 
        say "--- 隧道节点列表 ---"
        view_nodes "argo"
        read -rp "按回车继续..." _
        ;;
      0) return ;;
      *) warn "无效输入" ;;
    esac
  done
}
delete_node() {
  local total ext_count real_count
  total=$(jq '.inbounds | length' "$CONFIG" 2>/dev/null || echo "0")
  ext_count=$(jq '[to_entries[] | select(.value.type=="hysteria2")] | length' "$META" 2>/dev/null || echo "0")
  real_count=$((total + ext_count))

  if (( real_count == 0 )); then
    say "暂无本地节点可删除（Argo 临时节点请重新运行隧道清除）"
    return
  fi

  say "================= 可删除的本地节点 =================="
  view_nodes "normal"   
  say "===================================================="
  say "提示：Argo 节点（端口为 Argo）无法在此删除"
  say "      需清除 Argo 节点请重新运行一次【1 → 4 Argo临时隧道 → 3 卸载】"
  say "===================================================="

  say "[0] 返回主菜单"
  say "[ss] 删除所有本地节点"
  read -rp "请输入要删除的本地节点序号（1-$real_count）: " idx

  [[ "$idx" == "0" || -z "$idx" ]] && return

  if [[ "$idx" == "ss" ]]; then
    read -rp "确认删除所有本地节点？(y/N): " c
    [[ "$c" != "y" && "$c" != "Y" ]] && { say "已取消"; return; }
    
    jq '.inbounds = []' "$CONFIG" > "${CONFIG}.tmp" && mv "${CONFIG}.tmp" "$CONFIG"
    
    if [[ -f "$META" ]]; then
        jq 'to_entries | map(select(.value.type == "argo")) | from_entries' "$META" > "${META}.tmp" && mv "${META}.tmp" "$META"
    else
        printf '{}' > "$META"
    fi
    
    shopt -s nullglob
    for f in /etc/systemd/system/hysteria2*.service; do
      systemctl disable --now "$(basename "$f" .service)" &>/dev/null || true
      rm -f "$f"
    done
    shopt -u nullglob
    systemctl daemon-reload &>/dev/null || true
    rm -rf /etc/hysteria2
    
    restart_singbox >/dev/null 2>&1
    ok "所有本地节点已删除（Argo 节点不受影响）"
    return
  fi

  if ! [[ "$idx" =~ ^[0-9]+$ ]] || (( idx < 1 || idx > real_count )); then
    warn "只能输入 1~$real_count 的序号"
    return
  fi

  local n=$((idx - 1))

  if (( n < total )); then
    local tag=$(jq -r ".inbounds[$n].tag // empty" "$CONFIG")
    jq "del(.inbounds[$n])" "$CONFIG" > "${CONFIG}.tmp" && mv "${CONFIG}.tmp" "$CONFIG"
    [[ -n "$tag" && "$tag" != "null" ]] && jq "del(.\"$tag\")" "$META" > "${META}.tmp" && mv "${META}.tmp" "$META"
    restart_singbox >/dev/null 2>&1
    ok "已删除本地节点 [$idx]"
  else
    n=$((n - total))
    local tag=$(jq -r --argjson i "$n" 'to_entries | map(select(.value.type=="hysteria2")) | .[$i].key' "$META")
    local port=$(jq -r --arg t "$tag" '.[$t].port // empty' "$META")
    
    jq "del(.\"$tag\")" "$META" > "${META}.tmp" && mv "${META}.tmp" "$META"
    
    if [[ -n "$port" ]]; then
      systemctl disable --now "hysteria2-${port}" &>/dev/null || true
      rm -f "/etc/systemd/system/hysteria2-${port}.service" "/etc/hysteria2/${port}".{yaml,key,crt}
    fi
    systemctl daemon-reload &>/dev/null || true
    ok "已删除 Hysteria2 节点 [$idx]"
  fi
}
is_docker() {
  if [ -f /.dockerenv ]; then
    return 0
  fi
  if grep -qE "/docker/|/lxc/" /proc/1/cgroup 2>/dev/null; then
    return 0
  fi
  return 1
}

OS_NAME=$(lsb_release -si 2>/dev/null || grep '^ID=' /etc/os-release | cut -d= -f2)
OS_VER=$(lsb_release -sr 2>/dev/os-release | cut -d= -f2 | tr -d '"')

if is_docker; then
  SYSTEM_INFO="$OS_NAME（docker）"
else
  SYSTEM_INFO="$OS_NAME"
fi

echo "系统: $SYSTEM_INFO"

show_version_info() {
  local OS OS_NAME VIRT BIN OUT VER ARCH

  OS=$(detect_os)
  [[ "$OS" == "unknown" ]] && OS_NAME="未知" || OS_NAME="${OS^}"

  if command -v systemd-detect-virt >/dev/null 2>&1; then
    VIRT=$(systemd-detect-virt)
    [[ "$VIRT" != "none" && -n "$VIRT" ]] && OS_NAME="${OS_NAME}（${VIRT}）"
  elif is_docker; then
    OS_NAME="${OS_NAME}（docker）"
  fi

  if [[ -x "/usr/local/bin/sing-box" ]]; then
    BIN="/usr/local/bin/sing-box"
  elif [[ -x "/usr/bin/sing-box" ]]; then
    BIN="/usr/bin/sing-box"
  elif [[ -x "/etc/sing-box/bin/sing-box" ]]; then
    BIN="/etc/sing-box/bin/sing-box"
  elif command -v sing-box >/dev/null 2>&1; then
    BIN="$(command -v sing-box)"
  else
    BIN=""
  fi

  if [[ -n "$BIN" && -x "$BIN" ]]; then
    OUT=$("$BIN" version 2>/dev/null)
    
    VER=$(echo "$OUT" | grep -oE 'version [0-9.]+(-[a-zA-Z0-9]+)?' | head -n1 | awk '{print $2}')
    ARCH=$(echo "$OUT" | grep -oE '(linux|android|darwin|windows)/(amd64|arm64|386|s390x|riscv64)' | head -n1)
    
    if [[ -z "$ARCH" ]]; then
       ARCH=$(echo "$OUT" | grep -oE 'go[0-9.]+' | head -n1)
    fi

    say "Sing-box 版本: ${VER:-未知}  | 架构: ${ARCH:-未知}  | 系统: ${OS_NAME}"
  else
    say "Sing-box 版本: 未安装  | 架构: -     | 系统: ${OS_NAME}"
  fi
}

script_services_menu() {
  while true; do
    say "====== 脚本服务 ======"
    say "1) 检测并修复（系统检测 + 建议 + 一键修复）"
    say "2) 重启 Sing-box 服务"
    say "3) 检查并更新 Sing-box 到最新版"
    say "4) 完全卸载 / 初始化重装"
    say "0) 返回主菜单"
    read -rp "请选择: " op
    case "$op" in
      1) check_and_repair_menu ;;
      2) restart_singbox ;;
      3) update_singbox ;;
      4) reinstall_menu ;;
      0) break ;;
      *) warn "无效输入" ;;
  esac
  done
}
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
  say "（提示：脚本将在 20 秒无操作后自动退出）" # <--- 提示已更新

  # 使用 read -t 20 设置 20 秒超时
  if ! read -t 20 -rp "请输入操作编号: " choice; then # <--- 20秒修改在这里
      local rc=$?
      if [ $rc -eq 1 ]; then # 无法读取输入 (非交互式或连接断开)
          echo "无法读取输入（非交互式模式），脚本退出。"
          exit 1
      elif [ $rc -eq 128 ]; then # 超时 (exit code 128 + signal number, 理论上是 128+1)
          echo ""
          say "超过 20 秒未操作，自动退出。"
          exit 0 # 自动退出
      fi
  fi

  # 如果 choice 为空 (用户直接按回车或超时但 Bash 版本处理不同)
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

# --- 脚本快捷指令自动设置（新增） ---
# --- 脚本快捷指令自动设置（新增） ---
setup_shortcuts() {
  local SCRIPT_PATH
  # 尝试获取当前脚本的绝对路径
  SCRIPT_PATH="$(readlink -f "$0" 2>/dev/null || echo '/root/my.sh')" # 路径适应你的安装脚本

  if [[ ! -f /root/.bashrc ]]; then
    touch /root/.bashrc
    ok "已创建 /root/.bashrc 文件。"
  fi

  # 清理旧的别名（如果存在）
  if grep -q "# SK5_QUICKSTART_ALIAS" /root/.bashrc; then
    sed -i '/# SK5_QUICKSTART_ALIAS/,+2d' /root/.bashrc
  fi

  # 写入新的别名，并携带 --menu 参数
  local ALIAS_TEXT="# SK5_QUICKSTART_ALIAS
alias my=\"$SCRIPT_PATH --menu\"
alias MY=\"$SCRIPT_PATH --menu\"
"
  echo -e "$ALIAS_TEXT" >> /root/.bashrc
  
  ok "✅ 快捷指令 'my' 和 'MY' 已设置成功！"

  # 核心改动：如果当前 shell 是交互式的，尝试让它加载新的别名。
  # 这种方法不能直接影响父 Shell，但对于某些环境和运行方式可能有效。
  if [[ $- =~ i ]]; then 
     say "尝试在当前会话中加载快捷指令..."
     source /root/.bashrc 2>/dev/null || {
         warn "自动加载失败。请手动运行: source /root/.bashrc"
     }
  fi
  
  say "（下次您只需输入 my 或 MY 即可直接启动菜单）"
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

# ==========================================
#      增强版 IP 自动获取逻辑 (IPv4+IPv6)
# ==========================================
get_public_ipv4() {
  local ip=""
  for url in "https://api.ipify.org" "https://ifconfig.me/ip" "https://ipinfo.io/ip" "https://checkip.amazonaws.com"; do
    ip=$(curl -s --max-time 3 "$url" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)
    if [[ -n "$ip" ]]; then echo "$ip"; return 0; fi
  done
  return 1
}

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

get_public_ipv6() {
  local ip=""
  for url in "https://api64.ipify.org" "https://ifconfig.co/ip" "https://ipv6.icanhazip.com"; do
    ip=$(curl -s -6 --max-time 3 "$url" | grep -Eo '([a-f0-9:]+:+)+[a-f0-9]+' | head -n1)
    if [[ -n "$ip" ]]; then echo "$ip"; return 0; fi
  done
  ip=$(ip -6 addr show scope global 2>/dev/null | grep inet6 | awk '{print $2}' | cut -d/ -f1 | grep -vE '^(fd|fc|fe80)' | head -n1)
  if [[ -n "$ip" ]]; then echo "$ip"; return 0; fi
  return 1
}

GLOBAL_IPV6=$(get_public_ipv6)

# ==========================================

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
    # 非交互式终端：启动服务后退出
    if is_docker || [ "$AUTO_DAEMON" = "1" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Docker 容器环境检测到，强制拉起 sing-box 守护进程"
        /usr/local/bin/sb-singleton --force >/dev/null 2>&1
        
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] sing-box 已启动，实时日志如下（容器不会退出）"
        tail -f /var/log/sing-box.log
    else
        # 非容器环境（例如 SSH 断开后）：确保服务启动，并立即退出脚本进程
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] 非交互环境检测到，启动 sing-box 服务后退出脚本界面"
        /usr/local/bin/sb-singleton --force >/dev/null 2>&1
        disown_temp_tunnel # 清理临时 Argo 进程的元数据
        exit 0 # 立即退出脚本进程，不进入菜单循环
    fi
else
    # 交互式终端：进入主菜单循环
    while true; do main_menu || break; done
fi
disown_temp_tunnel
