#!/usr/bin/env bash
# === Ctrl+C 安全处理 & 守护启动工具 ===
# === Ctrl+C 安全处理（只退菜单，不清理/不杀服务） ===

on_int_menu_quit_only() {
  restart_singbox >/dev/null 2>&1  # 静默重启 sing-box
  trap - EXIT  # 清空 EXIT trap
  exit 0
}
trap on_int_menu_quit_only INT
trap '' SIGHUP 2>/dev/null || true  # 断开终端也不触发退出清理

daemonize() { setsid "$@" </dev/null >/dev/null 2>&1 & }

# 提示用户使用 Bash 运行
if [ -z "$BASH_VERSION" ]; then
  echo "本脚本需要 Bash 解释器，请使用 Bash 运行。"
  exit 1
fi

# ===== 233boy install.sh 全静默执行（一次性） =====
sb233_run_install_silent() {
  set -e
  # --- Sing-box 版本/架构探测（兼容 233 的 /etc/sing-box/bin） ---
  # 让 233 的二进制优先被找到（不改变系统 PATH 的持久配置，仅对本进程生效）
  export PATH="/etc/sing-box/bin:$PATH"

  # 找到 sing-box 的有效路径：优先显式变量、其次 233 路径、然后 PATH，最后从运行进程反查
  resolve_singbox_bin() {
    if [ -n "${SING_BOX_BIN:-}" ] && [ -x "$SING_BOX_BIN" ]; then
      echo "$SING_BOX_BIN"; return 0
    fi
    for p in /etc/sing-box/bin/sing-box /usr/local/bin/sing-box /usr/bin/sing-box; do
      [ -x "$p" ] && echo "$p" && return 0
    done
    if command -v sing-box >/dev/null 2>&1; then
      readlink -f "$(command -v sing-box)"; return 0
    fi
    local pid
    pid="$(pgrep -x sing-box | head -n1 || true)"
    [ -n "$pid" ] && readlink -f "/proc/$pid/exe" 2>/dev/null || true
  }

  # 输出形如：Sing-box 版本: 1.12.0  | 架构: go1.24.5 linux/arm64
  probe_singbox_version_line() {
    local bin ver go arch out meta
    bin="$(resolve_singbox_bin)"
    if [ -z "$bin" ] || [ ! -x "$bin" ]; then
      echo "Sing-box 版本: 未知  | 架构: 未知"
      return
    fi

    out="$("$bin" version 2>/dev/null || true)"

    # 先尝试直接抓语义化版本
    ver="$(printf '%s\n' "$out" | grep -Eo '([0-9]+\.){1,3}[0-9]+' | head -n1)"
    # 兜底：从 'sing-box version X' 这一行取第3列（避免 sed 的 \+ 兼容性）
    [ -z "$ver" ] && ver="$(printf '%s\n' "$out" | awk '/^sing-box[[:space:]]+version[[:space:]]+/ {print $3; exit}')"

    # go 版本与平台
    go="$(printf '%s\n' "$out" | grep -Eo 'go[0-9]+(\.[0-9]+){1,2}' | head -n1)"
    arch="$(printf '%s\n' "$out" | grep -Eo '(linux|darwin|windows)/[a-z0-9_]+' | head -n1)"

    if [ -n "$go" ] || [ -n "$arch" ]; then
      meta="$(printf '%s\n' "$go $arch" | xargs)"
    else
      meta="未知"
    fi

    echo "Sing-box 版本: ${ver:-未知}  | 架构: ${meta}"
  }

  export DEBIAN_FRONTEND=noninteractive
  umask 022

  SB_VER="${SB_VER:-}"  # 可选锁版本
  FLAG_DONE="/etc/sing-box/.sb233_installed"
  FLAG_START="/etc/sing-box/.sb233_installing"
  LOG="/var/log/sb233.install.log"
  URL="https://github.com/233boy/sing-box/raw/main/install.sh"

  # 已完成 -> 直接返回
  [[ -f "$FLAG_DONE" ]] && return 0

  mkdir -p /etc/sing-box /var/log || true
  : > "$LOG" || true

  # 准备下载器（缺啥就静默装）
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      apt-get -yq update >/dev/null 2>&1 || true
      apt-get -yq install curl >/dev/null 2>&1 || apt-get -yq install wget >/dev/null 2>&1 || true
    elif command -v yum >/dev/null 2>&1; then
      yum -y -q install curl >/dev/null 2>&1 || yum -y -q install wget >/dev/null 2>&1 || true
    fi
  fi

  echo "(info) running 233 installer (blocking) ..." >>"$LOG"
  echo "(info) URL=$URL SB_VER=${SB_VER:-latest}" >>"$LOG"

  echo > "$FLAG_START"

  # 前台静默执行，完成后打标记；失败返回非零
  set +e
  if command -v curl >/dev/null 2>&1; then
    if [ -n "$SB_VER" ]; then
      curl -fsSL "$URL" | bash -s -- -v "$SB_VER" >>"$LOG" 2>&1
    else
      curl -fsSL "$URL" | bash -s -- >>"$LOG" 2>&1
    fi
  else
    if [ -n "$SB_VER" ]; then
      wget -qO- "$URL" | bash -s -- -v "$SB_VER" >>"$LOG" 2>&1
    else
      wget -qO- "$URL" | bash -s -- >>"$LOG" 2>&1
    fi
  fi
  rc=$?
  set -e

  rm -f "$FLAG_START" 2>/dev/null || true
  if [ $rc -eq 0 ] && [ -x /etc/sing-box/bin/sing-box ]; then
    touch "$FLAG_DONE"
    echo "(info) 233 installer finished successfully." >>"$LOG"
    return 0
  else
    echo "(warn) 233 installer failed (rc=$rc). Fallback to local installer." >>"$LOG"
    return $rc
  fi
}
# sk5.sh — Sing-box 管理脚本（systemd/OpenRC 自适应）
# 功能：依赖安装、sing-box 安装/自启动、添加/查看/删除节点、脚本服务（检测并修复/升级/重启/重装）、NAT 模式
# 修复：
# - 修正 jq 引号与 -s 用法，避免 “Unix shell quoting issues?”
# - TCP/UDP 自定义端口分别存储 custom_tcp/custom_udp，互不覆盖；删除使用 index() 过滤
# - 移除错误的自调用包装函数，避免递归
# - 当端口池用尽时明确提示；自动选择端口必定输出数字
# - 菜单与提示语符合你的中文文案
umask 022

CONFIG="/etc/sing-box/config.json"
META="/etc/sing-box/nodes_meta.json"
NAT_FILE="/etc/sing-box/nat_ports.json"
LOG_FILE="/var/log/sing-box.log"

DEPS_CHECKED=0  # 新增全局标志，避免重复依赖检查

say()  { printf "%s\n" "$*"; }
err()  { printf " %s\n" "$*" >&2; }
ok()   { printf " %s\n" "$*"; }
warn() { printf " %s\n" "$*" >&2; }
log_msg() {
  local level="$1" msg="$2"
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $msg" >> "$LOG_FILE"
}

# ============= 基础工具 =============
detect_os() {
  if [[ -f /etc/os-release ]]; then . /etc/os-release; echo "$ID"; else echo "unknown"; fi
}

detect_init_system() {
  if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    echo systemd; return
  fi
  if command -v rc-service >/dev/null 2>&1 && [[ -d /run/openrc ]]; then
    echo openrc; return
  fi
  echo unknown
}

is_real_systemd() {
  [[ -d /run/systemd/system ]] && ps -p 1 -o comm= 2>/dev/null | grep -q '^systemd$'
}

is_pseudo_systemd() {
  ps -p 1 -o comm,args= 2>/dev/null | grep -q 'systemctl' && ! is_real_systemd
}

# 工具函数：获取 sing-box 二进制路径/配置路径
_sb_bin() {
  local b="${SING_BOX_BIN:-/usr/local/bin/sing-box}"
  [[ -x "$b" ]] || b="/etc/sing-box/bin/sing-box"
  [[ -x "$b" ]] || b="$(command -v sing-box 2>/dev/null || true)"
  printf "%s" "$b"
}
_sb_cfg() { printf "%s" "${CONFIG:-/etc/sing-box/config.json}"; }

# 任一入站端口开始监听即视为 OK（检测 TCP 监听）
_sb_any_port_listening() {
  local cfg="$(_sb_cfg)"
  [[ -s "$cfg" ]] || return 1
  local any=""
  while read -r p; do
    [[ -z "$p" ]] && continue
    if ss -ltnp 2>/dev/null | grep -q ":$p "; then any=1; break; fi
    timeout 1 bash -lc "echo >/dev/tcp/127.0.0.1/$p" >/dev/null 2>&1 && { any=1; break; }
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
  local need=()
  command -v curl >/dev/null 2>&1    || need+=("curl")
  command -v jq >/dev/null 2>&1      || need+=("jq")
  command -v uuidgen >/dev/null 2>&1 || need+=("uuid-runtime")
  command -v openssl >/dev/null 2>&1 || need+=("openssl")
  command -v ss >/dev/null 2>&1      || need+=("iproute2")
  command -v lsof >/dev/null 2>&1    || need+=("lsof")
  command -v bash >/dev/null 2>&1    || need+=("bash")
  if ((${#need[@]})); then
    case "$(detect_os)" in
      debian|ubuntu)
        printf "\n[等待] 正在更新软件源，请稍候...\n"
        DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
        printf "[等待] 正在安装运行所需依赖，请稍候...\n"
        DEBIAN_FRONTEND=noninteractive apt-get install -y "${need[@]}" >/dev/null 2>&1 || true ;;
      alpine)
        printf "[等待] 正在安装运行所需依赖（Alpine）...\n"
        apk add --no-cache "${need[@]}" >/dev/null 2>&1 || true ;;
      centos|rhel)
        printf "[等待] 正在安装运行所需依赖（CentOS/RHEL）...\n"
        yum install -y "${need[@]}" >/dev/null 2>&1 || true ;;
      fedora)
        printf "[等待] 正在安装运行所需依赖（Fedora）...\n"
        dnf install -y "${need[@]}" >/dev/null 2>&1 || true ;;
      *) warn "未识别系统，请确保安装：${need[*]}" ;;
    esac
  fi
  ok "依赖已满足（curl/jq/uuidgen/openssl/iproute2/lsof）"
}

# —— 新增：逐项确保指定命令可用（按不同发行版安装对应包）——
ensure_cmd() {
  # 用法：ensure_cmd <command> <debian_pkg> <alpine_pkg> <centos_pkg> <fedora_pkg>
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
# —— 新增：在需要用到前“兜底安装”关键依赖（多次调用无副作用）——
ensure_runtime_deps() {
  # curl / jq / uuidgen / openssl / ss / lsof
  ensure_cmd curl     curl        curl        curl        curl
  ensure_cmd jq       jq          jq          jq          jq
  # uuidgen 在 Debian/Ubuntu 提供于 uuid-runtime；在 Alpine 是 util-linux
  ensure_cmd uuidgen  uuid-runtime util-linux util-linux  util-linux
  ensure_cmd openssl  openssl      openssl     openssl     openssl
  # ss 在 Debian/Ubuntu 来自 iproute2；Alpine 也叫 iproute2
  ensure_cmd ss       iproute2     iproute2    iproute    iproute
  ensure_cmd lsof     lsof         lsof        lsof        lsof
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

# 地理信息（失败则 ZZ）
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

# ============= 端口占用检查（TCP监听） =============
port_status() {
  local port="$1"
  local have=0 seen_s=0 seen_o=0
  if command -v ss >/dev/null 2>&1; then
    have=1
    local t=$(ss -ltnp "sport = :$port" 2>/dev/null || true)
    if grep -q LISTEN <<<"$t"; then
      if grep -Eqi 'users:\(\(".*sing-box' <<<"$t"; then seen_s=1; else seen_o=1; fi
    fi
    local u=$(ss -lunp "sport = :$port" 2>/dev/null || true)
    if grep -Eqi 'users:\(\(".*' <<<"$u"; then
      if grep -Eqi 'users:\(\(".*sing-box' <<<"$u"; then seen_s=1; else seen_o=1; fi
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

# 预加载 NAT 数据
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

# 生成自签证书函数
generate_self_signed_cert() {
  local key_file="$1" cert_file="$2" domain="$3"
  umask 077
  openssl ecparam -name prime256v1 -genkey -noout -out "$key_file" 2>/dev/null || \
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$key_file" 2>/dev/null
  openssl req -new -x509 -nodes -key "$key_file" -out "$cert_file" -subj "/CN=$domain" -days 36500 >/dev/null 2>&1
  chmod 600 "$key_file" "$cert_file"
  if [[ -f "$cert_file" && -f "$key_file" ]]; then return 0; else return 1; fi
}

# ============= systemd/OpenRC =============
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

# 合并：系统检测与修复（给出建议并可一键执行）
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

  # 等待用户确认后返回上一层菜单（不退出脚本）
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
    sleep 0.5
  done
  if (( okflag==1 )); then ok "已安装并启用 systemd 自启动服务：sing-box"; return 0; fi

  warn "systemd 服务启动失败，切换为容器友好后台运行（fallback）"
  install_singleton_wrapper
  install_autostart_fallback
  start_singbox_singleton_force

  for i in $(seq 1 20); do
    _sb_any_port_listening && { ok "fallback 已启动 sing-box（后台）"; return 0; }
    sleep 0.5
  done
  err "fallback 启动失败，请检查 $LOG_FILE"
  return 1
}

choose_start_mode() {
  # Allow override: START_MODE=legacy|singleton
  if [[ -n "${START_MODE:-}" ]]; then echo "$START_MODE"; return; fi
  if is_pseudo_systemd; then echo "legacy"; else echo "singleton"; fi
}

ensure_rc_local_template() {
  local rc="/etc/rc.local"
  if [[ ! -f "$rc" ]]; then
    cat > "$rc" <<'RC'
#!/bin/sh -e
sleep 1
/usr/local/bin/sb-singleton >> $LOG_FILE 2>&1 &
exit 0
RC
    chmod +x "$rc"
  else
    grep -q '^#!/bin/sh' "$rc" || sed -i '1i #!/bin/sh -e' "$rc"
    grep -q '^exit 0$' "$rc" || printf '\nexit 0\n' >> "$rc"
    if ! grep -q '/usr/local/bin/sb-singleton' "$rc"; then
      sed -i '/^exit 0/i /usr/local/bin/sb-singleton >> $LOG_FILE 2>&1 &' "$rc"
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

setsid bash -lc "$CMD" >>"$LOG" 2>&1 </dev/null &
echo $! > "$PIDFILE"
exit 0
WRAP
  chmod +x /usr/local/bin/sb-singleton
}

install_autostart_fallback() {
  if [[ -f /etc/alpine-release ]]; then
    # Alpine: 使用 local.d 脚本和 rc-update 确保自启动
    mkdir -p /etc/local.d
    cat > /etc/local.d/sb-singbox.start <<'EOL'
#!/bin/sh
/usr/local/bin/sb-singleton >> $LOG_FILE 2>&1 &
EOL
    chmod +x /etc/local.d/sb-singbox.start
    rc-update add local default >/dev/null 2>&1 || log_msg "WARN" "rc-update failed"
  else
    # 其他系统：使用 rc.local
    ensure_rc_local_template
  fi

  # 添加 Cron 看门狗 (@reboot + 每分钟)，防止进程退出
  if command -v crontab >/dev/null 2>&1; then
    local marker="# sing-box-watchdog"
    crontab -l 2>/dev/null | grep -v "$marker" > /tmp/crontab.tmp 2>/dev/null || true
    echo "* * * * * /usr/local/bin/sb-singleton >/dev/null 2>&1  $marker" >> /tmp/crontab.tmp
    echo "@reboot /usr/local/bin/sb-singleton >/dev/null 2>&1  $marker" >> /tmp/crontab.tmp
    crontab /tmp/crontab.tmp
    rm -f /tmp/crontab.tmp
  fi
}

start_singbox_legacy_nohup() {
  # 使用 setsid 脱离前台会话，避免 Ctrl+C 影响
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

# ============= NAT 规则存取/校验（清爽展示 + 左右分栏菜单） =============
view_nat_ports() {
  if [[ ! -f "$NAT_FILE" ]]; then
    warn "当前未设置 NAT 模式规则"
    return
  fi

  # 颜色（终端支持时启用）
  local BOLD="" C_END="" C_CYAN="" C_GRN="" C_YLW=""
  if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && [[ $(tput colors 2>/dev/null) -ge 8 ]]; then
    BOLD=$'\033[1m'; C_END=$'\033[0m'
    C_CYAN=$'\033[36m'; C_GRN=$'\033[32m'; C_YLW=$'\033[33m'
  fi

  # 网格打印（用 * 指定宽度，避免把变量拼进格式串）
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
  # 分拆打印，彻底规避选项误判
  printf "%s" "$BOLD"; printf "%s" "当前 NAT 模式:"; printf "%s" "$C_END"; printf " %s\n\n" "$mode"

  # 使用预加载数据
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

  # 菜单（同样用 * 指定宽度）
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
      load_nat_data  # 重新加载 NAT 数据
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

# ============= 升级/重装/系统检测与修复 =============
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
    curl -fsSLO "https://github.com/SagerNet/sing-box/releases/download/v${LATEST}/sing-box-${LATEST}-linux-${ARCH}.tar.gz"
    tar -xzf "sing-box-${LATEST}-linux-${ARCH}.tar.gz"
    local init; init=$(detect_init_system)
    [[ "$init" == "systemd" ]] && systemctl stop sing-box || true
    [[ "$init" == "openrc"  ]] && rc-service sing-box stop >/dev/null 2>&1 || true
    install -m 0755 "sing-box-${LATEST}-linux-${ARCH}/sing-box" /usr/local/bin/sing-box
    [[ "$init" == "systemd" ]] && systemctl start sing-box || true
    [[ "$init" == "openrc"  ]] && rc-service sing-box start >/dev/null 2>&1 || true
  ) || { err "升级失败"; return 1; }
  ok "已成功升级为 v${LATEST}"

  # 统一保证更新后重启服务，避免失效
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

      # 停止服务并清理
      systemctl stop sing-box 2>/dev/null
      systemctl disable sing-box 2>/dev/null
      shopt -s nullglob
      for f in /etc/systemd/system/hysteria2*.service; do
        name=$(basename "$f")
        systemctl stop "$name" 2>/dev/null || true
        systemctl disable "$name" 2>/dev/null || true
      done
      shopt -u nullglob
      rm -f /etc/systemd/system/sing-box.service
      rm -f /lib/systemd/system/sing-box.service
      rm -f /etc/systemd/system/hysteria2*.service
      rm -f /lib/systemd/system/hysteria2*.service
      rm -f /usr/local/bin/sing-box /usr/bin/sing-box
      rm -f /usr/local/bin/hysteria /usr/bin/hysteria
      rm -rf /etc/sing-box /var/lib/sing-box /var/log/sing-box /tmp/sing-box*
      rm -rf /etc/hysteria2 /var/lib/hysteria2 /var/log/hysteria2 /tmp/hysteria2*
      rm -f "$META"
      apt-get clean
      systemctl daemon-reload

      say " Sing-box、Hysteria2 已完全卸载"

      # 删除当前脚本文件
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
    # 重新安装后，确保服务被正确安装并重启
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
  if [[ -n "${SB233_FAILED:-}" || ! -x /etc/sing-box/bin/sing-box ]]; then
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
      sleep 0.5
    done
    if (( okflag==1 )); then ok "Sing-box 重启完成（systemd）"; return 0; fi
    warn "当前环境虽有 systemctl，但重启失败；切换 fallback 后台运行"
  elif command -v rc-service >/dev/null 2>&1 && [[ -f /etc/init.d/sing-box ]]; then
    # OpenRC 环境：使用 rc-service 重启
    rc-service sing-box restart >/dev/null 2>&1 || rc-service sing-box start >/dev/null 2>&1 || log_msg "WARN" "rc-service failed"
    local okflag=0
    for i in $(seq 1 30); do
      rc-service sing-box status 2>/dev/null | grep -q started && { okflag=1; break; }
      _sb_any_port_listening && { okflag=1; break; }
      sleep 0.5
    done
    if (( okflag==1 )); then ok "Sing-box 重启完成（OpenRC）"; return 0; fi
    warn "OpenRC 服务重启失败；切换 fallback 后台运行"
  fi

  pkill -9 -f "$bin run -c $cfg" 2>/dev/null || true
  pkill -9 -x sing-box 2>/dev/null || true
  install_singleton_wrapper
  install_autostart_fallback
  start_singbox_singleton_force

  for i in $(seq 1 30); do
    _sb_any_port_listening && { ok "Sing-box 重启完成（fallback 后台）"; return 0; }
    sleep 0.5
  done
  err "Sing-box 重启失败（fallback 也未监听），请查看 $LOG_FILE"
  return 1
}


# ============= 节点操作（含 NAT 端口约束） =============
add_node() {
# 进入添加节点前，再次兜底确保依赖完整
ensure_runtime_deps
  while true; do
    say "请选择协议类型："
    say "0) 返回主菜单"
    say "1) SOCKS5"
    say "2) VLESS-REALITY"
    say "3) Hysteria2"
    read -rp "输入协议编号（默认 1，输入 0 返回）: " proto
    proto=${proto:-1}
    [[ "$proto" == "0" ]] && return
    [[ "$proto" =~ ^[123]$ ]] && break
    warn "无效输入"
  done

  if [[ "$proto" == "3" ]]; then
    add_hysteria2_node || return 1
    return
  elif [[ "$proto" == "2" ]]; then
    # VLESS (TCP 语义端口)
    if ! command -v sing-box >/dev/null 2>&1; then
      err "未检测到 sing-box，无法生成 Reality 密钥。请先在“脚本服务”里重装/安装。"
      return 1
    fi
    local port proto_type="tcp"
    while true; do
      if [[ -n "$nat_mode" ]]; then
        [[ "$nat_mode" == "custom" ]] && say "已启用自定义端口模式：VLESS 仅允许使用 自定义TCP端口 集合"
        [[ "$nat_mode" == "range"  ]] && say "已启用范围端口模式：VLESS 仅允许使用 范围内端口"
      fi
      read -rp "请输入端口号（留空自动挑选允许端口；输入 0 返回）: " port
      if [[ -z "$port" ]]; then
        port=$(get_random_allowed_port "$proto_type")
        [[ "$port" == "NO_PORT" ]] && { err "无可用端口"; return 1; }
        say "（已自动选择随机端口：$port）"
      fi
      [[ "$port" == "0" ]] && return
      [[ "$port" =~ ^[0-9]+$ ]] && ((port>=1 && port<=65535)) || { warn "端口无效"; continue; }
      (( port < 1024 )) && warn "端口<1024可能需root权限"
      if ! check_nat_allow "$port" "$proto_type"; then warn "端口 $port 不符合 NAT 规则（协议: $proto_type）"; continue; fi
      if jq -e --argjson p "$port" '.inbounds[] | select(.listen_port == $p)' "$CONFIG" >/dev/null 2>&1; then warn "端口 $port 已存在"; continue; fi
      if jq -e --argjson p "$port" 'to_entries[]? | select(.value.type=="hysteria2" and .value.port == $p)' "$META" >/dev/null 2>&1; then warn "端口 $port 已被 Hysteria2 使用"; continue; fi
      break
    done

    local uuid fp flow server_name key_pair private_key public_key short_id tag tmpcfg
    if command -v uuidgen >/dev/null 2>&1; then uuid=$(uuidgen); else uuid=$(openssl rand -hex 16 | sed 's/\(..\)/\1/g; s/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/'); fi
    server_name="www.cloudflare.com"
    flow="xtls-rprx-vision"
    case $((RANDOM%5)) in 0) fp="chrome";; *) fp="firefox";; esac

    key_pair=$(sing-box generate reality-keypair 2>/dev/null)
    private_key=$(awk -F': ' '/PrivateKey/{print $2}' <<<"$key_pair")
    public_key=$(awk -F': ' '/PublicKey/{print $2}' <<<"$key_pair")
    [[ -z "$private_key" || -z "$public_key" ]] && { err "生成 Reality 密钥失败"; return 1; }
    short_id=$(openssl rand -hex 4)
    tag=$(generate_unique_tag)

    tmpcfg=$(mktemp)
    trap 'rm -f "$tmpcfg"' EXIT
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

    local tmpmeta; tmpmeta=$(mktemp)
    trap 'rm -f "$tmpmeta"' EXIT
    jq --arg tag "$tag" --arg pbk "$public_key" --arg sid "$short_id" --arg sni "$server_name" --arg port "$port" --arg fp "$fp" \
      '. + {($tag): {pbk:$pbk, sid:$sid, sni:$sni, port:$port, fp:$fp}}' "$META" >"$tmpmeta" && mv "$tmpmeta" "$META"

    say ""; ok "添加成功：VLESS Reality"
    say "端口: $port"
    say "UUID: $uuid"
    say "Public Key: $public_key"
    say "Short ID: $short_id"
    say "SNI: $server_name"
    say "Fingerprint: $fp"
    say "TAG: $tag"
    say ""
    say " 客户端链接："
    say "vless://${uuid}@${GLOBAL_IPV4}:${port}?encryption=none&flow=${flow}&type=tcp&security=reality&pbk=${public_key}&sid=${short_id}&sni=${server_name}&fp=${fp}#${tag}"
    say ""
    return
  else
    # SOCKS5 (TCP 语义端口)
    local port user pass tag tmpcfg proto_type="tcp"
    while true; do
      if [[ -n "$nat_mode" ]]; then
        [[ "$nat_mode" == "custom" ]] && say "已启用自定义端口模式：SOCKS5 仅允许使用 自定义TCP端口 集合"
        [[ "$nat_mode" == "range"  ]] && say "已启用范围端口模式：SOCKS5 仅允许使用 范围内端口"
      fi
      read -rp "请输入端口号（留空自动挑选允许端口；输入 0 返回）: " port
      if [[ -z "$port" ]]; then
        port=$(get_random_allowed_port "$proto_type")
        [[ "$port" == "NO_PORT" ]] && { err "无可用端口"; return 1; }
        say "（已自动选择随机端口：$port）"
      fi
      [[ "$port" == "0" ]] && return
      [[ "$port" =~ ^[0-9]+$ ]] && ((port>=1 && port<=65535)) || { warn "端口无效"; continue; }
      (( port < 1024 )) && warn "端口<1024可能需root权限"
      if ! check_nat_allow "$port" "$proto_type"; then warn "端口 $port 不符合 NAT 规则（协议: $proto_type）"; continue; fi
      if jq -e --argjson p "$port" '.inbounds[] | select(.listen_port == $p)' "$CONFIG" >/dev/null 2>&1; then warn "端口 $port 已存在"; continue; fi
      if jq -e --argjson p "$port" 'to_entries[]? | select(.value.type=="hysteria2" and .value.port == $p)' "$META" >/dev/null 2>&1; then warn "端口 $port 已被 Hysteria2 使用"; continue; fi
      break
    done
    read -rp "请输入用户名（默认 user）: " user; user=${user:-user}
    read -rp "请输入密码（默认 pass123）: " pass; pass=${pass:-pass123}
    tag="sk5-$(get_country_code)-$(tr -dc 'A-Z' </dev/urandom | head -c1)"

    tmpcfg=$(mktemp)
    trap 'rm -f "$tmpcfg"' EXIT
    jq --arg port "$port" --arg user "$user" --arg pass "$pass" --arg tag "$tag" \
      '.inbounds += [{"type":"socks","tag":$tag,"listen":"::","listen_port":($port|tonumber),"users":[{"username":$user,"password":$pass}]}]' \
      "$CONFIG" >"$tmpcfg" && mv "$tmpcfg" "$CONFIG"

    say " 正在校验配置..."
    if sing-box check -c "$CONFIG" >/dev/null 2>&1; then
      ok "配置通过，正在重启..."
      restart_singbox || { err "重启失败"; return 1; }
    else
      err "配置校验失败"; sing-box check -c "$CONFIG"; return 1
    fi

    say ""; ok "添加成功：SOCKS5"
    say "端口: $port"
    say "用户名: $user"
    say "密码: $pass"
    say "TAG: $tag"
    say ""
    say " 客户端链接："
    local creds; creds=$(printf "%s" "$user:$pass" | base64)
    say "IPv4: socks://${creds}@${GLOBAL_IPV4}:${port}#${tag}"
    [[ -n "$GLOBAL_IPV6" ]] && say "IPv6: socks://${creds}@[${GLOBAL_IPV6}]:${port}#${tag}"
    say ""
  fi
}

add_hysteria2_node() {
  local port proto_type="udp"
  ensure_runtime_deps
  while true; do
    if [[ -n "$nat_mode" ]]; then
      [[ "$nat_mode" == "custom" ]] && say "已启用自定义端口模式：Hysteria2 仅允许使用 自定义UDP端口 集合"
      [[ "$nat_mode" == "range"  ]] && say "已启用范围端口模式：Hysteria2 仅允许使用 范围内端口"
    fi
    read -rp "请输入端口号（留空自动挑选允许端口；输入 0 返回）: " port
    if [[ -z "$port" ]]; then
      port=$(get_random_allowed_port "$proto_type")
      [[ "$port" == "NO_PORT" ]] && { err "无可用端口"; return 1; }
      say "（已自动选择随机端口：$port）"
    fi
    [[ "$port" == "0" ]] && return
    [[ "$port" =~ ^[0-9]+$ ]] && ((port>=1 && port<=65535)) || { warn "端口无效"; continue; }
    (( port < 1024 )) && warn "端口<1024可能需root权限"
    if ! check_nat_allow "$port" "$proto_type"; then warn "端口 $port 不符合 NAT 规则（协议: $proto_type）"; continue; fi
    if jq -e --argjson p "$port" '.inbounds[] | select(.listen_port == $p)' "$CONFIG" >/dev/null 2>&1; then warn "端口 $port 已被 sing-box 使用"; continue; fi
    if jq -e --argjson p "$port" 'to_entries[]? | select(.value.type=="hysteria2" and .value.port == $p)' "$META" >/dev/null 2>&1; then warn "端口 $port 已存在"; continue; fi
    break
  done

  local domain="bing.com"

  if ! command -v hysteria >/dev/null 2>&1; then
    warn "未检测到 hysteria，正在安装..."
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
    ok "hysteria 安装完成"
  fi

  mkdir -p /etc/hysteria2

  generate_self_signed_cert "/etc/hysteria2/${port}.key" "/etc/hysteria2/${port}.crt" "$domain" || { err "自签证书生成失败"; return 1; }

  local auth_pwd obfs_pwd
  auth_pwd=$(openssl rand -base64 16 | tr -d '=+/' | cut -c1-16)
  obfs_pwd=$(openssl rand -base64 8 | tr -d '=+/' | cut -c1-8)

  local tag="hysteria2-$(get_country_code)-$(tr -dc 'A-Z' </dev/urandom | head -c1)"
  if jq -e --arg t "$tag" '.inbounds[] | select(.tag == $t)' "$CONFIG" >/dev/null 2>&1 || jq -e --arg t "$tag" 'has($t)' "$META" >/dev/null 2>&1; then
    tag="hysteria2-$(get_country_code)-$(date +%s)"
  fi

  cat > /etc/hysteria2/${port}.yaml <<EOF
listen: ":${port}"
tls:
  cert: /etc/hysteria2/${port}.crt
  key: /etc/hysteria2/${port}.key
obfs:
  type: salamander
  salamander:
    password: ${obfs_pwd}
auth:
  type: password
  password: ${auth_pwd}
masquerade:
  type: proxy
  proxy:
    url: https://${domain}
    rewriteHost: true
    insecure: true
EOF

  cat > /etc/systemd/system/hysteria2-${port}.service <<EOF
[Unit]
Description=Hysteria2 Service (${port})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria2/${port}.yaml
Restart=always
RestartSec=3s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload >/dev/null 2>&1 || log_msg "WARN" "daemon-reload failed"
  systemctl enable hysteria2-${port}.service >/dev/null 2>&1 || log_msg "WARN" "enable hysteria2-${port} failed"
  systemctl restart hysteria2-${port}.service >/dev/null 2>&1 || log_msg "WARN" "restart hysteria2-${port} failed"

  sleep 1
  if systemctl is-active --quiet hysteria2-${port}; then ok "Hysteria2 服务已启动"
  else err "Hysteria2 服务启动失败，请检查日志 (journalctl -u hysteria2-${port})"; return 1; fi

  local tmpmeta; tmpmeta=$(mktemp)
  trap 'rm -f "$tmpmeta"' EXIT
  jq --arg tag "$tag" --arg port "$port" --arg sni "$domain" --arg obfs "$obfs_pwd" --arg auth "$auth_pwd" \
    '. + {($tag): {type:"hysteria2", port:$port, sni:$sni, obfs:$obfs, auth:$auth}}' "$META" >"$tmpmeta" && mv "$tmpmeta" "$META"

  say ""; ok "添加成功：Hysteria2"
  say "端口: $port"
  say "Auth密码: $auth_pwd"
  say "Obfs密码: $obfs_pwd"
  say "SNI域名: $domain"
  say "TAG: $tag"
  say ""
  say " 客户端链接："
  [[ -n "$GLOBAL_IPV4" ]] && say "hysteria2://${auth_pwd}@${GLOBAL_IPV4}:${port}?obfs=salamander&obfs-password=${obfs_pwd}&sni=${domain}&insecure=1#${tag}"
  [[ -n "$GLOBAL_IPV6" ]] && say "hysteria2://${auth_pwd}@[${GLOBAL_IPV6}]:${port}?obfs=salamander&obfs-password=${obfs_pwd}&sni=${domain}&insecure=1#${tag}"
  say ""
}

view_nodes() {
  set +e
  local total ext_count
  total=$(jq '.inbounds | length' "$CONFIG" 2>/dev/null || echo "0")
  ext_count=$(jq '[to_entries[] | select(.value.type=="hysteria2")] | length' "$META" 2>/dev/null || echo "0")
  if [[ ( -z "$total" || "$total" == "0" ) && ( -z "$ext_count" || "$ext_count" == "0" ) ]]; then say "暂无节点"; set -e; return; fi

  declare -A node_ports node_types node_tags node_uuids node_users node_passes node_pbks node_sids node_snis node_fps
  local idx=0
  while read -r line; do
    local tag port type uuid user pass
    tag=$(jq -r '.tag' <<<"$line")
    port=$(jq -r '.listen_port' <<<"$line")
    type=$(jq -r '.type' <<<"$line")
    uuid=$(jq -r '.users[0].uuid // empty' <<<"$line")
    user=$(jq -r '.users[0].username // empty' <<<"$line")
    pass=$(jq -r '.users[0].password // empty' <<<"$line")
    node_tags[$idx]="$tag"
    node_ports[$idx]="$port"
    node_types[$idx]="$type"
    node_uuids[$idx]="$uuid"
    node_users[$idx]="$user"
    node_passes[$idx]="$pass"
    node_pbks[$idx]=$(jq -r --arg t "$tag" '.[$t].pbk // empty' "$META")
    node_sids[$idx]=$(jq -r --arg t "$tag" '.[$t].sid // empty' "$META")
    node_snis[$idx]=$(jq -r --arg t "$tag" '.[$t].sni // empty' "$META")
    node_fps[$idx]=$(jq -r --arg t "$tag" '.[$t].fp // "chrome"' "$META")
    idx=$((idx+1))
  done < <(jq -c '.inbounds[]' "$CONFIG" 2>/dev/null)

  if [[ $ext_count -gt 0 ]]; then
    while read -r line; do
      local tag port auth obfs sni
      tag=$(jq -r '.key' <<<"$line")
      port=$(jq -r '.value.port // empty' <<<"$line")
      auth=$(jq -r '.value.auth // empty' <<<"$line")
      obfs=$(jq -r '.value.obfs // empty' <<<"$line")
      sni=$(jq -r '.value.sni // empty' <<<"$line")
      node_tags[$idx]="$tag"
      node_ports[$idx]="$port"
      node_types[$idx]="hysteria2"
      node_uuids[$idx]=""
      node_users[$idx]=""
      node_passes[$idx]="$auth"
      node_pbks[$idx]=""
      node_sids[$idx]=""
      node_snis[$idx]="$sni"
      node_fps[$idx]=""
      node_obfs[$idx]="$obfs"
      idx=$((idx+1))
    done < <(jq -c 'to_entries[] | select(.value.type=="hysteria2")' "$META" 2>/dev/null)
  fi

  local ss_tcp=$(ss -ltnp 2>/dev/null || true)
  local ss_udp=$(ss -lunp 2>/dev/null || true)

  idx=0
  while (( idx < total + ext_count )); do
    local port="${node_ports[$idx]}" tag="${node_tags[$idx]}" type="${node_types[$idx]}"
    say "[$((idx+1))] 端口: $port | 协议: $type | 名称: $tag"
    if grep -q ":$port " <<<"$ss_tcp" || grep -q ":$port " <<<"$ss_udp"; then
      : # OK
    else
      warn "端口 $port 未监听"
    fi
    if [[ "$type" == "vless" ]]; then
      local uuid="${node_uuids[$idx]}" pbk="${node_pbks[$idx]}" sid="${node_sids[$idx]}" sni="${node_snis[$idx]}" fp="${node_fps[$idx]}"
      if [[ -n "$pbk" && -n "$sid" && -n "$sni" ]]; then
        say "vless://${uuid}@${GLOBAL_IPV4}:${port}?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&pbk=${pbk}&sid=${sid}&sni=${sni}&fp=${fp}#${tag}"
      else
        warn "节点参数不完整，无法生成链接"
      fi
    elif [[ "$type" == "socks" ]]; then
      local user="${node_users[$idx]}" pass="${node_passes[$idx]}" encoded
      encoded=$(printf "%s" "$user:$pass" | base64)
      say "IPv4: socks://${encoded}@${GLOBAL_IPV4}:${port}#${tag}"
      [[ -n "$GLOBAL_IPV6" ]] && say "IPv6: socks://${encoded}@[${GLOBAL_IPV6}]:${port}#${tag}"
    elif [[ "$type" == "hysteria2" ]]; then
      local auth="${node_passes[$idx]}" obfs="${node_obfs[$idx]}" sni="${node_snis[$idx]}"
      if [[ -n "$auth" && -n "$obfs" && -n "$sni" ]]; then
        say "hysteria2://${auth}@${GLOBAL_IPV4}:${port}?obfs=salamander&obfs-password=${obfs}&sni=${sni}&insecure=1#${tag}"
        [[ -n "$GLOBAL_IPV6" ]] && say "hysteria2://${auth}@[${GLOBAL_IPV6}]:${port}?obfs=salamander&obfs-password=${obfs}&sni=${sni}&insecure=1#${tag}"
      else
        warn "节点参数不完整，无法生成链接"
      fi
    fi
    say "---------------------------------------------------"
    idx=$((idx+1))
  done
  set -e
}

delete_node() {
  local count; count=$(jq '.inbounds | length' "$CONFIG" 2>/dev/null)
  local ext_count; ext_count=$(jq '[to_entries[] | select(.value.type=="hysteria2")] | length' "$META" 2>/dev/null)
  if [[ ( -z "$count" || "$count" == "0" ) && ( -z "$ext_count" || "$ext_count" == "0" ) ]]; then say "暂无节点"; return; fi
  view_nodes
  say "[0] 返回主菜单"
  say "[ss] 删除所有节点"
  read -rp "请输入要删除的节点序号： " idx
  [[ "$idx" == "0" || -z "$idx" ]] && return
  if [[ "$idx" == "ss" ]]; then
    read -rp " 确认删除全部节点？(y/N): " c; [[ "$c" == "y" ]] || { say "已取消"; return; }
    local tmpcfg; tmpcfg=$(mktemp)
    trap 'rm -f "$tmpcfg"' EXIT
    jq '.inbounds = []' "$CONFIG" >"$tmpcfg" && mv "$tmpcfg" "$CONFIG"
    printf '{}' >"$META"
    shopt -s nullglob
    for f in /etc/systemd/system/hysteria2*.service; do
      name=$(basename "$f")
      systemctl disable --now "$name" >/dev/null 2>&1 || true
      rm -f "$f"
    done
    shopt -u nullglob
    systemctl daemon-reload || log_msg "WARN" "daemon-reload failed"
    rm -rf /etc/hysteria2
    ok "所有节点已删除"; return
  fi
  if ! [[ "$idx" =~ ^[0-9]+$ ]]; then warn "无效输入"; return; fi
  local idx0=$((idx-1))
  if (( idx0 < 0 || idx0 >= (count + ext_count) )); then warn "序号越界"; return; fi

  if (( idx0 >= count )); then
    local ext_index=$((idx0 - count))
    local tag_to_delete; tag_to_delete=$(jq -r --argjson i "$ext_index" 'to_entries | map(select(.value.type=="hysteria2")) | .[$i].key // empty' "$META")
    if [[ -n "$tag_to_delete" && "$tag_to_delete" != "null" ]]; then
      local port_del; port_del=$(jq -r --arg t "$tag_to_delete" '.[$t].port // empty' "$META")
      local tmpmeta; tmpmeta=$(mktemp)
      trap 'rm -f "$tmpmeta"' EXIT
      jq "del(.\"$tag_to_delete\")" "$META" >"$tmpmeta" && mv "$tmpmeta" "$META"
      if [[ -f "/etc/systemd/system/hysteria2-${port_del}.service" ]]; then
        systemctl disable --now "hysteria2-${port_del}" >/dev/null 2>&1 || true
        rm -f "/etc/systemd/system/hysteria2-${port_del}.service"
      fi
      systemctl daemon-reload || log_msg "WARN" "daemon-reload failed"
      [[ -n "$port_del" ]] && rm -f "/etc/hysteria2/${port_del}.yaml" "/etc/hysteria2/${port_del}.key" "/etc/hysteria2/${port_del}.crt"
      ok "已删除节点 [$idx]"
      return
    fi
  fi
  local tag; tag=$(jq -r ".inbounds[$idx0].tag // empty" "$CONFIG")
  local tmpcfg; tmpcfg=$(mktemp)
  trap 'rm -f "$tmpcfg"' EXIT
  jq "del(.inbounds[$idx0])" "$CONFIG" >"$tmpcfg" && mv "$tmpcfg" "$CONFIG"
  if [[ -n "$tag" && "$tag" != "null" ]]; then
    local tmpmeta; tmpmeta=$(mktemp)
    trap 'rm -f "$tmpmeta"' EXIT
    jq "del(.\"$tag\")" "$META" >"$tmpmeta" && mv "$tmpmeta" "$META"
  fi
  ok "已删除节点 [$idx]"
}

is_docker() {
  # 检查 /.dockerenv 文件（Docker 容器默认会有）
  if [ -f /.dockerenv ]; then
    return 0
  fi

  # 检查 cgroup 信息（Docker 容器的 cgroup 通常包含 docker）
  if grep -qE "/docker/|/lxc/" /proc/1/cgroup 2>/dev/null; then
    return 0
  fi

  return 1
}

# 获取系统信息
OS_NAME=$(lsb_release -si 2>/dev/null || grep '^ID=' /etc/os-release | cut -d= -f2)
OS_VER=$(lsb_release -sr 2>/dev/null || grep '^VERSION_ID=' /etc/os-release | cut -d= -f2 | tr -d '"')

# 检测 docker 并显示
if is_docker; then
  SYSTEM_INFO="$OS_NAME（docker）"
else
  SYSTEM_INFO="$OS_NAME"
fi

echo "系统: $SYSTEM_INFO"

show_version_info() {
  local OS OS_NAME VIRT
  OS=$(detect_os)
  if [[ "$OS" == "unknown" ]]; then
    OS_NAME="未知"
  else
    OS_NAME="${OS^}"
  fi

  # 检测虚拟化类型
  if command -v systemd-detect-virt >/dev/null 2>&1; then
    VIRT=$(systemd-detect-virt)
    if [[ "$VIRT" != "none" && -n "$VIRT" ]]; then
      OS_NAME="${OS_NAME}（${VIRT}）"
    fi
  else
    # Docker/LXC 兜底检测
    if [[ -f /.dockerenv ]] || grep -qE "/docker/|/lxc/" /proc/1/cgroup 2>/dev/null; then
      OS_NAME="${OS_NAME}（docker）"
    fi
  fi

  SINGBOX_BIN=$(command -v sing-box || echo "/usr/local/bin/sing-box")
  if [[ -x "$SINGBOX_BIN" ]]; then
    VER=$($SINGBOX_BIN version 2>/dev/null | head -n1 | awk '{print $NF}')
    ENV=$($SINGBOX_BIN version 2>/dev/null | awk -F'Environment: ' '/Environment:/{print $2}')
    say "Sing-box 版本: ${VER:-未知}  | 架构: ${ENV:-未知}  | 系统: ${OS_NAME}"
  else
    say "Sing-box 版本: 未知  | 架构: 未知  | 系统: ${OS_NAME}"
  fi
}

# ============= 脚本服务菜单 =============
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

# ============= 主菜单 =============
main_menu() {
  say ""
  show_version_info
  say "============= 嘻嘻哈哈 节点管理工具（IPv4 + IPv6） ============="
  say "1) 添加节点"
  say "2) 查看所有节点"
  say "3) 删除节点"
  say "4) 脚本服务"
  say "5) NAT 模式设置"
  say "0) 退出"
  say "==============================================================="
  read -rp "请输入操作编号: " choice
  case "$choice" in
    1) add_node ;;
    2) view_nodes ;;
    3) delete_node ;;
    4) script_services_menu ;;
    5) nat_mode_menu ;;
    0) exit 0 ;;
    *) warn "无效输入" ;;
  esac
}

# ============= 启动入口 =============
# export SB_VER=1.12.0   # 如需锁定版本
sb233_run_install_silent || true

ensure_dirs
install_dependencies
if [[ -n "${SB233_FAILED:-}" || ! -x /etc/sing-box/bin/sing-box ]]; then
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
    # 对于伪 systemd 或无 init 的容器环境，使用 fallback 后台运行
    install_singleton_wrapper
    install_autostart_fallback
    install_logrotate
    install_watchdog_cron
    # 立即启动
    start_singbox_legacy_nohup
    ;;
esac

GLOBAL_IPV4=$(curl -s --max-time 2 https://api.ipify.org || echo "<服务器IP>")
GLOBAL_IPV6=$(get_ipv6_address)

load_nat_data

trap on_int_menu_quit_only INT
while true; do main_menu; done
