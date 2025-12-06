#!/usr/bin/env bash
# core.sh - 核心功能库 (由 sk5.sh 调用)
# 🚀 代码大师重构版：逻辑与界面分离

export LC_ALL=C

# ============= 全局变量与配置 =============
ARGO_TEMP_CACHE="/root/agsbx/jh.txt"
ARGO_FIXED_CACHE="/root/agsbx/gd.txt"
ARGO_META_TAG_PREFIX="Argo-"
CONFIG="/etc/sing-box/config.json"
META="/etc/sing-box/nodes_meta.json"
NAT_FILE="/etc/sing-box/nat_ports.json"
LOG_FILE="/var/log/sing-box.log"
DEPS_CHECKED=0
_OS_CACHE=""
_INIT_SYS_CACHE=""

# 颜色定义
C_RESET='\033[0m'
C_GREEN='\033[32m'
C_YELLOW='\033[33m'
C_CYAN='\033[36m'
C_RED='\033[31m'

# ============= 基础检测函数 =============
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

is_docker() {
  if [ -f /.dockerenv ]; then return 0; fi
  if grep -qE "/docker/|/lxc/" /proc/1/cgroup 2>/dev/null; then return 0; fi
  return 1
}

# ============= 工具函数 =============
say()  { printf "%s\n" "$*"; }
err()  { printf " %s\n" "$*" >&2; }
ok()   { printf " %s\n" "$*" >&2; }
warn() { printf " %s\n" "$*" >&2; }
log_msg() {
  local level="$1" msg="$2"
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $msg" >> "$LOG_FILE"
}

print_card() {
  local title="$1" name="$2" info="$3" link="$4"
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

daemonize() { setsid "$@" </dev/null >/dev/null 2>&1 & }

resolve_service_cmd() {
  local cmd="$1"
  if command -v "$cmd" >/dev/null 2>&1; then readlink -f "$(command -v "$cmd")"; return 0; fi
  for p in /usr/bin/"$cmd" /bin/"$cmd" /sbin/"$cmd"; do [ -x "$p" ] && echo "$p" && return 0; done
  return 1
}
_SYSTEMCTL_CMD="$(resolve_service_cmd systemctl || true)"

# ============= 进程与端口管理 =============
disown_temp_tunnel() {
  local TEMP_ARGO_DIR="/root/agsbx/temp_node"
  local TEMP_PID_FILE="$TEMP_ARGO_DIR/temp_cloudflared.pid"
  local TEMP_XRAY_PID_FILE="$TEMP_ARGO_DIR/temp_xray.pid"  
  
  if [[ -f "$TEMP_PID_FILE" ]]; then local cfd_pid=$(cat "$TEMP_PID_FILE" 2>/dev/null); else local cfd_pid=$(pgrep -f "$TEMP_ARGO_DIR/cloudflared_temp" | head -n 1); fi
  if [ -n "$cfd_pid" ] && ps -p "$cfd_pid" >/dev/null 2>&1; then disown "$cfd_pid" 2>/dev/null || true; fi
  
  if [[ -f "$TEMP_XRAY_PID_FILE" ]]; then local xray_pid=$(cat "$TEMP_XRAY_PID_FILE" 2>/dev/null); else local xray_pid=$(pgrep -f "$TEMP_ARGO_DIR/xray_temp" | head -n 1); fi
  if [ -n "$xray_pid" ] && ps -p "$xray_pid" >/dev/null 2>&1; then disown "$xray_pid" 2>/dev/null || true; fi
  
  rm -f "$TEMP_PID_FILE" "$TEMP_XRAY_PID_FILE"
  return 0
}

on_int_menu_quit_only() {
  disown_temp_tunnel 
  restart_singbox >/dev/null 2>&1
  trap - EXIT
  echo ""
  exit 0
}

_sb_bin() {
  local b="${SING_BOX_BIN:-/usr/local/bin/sing-box}"
  [[ -x "$b" ]] || b="/etc/sing-box/bin/sing-box"
  [[ -x "$b" ]] || b="$(command -v sing-box 2>/dev/null || true)"
  printf "%s" "$b"
}
_sb_cfg() { printf "%s" "${CONFIG:-/etc/sing-box/config.json}"; }

_sb_any_port_listening() {
  local cfg="$(_sb_cfg)"
  [[ -s "$cfg" ]] || return 1
  local ss_out=$(ss -ltnp 2>/dev/null)
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

# ============= 依赖安装 =============
ensure_cmd() {
  local cmd="$1" deb="$2" alp="$3" cen="$4" fed="$5"
  command -v "$cmd" >/dev/null 2>&1 && return 0
  case "$(detect_os)" in
    debian|ubuntu)
      DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
      DEBIAN_FRONTEND=noninteractive apt-get install -y "$deb" >/dev/null 2>&1 || true ;;
    alpine) apk add --no-cache "$alp" >/dev/null 2>&1 || true ;;
    centos|rhel) yum install -y "$cen" >/dev/null 2>&1 || true ;;
    fedora) dnf install -y "$fed" >/dev/null 2>&1 || true ;;
    *) warn "未识别系统，请手动安装：$cmd" ;;
  esac
}

install_dependencies() {
  if (( DEPS_CHECKED == 1 )); then return 0; fi
  ensure_cmd curl     curl        curl        curl        curl
  ensure_cmd jq       jq          jq          jq          jq
  ensure_cmd uuidgen  uuid-runtime util-linux util-linux  util-linux
  ensure_cmd openssl  openssl      openssl     openssl     openssl
  ensure_cmd ss       iproute2     iproute2    iproute    iproute
  ensure_cmd lsof     lsof         lsof        lsof        lsof
  DEPS_CHECKED=1
}
ensure_runtime_deps() { install_dependencies; }

install_singbox_if_needed() {
  if command -v sing-box >/dev/null 2>&1; then return 0; fi
  warn "未检测到 sing-box，正在安装..."
  
  # CA 证书修复
  if [[ ! -f /etc/ssl/certs/ca-certificates.crt ]]; then
      if command -v apk >/dev/null 2>&1; then apk add --no-cache ca-certificates; update-ca-certificates 2>/dev/null;
      elif command -v apt-get >/dev/null 2>&1; then apt-get update -y; apt-get install -y ca-certificates; update-ca-certificates;
      elif command -v yum >/dev/null 2>&1; then yum install -y ca-certificates; fi
  fi

  local VERSION="1.12.0"
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
    local FILE="sing-box-${VERSION}-linux-${arch}.tar.gz"
    local URL="https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/${FILE}"
    if ! curl -fL -o "$FILE" "$URL"; then curl -fL -o "$FILE" "https://ghproxy.com/${URL}"; fi
    tar -xzf "$FILE"
    install -m 0755 "sing-box-${VERSION}-linux-${arch}/sing-box" /usr/local/bin/sing-box
  ) || { err "安装 sing-box 失败"; return 1; }
  ok "sing-box 安装完成"
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
    if ! curl -fL -o "$FILE" "$URL"; then curl -fL -o "$FILE" "https://ghproxy.com/${URL}"; fi
    tar -xzf "$FILE"
    local init; init=$(detect_init_system)
    [[ "$init" == "systemd" ]] && systemctl stop sing-box || true
    [[ "$init" == "openrc"  ]] && rc-service sing-box stop >/dev/null 2>&1 || true
    install -m 0755 "sing-box-${LATEST}-linux-${ARCH}/sing-box" /usr/local/bin/sing-box
    [[ "$init" == "systemd" ]] && systemctl start sing-box || true
    [[ "$init" == "openrc"  ]] && rc-service sing-box start >/dev/null 2>&1 || true
  ) || { err "升级失败"; return 1; }
  ok "已成功升级为 v${LATEST}"
  restart_singbox
}

# ============= 网络与端口辅助 =============
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
    if [[ $try -ge 26 ]]; then printf "%s-%s\n" "$base" "$(date +%s)"; return; fi
  done
}

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
    else echo $((RANDOM%1000 + 30000))
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
  else return 0; fi
}

# ============= 服务与自启管理 =============
generate_self_signed_cert() {
  local key_file="$1" cert_file="$2" domain="$3"
  umask 077
  openssl ecparam -name prime256v1 -genkey -noout -out "$key_file" 2>/dev/null || \
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$key_file" 2>/dev/null
  openssl req -new -x509 -nodes -key "$key_file" -out "$cert_file" -subj "/CN=$domain" -days 36500 >/dev/null 2>&1
  chmod 600 "$key_file" "$cert_file"
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
depend() { need net; after firewall; }
start_pre() { /usr/local/bin/sing-box check -c /etc/sing-box/config.json || return 1; }
EOF
  chmod +x /etc/init.d/sing-box
  rc-update add sing-box default >/dev/null 2>&1 || true
  rc-service sing-box restart >/dev/null 2>&1 || rc-service sing-box start >/dev/null 2>&1
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
  for i in $(seq 1 20); do
    systemctl is-active --quiet sing-box && { okflag=1; break; }
    _sb_any_port_listening && { okflag=1; break; }
    sleep 1
  done
  if (( okflag==1 )); then ok "已安装并启用 systemd 自启动服务：sing-box"; return 0; fi
  warn "systemd 服务启动失败，切换为容器友好后台运行（fallback）"
  install_singleton_wrapper
  install_autostart_fallback
  start_singbox_singleton_force
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
if ! "$BIN" check -c "$CONFIG" >/dev/null 2>&1; then echo "[sb-singleton] invalid config" >>"$LOG"; exit 1; fi
setsid bash -c "$CMD" >>"$LOG" 2>&1 </dev/null &
echo $! > "$PIDFILE"
exit 0
WRAP
  chmod +x /usr/local/bin/sb-singleton
}

install_autostart_fallback() {
  if [[ -f /etc/alpine-release ]]; then
    mkdir -p /etc/local.d
    echo '#!/bin/sh' > /etc/local.d/sb-singbox.start
    echo '/usr/local/bin/sb-singleton >> /var/log/sing-box.log 2>&1 &' >> /etc/local.d/sb-singbox.start
    chmod +x /etc/local.d/sb-singbox.start
    rc-update add local default >/dev/null 2>&1 || true
  else
    local rc="/etc/rc.local"
    if [[ ! -f "$rc" ]]; then
      echo -e '#!/bin/sh -e\nsleep 1\n/usr/local/bin/sb-singleton >> /var/log/sing-box.log 2>&1 &\nexit 0' > "$rc"
    else
      grep -q '^#!/bin/sh' "$rc" || sed -i '1i #!/bin/sh -e' "$rc"
      grep -q '^exit 0$' "$rc" || printf '\nexit 0\n' >> "$rc"
      if ! grep -q '/usr/local/bin/sb-singleton' "$rc"; then
        sed -i '/^exit 0/i /usr/local/bin/sb-singleton >> /var/log/sing-box.log 2>&1 &' "$rc"
      fi
    fi
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
  crontab -l 2>/dev/null | grep -v "$marker" > /tmp/crontab.tmp 2>/dev/null || true
  echo "* * * * * /usr/local/bin/sb-singleton >/dev/null 2>&1  $marker" >> /tmp/crontab.tmp
  crontab /tmp/crontab.tmp
  rm -f /tmp/crontab.tmp
}

auto_optimize_cpu() {
  if ! command -v renice >/dev/null 2>&1; then
    ensure_cmd renice bsdutils util-linux util-linux util-linux
  fi
  local sb_pid
  sb_pid=$(pgrep -x sing-box | head -n1)
  if [[ -n "$sb_pid" ]]; then renice -n -10 -p "$sb_pid" >/dev/null 2>&1; fi
  if is_docker || [[ -f /.dockerenv ]]; then renice -n 10 -p $$ >/dev/null 2>&1 || true; fi
}

start_singbox_legacy_nohup() {
  if command -v /usr/local/bin/sb-singleton >/dev/null 2>&1; then daemonize /usr/local/bin/sb-singleton --force
  else daemonize /usr/local/bin/sing-box run -c /etc/sing-box/config.json; fi
}

start_singbox_singleton_force() {
  pkill -x sing-box >/dev/null 2>&1 || true
  rm -f /var/run/sing-box.pid >/dev/null 2>&1 || true
  sleep 1
  daemonize /usr/local/bin/sb-singleton --force
}

restart_singbox() {
  local bin="$(_sb_bin)"
  local cfg="$(_sb_cfg)"

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
  elif command -v rc-service >/dev/null 2>&1 && [[ -f /etc/init.d/sing-box ]]; then
    rc-service sing-box restart >/dev/null 2>&1 || rc-service sing-box start >/dev/null 2>&1
    local okflag=0
    for i in $(seq 1 30); do
      rc-service sing-box status 2>/dev/null | grep -q started && { okflag=1; break; }
      _sb_any_port_listening && { okflag=1; break; }
      sleep 1
    done
    if (( okflag==1 )); then ok "Sing-box 重启完成（OpenRC）"; return 0; fi
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

# ============= 核心业务逻辑 (添加/删除节点) =============

add_node() {
  ensure_runtime_deps
  while true; do
    say "请选择协议类型：0)返回 1)SOCKS5 2)VLESS-REALITY 3)Hysteria2 4)CF Tunnel"
    read -rp "输入协议编号: " proto
    proto=${proto:-1}
    [[ "$proto" == "0" ]] && return
    [[ "$proto" =~ ^[1-4]$ ]] && break
    warn "无效输入"
  done

  if [[ "$proto" == "3" ]]; then add_hysteria2_node || return 1; return; fi
  if [[ "$proto" == "4" ]]; then cf_tunnel_menu; return; fi

  # 1. SOCKS5 & VLESS 共用端口选择
  local port proto_type="tcp"
  while true; do
    read -rp "请输入端口号（留空随机）: " port
    if [[ -z "$port" ]]; then
      port=$(get_random_allowed_port "$proto_type")
      [[ "$port" == "NO_PORT" ]] && { err "无可用端口"; return 1; }
      say "（已自动选择：$port）"
    fi
    [[ "$port" =~ ^[0-9]+$ ]] && ((port>=1 && port<=65535)) || { warn "端口无效"; continue; }
    if ! check_nat_allow "$port" "$proto_type"; then warn "NAT规则不允许该端口"; continue; fi
    if jq -e --argjson p "$port" '.inbounds[] | select(.listen_port == $p)' "$CONFIG" >/dev/null 2>&1; then warn "端口冲突"; continue; fi
    break
  done

  # 2. VLESS 逻辑
  if [[ "$proto" == "2" ]]; then
    local uuid=$(uuidgen 2>/dev/null || openssl rand -hex 16 | sed 's/\(..\)/\1/g; s/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
    read -rp "请输入伪装域名 (默认 www.microsoft.com): " server_name
    server_name=${server_name:-www.microsoft.com}
    local flow="xtls-rprx-vision"
    local fp="chrome"
    local key_pair=$(sing-box generate reality-keypair 2>/dev/null)
    local private_key=$(awk -F': ' '/PrivateKey/{print $2}' <<<"$key_pair")
    local public_key=$(awk -F': ' '/PublicKey/{print $2}' <<<"$key_pair")
    local short_id=$(openssl rand -hex 4)
    local tag=$(generate_unique_tag)
    
    local tmpcfg=$(mktemp); trap 'rm -f "$tmpcfg"' RETURN
    jq --arg port "$port" --arg uuid "$uuid" --arg prikey "$private_key" --arg sid "$short_id" --arg server "$server_name" --arg fp "$fp" --arg flow "$flow" --arg tag "$tag" \
       '.inbounds += [{
         "type": "vless", "tag": $tag, "listen": "::", "listen_port": ($port | tonumber),
         "users": [{ "uuid": $uuid, "flow": $flow }],
         "tls": { "enabled": true, "server_name": $server, "reality": { "enabled": true, "handshake": { "server": $server, "server_port": 443 }, "private_key": $prikey, "short_id": [ $sid ] } }
       }]' "$CONFIG" >"$tmpcfg" && mv "$tmpcfg" "$CONFIG"

    sing-box check -c "$CONFIG" >/dev/null 2>&1 || { err "校验失败"; return 1; }
    restart_singbox || { err "重启失败"; return 1; }
    
    local tmpmeta=$(mktemp)
    jq --arg tag "$tag" --arg pbk "$public_key" --arg sid "$short_id" --arg sni "$server_name" --arg port "$port" --arg fp "$fp" \
      '. + {($tag): {pbk:$pbk, sid:$sid, sni:$sni, port:$port, fp:$fp}}' "$META" >"$tmpmeta" && mv "$tmpmeta" "$META"

    local link="vless://${uuid}@${GLOBAL_IPV4}:${port}?encryption=none&flow=${flow}&type=tcp&security=reality&pbk=${public_key}&sid=${short_id}&sni=${server_name}&fp=${fp}#${tag}"
    print_card "VLESS-REALITY 搭建成功" "$tag" "端口:$port\nSNI:$server_name" "$link"
    return
  fi

  # 3. SOCKS5 逻辑
  read -rp "用户名 (默认 user): " user; user=${user:-user}
  read -rp "密码 (默认 pass123): " pass; pass=${pass:-pass123}
  tag="sk5-$(get_country_code)-$(tr -dc 'A-Z' </dev/urandom | head -c1)"
  
  local tmpcfg=$(mktemp); trap 'rm -f "$tmpcfg"' RETURN
  jq --arg port "$port" --arg user "$user" --arg pass "$pass" --arg tag "$tag" \
    '.inbounds += [{"type":"socks","tag":$tag,"listen":"::","listen_port":($port|tonumber),"users":[{"username":$user,"password":$pass}]}]' \
    "$CONFIG" >"$tmpcfg" && mv "$tmpcfg" "$CONFIG"

  restart_singbox || return 1
  local creds=$(printf "%s:%s" "$user" "$pass" | base64 -w0)
  print_card "SOCKS5 搭建成功" "$tag" "端口:$port\n用户:$user" "socks://${creds}@${GLOBAL_IPV4}:${port}#${tag}"
}

add_hysteria2_node() {
  ensure_runtime_deps
  local port proto_type="udp"
  while true; do
    read -rp "Hysteria2 端口 (留空随机): " input_port
    if [[ -z "$input_port" ]]; then
       port=$(get_random_allowed_port "$proto_type")
       [[ "$port" == "NO_PORT" ]] && { err "无可用端口"; return 1; }
    else
       port="$input_port"
    fi
    if ! check_nat_allow "$port" "$proto_type"; then warn "NAT不许"; continue; fi
    if port_status "$port"; then warn "端口被占用"; continue; fi
    break
  done

  if ! command -v hysteria >/dev/null 2>&1; then
    local H_VERSION="2.6.2" arch=$(uname -m)
    case "$arch" in x86_64|amd64) arch="amd64";; aarch64|arm64) arch="arm64";; *) err "不支持"; return 1;; esac
    curl -sSL "https://github.com/apernet/hysteria/releases/download/app/v${H_VERSION}/hysteria-linux-${arch}" -o /usr/local/bin/hysteria
    chmod +x /usr/local/bin/hysteria
  fi

  mkdir -p /etc/hysteria2
  local cert="/etc/hysteria2/${port}.crt" key="/etc/hysteria2/${port}.key" sni="www.bing.com"
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout "$key" -out "$cert" -days 3650 -subj "/CN=$sni" >/dev/null 2>&1
  chmod 644 "$cert" "$key"
  local auth=$(openssl rand -base64 16 | tr -d '=+/' | cut -c1-16)
  local obfs=$(openssl rand -base64 8 | tr -d '=+/' | cut -c1-8)

  cat > "/etc/hysteria2/${port}.yaml" <<EOF
listen: :${port}
tls: { cert: ${cert}, key: ${key} }
auth: { type: password, password: ${auth} }
obfs: { type: salamander, salamander: { password: ${obfs} } }
masquerade: { type: proxy, proxy: { url: https://${sni}/, rewriteHost: true, insecure: true } }
EOF

  local svc="hysteria2-${port}"
  if [[ "$(detect_init_system)" == "systemd" ]]; then
    cat > "/etc/systemd/system/${svc}.service" <<EOF
[Unit]
Description=Hy2 Port ${port}
After=network.target
[Service]
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria2/${port}.yaml
Restart=always
User=root
[Install]
WantedBy=multi-user.target
EOF
    systemctl enable --now "$svc" >/dev/null 2>&1
  else
    cat > "/etc/init.d/${svc}" <<EOF
#!/sbin/openrc-run
name="${svc}"
command="/usr/local/bin/hysteria"
command_args="server -c /etc/hysteria2/${port}.yaml"
pidfile="/run/${svc}.pid"
command_background="yes"
EOF
    chmod +x "/etc/init.d/${svc}"
    rc-update add "$svc" default >/dev/null 2>&1
    rc-service "$svc" start >/dev/null 2>&1
  fi
  
  local tag="Hy2-Default-$(date +%s)"
  local tmpmeta=$(mktemp); trap 'rm -f "$tmpmeta"' EXIT
  jq --arg tag "$tag" --arg port "$port" --arg sni "$sni" --arg obfs "$obfs" --arg auth "$auth" \
    '. + {($tag): {type:"hysteria2", port:$port, sni:$sni, obfs:$obfs, auth:$auth}}' "$META" >"$tmpmeta" && mv "$tmpmeta" "$META"
  
  print_card "Hysteria2 部署成功" "$tag" "端口:$port\n密码:$auth" "hysteria2://${auth}@${GLOBAL_IPV4}:${port}?obfs=salamander&obfs-password=${obfs}&sni=${sni}&insecure=1#${tag}"
}

# ============= CF Tunnel 相关 =============
cf_tunnel_menu() {
  local ARGO_NODES_DIR="/etc/sing-box/argo_users"
  local ARGO_BIN_DIR="/root/agsbx"
  
  ensure_argo_deps() {
    mkdir -p "$ARGO_NODES_DIR" "$ARGO_BIN_DIR"
    local c_cpu c_argo
    case "$(uname -m)" in aarch64) c_cpu="arm64-v8a"; c_argo="arm64";; x86_64) c_cpu="64"; c_argo="amd64";; *) return 1;; esac
    if [ ! -x "$ARGO_BIN_DIR/xray" ]; then
        wget -qO "$ARGO_BIN_DIR/xray.zip" "https://github.com/XTLS/Xray-core/releases/download/v1.8.11/Xray-linux-${c_cpu}.zip"
        unzip -o "$ARGO_BIN_DIR/xray.zip" -d "$ARGO_BIN_DIR" "xray" >/dev/null 2>&1
        chmod +x "$ARGO_BIN_DIR/xray"
    fi
    if [ ! -x "$ARGO_BIN_DIR/cloudflared" ]; then
        wget -qO "$ARGO_BIN_DIR/cloudflared" "https://github.com/cloudflare/cloudflared/releases/download/2024.6.1/cloudflared-linux-${c_argo}"
        chmod +x "$ARGO_BIN_DIR/cloudflared"
    fi
  }

  temp_tunnel_logic() {
    local TEMP_ARGO_DIR="/root/agsbx/temp_node"
    ensure_argo_deps || return
    mkdir -p "$TEMP_ARGO_DIR"
    pkill -9 -f "$TEMP_ARGO_DIR/xray_temp" >/dev/null 2>&1 || true
    pkill -9 -f "$TEMP_ARGO_DIR/cloudflared_temp" >/dev/null 2>&1 || true
    rm -f "$TEMP_ARGO_DIR/argo.log"
    cp "$ARGO_BIN_DIR/xray" "$TEMP_ARGO_DIR/xray_temp"
    cp "$ARGO_BIN_DIR/cloudflared" "$TEMP_ARGO_DIR/cloudflared_temp"
    
    local uuid=$(uuidgen 2>/dev/null); local port=$(shuf -i 10000-60000 -n 1)
    local config="$TEMP_ARGO_DIR/config.json"; local log="$TEMP_ARGO_DIR/argo.log"
    cat > "$config" <<EOF
{"log":{"loglevel":"none"},"inbounds":[{"port":${port},"listen":"127.0.0.1","protocol":"vmess","settings":{"clients":[{"id":"${uuid}","alterId":0}]},"streamSettings":{"network":"ws","wsSettings":{"path":"/${uuid}-vm"}}}],"outbounds":[{"protocol":"freedom"}]}
EOF
    setsid bash -c "exec \"$TEMP_ARGO_DIR/xray_temp\" run -c \"$config\" >/dev/null 2>&1" &
    sleep 1
    setsid bash -c "exec \"$TEMP_ARGO_DIR/cloudflared_temp\" tunnel --url http://127.0.0.1:${port} --edge-ip-version auto --no-autoupdate > \"$log\" 2>&1" &
    sleep 5
    
    local argo_url=$(grep -oE 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' "$log" | head -n 1 | sed 's/https:\/\///')
    [[ -z "$argo_url" ]] && { err "获取域名失败"; return; }
    
    local vmess_json='{"v":"2","ps":"Argo-Temp","add":"www.visa.com.sg","port":"443","id":"'$uuid'","net":"ws","type":"none","host":"'$argo_url'","path":"/'$uuid'-vm","tls":"tls","sni":"'$argo_url'"}'
    local link="vmess://$(echo -n "$vmess_json" | base64 -w 0)"
    
    # 更新 Meta
    jq --arg t "Argo-Temp" --arg u "$link" '.[$t] = {type:"argo", subtype:"temp", raw:$u}' "$META" > "${META}.tmp" && mv "${META}.tmp" "$META"
    restart_singbox >/dev/null 2>&1
    print_card "临时隧道成功" "Argo-Temp" "域名:$argo_url" "$link"
  }

  while true; do
      say "====== Cloudflare 隧道 ======"
      say "1) 临时隧道 (trycloudflare)"
      say "2) 卸载所有 CF 组件"
      say "0) 返回"
      read -rp "选择: " op
      case "$op" in
        1) temp_tunnel_logic ;;
        2) 
           pkill -f "$ARGO_BIN_DIR"
           rm -rf "$ARGO_BIN_DIR" "$ARGO_NODES_DIR"
           jq 'to_entries | map(select(.value.type != "argo")) | from_entries' "$META" > "${META}.tmp" && mv "${META}.tmp" "$META"
           restart_singbox >/dev/null 2>&1
           ok "卸载完成" ;;
        0) return ;;
      esac
  done
}

delete_node() {
  local total=$(jq '.inbounds | length' "$CONFIG" 2>/dev/null || echo "0")
  say "--- 本地普通节点 ---"
  view_nodes "normal"
  read -rp "输入序号删除 (0返回): " idx
  [[ "$idx" == "0" || -z "$idx" ]] && return
  local n=$((idx - 1))
  jq "del(.inbounds[$n])" "$CONFIG" > "${CONFIG}.tmp" && mv "${CONFIG}.tmp" "$CONFIG"
  restart_singbox >/dev/null 2>&1
  ok "已删除"
}

view_nodes() {
  local mode="$1"
  local idx=1
  echo -e "${C_GREEN}序号  类型        端口         备注${C_RESET}"
  jq -c '.inbounds[]' "$CONFIG" 2>/dev/null | while read -r line; do
      local type=$(echo "$line" | jq -r '.type')
      local port=$(echo "$line" | jq -r '.listen_port')
      local tag=$(echo "$line" | jq -r '.tag')
      printf "[%2d] %-10s | %-10s | %s\n" "$idx" "$type" "$port" "$tag"
      idx=$((idx+1))
  done
}

# ============= 网络与系统检测 =============
check_and_repair_menu() {
  system_check() {
    local issues=0
    if ! command -v sing-box >/dev/null; then issues=1; fi
    if ! sing-box check -c "$CONFIG" >/dev/null 2>&1; then issues=1; fi
    return $issues
  }
  if system_check; then ok "系统状态良好"; else warn "检测到异常，尝试修复..."; install_singbox_if_needed; restart_singbox; fi
}

reinstall_menu() {
  read -rp "确认完全卸载并清理？(y/N): " c
  if [[ "$c" == "y" ]]; then
      pkill -9 sing-box
      rm -rf /etc/sing-box /var/log/sing-box.log /usr/local/bin/sing-box /etc/systemd/system/sing-box.service
      systemctl daemon-reload 2>/dev/null
      ok "已清理"
      exit 0
  fi
}

nat_mode_menu() {
  set_nat() {
      jq -n --arg m "$1" --argjson r "$2" --argjson t "$3" --argjson u "$4" \
      '{"mode":$m,"ranges":$r,"custom_tcp":$t,"custom_udp":$u}' > "$NAT_FILE"
      load_nat_data
      ok "已保存"
  }
  say "1)设置范围(如10000-20000) 2)设置TCP端口 3)清除规则"
  read -rp "选择: " o
  case "$o" in
    1) read -rp "范围: " r; set_nat "range" "[\"$r\"]" "[]" "[]" ;;
    2) read -rp "TCP端口(空格隔开): " p; local arr=$(echo "$p" | jq -R 'split(" ")|map(tonumber)'); set_nat "custom" "[]" "$arr" "[]" ;;
    3) rm -f "$NAT_FILE"; load_nat_data; ok "已清除" ;;
  esac
}

# ============= 核心初始化 =============
initialize_core() {
  say "🚀 正在加载核心组件..."
  ensure_dirs
  ensure_cmd curl curl curl curl curl
  ensure_cmd jq jq jq jq jq

  # 网络初始化
  local_ipv4=$(curl -s --max-time 3 https://api.ipify.org || echo "127.0.0.1")
  GLOBAL_IPV4="$local_ipv4"
  GLOBAL_IPV6=$(curl -s -6 --max-time 3 https://api64.ipify.org || echo "")

  if ! command -v sing-box >/dev/null 2>&1; then install_singbox_if_needed || true; fi
  load_nat_data
  auto_optimize_cpu
  trap 'disown_temp_tunnel >/dev/null 2>&1; echo; exit 0' INT
  
  if ! pgrep -f "sb-singleton" >/dev/null 2>&1 && ! systemctl is-active sing-box >/dev/null 2>&1; then
      case "$(detect_init_system)" in
        systemd) install_systemd_service ;;
        openrc) ensure_service_openrc ;;
        *) install_singleton_wrapper; install_autostart_fallback; start_singbox_legacy_nohup & ;;
      esac
  fi
}