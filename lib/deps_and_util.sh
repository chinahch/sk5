#!/usr/bin/env bash
# sk5.sh 模块: 依赖与通用工具

# 全局变量需要在 main.sh 中定义并 source

# ============= 基础工具 =============
is_docker() {
  if [ -f /.dockerenv ]; then return 0; fi
  if grep -qE "/docker/|/lxc/" /proc/1/cgroup 2>/dev/null; then return 0; fi
  return 1
}

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

port_status() {
  local port="$1"
  local have=0 seen_s=0 seen_o=0
  
  local ss_output=""
  if command -v ss >/dev/null 2>&1; then
    have=1
    ss_output=$(ss -luntp 2>/dev/null || true)
    
    if echo "$ss_output" | grep -q ":$port "; then
       if echo "$ss_output" | grep ":$port " | grep -qi 'users:((".*sing-box'; then
          seen_s=1
       else
          seen_o=1
       fi
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


# ============= 依赖安装 =============
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

install_dependencies() {
  if (( DEPS_CHECKED == 1 )); then return 0; fi

  ensure_cmd curl     curl        curl        curl        curl
  ensure_cmd jq       jq          jq          jq          jq
  ensure_cmd uuidgen  uuid-runtime util-linux util-linux  util-linux
  ensure_cmd openssl  openssl      openssl     openssl     openssl
  ensure_cmd ss       iproute2     iproute2    iproute    iproute
  ensure_cmd lsof     lsof         lsof        lsof        lsof
  
  DEPS_CHECKED=1
  ok "依赖已满足（curl/jq/uuidgen/openssl/iproute2/lsof）"
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

# ============= 杂项工具 =============
get_public_ipv4() {
  local ip=""
  for url in "https://api.ipify.org" "https://ifconfig.me/ip" "https://ipinfo.io/ip" "https://checkip.amazonaws.com"; do
    ip=$(curl -s --max-time 3 "$url" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)
    if [[ -n "$ip" ]]; then echo "$ip"; return 0; fi
  done
  return 1
}

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

  if command -v sing-box >/dev/null 2>&1; then
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