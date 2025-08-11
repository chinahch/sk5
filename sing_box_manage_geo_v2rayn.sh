#!/usr/bin/env bash
# sk5.sh — Sing-box 管理脚本（systemd/OpenRC 自适应）
# 功能：依赖安装、sing-box 安装/自启动、添加/查看/删除节点、脚本服务（检测并修复/升级/重启/重装）、NAT模式
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

say()  { printf "%s\n" "$*"; }
err()  { printf " %s\n" "$*" >&2; }
ok()   { printf " %s\n" "$*"; }
warn() { printf " %s\n" "$*"; }

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

ensure_dirs() {
  mkdir -p /etc/sing-box
  [[ -f "$CONFIG" ]] || printf '%s\n' '{"inbounds":[],"outbounds":[{"type":"direct"}],"route":{"rules":[]}}' >"$CONFIG"
  [[ -f "$META"   ]] || printf '%s\n' '{}' >"$META"
}

install_dependencies() {
  local need=()
  command -v curl >/dev/null 2>&1    || need+=("curl")
  command -v jq >/dev/null 2>&1      || need+=("jq")
  command -v uuidgen >/dev/null 2>&1 || need+=("uuid-runtime")
  command -v openssl >/dev/null 2>&1 || need+=("openssl")
  command -v ss >/dev/null 2>&1      || need+=("iproute2")
  command -v lsof >/dev/null 2>&1    || need+=("lsof")
  if ((${#need[@]})); then
    case "$(detect_os)" in
      debian|ubuntu)
        printf "\n[等待] 正在更新软件源，请稍候...\n"
        DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
        printf "[等待] 正在安装运行所需依赖，请稍候...\n"
        DEBIAN_FRONTEND=noninteractive apt-get install -y "${need[@]}" >/dev/null 2>&1 || true ;;
      alpine) printf "[等待] 正在安装运行所需依赖（Alpine）...\n"
        apk add --no-cache "${need[@]}" >/dev/null 2>&1 || true ;;
      centos|rhel) printf "[等待] 正在安装运行所需依赖（CentOS/RHEL）...\n"
        yum install -y "${need[@]}" >/dev/null 2>&1 || true ;;
      fedora) printf "[等待] 正在安装运行所需依赖（Fedora）...\n"
        dnf install -y "${need[@]}" >/dev/null 2>&1 || true ;;
      *) warn "未识别系统，请确保安装：${need[*]}" ;;
    esac
  fi
  ok "依赖已满足（curl/jq/uuidgen/openssl/iproute2/lsof）"
}

install_singbox_if_needed() {
  if command -v sing-box >/dev/null 2>&1; then return 0; fi

  fix_ca_certificates() {
    if [[ ! -f /etc/ssl/certs/ca-certificates.crt ]]; then
      warn "检测到 CA 证书缺失，正在安装 ca-certificates..."
      apt-get update -y
      apt-get install --reinstall -y ca-certificates
      update-ca-certificates
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
  ) || { err "安装 sing-box 失败"; rm -rf "$tmp"; return 1; }
  rm -rf "$tmp"
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
  # 0=sing-box监听, 1=其他进程占用, 2=未监听/无法检测
  if command -v lsof >/dev/null 2>&1; then
    local out
    out=$(lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $1}')
    if [[ -z "$out" ]]; then return 2; fi
    if echo "$out" | grep -Eq '^(sing-box)$'; then return 0; else return 1; fi
  elif command -v ss >/dev/null 2>&1; then
    local out
    out=$(ss -ltnp "sport = :$port" 2>/dev/null || true)
    if ! grep -q LISTEN <<<"$out"; then return 2; fi
    if grep -q 'users:(("sing-box"' <<<"$out"; then return 0; else return 1; fi
  else
    return 2
  fi
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
  rc-update add sing-box default >/dev/null 2>&1 || true
  rc-service sing-box restart >/dev/null 2>&1 || rc-service sing-box start >/dev/null 2>&1 || true
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

restart_singbox() {
  local init; init=$(detect_init_system)
  if [[ "$init" == "systemd" ]]; then
    kill_rogue_singbox
    timeout 8s systemctl stop sing-box >/dev/null 2>&1 || true
    systemctl kill -s SIGKILL sing-box >/dev/null 2>&1 || true
    sleep 0.4
    systemctl start sing-box --no-block >/dev/null 2>&1 || true

    local okflag=0 i any_listen
    for i in {1..60}; do
      any_listen=$(jq -r '.inbounds[].listen_port' "$CONFIG" 2>/dev/null | while read -r p; do
        [[ -z "$p" ]] && continue
        if ss -ltnp 2>/dev/null | grep -q ":$p "; then echo ok; break; fi
        if timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" >/dev/null 2>&1; then echo ok; break; fi
      done)
      if [[ "$any_listen" == "ok" ]]; then okflag=1; break; fi
      if systemctl is-active --quiet sing-box; then okflag=1; break; fi
      printf "."; sleep 0.5
    done
    echo
    if [[ $okflag -eq 1 ]]; then ok "Sing-box 重启完成"; else
      err "Sing-box 重启失败"
      journalctl -u sing-box --no-pager -n 120 2>/dev/null || true
      return 1
    fi
  elif [[ "$init" == "openrc" ]]; then
    timeout 8s rc-service sing-box stop >/dev/null 2>&1 || true
    pids=$(pgrep -x sing-box) || true
    if [[ -n "$pids" ]]; then for pid in $pids; do kill -9 "$pid" 2>/dev/null || true; done; fi
    sleep 0.4
    timeout 8s rc-service sing-box start >/dev/null 2>&1 || true
    sleep 1
    if rc-service sing-box status 2>/dev/null | grep -q started; then ok "Sing-box 重启完成（OpenRC）"
    else err "Sing-box 重启失败（OpenRC）"; tail -n 120 /var/log/sing-box.log 2>/dev/null || true; return 1; fi
  else
    warn "未检测到受支持的服务管理器，将后台启动 Sing-box 进程"
    pids=$(pgrep -x sing-box) || true
    if [[ -n "$pids" ]]; then for pid in $pids; do kill -9 "$pid" 2>/dev/null || true; done; fi
    if ! /usr/local/bin/sing-box check -c "$CONFIG" >/dev/null 2>&1; then
      err "配置文件校验失败，无法重启"; sing-box check -c "$CONFIG"; return 1
    fi
    nohup /usr/local/bin/sing-box run -c "$CONFIG" >/var/log/sing-box.log 2>&1 &
    local SING_PID=$! okflag=0 i any_listen
    for i in {1..60}; do
      any_listen=$(jq -r '.inbounds[].listen_port' "$CONFIG" 2>/dev/null | while read -r p; do
        [[ -z "$p" ]] && continue
        if ss -ltnp 2>/dev/null | grep -q ":$p "; then echo ok; break; fi
        if timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" >/dev/null 2>&1; then echo ok; break; fi
      done)
      if [[ "$any_listen" == "ok" ]]; then okflag=1; break; fi
      if kill -0 "$SING_PID" 2>/dev/null; then sleep 0.5; else break; fi
    done
    if [[ $okflag -eq 1 ]]; then ok "Sing-box 重启完成（进程已启动）"
    else err "Sing-box 重启失败"; tail -n 120 /var/log/sing-box.log 2>/dev/null || true; return 1; fi
  fi
}

install_systemd_service() {
  local SERVICE_FILE="/lib/systemd/system/sing-box.service"
  cat > "$SERVICE_FILE" <<'EOF'
[Unit]
Description=Sing-box Service
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=always
RestartSec=5
LimitNOFILE=1048576
User=root

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  echo "已安装/刷新 systemd 自启动服务：sing-box"
}

# ============= NAT 规则存取/校验 =============
view_nat_ports() {
  if [[ ! -f "$NAT_FILE" ]]; then warn "当前未设置 NAT 模式规则"; return; fi
  say "当前 NAT 规则："; cat "$NAT_FILE"
  say "------ 端口规则管理 ------"
  say "1) 添加范围段（例如 12000-12020；可多段空格分隔）"
  say "2) 删除某个范围段（输入与上面一致的段值）"
  say "3) 添加自定义TCP端口（空格分隔）"
  say "4) 删除自定义TCP中的端口（空格分隔）"
  say "5) 添加自定义UDP端口（空格分隔）"
  say "6) 删除自定义UDP中的端口（空格分隔）"
  say "0) 返回"
  read -rp "选择: " op
  case "$op" in
    1)
      read -rp "输入范围段: " ranges
      if [[ -z "$ranges" ]]; then warn "未输入"; return; fi
      local tmp; tmp=$(mktemp)
      jq --argjson arr "$(printf '%s\n' "$ranges" | jq -R 'split(" ")')" \
         '.mode="range"| .ranges = ((.ranges // []) + $arr) | .custom_tcp = (.custom_tcp // []) | .custom_udp = (.custom_udp // [])' \
         "$NAT_FILE" >"$tmp" && mv "$tmp" "$NAT_FILE"
      ok "已添加范围段"
      ;;
    2)
      read -rp "输入要删除的范围段（完全匹配）: " seg
      [[ -z "$seg" ]] && { warn "未输入"; return; }
      local tmp; tmp=$(mktemp)
      jq --arg seg "$seg" '.ranges = ((.ranges // []) | map(select(. != $seg)))' "$NAT_FILE" >"$tmp" && mv "$tmp" "$NAT_FILE"
      ok "已删除范围段"
      ;;
    3)
      read -rp "输入要添加的TCP端口（空格分隔）: " ports
      local tmp; tmp=$(mktemp)
      jq --argjson add "$(printf '%s\n' "$ports" | jq -R 'split(" ")|map(tonumber)')" \
         '.mode="custom"| .custom_tcp = ((.custom_tcp // []) + $add) | .custom_udp = (.custom_udp // []) | .ranges=[]' \
         "$NAT_FILE" >"$tmp" && mv "$tmp" "$NAT_FILE"
      ok "已添加TCP端口"
      ;;
    4)
      read -rp "输入要删除的TCP端口（空格分隔）: " ports
      local tmp; tmp=$(mktemp)
      jq --argjson del "$(printf '%s\n' "$ports" | jq -R 'split(" ")|map(tonumber)')" \
         '.custom_tcp = ((.custom_tcp // []) | map(select(inside($del[])|not)))' "$NAT_FILE" >"$tmp" && mv "$tmp" "$NAT_FILE"
      ok "已删除TCP端口"
      ;;
    5)
      read -rp "输入要添加的UDP端口（空格分隔）: " ports
      local tmp; tmp=$(mktemp)
      jq --argjson add "$(printf '%s\n' "$ports" | jq -R 'split(" ")|map(tonumber)')" \
         '.mode="custom"| .custom_udp = ((.custom_udp // []) + $add) | .custom_tcp = (.custom_tcp // []) | .ranges=[]' \
         "$NAT_FILE" >"$tmp" && mv "$tmp" "$NAT_FILE"
      ok "已添加UDP端口"
      ;;
    6)
      read -rp "输入要删除的UDP端口（空格分隔）: " ports
      local tmp; tmp=$(mktemp)
      jq --argjson del "$(printf '%s\n' "$ports" | jq -R 'split(" ")|map(tonumber)')" \
         '.custom_udp = ((.custom_udp // []) | map(select(inside($del[])|not)))' "$NAT_FILE" >"$tmp" && mv "$tmp" "$NAT_FILE"
      ok "已删除UDP端口"
      ;;
    0) return ;;
    *) warn "无效输入" ;;
  esac
}

disable_nat_mode() {
  if [[ -f "$NAT_FILE" ]]; then rm -f "$NAT_FILE"; ok "NAT模式已关闭（规则已清除）"
  else warn "当前未启用 NAT 模式"; fi
}

set_nat_range() {
  read -rp "请输入范围端口（多个用空格分隔，如 12000-12020 34050-34070）: " ranges
  jq -n --argjson arr "$(printf '%s\n' "$ranges" | jq -R 'split(" ")')" \
    '{"mode":"range","ranges":$arr,"custom_tcp":[],"custom_udp":[]}' > "$NAT_FILE"
  ok "范围端口已保存"
}
set_nat_custom_tcp() {
  local nat_file="/etc/sing-box/nat_ports.json"
  read -rp "请输入自定义TCP端口（空格分隔）: " ports
  if [[ -f "$nat_file" ]]; then
    jq --argjson arr "$(printf '%s\n' "$ports" | jq -R 'split(" ") | map(tonumber)')" '.custom_tcp = $arr' "$nat_file" > "${nat_file}.tmp" && mv "${nat_file}.tmp" "$nat_file"
  else
    jq -n --argjson arr "$(printf '%s\n' "$ports" | jq -R 'split(" ") | map(tonumber)')" '{"mode":"custom","ranges":[],"custom_tcp":$arr,"custom_udp":[]}' > "$nat_file"
  fi
  echo "自定义TCP端口已保存"
}

set_nat_custom_udp() {
  local nat_file="/etc/sing-box/nat_ports.json"
  read -rp "请输入自定义UDP端口（空格分隔）: " ports
  if [[ -f "$nat_file" ]]; then
    jq --argjson arr "$(printf '%s\n' "$ports" | jq -R 'split(" ") | map(tonumber)')" '.custom_udp = $arr' "$nat_file" > "${nat_file}.tmp" && mv "${nat_file}.tmp" "$nat_file"
  else
    jq -n --argjson arr "$(printf '%s\n' "$ports" | jq -R 'split(" ") | map(tonumber)')" '{"mode":"custom","ranges":[],"custom_tcp":[],"custom_udp":$arr}' > "$nat_file"
  fi
  echo "自定义UDP端口已保存"
}

# NAT 菜单（按你的格式）
nat_mode_menu() {
  say "====== NAT模式设置 ======"
  say "1) 设置范围端口"
  say "2) 设置自定义TCP端口"
  say "3) 设置自定义UDP端口"
  say "4) 查看当前NAT端口规则"
  say "5) 退出NAT模式"
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

# 协议感知校验：范围模式允许范围内所有端口；自定义模式区分 TCP/UDP 集合
check_nat_allow() {
  local port="$1" proto="$2"
  if [[ ! -f "$NAT_FILE" ]]; then return 0; fi
  local mode; mode=$(jq -r '.mode' "$NAT_FILE")
  if [[ "$mode" == "range" ]]; then
    while read -r range; do
      local s=${range%-*} e=${range#*-}
      if (( port>=s && port<=e )); then return 0; fi
    done < <(jq -r '.ranges[]?' "$NAT_FILE")
    return 1
  elif [[ "$mode" == "custom" ]]; then
    if [[ "$proto" == "tcp" ]]; then
      jq -r '.custom_tcp[]?' "$NAT_FILE" | grep -qx "$port"; return $?
    elif [[ "$proto" == "udp" ]]; then
      jq -r '.custom_udp[]?' "$NAT_FILE" | grep -qx "$port"; return $?
    else
      jq -r '.custom_tcp[]?, .custom_udp[]?' "$NAT_FILE" | grep -qx "$port"; return $?
    fi
  else
    return 0
  fi
}

get_random_allowed_port() {
  local proto="$1"
  local -a used=()
  mapfile -t used < <(jq -r '.inbounds[].listen_port' "$CONFIG" 2>/dev/null | grep -E '^[0-9]+$' || true)
  mapfile -t hy2u < <(jq -r 'to_entries[]? | select(.value.type=="hysteria2") | .value.port' "$META" 2>/dev/null || true)
  used+=("${hy2u[@]}")

  if [[ -f "$NAT_FILE" ]]; then
    local mode; mode=$(jq -r '.mode' "$NAT_FILE")
    local -a candidates=()
    if [[ "$mode" == "range" ]]; then
      while read -r range; do
        local s=${range%-*} e=${range#*-} p
        for ((p=s; p<=e; p++)); do candidates+=("$p"); done
      done < <(jq -r '.ranges[]?' "$NAT_FILE")
    else
      if [[ "$proto" == "tcp" ]]; then
        mapfile -t candidates < <(jq -r '.custom_tcp[]?' "$NAT_FILE")
      elif [[ "$proto" == "udp" ]]; then
        mapfile -t candidates < <(jq -r '.custom_udp[]?' "$NAT_FILE")
      else
        mapfile -t candidates < <(jq -r '.custom_tcp[]?, .custom_udp[]?' "$NAT_FILE")
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
  ) || { err "升级失败"; rm -rf "$tmp"; return 1; }
  rm -rf "$tmp"
  ok "已成功升级为 v${LATEST}"
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
    else if [[ -f /etc/init.d/sing-box ]]; then err "Sing-box 服务未运行 (OpenRC)"; issues=1; else err "Sing-box 服务未配置 (OpenRC)"; issues=1; fi
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
  install_singbox_if_needed || true
  install_systemd_service

  local need_hy_install=0
  shopt -s nullglob
  for f in /etc/systemd/system/hysteria2*.service; do
    if ! command -v hysteria >/dev/null 2>&1; then need_hy_install=1; break; fi
  done
  if [[ $need_hy_install -eq 1 ]]; then
    local H_VERSION="2.6.2" arch=$(uname -m)
    case "$arch" in x86_64|amd64) arch="amd64";; aarch64|arm64) arch="arm64";; *) err "暂不支持架构：$arch";; esac
    local tmp; tmp=$(mktemp -d)
    (
      set -e
      cd "$tmp"
      curl -sSL "https://github.com/apernet/hysteria/releases/download/app/v${H_VERSION}/hysteria-linux-${arch}" -o hysteria-bin || { err "下载 hysteria 失败"; exit 1; }
      install -m 0755 hysteria-bin /usr/local/bin/hysteria
    ) || true
    rm -rf "$tmp"
    command -v hysteria >/dev/null 2>&1 && ok "hysteria 安装完成"
  fi

  for f in /etc/systemd/system/hysteria2*.service; do
    local name=$(basename "$f")
    local port=${name#hysteria2-}; port=${port%.service}
    if ! systemctl is-active --quiet "$name"; then
      if [[ ! -f /etc/hysteria2/${port}.crt || ! -f /etc/hysteria2/${port}.key ]]; then
        openssl ecparam -name prime256v1 -genkey -noout -out /etc/hysteria2/${port}.key 2>/dev/null || \
        openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out /etc/hysteria2/${port}.key 2>/dev/null
        openssl req -new -x509 -nodes -key /etc/hysteria2/${port}.key -out /etc/hysteria2/${port}.crt -subj "/CN=bing.com" -days 36500 >/dev/null 2>&1 || true
        [[ -f /etc/hysteria2/${port}.crt && -f /etc/hysteria2/${port}.key ]] && ok "已重新生成端口 $port 证书"
      fi
      systemctl daemon-reload >/dev/null 2>&1 || true
      systemctl restart "$name" >/dev/null 2>&1 || true
      sleep 1
      systemctl is-active --quiet "$name" && ok "Hysteria2-${port} 服务已启动" || err "Hysteria2-${port} 服务仍无法启动"
    fi
  done
  shopt -u nullglob
}

# 合并：系统检测与修复（给出建议并可一键执行）
check_and_repair_menu() {
  say "====== 系统检测与修复（合并） ======"
  system_check
  local status=$?
  if (( status != 0 )); then
    say ""
    warn "检测到异常，建议执行自动修复（安装缺依赖 / 修复服务 / 纠正证书等）。"
    read -rp "是否立即按建议修复？(Y/n): " dofix
    dofix=${dofix:-Y}
    if [[ "$dofix" == "Y" || "$dofix" == "y" ]]; then
      fix_errors
      say ""
      ok "修复操作完成，正在重新检测..."
      system_check
    else
      say "已跳过修复。"
    fi
  else
    ok "系统状态良好，无需修复。"
  fi
  # 等待用户确认后返回上一层菜单
  read -rp "按回车返回脚本服务菜单..." _
  return
}


# ============= 节点操作（含 NAT 端口约束） =============
add_node() {
  while true; do
    say "请选择协议类型："
    say "0) 返回主菜单"
    say "1) SOCKS5"
    say "2) VLESS-REALITY"
    say "3) Hysteria2"
    read -rp "输入协议编号（默认 1，输入 0 返回）: " PROTO
    PROTO=${PROTO:-1}
    [[ "$PROTO" == "0" ]] && return
    [[ "$PROTO" =~ ^[123]$ ]] && break
    warn "无效输入"
  done

  if [[ "$PROTO" == "3" ]]; then
    add_hysteria2_node || return 1
    return
  elif [[ "$PROTO" == "2" ]]; then
    # VLESS (TCP 语义端口)
    if ! command -v sing-box >/dev/null 2>&1; then
      err "未检测到 sing-box，无法生成 Reality 密钥。请先在“脚本服务”里重装/安装。"
      return 1
    fi
    local PORT mode proto="tcp"
    while true; do
      if [[ -f "$NAT_FILE" ]]; then
        mode=$(jq -r '.mode' "$NAT_FILE")
        [[ "$mode" == "custom" ]] && say "已启用自定义端口模式：VLESS 仅允许使用 自定义TCP端口 集合"
        [[ "$mode" == "range"  ]] && say "已启用范围端口模式：VLESS 仅允许使用 范围内端口"
      fi
      read -rp "请输入端口号（留空自动挑选允许端口；输入 0 返回）: " PORT
      if [[ -z "$PORT" ]]; then
        PORT=$(get_random_allowed_port "$proto")
        [[ "$PORT" == "NO_PORT" ]] && { err "无可用端口"; return 1; }
        say "（已自动选择随机端口：$PORT）"
      fi
      [[ "$PORT" == "0" ]] && return
      [[ "$PORT" =~ ^[0-9]+$ ]] && ((PORT>=1 && PORT<=65535)) || { warn "端口无效"; continue; }
      if ! check_nat_allow "$PORT" "$proto"; then warn "端口 $PORT 不符合 NAT 规则（协议: $proto）"; continue; fi
      if jq -e --argjson p "$PORT" '.inbounds[] | select(.listen_port == $p)' "$CONFIG" >/dev/null 2>&1; then warn "端口 $PORT 已存在"; continue; fi
      if jq -e --argjson p "$PORT" 'to_entries[]? | select(.value.type=="hysteria2" and .value.port == $p)' "$META" >/dev/null 2>&1; then warn "端口 $PORT 已被 Hysteria2 使用"; continue; fi
      break
    done

    local UUID FP FLOW SERVER_NAME KEY_PAIR PRIVATE_KEY PUBLIC_KEY SHORT_ID TAG tmpcfg
    if command -v uuidgen >/dev/null 2>&1; then UUID=$(uuidgen); else UUID=$(openssl rand -hex 16 | sed 's/\(..\)/\1/g; s/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/'); fi
    SERVER_NAME="www.cloudflare.com"
    FLOW="xtls-rprx-vision"
    case $((RANDOM%5)) in 0) FP="chrome";; *) FP="firefox";; esac

    KEY_PAIR=$(sing-box generate reality-keypair 2>/dev/null)
    PRIVATE_KEY=$(awk -F': ' '/PrivateKey/{print $2}' <<<"$KEY_PAIR")
    PUBLIC_KEY=$(awk -F': ' '/PublicKey/{print $2}' <<<"$KEY_PAIR")
    [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]] && { err "生成 Reality 密钥失败"; return 1; }
    SHORT_ID=$(openssl rand -hex 4)
    TAG=$(generate_unique_tag)

    tmpcfg=$(mktemp)
    jq --arg port "$PORT" \
       --arg uuid "$UUID" \
       --arg prikey "$PRIVATE_KEY" \
       --arg sid "$SHORT_ID" \
       --arg server "$SERVER_NAME" \
       --arg fp "$FP" \
       --arg flow "$FLOW" \
       --arg tag "$TAG" \
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
    jq --arg tag "$TAG" --arg pbk "$PUBLIC_KEY" --arg sid "$SHORT_ID" --arg sni "$SERVER_NAME" --arg port "$PORT" --arg fp "$FP" \
      '. + {($tag): {pbk:$pbk, sid:$sid, sni:$sni, port:$port, fp:$fp}}' "$META" >"$tmpmeta" && mv "$tmpmeta" "$META"

    local IPV4; IPV4=$(curl -s --max-time 2 https://api.ipify.org)
    say ""; ok "添加成功：VLESS Reality"
    say "端口: $PORT"
    say "UUID: $UUID"
    say "Public Key: $PUBLIC_KEY"
    say "Short ID: $SHORT_ID"
    say "SNI: $SERVER_NAME"
    say "Fingerprint: $FP"
    say "TAG: $TAG"
    say ""
    say " 客户端链接："
    say "vless://${UUID}@${IPV4}:${PORT}?encryption=none&flow=${FLOW}&type=tcp&security=reality&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&sni=${SERVER_NAME}&fp=${FP}#${TAG}"
    say ""
    return
  else
    # SOCKS5 (TCP 语义端口)
    local PORT USER PASS TAG tmpcfg proto="tcp" mode
    while true; do
      if [[ -f "$NAT_FILE" ]]; then
        mode=$(jq -r '.mode' "$NAT_FILE")
        [[ "$mode" == "custom" ]] && say "已启用自定义端口模式：SOCKS5 仅允许使用 自定义TCP端口 集合"
        [[ "$mode" == "range"  ]] && say "已启用范围端口模式：SOCKS5 仅允许使用 范围内端口"
      fi
      read -rp "请输入端口号（留空自动挑选允许端口；输入 0 返回）: " PORT
      if [[ -z "$PORT" ]]; then
        PORT=$(get_random_allowed_port "$proto")
        [[ "$PORT" == "NO_PORT" ]] && { err "无可用端口"; return 1; }
        say "（已自动选择随机端口：$PORT）"
      fi
      [[ "$PORT" == "0" ]] && return
      [[ "$PORT" =~ ^[0-9]+$ ]] && ((PORT>=1 && PORT<=65535)) || { warn "端口无效"; continue; }
      if ! check_nat_allow "$PORT" "$proto"; then warn "端口 $PORT 不符合 NAT 规则（协议: $proto）"; continue; fi
      if jq -e --argjson p "$PORT" '.inbounds[] | select(.listen_port == $p)' "$CONFIG" >/dev/null 2>&1; then warn "端口 $PORT 已存在"; continue; fi
      if jq -e --argjson p "$PORT" 'to_entries[]? | select(.value.type=="hysteria2" and .value.port == $p)' "$META" >/dev/null 2>&1; then warn "端口 $PORT 已被 Hysteria2 使用"; continue; fi
      break
    done
    read -rp "请输入用户名（默认 user）: " USER; USER=${USER:-user}
    read -rp "请输入密码（默认 pass123）: " PASS; PASS=${PASS:-pass123}
    TAG="sk5-$(get_country_code)-$(tr -dc 'A-Z' </dev/urandom | head -c1)"

    tmpcfg=$(mktemp)
    jq --arg port "$PORT" --arg user "$USER" --arg pass "$PASS" --arg tag "$TAG" \
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
    say "端口: $PORT"
    say "用户名: $USER"
    say "密码: $PASS"
    say "TAG: $TAG"
    say ""
    say " 客户端链接："
    local IPV4; IPV4=$(curl -s --max-time 2 https://api.ipify.org)
    local IPV6; IPV6=$(get_ipv6_address)
    if [[ -n "$IPV4" ]]; then
      local CREDS; CREDS=$(printf "%s" "$USER:$PASS" | base64)
      say "IPv4: socks://${CREDS}@${IPV4}:${PORT}#${TAG}"
      [[ -n "$IPV6" ]] && say "IPv6: socks://${CREDS}@[${IPV6}]:${PORT}#${TAG}"
    else
      say "请使用 domain/IP 和端口连接 SOCKS5 节点 (用户名: $USER, 密码: $PASS)"
    fi
    say ""
  fi
}

add_hysteria2_node() {
  local PORT proto="udp" mode
  while true; do
    if [[ -f "$NAT_FILE" ]]; then
      mode=$(jq -r '.mode' "$NAT_FILE")
      [[ "$mode" == "custom" ]] && say "已启用自定义端口模式：Hysteria2 仅允许使用 自定义UDP端口 集合"
      [[ "$mode" == "range"  ]] && say "已启用范围端口模式：Hysteria2 仅允许使用 范围内端口"
    fi
    read -rp "请输入端口号（留空自动挑选允许端口；输入 0 返回）: " PORT
    if [[ -z "$PORT" ]]; then
      PORT=$(get_random_allowed_port "$proto")
      [[ "$PORT" == "NO_PORT" ]] && { err "无可用端口"; return 1; }
      say "（已自动选择随机端口：$PORT）"
    fi
    [[ "$PORT" == "0" ]] && return
    [[ "$PORT" =~ ^[0-9]+$ ]] && ((PORT>=1 && PORT<=65535)) || { warn "端口无效"; continue; }
    if ! check_nat_allow "$PORT" "$proto"; then warn "端口 $PORT 不符合 NAT 规则（协议: $proto）"; continue; fi
    if jq -e --argjson p "$PORT" '.inbounds[] | select(.listen_port == $p)' "$CONFIG" >/dev/null 2>&1; then warn "端口 $PORT" "已被 sing-box 使用"; continue; fi
    if jq -e --argjson p "$PORT" 'to_entries[]? | select(.value.type=="hysteria2" and .value.port == $p)' "$META" >/dev/null 2>&1; then warn "端口 $PORT 已存在"; continue; fi
    break
  done

  local DOMAIN="bing.com"

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
    (
      set -e
      cd "$tmp"
      curl -sSL "https://github.com/apernet/hysteria/releases/download/app/v${H_VERSION}/hysteria-linux-${arch}" -o hysteria-bin || { err "下载 hysteria 失败"; exit 1; }
      install -m 0755 hysteria-bin /usr/local/bin/hysteria
    ) || { rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
    ok "hysteria 安装完成"
  fi

  mkdir -p /etc/hysteria2

  openssl ecparam -name prime256v1 -genkey -noout -out /etc/hysteria2/${PORT}.key 2>/dev/null || \
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out /etc/hysteria2/${PORT}.key 2>/dev/null
  openssl req -new -x509 -nodes -key /etc/hysteria2/${PORT}.key -out /etc/hysteria2/${PORT}.crt -subj "/CN=${DOMAIN}" -days 36500 >/dev/null 2>&1 || {
    err "自签证书生成失败"; return 1; }

  local AUTH_PWD OBFS_PWD
  AUTH_PWD=$(openssl rand -base64 16 | tr -d '=+/' | cut -c1-16)
  OBFS_PWD=$(openssl rand -base64 8 | tr -d '=+/' | cut -c1-8)

  local TAG="hysteria2-$(get_country_code)-$(tr -dc 'A-Z' </dev/urandom | head -c1)"
  if jq -e --arg t "$TAG" '.inbounds[] | select(.tag == $t)' "$CONFIG" >/dev/null 2>&1 || jq -e --arg t "$TAG" 'has($t)' "$META" >/dev/null 2>&1; then
    TAG="hysteria2-$(get_country_code)-$(date +%s)"
  fi

  cat > /etc/hysteria2/${PORT}.yaml <<EOF
listen: ":${PORT}"
tls:
  cert: /etc/hysteria2/${PORT}.crt
  key: /etc/hysteria2/${PORT}.key
obfs:
  type: salamander
  salamander:
    password: ${OBFS_PWD}
auth:
  type: password
  password: ${AUTH_PWD}
masquerade:
  type: proxy
  proxy:
    url: https://${DOMAIN}
    rewriteHost: true
    insecure: true
EOF

  cat > /etc/systemd/system/hysteria2-${PORT}.service <<EOF
[Unit]
Description=Hysteria2 Service (${PORT})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria2/${PORT}.yaml
Restart=always
RestartSec=3s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload >/dev/null 2>&1
  systemctl enable hysteria2-${PORT}.service >/dev/null 2>&1 || true
  systemctl restart hysteria2-${PORT}.service >/dev/null 2>&1 || true

  sleep 1
  if systemctl is-active --quiet hysteria2-${PORT}; then ok "Hysteria2 服务已启动"
  else err "Hysteria2 服务启动失败，请检查日志 (journalctl -u hysteria2-${PORT})"; return 1; fi

  local tmpmeta; tmpmeta=$(mktemp)
  jq --arg tag "$TAG" --arg port "$PORT" --arg sni "$DOMAIN" --arg obfs "$OBFS_PWD" --arg auth "$AUTH_PWD" \
    '. + {($tag): {type:"hysteria2", port:$port, sni:$sni, obfs:$obfs, auth:$auth}}' "$META" >"$tmpmeta" && mv "$tmpmeta" "$META"

  local IPV4 IPV6
  IPV4=$(curl -s --max-time 2 https://api.ipify.org || echo "")
  [[ -z "$IPV4" ]] && IPV4="<服务器IP>"
  IPV6=$(get_ipv6_address)
  say ""; ok "添加成功：Hysteria2"
  say "端口: $PORT"
  say "Auth密码: $AUTH_PWD"
  say "Obfs密码: $OBFS_PWD"
  say "SNI域名: $DOMAIN"
  say "TAG: $TAG"
  say ""
  say " 客户端链接："
  [[ -n "$IPV4" ]] && say "hysteria2://${AUTH_PWD}@${IPV4}:${PORT}?obfs=salamander&obfs-password=${OBFS_PWD}&sni=${DOMAIN}&insecure=1#${TAG}"
  [[ -n "$IPV6" ]] && say "hysteria2://${AUTH_PWD}@[${IPV6}]:${PORT}?obfs=salamander&obfs-password=${OBFS_PWD}&sni=${DOMAIN}&insecure=1#${TAG}"
  say ""
}

view_nodes() {
  set +e
  local IPV4; IPV4=$(curl -s --max-time 2 https://api.ipify.org || echo "")
  [[ -z "$IPV4" ]] && IPV4="<服务器IP>"
  local IPV6; IPV6=$(get_ipv6_address)

  local total ext_count
  total=$(jq '.inbounds | length' "$CONFIG" 2>/dev/null || echo "0")
  ext_count=$(jq '[to_entries[] | select(.value.type=="hysteria2")] | length' "$META" 2>/dev/null || echo "0")
  if [[ ( -z "$total" || "$total" == "0" ) && ( -z "$ext_count" || "$ext_count" == "0" ) ]]; then say "暂无节点"; set -e; return; fi

  local idx=0 json
  while IFS= read -r json; do
    idx=$((idx+1))
    local PORT TAG TYPE
    PORT=$(jq -r '.listen_port' <<<"$json")
    TAG=$(jq -r '.tag' <<<"$json")
    TYPE=$(jq -r '.type' <<<"$json")
    say "[$idx] 端口: $PORT | 协议: $TYPE | 名称: $TAG"
    port_status "$PORT"; case $? in 1) warn "端口 $PORT 被其他进程占用";; 2) warn "端口 $PORT 未监听";; esac

    if [[ "$TYPE" == "vless" ]]; then
      local UUID PBK SID SERVER_NAME FP
      UUID=$(jq -r '.users[0].uuid' <<<"$json")
      PBK=$(jq -r --arg tag "$TAG" '.[$tag].pbk // empty' "$META" 2>/dev/null)
      SID=$(jq -r --arg tag "$TAG" '.[$tag].sid // empty' "$META" 2>/dev/null)
      SERVER_NAME=$(jq -r --arg tag "$TAG" '.[$tag].sni // empty' "$META" 2>/dev/null)
      FP=$(jq -r --arg tag "$TAG" '.[$tag].fp // "chrome"' "$META" 2>/dev/null)
      [[ -z "$SERVER_NAME" || "$SERVER_NAME" == "null" ]] && SERVER_NAME=$(jq -r '.tls.reality.handshake.server // .tls.server_name // empty' <<<"$json")
      [[ -z "$SID" || "$SID" == "null" ]] && SID=$(jq -r '.tls.reality.short_id[0] // empty' <<<"$json")
      if [[ -n "$PBK" && -n "$SID" && -n "$SERVER_NAME" ]]; then
        say "vless://${UUID}@${IPV4}:${PORT}?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&pbk=${PBK}&sid=${SID}&sni=${SERVER_NAME}&fp=${FP}#${TAG}"
      else
        warn "节点参数不完整，无法生成链接"
      fi
    elif [[ "$TYPE" == "socks" ]]; then
      local USER PASS ENCODED
      USER=$(jq -r '.users[0].username' <<<"$json")
      PASS=$(jq -r '.users[0].password' <<<"$json")
      ENCODED=$(printf "%s" "$USER:$PASS" | base64)
      say "IPv4: socks://${ENCODED}@${IPV4}:${PORT}#${TAG}"
      [[ -n "$IPV6" ]] && say "IPv6: socks://${ENCODED}@[${IPV6}]:${PORT}#${TAG}"
    fi
    say "---------------------------------------------------"
  done < <(jq -c '.inbounds[]' "$CONFIG" 2>/dev/null)

  if [[ -n "$ext_count" && "$ext_count" != "0" ]]; then
    for key in $(jq -r 'to_entries[] | select(.value.type=="hysteria2") | .key' "$META"); do
      idx=$((idx+1))
      local PORT TAG AUTH OBFS SNI
      TAG="$key"
      PORT=$(jq -r --arg t "$TAG" '.[$t].port // empty' "$META")
      say "[$idx] 端口: $PORT | 协议: hysteria2 | 名称: $TAG"	  
      AUTH=$(jq -r --arg t "$TAG" '.[$t].auth // empty' "$META")
      OBFS=$(jq -r --arg t "$TAG" '.[$t].obfs // empty' "$META")
      SNI=$(jq -r --arg t "$TAG" '.[$t].sni // empty' "$META")
      if [[ -n "$AUTH" && -n "$OBFS" && -n "$SNI" ]]; then
        say "hysteria2://${AUTH}@${IPV4}:${PORT}?obfs=salamander&obfs-password=${OBFS}&sni=${SNI}&insecure=1#${TAG}"
        [[ -n "$IPV6" ]] && say "hysteria2://${AUTH}@[${IPV6}]:${PORT}?obfs=salamander&obfs-password=${OBFS}&sni=${SNI}&insecure=1#${TAG}"
      else
        warn "节点参数不完整，无法生成链接"
      fi
      say "---------------------------------------------------"
    done
  fi
  set -e
}

delete_node() {
  local COUNT; COUNT=$(jq '.inbounds | length' "$CONFIG" 2>/dev/null)
  local ext_count; ext_count=$(jq '[to_entries[] | select(.value.type=="hysteria2")] | length' "$META" 2>/dev/null)
  if [[ ( -z "$COUNT" || "$COUNT" == "0" ) && ( -z "$ext_count" || "$ext_count" == "0" ) ]]; then say "暂无节点"; return; fi
  view_nodes
  say "[0] 返回主菜单"
  say "[ss] 删除所有节点"
  read -rp "请输入要删除的节点序号： " IDX
  [[ "$IDX" == "0" || -z "$IDX" ]] && return
  if [[ "$IDX" == "ss" ]]; then
    read -rp " 确认删除全部节点？(y/N): " c; [[ "$c" == "y" ]] || { say "已取消"; return; }
    local tmpcfg; tmpcfg=$(mktemp)
    jq '.inbounds = []' "$CONFIG" >"$tmpcfg" && mv "$tmpcfg" "$CONFIG"
    printf '{}' >"$META"
    shopt -s nullglob
    for f in /etc/systemd/system/hysteria2*.service; do
      name=$(basename "$f")
      systemctl disable --now "$name" >/dev/null 2>&1 || true
      rm -f "$f"
    done
    shopt -u nullglob
    systemctl daemon-reload || true
    rm -rf /etc/hysteria2
    ok "所有节点已删除"; return
  fi
  if ! [[ "$IDX" =~ ^[0-9]+$ ]]; then warn "无效输入"; return; fi
  local idx0=$((IDX-1))
  if (( idx0 < 0 || idx0 >= (COUNT + ext_count) )); then warn "序号越界"; return; fi

  if (( idx0 >= COUNT )); then
    local ext_index=$((idx0 - COUNT))
    local tag_to_delete; tag_to_delete=$(jq -r --argjson i "$ext_index" 'to_entries | map(select(.value.type=="hysteria2")) | .[$i].key // empty' "$META")
    if [[ -n "$tag_to_delete" && "$tag_to_delete" != "null" ]]; then
      local port_del; port_del=$(jq -r --arg t "$tag_to_delete" '.[$t].port // empty' "$META")
      local tmpmeta; tmpmeta=$(mktemp)
      jq "del(.\"$tag_to_delete\")" "$META" >"$tmpmeta" && mv "$tmpmeta" "$META"
      if [[ -f "/etc/systemd/system/hysteria2-${port_del}.service" ]]; then
        systemctl disable --now "hysteria2-${port_del}" >/dev/null 2>&1 || true
        rm -f "/etc/systemd/system/hysteria2-${port_del}.service"
      fi
      systemctl daemon-reload || true
      [[ -n "$port_del" ]] && rm -f "/etc/hysteria2/${port_del}.yaml" "/etc/hysteria2/${port_del}.key" "/etc/hysteria2/${port_del}.crt"
      ok "已删除节点 [$IDX]"
      return
    fi
  fi
  local tag; tag=$(jq -r ".inbounds[$((idx0))].tag // empty" "$CONFIG")
  local tmpcfg; tmpcfg=$(mktemp)
  jq "del(.inbounds[$((idx0))])" "$CONFIG" >"$tmpcfg" && mv "$tmpcfg" "$CONFIG"
  if [[ -n "$tag" && "$tag" != "null" ]]; then
    local tmpmeta; tmpmeta=$(mktemp)
    jq "del(.\"$tag\")" "$META" >"$tmpmeta" && mv "$tmpmeta" "$META"
  fi
  ok "已删除节点 [$IDX]"
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
    0) return ;;
    *) warn "无效输入" ;;
  esac
}

# ============= NAT 菜单 =============
nat_mode_menu() {
  say "====== NAT模式设置 ======"
  say "1) 设置范围端口"
  say "2) 设置TCP端口"
  say "3) 设置UDP端口"
  say "4) 查看当前NAT端口规则"
  say "5) 退出NAT模式"
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

# ============= 主菜单 =============
main_menu() {
  say ""
  show_version_info
  say "============= 嘻嘻哈哈 节点管理工具（IPv4 + IPv6） ============="
  say "1) 添加节点"
  say "2) 查看所有节点"
  say "3) 删除节点"
  say "4) 脚本服务"
  say "5) NAT模式设置"
  say "0) 退出"
  say "==============================================================="
  read -rp "请输入操作编号: " CHOICE
  case "$CHOICE" in
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
ensure_dirs
install_dependencies
install_singbox_if_needed || true
install_systemd_service
while true; do main_menu; done
