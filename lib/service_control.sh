#!/usr/bin/env bash
# sk5.sh 模块: 服务控制

# 依赖: main.sh 中的全局变量和辅助函数，以及 deps_and_util.sh 中的 _SYSTEMCTL_CMD, _RCSERVICE_CMD, _sb_any_port_listening 等

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

  "$_SYSTEMCTL_CMD" daemon-reload >/dev/null 2>&1 || log_msg "WARN" "daemon-reload failed"
  "$_SYSTEMCTL_CMD" enable --now sing-box >/dev/null 2>&1 || log_msg "WARN" "enable sing-box failed"

  local okflag=0
  for i in $(seq 1 20); do
    "$_SYSTEMCTL_CMD" is-active --quiet sing-box && { okflag=1; break; }
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
  "$_RCSERVICE_CMD" add sing-box default >/dev/null 2>&1 || log_msg "WARN" "rc-update failed"
  "$_RCSERVICE_CMD" sing-box restart >/dev/null 2>&1 || "$_RCSERVICE_CMD" sing-box start >/dev/null 2>&1 || log_msg "WARN" "rc-service start failed"
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

restart_singbox() {
  local bin; bin="$(_sb_bin)"
  local cfg; cfg="$(_sb_cfg)"

  if [[ -n "$_SYSTEMCTL_CMD" ]]; then
    pkill -9 sing-box >/dev/null 2>&1 || true
    "$_SYSTEMCTL_CMD" kill -s SIGKILL sing-box >/dev/null 2>&1 || true
    sleep 0.4
    if ! "$bin" check -c "$cfg" >/dev/null 2>&1; then
      err "配置文件校验失败：$cfg"; "$bin" check -c "$cfg" || true; return 1
    fi
    
    # 使用 systemctl restart 是最标准的方式
    "$_SYSTEMCTL_CMD" restart sing-box >/dev/null 2>&1 || { warn "systemctl restart failed, falling back to nohup"; nohup sing-box run -c /etc/sing-box/config.json > $LOG_FILE 2>&1 & }
    
    local okflag=0
    for i in $(seq 1 30); do
      "$_SYSTEMCTL_CMD" is-active --quiet sing-box && { okflag=1; break; }
      _sb_any_port_listening && { okflag=1; break; }
      sleep 1
    done
    if (( okflag==1 )); then ok "Sing-box 重启完成（systemd）"; return 0; fi
    warn "当前环境虽有 systemctl，但重启失败；切换 fallback 后台运行"
  elif [[ -n "$_RCSERVICE_CMD" ]] && [[ -f /etc/init.d/sing-box ]]; then
    "$_RCSERVICE_CMD" sing-box restart >/dev/null 2>&1 || "$_RCSERVICE_CMD" sing-box start >/dev/null 2>&1 || log_msg "WARN" "rc-service failed"
    local okflag=0
    for i in $(seq 1 30); do
      "$_RCSERVICE_CMD" sing-box status 2>/dev/null | grep -q started && { okflag=1; break; }
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
     if [ -t 1 ]; then say " [自动优化] Sing-box 进程优先级已提升。"; fi
  fi
  
  if is_docker || [[ -f /.dockerenv ]]; then
    renice -n 10 -p $$ >/dev/null 2>&1 || true
  fi
}

# ============= 系统检测与修复菜单 =============
system_check() {
  local issues=0
  if command -v sing-box >/dev/null 2>&1; then ok "sing-box 已安装"; else err "sing-box 未安装"; issues=1; fi
  local init; init=$(detect_init_system)
  if [[ "$init" == "systemd" ]]; then
    if "$_SYSTEMCTL_CMD" is-active --quiet sing-box; then ok "Sing-box 服务运行中"
    else
      if ! "$_SYSTEMCTL_CMD" status sing-box >/dev/null 2>&1; then err "Sing-box 服务未配置 (systemd)"; issues=1
      elif "$_SYSTEMCTL_CMD" is-failed --quiet sing-box; then err "Sing-box 服务启动失败"; issues=1
      else err "Sing-box 服务未运行"; issues=1
      fi
    fi
  elif [[ "$init" == "openrc" ]]; then
    if "$_RCSERVICE_CMD" sing-box status 2>/dev/null | grep -q started; then ok "Sing-box 服务运行中 (OpenRC)"
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
    if ! "$_SYSTEMCTL_CMD" is-active --quiet "$name"; then
      if [[ ! -f /etc/hysteria2/${port}.crt || ! -f /etc/hysteria2/${port}.key ]]; then
        generate_self_signed_cert "/etc/hysteria2/${port}.key" "/etc/hysteria2/${port}.crt" "bing.com" && ok "已重新生成端口 $port 证书"
      fi
      "$_SYSTEMCTL_CMD" daemon-reload >/dev/null 2>&1 || log_msg "WARN" "daemon-reload failed"
      "$_SYSTEMCTL_CMD" enable "$name" >/dev/null 2>&1 || log_msg "WARN" "enable $name failed"
      "$_SYSTEMCTL_CMD" restart "$name" >/dev/null 2>&1 || log_msg "WARN" "restart $name failed"
      sleep 1
      "$_SYSTEMCTL_CMD" is-active --quiet "$name" && ok "Hysteria2-${port} 服务已启动" || err "Hysteria2-${port} 服务仍无法启动"
    fi
  done
  shopt -u nullglob
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
    [[ "$init" == "systemd" ]] && "$_SYSTEMCTL_CMD" stop sing-box || true
    [[ "$init" == "openrc"  ]] && "$_RCSERVICE_CMD" sing-box stop >/dev/null 2>&1 || true
    install -m 0755 "sing-box-${LATEST}-linux-${ARCH}/sing-box" /usr/local/bin/sing-box
    [[ "$init" == "systemd" ]] && "$_SYSTEMCTL_CMD" start sing-box || true
    [[ "$init" == "openrc"  ]] && "$_RCSERVICE_CMD" sing-box start >/dev/null 2>&1 || true
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
        for f in /etc/systemd/system/hysteria2*.service /etc/systemd/system/cf-tunnel-*.service; do
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
      rm -f /etc/systemd/system/cf-tunnel-*.service
      rm -f /lib/systemd/system/cf-tunnel-*.service
      [ -n "$(command -v systemctl)" ] && systemctl daemon-reload >/dev/null 2>&1 || true

      rm -f /etc/init.d/sing-box
      rm -f /etc/local.d/sb-singbox.start
      rm -f /etc/local.d/argo_*.start # CF Tunnel local.d

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
      SCRIPT_PATH="$(realpath "$0")" # 假设在 main.sh 运行
      rm -f "$SCRIPT_PATH"
      rm -rf "$SCRIPT_DIR/lib" # 删除模块文件

      echo "脚本已删除，程序退出。"
      exit 0
      ;;
    2)
      systemctl stop sing-box 2>/dev/null
      echo " 正在重新安装 Sing-box（保留节点配置）..."
      # 简易安装逻辑，避免依赖外部 install.sh
      install_singbox_if_needed
      
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