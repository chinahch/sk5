#!/usr/bin/env bash
# sk5.sh — Sing-box 管理脚本（systemd/OpenRC 自适应）
# 功能：依赖安装、sing-box 安装/自启动、添加/查看/删除节点、修复/重装、升级、重启
# 重点：采用"端口监听 + systemd running"双判据的稳健重启逻辑；避免阻塞与假失败
# 说明：本脚本不使用 "set -e" 以避免交互菜单被中断；每步有自己的错误处理。

umask 022

CONFIG="/etc/sing-box/config.json"
META="/etc/sing-box/nodes_meta.json"

say() { printf "%s\n" "$*"; }
err() { printf " %s\n" "$*" >&2; }
ok()  { printf " %s\n" "$*"; }
warn(){ printf " %s\n" "$*"; }

# ---------------------- 工具函数 ----------------------
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
        DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y "${need[@]}" >/dev/null 2>&1 || true ;;
      alpine) apk add --no-cache "${need[@]}" >/dev/null 2>&1 || true ;;
      centos|rhel) yum install -y "${need[@]}" >/dev/null 2>&1 || true ;;
      fedora) dnf install -y "${need[@]}" >/dev/null 2>&1 || true ;;
      *) warn "未识别系统，请确保安装：${need[*]}" ;;
    esac
  fi
  ok "依赖已满足（curl/jq/uuidgen/openssl/ss/lsof）"
}

install_singbox_if_needed() {
  if command -v sing-box >/dev/null 2>&1; then
    return 0
  fi

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

# 生成唯一 tag
generate_unique_tag() {
  local base="vless-reality-$(get_country_code)"
  local try=0 RAND CANDIDATE
  while true; do
    RAND=$(tr -dc 'A-Z' </dev/urandom 2>/dev/null | head -c1)
    CANDIDATE="${base}-${RAND}"
    if ! jq -e --arg t "$CANDIDATE" '.inbounds[] | select(.tag == $t)' "$CONFIG" >/dev/null 2>&1; then
      printf "%s\n" "$CANDIDATE"
      return
    fi
    try=$((try+1))
    if [[ $try -ge 26 ]]; then
      printf "%s-%s\n" "$base" "$(date +%s)"
      return
    fi
  done
}
get_ipv6_address() {
  ip -6 addr show scope global 2>/dev/null | awk '/inet6/{print $2}' | cut -d/ -f1 | head -n1
}

# 端口状态检查函数
# 修复后的 port_status 函数
port_status() {
  local port="$1"

  # 如果当前节点是 hysteria2，直接返回 0（正常）
  if [[ "$protocol" == "hysteria2" ]]; then
    return 0
  fi

  # 0=sing-box监听, 1=其他进程占用, 2=未监听/无法检测
  if command -v lsof >/dev/null 2>&1; then
    local out
    out=$(lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $1}')
    if [[ -z "$out" ]]; then
      return 2
    fi
    if echo "$out" | grep -Eq '^(sing-box)$'; then
      return 0
    else
      return 1
    fi
  elif command -v ss >/dev/null 2>&1; then
    local out
    out=$(ss -ltnp "sport = :$port" 2>/dev/null || true)
    if ! grep -q LISTEN <<<"$out"; then
      return 2
    fi
    if grep -q 'users:(("sing-box"' <<<"$out"; then
      return 0
    else
      return 1
    fi
  else
    return 2
  fi
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
  rc-update add sing-box default >/dev/null 2>&1 || true
  rc-service sing-box restart >/dev/null 2>&1 || rc-service sing-box start >/dev/null 2>&1 || true
}

kill_rogue_singbox() {
  local sysd_pid pids
  sysd_pid=$(systemctl show -p MainPID --value sing-box 2>/dev/null || echo "")
  pids=$(pgrep -f "/usr/local/bin/sing-box run -c /etc/sing-box/config.json" || true)
  for p in $pids; do
    if [[ -n "$sysd_pid" && "$p" == "$sysd_pid" ]]; then
      continue
    fi
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

    local ok=0 i any_listen
    for i in {1..60}; do  # 30s
      any_listen=$(jq -r '.inbounds[].listen_port' "$CONFIG" 2>/dev/null | while read -r p; do
        [[ -z "$p" ]] && continue
        if ss -ltnp 2>/dev/null | grep -q ":$p "; then echo ok; break; fi
        if timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" >/dev/null 2>&1; then echo ok; break; fi
      done)
      if [[ "$any_listen" == "ok" ]]; then ok=1; break; fi
      if systemctl is-active --quiet sing-box; then ok=1; break; fi
      printf "."; sleep 0.5
    done
    echo
    if [[ $ok -eq 1 ]]; then
      ok "Sing-box 重启完成（检测到入站端口在监听或服务已 running）"
    else
      err "Sing-box 重启失败（未见端口监听/服务未进入 running）"
      journalctl -u sing-box --no-pager -n 80 2>/dev/null || true
      return 1
    fi
  elif [[ "$init" == "openrc" ]]; then
    timeout 8s rc-service sing-box stop >/dev/null 2>&1 || true
    # 强制终止可能残留的 sing-box 进程，避免端口占用
    pids=$(pgrep -x sing-box) || true
    if [[ -n "$pids" ]]; then
      for pid in $pids; do kill -9 "$pid" 2>/dev/null || true; done
    fi
    sleep 0.4
    timeout 8s rc-service sing-box start >/dev/null 2>&1 || true
    sleep 1
    if rc-service sing-box status 2>/dev/null | grep -q started; then
      ok "Sing-box 重启完成（OpenRC）"
    else
      err "Sing-box 重启失败（OpenRC）"
      tail -n 80 /var/log/sing-box.log 2>/dev/null || true
      return 1
    fi
  else
    warn "未检测到受支持的服务管理器，将后台启动 Sing-box 进程"
    # 强制终止可能残留的 sing-box 进程，避免端口占用
    pids=$(pgrep -x sing-box) || true
    if [[ -n "$pids" ]]; then
      for pid in $pids; do kill -9 "$pid" 2>/dev/null || true; done
    fi
    # 启动前验证配置有效性
    if ! /usr/local/bin/sing-box check -c "$CONFIG" >/dev/null 2>&1; then
      err "配置文件校验失败，无法重启 Sing-box，请检查 $CONFIG"
      sing-box check -c "$CONFIG"
      return 1
    fi
    # 后台启动 Sing-box 进程
    nohup /usr/local/bin/sing-box run -c "$CONFIG" >/var/log/sing-box.log 2>&1 &
    local SING_PID=$!
    local ok_flag=0 i any_listen
    for i in {1..60}; do
      any_listen=$(jq -r '.inbounds[].listen_port' "$CONFIG" 2>/dev/null | while read -r p; do
        [[ -z "$p" ]] && continue
        if ss -ltnp 2>/dev/null | grep -q ":$p "; then echo ok; break; fi
        if timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" >/dev/null 2>&1; then echo ok; break; fi
      done)
      if [[ "$any_listen" == "ok" ]]; then
        ok_flag=1
        break
      fi
      if kill -0 "$SING_PID" 2>/dev/null; then
        sleep 0.5
      else
        break
      fi
    done
    if [[ $ok_flag -eq 1 ]]; then
      ok "Sing-box 重启完成（进程已启动）"
    else
      err "Sing-box 重启失败（未检测到端口监听/进程未运行）"
      tail -n 80 /var/log/sing-box.log 2>/dev/null || true
      return 1
    fi
  fi
}
install_systemd_service() {
    local SERVICE_FILE="/lib/systemd/system/sing-box.service"
    cat > "$SERVICE_FILE" <<EOF
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

    echo "已安装并启用 systemd 自启动服务：sing-box"
}

# 调用
install_systemd_service

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
    echo "====== 修复 / 重装 Sing-box ======"
    echo "1) 完全卸载（清空所有服务）"
    echo "2) 保留节点配置并重装 Sing-box"
    echo "0) 返回主菜单"
    read -rp "请选择: " choice
    case "$choice" in
        1)
            echo " 即将卸载 Sing-box、Hysteria2 及相关文件..."
            read -rp "确认继续 (y/N): " confirm
            [[ "$confirm" != "y" && "$confirm" != "Y" ]] && return

            # ======= 停止并禁用服务 =======
            systemctl stop sing-box 2>/dev/null
            systemctl disable sing-box 2>/dev/null
            # 停止并禁用所有 Hysteria2 实例
            shopt -s nullglob
            for f in /etc/systemd/system/hysteria2*.service; do
                name=$(basename "$f")
                systemctl stop "$name" 2>/dev/null || true
                systemctl disable "$name" 2>/dev/null || true
            done
            shopt -u nullglob

            # ======= 删除 systemd 单元 =======
            rm -f /etc/systemd/system/sing-box.service
            rm -f /lib/systemd/system/sing-box.service
            rm -f /etc/systemd/system/hysteria2*.service
            rm -f /lib/systemd/system/hysteria2*.service

            # ======= 删除可执行文件 =======
            rm -f /usr/local/bin/sing-box
            rm -f /usr/bin/sing-box
            rm -f /usr/local/bin/hysteria
            rm -f /usr/bin/hysteria

            # ======= 删除配置和缓存 =======
            rm -rf /etc/sing-box
            rm -rf /var/lib/sing-box
            rm -rf /var/log/sing-box
            rm -rf /tmp/sing-box*
            rm -rf /etc/hysteria2
            rm -rf /var/lib/hysteria2
            rm -rf /var/log/hysteria2
            rm -rf /tmp/hysteria2*

            # ======= 删除元数据文件（如果有） =======
            rm -f "$META"

            # ======= 卸载 uuidgen/openssl =======
            apt-get clean

            # ======= 刷新 systemd =======
            systemctl daemon-reload

            # ======= 删除当前脚本 =======
            SCRIPT_PATH="$0"
            rm -f "$SCRIPT_PATH"

            echo " Sing-box、Hysteria2 已完全卸载，脚本文件已删除"
            exit 0
            ;;
        2)
            systemctl stop sing-box 2>/dev/null
            echo " 正在重新安装 Sing-box（保留节点配置）..."
            bash <(curl -fsSL https://sing-box.app/install.sh)
            echo " Sing-box 已重新安装完成（节点已保留）"
            ;;
        0)
            return
            ;;
        *)
            echo "无效选择"
            ;;
    esac
}
# ---------------------- 系统检测与修复 ----------------------
diagnose_menu() {
    echo "====== 系统检测与修复 ======"
    echo "1) 系统检测"
    echo "2) 修复错误"
    echo "0) 返回主菜单"
    read -rp "请选择: " opt
    case "$opt" in
            4) disable_nat_mode ;;
1)
            system_check
            ;;
        2)
            fix_errors
            ok "修复操作已完成，正在重新检测..."
            system_check
            echo ""
            warn "如 Sing-box 服务仍无法启动，请运行 'journalctl -u sing-box -e' 查看错误日志"
            warn "如 config.json 配置有误，请执行 'sing-box check -c $CONFIG' 检查并修正"
            warn "如端口冲突或被占用，请修改配置端口或停止冲突进程 (使用 lsof -i:<端口号> 查看占用)"
            warn "如 Hysteria2 证书缺失，请确保 /etc/hysteria2/<端口>.crt 和 .key 文件存在，必要时重新生成证书"
            warn "如依赖未自动安装成功，请手动安装 curl、jq、uuidgen、openssl、lsof、ss"
            warn "如未使用 systemd，可通过查看 /var/log/sing-box.log 获取 Sing-box 日志输出"
            ;;
        0)
            return
            ;;
        *)
            warn "无效输入"
            ;;
    esac
}

system_check() {
    if command -v sing-box >/dev/null 2>&1; then
        ok "sing-box 已安装"
    else
        err "sing-box 未安装"
    fi

    local init; init=$(detect_init_system)
    if [[ "$init" == "systemd" ]]; then
        if systemctl is-active --quiet sing-box; then
            ok "Sing-box 服务正在运行"
        else
            if ! systemctl status sing-box >/dev/null 2>&1; then
                err "Sing-box 服务未配置 (systemd)"
            elif systemctl is-failed --quiet sing-box; then
                err "Sing-box 服务启动失败"
            else
                err "Sing-box 服务未运行"
            fi
        fi
    elif [[ "$init" == "openrc" ]]; then
        if rc-service sing-box status 2>/dev/null | grep -q started; then
            ok "Sing-box 服务正在运行 (OpenRC)"
        else
            if [[ -f /etc/init.d/sing-box ]]; then
                err "Sing-box 服务未运行 (OpenRC)"
            else
                err "Sing-box 服务未配置 (OpenRC)"
            fi
        fi
    else
        if pgrep -x sing-box >/dev/null 2>&1; then
            ok "Sing-box 进程正在运行"
        else
            err "Sing-box 进程未运行"
        fi
    fi

    # 检查 Hysteria2 服务状态
    local hyst_found=0
    shopt -s nullglob
    for f in /etc/systemd/system/hysteria2*.service; do
        hyst_found=1
        local name=$(basename "$f")
        local port=${name#hysteria2-}; port=${port%.service}
        if systemctl is-active --quiet "$name"; then
            ok "Hysteria2-${port} 服务运行中"
        else
            if systemctl is-failed --quiet "$name"; then
                err "Hysteria2-${port} 服务启动失败"
            else
                err "Hysteria2-${port} 服务未运行"
            fi
        fi
    done
    shopt -u nullglob
    if [[ $hyst_found -eq 0 ]]; then
        ok "Hysteria2 服务未启用"
    fi

    # 检查配置文件合法性
    if command -v sing-box >/dev/null 2>&1; then
        if ! sing-box check -c "$CONFIG" >/dev/null 2>&1; then
            err "配置文件 $(basename "$CONFIG") 不合法"
        else
            ok "配置文件合法"
        fi
    else
        warn "无法验证配置文件 (sing-box 未安装)"
    fi

    # 检查所有入站端口状态
    local any_issue=0
    local port
    for port in $(jq -r '.inbounds[].listen_port' "$CONFIG" 2>/dev/null); do
        [[ -z "$port" ]] && continue
        port_status "$port"
        case $ in
            0) : ;;
            1) warn "端口 $port 被其他进程占用"; any_issue=1 ;;
            2) warn "端口 $port 未监听"; any_issue=1 ;;
        esac
    done
    local dup_ports
    dup_ports=$(jq -r '.inbounds[].listen_port' "$CONFIG" 2>/dev/null | sort | uniq -d)
    if [[ -n "$dup_ports" ]]; then
        err "配置文件端口冲突: $(echo "$dup_ports" | xargs)"
        any_issue=1
    fi
    if [[ $any_issue -eq 0 ]]; then
        ok "所有入站端口监听正常"
    fi

    # 检查依赖项是否存在
    local missing=()
    for cmd in curl jq uuidgen openssl lsof ss; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if ((${#missing[@]} > 0)); then
        err "缺少依赖: ${missing[*]}"
    else
        ok "依赖项齐全 (curl/jq/uuidgen/openssl/lsof/ss)"
    fi
}

fix_errors() {
    # 自动安装缺失的依赖
    install_dependencies

    # 自动安装 sing-box（如果未安装）
    install_singbox_if_needed || true

    # 统一用 systemd 启动 sing-box
    install_systemd_service
    # 修复 Hysteria2 服务
    local need_hy_install=0
    shopt -s nullglob
    for f in /etc/systemd/system/hysteria2*.service; do
        if ! command -v hysteria >/dev/null 2>&1; then
            need_hy_install=1
            break
        fi
    done
    if [[ $need_hy_install -eq 1 ]]; then
        local H_VERSION="2.6.2"
        local arch=$(uname -m)
        case "$arch" in
            x86_64|amd64) arch="amd64" ;;
            aarch64|arm64) arch="arm64" ;;
            *) err "暂不支持的架构：$arch" ;;
        esac
        local tmp; tmp=$(mktemp -d)
        (
            set -e
            cd "$tmp"
            curl -sSL "https://github.com/apernet/hysteria/releases/download/app/v${H_VERSION}/hysteria-linux-${arch}" -o hysteria-bin || { err "下载 hysteria 失败"; exit 1; }
            install -m 0755 hysteria-bin /usr/local/bin/hysteria
        ) || true
        rm -rf "$tmp"
        if command -v hysteria >/dev/null 2>&1; then
            ok "hysteria 安装完成"
        fi
    fi

    for f in /etc/systemd/system/hysteria2*.service; do
        local name=$(basename "$f")
        local port=${name#hysteria2-}; port=${port%.service}
        if ! systemctl is-active --quiet "$name"; then
            if [[ ! -f /etc/hysteria2/${port}.crt || ! -f /etc/hysteria2/${port}.key ]]; then
                openssl ecparam -name prime256v1 -genkey -noout -out /etc/hysteria2/${port}.key 2>/dev/null || \
                    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out /etc/hysteria2/${port}.key 2>/dev/null
                if [[ $ -ne 0 ]]; then
                    err "端口 $port 私钥生成失败"
                else
                    openssl req -new -x509 -nodes -key /etc/hysteria2/${port}.key -out /etc/hysteria2/${port}.crt -subj "/CN=bing.com" -days 36500 >/dev/null 2>&1 || \
                        err "端口 $port 证书生成失败"
                fi
                if [[ -f /etc/hysteria2/${port}.crt && -f /etc/hysteria2/${port}.key ]]; then
                    ok "已重新生成端口 $port 证书"
                endif
                fi
            fi
            systemctl daemon-reload >/dev/null 2>&1 || true
            systemctl restart "$name" >/dev/null 2>&1 || true
            sleep 1
            if systemctl is-active --quiet "$name"; then
                ok "Hysteria2-${port} 服务已启动"
            else
                err "Hysteria2-${port} 服务仍无法启动"
            fi
        fi
    done
    shopt -u nullglob
}

# ---------------------- 节点操作 ----------------------
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
    if ! command -v sing-box >/dev/null 2>&1; then
      err "未检测到 sing-box，无法生成 Reality 密钥。请先选择菜单 6 → 重装（保留节点）或安装。"
      return 1
    fi

    local PORT
    while true; do
  local prompt_text
  if [[ -f /etc/sing-box/nat_ports.json ]]; then
    prompt_text="请输入端口号（留空自动随机 NAT 范围；输入 0 返回）: "
  else
    prompt_text="请输入端口号（留空自动随机 30000-39999；输入 0 返回）: "
  fi
  read -rp "$prompt_text" PORT
  if [[ -z "$PORT" ]]; then
    if [[ -f /etc/sing-box/nat_ports.json ]]; then
      PORT=$(get_random_nat_port)
    else
      PORT=$((RANDOM % 1000 + 30000))
    fi
    say "（已自动选择随机端口：$PORT）"
  fi
  [[ "$PORT" == "0" ]] && return
  if ! [[ "$PORT" =~ ^[0-9]+$ ]] || ((PORT<1 || PORT>65535)); then
    warn "端口无效"; continue
  fi
  if ! check_nat_port "$PORT"; then
    warn "端口 $PORT 不在 NAT 模式允许的范围内，请重新输入"
    continue
  fi
      if [[ -z "$PORT" ]]; then 
        PORT=$((RANDOM % 1000 + 30000))
        say "（已自动选择随机端口：$PORT）"
      fi
      [[ "$PORT" == "0" ]] && return
      if ! [[ "$PORT" =~ ^[0-9]+$ ]] || ((PORT<1 || PORT>65535)); then
        warn "端口无效"; continue
      fi
      if ! check_nat_port "$PORT"; then warn "端口 $PORT 不在 NAT 模式允许的范围内，请重新输入"; continue; fi
      if jq -e --argjson p "$PORT" '.inbounds[] | select(.listen_port == $p)' "$CONFIG" >/dev/null 2>&1; then
        warn "端口 $PORT 已存在，请换一个。"
        continue
      fi
      break
    done

    local UUID FP FLOW SERVER_NAME KEY_PAIR PRIVATE_KEY PUBLIC_KEY SHORT_ID TAG tmpcfg
    if command -v uuidgen >/dev/null 2>&1; then 
      UUID=$(uuidgen)
    else 
      UUID=$(openssl rand -hex 16 | sed 's/\(..\)/\1/g; s/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
    fi
    SERVER_NAME="www.cloudflare.com"
    FLOW="xtls-rprx-vision"
    # 指纹随机
    case $((RANDOM%5)) in
      0) FP="chrome";;
      *) FP="firefox";;
    esac

    KEY_PAIR=$(sing-box generate reality-keypair 2>/dev/null)
    PRIVATE_KEY=$(awk -F': ' '/PrivateKey/{print $2}' <<<"$KEY_PAIR")
    PUBLIC_KEY=$(awk -F': ' '/PublicKey/{print $2}' <<<"$KEY_PAIR")
    if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then 
      err "生成 Reality 密钥失败"
      return 1
    fi
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
      err "配置校验失败，请检查 $CONFIG"
      sing-box check -c "$CONFIG"
      return 1
    fi

    # 保存元数据
    local tmpmeta; tmpmeta=$(mktemp)
    jq --arg tag "$TAG" --arg pbk "$PUBLIC_KEY" --arg sid "$SHORT_ID" --arg sni "$SERVER_NAME" --arg port "$PORT" --arg fp "$FP" \
      '. + {($tag): {pbk:$pbk, sid:$sid, sni:$sni, port:$port, fp:$fp}}' "$META" >"$tmpmeta" && mv "$tmpmeta" "$META"

    local IPV4; IPV4=$(curl -s --max-time 2 https://api.ipify.org)
    say ""
    ok "添加成功：VLESS Reality"
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
    # SOCKS5
    local PORT USER PASS TAG tmpcfg
    while true; do
  local prompt_text
  if [[ -f /etc/sing-box/nat_ports.json ]]; then
    prompt_text="请输入端口号（留空自动随机 NAT 范围；输入 0 返回）: "
  else
    prompt_text="请输入端口号（留空自动随机 40000-49999；输入 0 返回）: "
  fi
  read -rp "$prompt_text" PORT
  if [[ -z "$PORT" ]]; then
    if [[ -f /etc/sing-box/nat_ports.json ]]; then
      PORT=$(get_random_nat_port)
    else
      PORT=$((RANDOM % 10000 + 40000))
    fi
    say "（已自动选择随机端口：$PORT）"
  fi
  [[ "$PORT" == "0" ]] && return
  if ! [[ "$PORT" =~ ^[0-9]+$ ]] || ((PORT<1 || PORT>65535)); then
    warn "端口无效"; continue
  fi
  if ! check_nat_port "$PORT"; then
    warn "端口 $PORT 不在 NAT 模式允许的范围内，请重新输入"
    continue
  fi
      if [[ -z "$PORT" ]]; then 
        PORT=$((RANDOM % 10000 + 40000))
        say "（已自动选择随机端口：$PORT）"
      fi
      [[ "$PORT" == "0" ]] && return
      if ! [[ "$PORT" =~ ^[0-9]+$ ]] || ((PORT<1 || PORT>65535)); then 
        warn "端口无效"; continue
      fi
      if ! check_nat_port "$PORT"; then warn "端口 $PORT 不在 NAT 模式允许的范围内，请重新输入"; continue; fi
      if jq -e --argjson p "$PORT" '.inbounds[] | select(.listen_port == $p)' "$CONFIG" >/dev/null 2>&1; then
        warn "端口 $PORT 已存在，请换一个。"; continue
      fi
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
      err "配置校验失败，请检查 $CONFIG"
      sing-box check -c "$CONFIG"
      return 1
    fi

    say ""
    ok "添加成功：SOCKS5"
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
  local PORT
  while true; do
  local prompt_text
  if [[ -f /etc/sing-box/nat_ports.json ]]; then
    prompt_text="请输入端口号（留空自动随机 NAT 范围；输入 0 返回）: "
  else
    prompt_text="请输入端口号（留空自动随机 50000-59999；输入 0 返回）: "
  fi
  read -rp "$prompt_text" PORT
  if [[ -z "$PORT" ]]; then
    if [[ -f /etc/sing-box/nat_ports.json ]]; then
      PORT=$(get_random_nat_port)
    else
      PORT=$((RANDOM % 10000 + 50000))
    fi
    say "（已自动选择随机端口：$PORT）"
  fi
  [[ "$PORT" == "0" ]] && return
  if ! [[ "$PORT" =~ ^[0-9]+$ ]] || ((PORT<1 || PORT>65535)); then
    warn "端口无效"; continue
  fi
  if ! check_nat_port "$PORT"; then
    warn "端口 $PORT 不在 NAT 模式允许的范围内，请重新输入"
    continue
  fi
    if [[ -z "$PORT" ]]; then
      PORT=$((RANDOM % 10000 + 50000))
      say "（已自动选择随机端口：$PORT）"
    fi
    [[ "$PORT" == "0" ]] && return
    if ! [[ "$PORT" =~ ^[0-9]+$ ]] || ((PORT<1 || PORT>65535)); then
      warn "端口无效"; continue
    fi
      if ! check_nat_port "$PORT"; then warn "端口 $PORT 不在 NAT 模式允许的范围内，请重新输入"; continue; fi
    if jq -e --argjson p "$PORT" '.inbounds[] | select(.listen_port == $p)' "$CONFIG" >/dev/null 2>&1; then
      warn "端口 $PORT 已存在，请换一个。"
      continue
    fi
    if jq -e --arg p "$PORT" 'to_entries[] | select(.value.type=="hysteria2" and (.value.port|tostring == $p))' "$META" >/dev/null 2>&1; then
      warn "端口 $PORT 已存在，请换一个。"
      continue
    fi
    break
  done

  local DOMAIN
  DOMAIN="bing.com"

  # 安装 Hysteria2（如未安装）
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
      curl -sSL "https://github.com/apernet/hysteria/releases/download/app/v${H_VERSION}/hysteria-linux-${arch}" -o hysteria-bin || {
        err "下载 hysteria 失败"; exit 1; }
      install -m 0755 hysteria-bin /usr/local/bin/hysteria
    ) || { rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
    ok "hysteria 安装完成"
  fi

  mkdir -p /etc/hysteria2

  # 生成自签证书
  openssl ecparam -name prime256v1 -genkey -noout -out /etc/hysteria2/${PORT}.key 2>/dev/null || \
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out /etc/hysteria2/${PORT}.key 2>/dev/null
  openssl req -new -x509 -nodes -key /etc/hysteria2/${PORT}.key -out /etc/hysteria2/${PORT}.crt -subj "/CN=${DOMAIN}" -days 36500 >/dev/null 2>&1 || {
    err "自签证书生成失败"; return 1; }

  # 生成密码
  local AUTH_PWD OBFS_PWD
  AUTH_PWD=$(openssl rand -base64 16 | tr -d '=+/' | cut -c1-16)
  OBFS_PWD=$(openssl rand -base64 8 | tr -d '=+/' | cut -c1-8)

  # 生成唯一 TAG
  local TAG="hysteria2-$(get_country_code)-$(tr -dc 'A-Z' </dev/urandom | head -c1)"
  if jq -e --arg t "$TAG" '.inbounds[] | select(.tag == $t)' "$CONFIG" >/dev/null 2>&1 || jq -e --arg t "$TAG" 'has($t)' "$META" >/dev/null 2>&1; then
    TAG="hysteria2-$(get_country_code)-$(date +%s)"
  fi

  # 写入配置文件
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

 # 创建 systemd 服务
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

# 让 systemd 重新加载配置，并设置开机自启（静默）
systemctl daemon-reload >/dev/null 2>&1
systemctl enable hysteria2-${PORT}.service >/dev/null 2>&1 || true
systemctl restart hysteria2-${PORT}.service >/dev/null 2>&1 || true


  sleep 1
  if systemctl is-active --quiet hysteria2-${PORT}; then
    ok "Hysteria2 服务已启动"
  else
    err "Hysteria2 服务启动失败，请检查日志 (journalctl -u hysteria2-${PORT})"
    return 1
  fi

  # 保存元数据
  local tmpmeta; tmpmeta=$(mktemp)
  jq --arg tag "$TAG" --arg port "$PORT" --arg sni "$DOMAIN" --arg obfs "$OBFS_PWD" --arg auth "$AUTH_PWD" \
    '. + {($tag): {type:"hysteria2", port:$port, sni:$sni, obfs:$obfs, auth:$auth}}' "$META" >"$tmpmeta" && mv "$tmpmeta" "$META"

  # 输出信息
  local IPV4 IPV6
  IPV4=$(curl -s --max-time 2 https://api.ipify.org || echo "")
  [[ -z "$IPV4" ]] && IPV4="<服务器IP>"
  IPV6=$(get_ipv6_address)
  say ""
  ok "添加成功：Hysteria2"
  say "端口: $PORT"
  say "Auth密码: $AUTH_PWD"
  say "Obfs密码: $OBFS_PWD"
  say "SNI域名: $DOMAIN"
  say "TAG: $TAG"
  say ""
  say " 客户端链接："
  if [[ -n "$IPV4" ]]; then
    say "hysteria2://${AUTH_PWD}@${IPV4}:${PORT}?obfs=salamander&obfs-password=${OBFS_PWD}&sni=${DOMAIN}&insecure=1#${TAG}"
  fi
  if [[ -n "$IPV6" ]]; then
    say "hysteria2://${AUTH_PWD}@[${IPV6}]:${PORT}?obfs=salamander&obfs-password=${OBFS_PWD}&sni=${DOMAIN}&insecure=1#${TAG}"
  fi
  say ""
}

view_nodes() {
  # 禁用严格错误模式
  set +e

  # 获取服务器IP地址
  local IPV4
  IPV4=$(curl -s --max-time 2 https://api.ipify.org || echo "")
  [[ -z "$IPV4" ]] && IPV4="<服务器IP>"
  
  local IPV6
  IPV6=$(get_ipv6_address)

  # 获取节点总数
  local total ext_count
  total=$(jq '.inbounds | length' "$CONFIG" 2>/dev/null || echo "0")
  ext_count=$(jq '[to_entries[] | select(.value.type=="hysteria2")] | length' "$META" 2>/dev/null || echo "0")

  if [[ ( -z "$total" || "$total" == "0" ) && ( -z "$ext_count" || "$ext_count" == "0" ) ]]; then 
    say "暂无节点"
    set -e
    return
  fi

  # 显示节点列表
  local idx=0 json
  while IFS= read -r json; do
    idx=$((idx+1))
    local PORT TAG TYPE UUID SERVER_NAME PBK SID FP
    PORT=$(jq -r '.listen_port' <<<"$json")
    TAG=$(jq -r '.tag' <<<"$json")
    TYPE=$(jq -r '.type' <<<"$json")

    say "[$idx] 端口: $PORT | 协议: $TYPE | 名称: $TAG"

    # 检查端口状态
    port_status "$PORT"
    case $ in
      0) : ;; # 正常监听，不显示警告
      1) warn "端口 $PORT 被其他进程占用" ;;
      2) warn "端口 $PORT 未监听" ;;
    esac

    if [[ "$TYPE" == "vless" ]]; then
      # 获取节点基本信息
      UUID=$(jq -r '.users[0].uuid' <<<"$json")
      # 获取元数据
      PBK=$(jq -r --arg tag "$TAG" '.[$tag].pbk // empty' "$META" 2>/dev/null)
      SID=$(jq -r --arg tag "$TAG" '.[$tag].sid // empty' "$META" 2>/dev/null)
      SERVER_NAME=$(jq -r --arg tag "$TAG" '.[$tag].sni // empty' "$META" 2>/dev/null)
      FP=$(jq -r --arg tag "$TAG" '.[$tag].fp // "chrome"' "$META" 2>/dev/null)
      # 从配置中提取后备值
      [[ -z "$SERVER_NAME" || "$SERVER_NAME" == "null" ]] && SERVER_NAME=$(jq -r '.tls.reality.handshake.server // .tls.server_name // empty' <<<"$json")
      [[ -z "$SID" || "$SID" == "null" ]] && SID=$(jq -r '.tls.reality.short_id[0] // empty' <<<"$json")
      # 生成客户端链接
      if [[ -n "$PBK" && -n "$SID" && -n "$SERVER_NAME" ]]; then
        say "vless://${UUID}@${IPV4}:${PORT}?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&pbk=${PBK}&sid=${SID}&sni=${SERVER_NAME}&fp=${FP}#${TAG}"
      else
        warn "节点参数不完整，无法生成链接"
      fi

    elif [[ "$TYPE" == "socks" ]]; then
      # SOCKS5节点处理
      local USER PASS ENCODED
      USER=$(jq -r '.users[0].username' <<<"$json")
      PASS=$(jq -r '.users[0].password' <<<"$json")
      ENCODED=$(printf "%s" "$USER:$PASS" | base64)
      say "IPv4: socks://${ENCODED}@${IPV4}:${PORT}#${TAG}"
      [[ -n "$IPV6" ]] && say "IPv6: socks://${ENCODED}@[${IPV6}]:${PORT}#${TAG}"
    fi

    say "---------------------------------------------------"
  done < <(jq -c '.inbounds[]' "$CONFIG" 2>/dev/null)

  # 列出 Hysteria2 节点
  if [[ -n "$ext_count" && "$ext_count" != "0" ]]; then
    for key in $(jq -r 'to_entries[] | select(.value.type=="hysteria2") | .key' "$META"); do
      idx=$((idx+1))
      local PORT TAG TYPE AUTH OBFS SNI
      TAG="$key"
      PORT=$(jq -r --arg t "$TAG" '.[$t].port // empty' "$META")
      TYPE="hysteria2"
      say "[$idx] 端口: $PORT | 协议: $TYPE | 名称: $TAG"
      if [[ "$TYPE" != "hysteria2" ]]; then
        port_status "$PORT"
        case $ in
          0) : ;;
          1) warn "端口 $PORT 被其他进程占用" ;;
          2) warn "端口 $PORT 未监听" ;;
        esac
      fi
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

  # 恢复严格错误模式
  set -e
}

delete_node() {
  local COUNT; COUNT=$(jq '.inbounds | length' "$CONFIG" 2>/dev/null)
  local ext_count; ext_count=$(jq '[to_entries[] | select(.value.type=="hysteria2")] | length' "$META" 2>/dev/null)
  if [[ ( -z "$COUNT" || "$COUNT" == "0" ) && ( -z "$ext_count" || "$ext_count" == "0" ) ]]; then 
    say "暂无节点"; return
  fi
  view_nodes
  say "[0] 返回主菜单"
  say "[all] 删除所有节点"
  read -rp "请输入要删除的节点序号 / all / 0: " IDX
  [[ "$IDX" == "0" || -z "$IDX" ]] && return
  if [[ "$IDX" == "all" ]]; then
    read -rp " 确认删除全部节点？(y/N): " c; [[ "$c" == "y" ]] || { say "已取消"; return; }
    local tmpcfg; tmpcfg=$(mktemp)
    jq '.inbounds = []' "$CONFIG" >"$tmpcfg" && mv "$tmpcfg" "$CONFIG"
    printf '{}' >"$META"
    # 停止并禁用所有 Hysteria2 实例
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
      local port_del
      port_del=$(jq -r --arg t "$tag_to_delete" '.[$t].port // empty' "$META")
      # 删除对应元数据
      local tmpmeta; tmpmeta=$(mktemp)
      jq "del(.\"$tag_to_delete\")" "$META" >"$tmpmeta" && mv "$tmpmeta" "$META"

      # 停止并移除对应服务
      if [[ -f "/etc/systemd/system/hysteria2-${port_del}.service" ]]; then
        systemctl disable --now "hysteria2-${port_del}" >/dev/null 2>&1 || true
        rm -f "/etc/systemd/system/hysteria2-${port_del}.service"
      else
        systemctl disable --now hysteria2 >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/hysteria2.service
        rm -f /lib/systemd/system/hysteria2.service
      fi
      systemctl daemon-reload || true
      # 删除配置文件和证书
      if [[ -f "/etc/hysteria2/${port_del}.yaml" ]]; then
        rm -f "/etc/hysteria2/${port_del}.yaml" "/etc/hysteria2/${port_del}.key" "/etc/hysteria2/${port_del}.crt"
      else
        rm -f /etc/hysteria2/server.yaml /etc/hysteria2/server.key /etc/hysteria2/server.crt
      fi
      ok "已删除节点 [$IDX]"
      return
    else
      systemctl disable --now hysteria2 >/dev/null 2>&1 || true
      rm -f /etc/systemd/system/hysteria2.service
      systemctl daemon-reload || true
      rm -f /etc/hysteria2/server.yaml /etc/hysteria2/server.key /etc/hysteria2/server.crt
      ok "已删除节点 [$IDX]"
      return
    fi
  fi
  local tag; tag=$(jq -r ".inbounds[$idx0].tag // empty" "$CONFIG")
  local tmpcfg; tmpcfg=$(mktemp)
  jq "del(.inbounds[$idx0])" "$CONFIG" >"$tmpcfg" && mv "$tmpcfg" "$CONFIG"
  if [[ -n "$tag" && "$tag" != "null" ]]; then
    local tmpmeta; tmpmeta=$(mktemp)
    jq "del(.\"$tag\")" "$META" >"$tmpmeta" && mv "$tmpmeta" "$META"
  fi
  ok "已删除节点 [$IDX]"
}

show_version_info() {
  local OS OS_NAME
  OS=$(detect_os)
  if [[ "$OS" == "unknown" ]]; then
    OS_NAME="未知"
  else
    OS_NAME="${OS^}"
  fi
  SINGBOX_BIN=$(command -v sing-box || echo "/usr/local/bin/sing-box")
  if [ -x "$SINGBOX_BIN" ]; then
    VER=$($SINGBOX_BIN version 2>/dev/null | head -n1 | awk '{print $NF}')
    ENV=$($SINGBOX_BIN version 2>/dev/null | awk -F'Environment: ' '/Environment:/{print $2}')
    say "Sing-box 版本: ${VER:-未知}  | 架构: ${ENV:-未知}  | 系统: ${OS_NAME}"
  else
    say "Sing-box 版本: 未知  | 架构: 未知  | 系统: ${OS_NAME}"
  fi

}

# ---------------------- NAT 模式功能 ----------------------
nat_mode_menu() {
  say "====== NAT模式设置 ======"
  say "1) 设置范围端口"
  say "2) 设置自定义端口"
  say "3) 查看当前NAT端口规则"
  say "4) 退出NAT模式"
  say "0) 返回主菜单"
  read -rp "请选择: " opt
  case "$opt" in
        4) disable_nat_mode ;;
1) set_nat_range ;;
    2) set_nat_custom ;;
    3) view_nat_ports ;;
    0) return ;;
    *) warn "无效输入" ;;
  esac
}

set_nat_range() {
  read -rp "请输入范围端口（可多个，用空格分隔，如 12000-12020 34050-34070）: " ranges
  jq -n --argjson arr "$(printf '%s\n' "$ranges" | jq -R 'split(" ")')"      '{"mode":"range","ranges":$arr,"custom":[]}' > /etc/sing-box/nat_ports.json
  ok "范围端口已保存"
}

set_nat_custom() {
  read -rp "请输入自定义端口（可多个，用空格分隔，如 12345 34567）: " ports
  jq -n --argjson arr "$(printf '%s\n' "$ports" | jq -R 'split(" ") | map(tonumber)')"      '{"mode":"custom","ranges":[],"custom":$arr}' > /etc/sing-box/nat_ports.json
  ok "自定义端口已保存"
}

view_nat_ports() {

disable_nat_mode() {
  local nat_file="/etc/sing-box/nat_ports.json"
  if [[ -f "$nat_file" ]]; then
    rm -f "$nat_file"
    ok "NAT模式已关闭（规则已清除）"
  else
    warn "当前未启用 NAT 模式"
  fi
}

  local nat_file="/etc/sing-box/nat_ports.json"
  if [[ ! -f "$nat_file" ]]; then
    warn "当前未设置 NAT 模式规则"
    return
  fi
  say "当前 NAT 模式配置："
  cat "$nat_file"
}

check_nat_port() {
  local port="$1"
  local nat_file="/etc/sing-box/nat_ports.json"
  [[ ! -f "$nat_file" ]] && return 0
  local mode
  mode=$(jq -r '.mode' "$nat_file")
  if [[ "$mode" == "range" ]]; then
    while read -r range; do
      local start=${range%-*}
      local end=${range#*-}
      if (( port >= start && port <= end )); then
        return 0
      fi
    done < <(jq -r '.ranges[]' "$nat_file")
    return 1
  elif [[ "$mode" == "custom" ]]; then
    jq -r '.custom[]' "$nat_file" | grep -qx "$port" && return 0
    return 1
  fi
  return 0
}


get_random_nat_port() {
  local nat_file="/etc/sing-box/nat_ports.json"
  if [[ -f "$nat_file" ]]; then
    local mode
    mode=$(jq -r '.mode' "$nat_file")
    if [[ "$mode" == "range" ]]; then
      local ports=()
      while read -r range; do
        local start=${range%-*}
        local end=${range#*-}
        for ((p=start; p<=end; p++)); do
          ports+=("$p")
        done
      done < <(jq -r '.ranges[]' "$nat_file")
      [[ ${#ports[@]} -gt 0 ]] && echo "${ports[RANDOM % ${#ports[@]}]}" && return
    elif [[ "$mode" == "custom" ]]; then
      mapfile -t ports < <(jq -r '.custom[]' "$nat_file")
      [[ ${#ports[@]} -gt 0 ]] && echo "${ports[RANDOM % ${#ports[@]}]}" && return
    fi
  fi
  # 默认随机
  echo $((RANDOM % 1000 + 30000))
}

# ---------------------- 主菜单 ----------------------
main_menu() {
  say ""
  show_version_info
  say "============= 嘻嘻哈哈 节点管理工具（IPv4 + IPv6） ============="
  say "1) 添加节点"
  say "2) 查看所有节点"
  say "3) 删除用户（通过序号）"
  say "4) 检查并更新 Sing-box 到最新版"
  say "5) 重启 Sing-box 服务"
  say "6) 完全卸载 / 初始化重装"
  say "0) 系统检测与修复"
  say "7) NAT模式设置"
  say "9) 退出"
  say "==============================================================="
  read -rp "请输入操作编号: " CHOICE
  case "$CHOICE" in
    7) nat_mode_menu ;;
    1) add_node ;;
    2) view_nodes ;;
    3) delete_node ;;
    4) update_singbox ;;
    5) restart_singbox ;;
    6) reinstall_menu ;;
    0) diagnose_menu ;;
    9) exit 0 ;;
    *) warn "无效输入" ;;
  esac
}

# ---------------------- 执行入口 ----------------------
ensure_dirs
install_dependencies
install_singbox_if_needed || true
# 如需快捷方式，可自行创建，例如 ln -sf "$(realpath "$0")" /usr/local/bin/sk5
while true; do main_menu; done
