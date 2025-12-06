#!/usr/bin/env bash
# sk5.sh 模块: 节点添加

# 依赖: main.sh/deps_and_util.sh/nat_control.sh 中的函数和变量

generate_self_signed_cert() {
  local key_file="$1" cert_file="$2" domain="$3"
  umask 077
  openssl ecparam -name prime256v1 -genkey -noout -out "$key_file" 2>/dev/null || \
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$key_file" 2>/dev/null
  openssl req -new -x509 -nodes -key "$key_file" -out "$cert_file" -subj "/CN=$domain" -days 36500 >/dev/null 2>&1
  chmod 600 "$key_file" "$cert_file"
  if [[ -f "$cert_file" && -f "$key_file" ]]; then return 0; else return 1; fi
}

# ============= Hysteria2 添加逻辑 =============
add_hysteria2_node() {
  install_dependencies # 确保安装了 openssl
  
  local port proto_type="udp"
  
  while true; do
    read -rp "请输入 Hysteria2 端口 (留空则自动随机): " input_port
    
    if [[ -z "$input_port" ]]; then
      say "正在自动寻找可用 UDP 端口..."
      local found_port=0
      for i in {1..10}; do
          port=$(get_random_allowed_port "$proto_type")
          if [[ "$port" == "NO_PORT" ]]; then err "无可用端口"; return 1; fi
          
          if jq -e --argjson p "$port" '.inbounds[] | select(.listen_port == $p)' "$CONFIG" >/dev/null 2>&1; then continue; fi
          if jq -e --argjson p "$port" 'to_entries[]? | select(.value.type=="hysteria2" and .value.port == $p)' "$META" >/dev/null 2>&1; then continue; fi
          if port_status "$port" -eq 0; then continue; fi
          
          found_port=1; break
      done
      
      if [[ $found_port -eq 0 ]]; then err "自动分配端口失败"; return 1; fi
      break
    else
      if ! [[ "$input_port" =~ ^[0-9]+$ ]] || (( input_port < 1 || input_port > 65535 )); then warn "端口无效"; continue; fi
      port="$input_port"
      
      if ! check_nat_allow "$port" "$proto_type"; then warn "该端口不符合当前的 NAT 端口规则"; continue; fi
      if jq -e --argjson p "$port" '.inbounds[] | select(.listen_port == $p)' "$CONFIG" >/dev/null 2>&1; then warn "端口 $port 已被 Sing-box 其他节点占用"; continue; fi
      if jq -e --argjson p "$port" 'to_entries[]? | select(.value.type=="hysteria2" and .value.port == $p)' "$META" >/dev/null 2>&1; then warn "端口 $port 已被其他 Hysteria2 节点占用"; continue; fi
      if port_status "$port" -ne 2; then warn "系统端口 $port 已被占用"; continue; fi
      
      break
    fi
  done
  
  say "已选定端口: $port"

  if ! command -v hysteria >/dev/null 2>&1; then
    say "正在安装 Hysteria 2 核心..."
    local H_VERSION="2.6.2" arch=$(uname -m)
    case "$arch" in x86_64|amd64) arch="amd64";; aarch64|arm64) arch="arm64";; *) err "暂不支持的架构：$arch"; return 1;; esac
    local tmp; tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
    ( set -e; cd "$tmp"
      curl -sSL "https://github.com/apernet/hysteria/releases/download/app/v${H_VERSION}/hysteria-linux-${arch}" -o hysteria-bin || { err "下载 hysteria 失败"; exit 1; }
      install -m 0755 hysteria-bin /usr/local/bin/hysteria
    ) || { return 1; }
    ok "Hysteria 2 安装完成"
  fi

  mkdir -p /etc/hysteria2
  local cert_file="/etc/hysteria2/${port}.crt" key_file="/etc/hysteria2/${port}.key" sni_domain="www.bing.com"

  say "正在生成自签名证书 ($sni_domain)..."
  generate_self_signed_cert "$key_file" "$cert_file" "$sni_domain" || { err "证书生成失败"; return 1; }

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

  local service_name="hysteria2-${port}"
  INIT_SYS=$(detect_init_system)
  
  if [[ "$INIT_SYS" == "systemd" ]]; then
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
      "$(_SYSTEMCTL_CMD)" daemon-reload >/dev/null 2>&1
      "$(_SYSTEMCTL_CMD)" enable "$service_name" >/dev/null 2>&1
      "$(_SYSTEMCTL_CMD)" restart "$service_name" >/dev/null 2>&1
      sleep 2
      if ! "$(_SYSTEMCTL_CMD)" is-active --quiet "$service_name"; then err "Hysteria2 服务启动失败"; return 1; fi
      
  elif [[ "$INIT_SYS" == "openrc" ]]; then
      cat > "/etc/init.d/${service_name}" <<EOF
#!/sbin/openrc-run
name="${service_name}"
description="Hysteria2 Service (Port ${port})"
command="/usr/local/bin/hysteria"
command_args="server -c /etc/hysteria2/${port}.yaml"
pidfile="/run/${service_name}.pid"
command_background="yes"
depend() { need net; }
EOF
      chmod +x "/etc/init.d/${service_name}"
      "$(_RCSERVICE_CMD)" add "${service_name}" default >/dev/null 2>&1
      "$(_RCSERVICE_CMD)" "${service_name}" start >/dev/null 2>&1
      sleep 2
      if ! "$(_RCSERVICE_CMD)" "${service_name}" status >/dev/null 2>&1; then err "Hysteria2 服务启动失败"; return 1; fi
  else
      err "未知初始化系统: $INIT_SYS，无法启动 Hysteria2 服务。"
      return 1
  fi

  local tag="Hy2-Default-$(date +%s)"
  local tmpmeta; tmpmeta=$(mktemp); trap 'rm -f "$tmpmeta"' EXIT
  
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


# ============= Cloudflare Tunnel 辅助函数 (依赖 view_and_del_node.sh 中的删除/激活) =============
ARGO_NODES_DIR="/etc/sing-box/argo_users"
ARGO_BIN_DIR="/root/agsbx"

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
         if command -v apt-get >/dev/null 2>&1; then apt-get update -y >/dev/null 2>&1 && apt-get install -y unzip >/dev/null 2>&1
         elif command -v yum >/dev/null 2>&1; then yum install -y unzip >/dev/null 2>&1
         elif command -v apk >/dev/null 2>&1; then apk add --no-cache unzip >/dev/null 2>&1; fi
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
        if [ ! -f "$ARGO_BIN_DIR/cloudflared" ]; then err "Cloudflared 下载失败。"; return 1; fi
        chmod +x "$ARGO_BIN_DIR/cloudflared"
    fi
    return 0
}

add_argo_user() {
    set +e
    if ! ensure_argo_deps; then read -rp "按回车返回..." _; return 1; fi

    say "========== 添加新的 CF Tunnel 用户 =========="
    
    local port proto_type="tcp" uuid agn_input agk_input vm_port tag user_tag
    
    while true; do
        read -rp "请输入 Xray 本地监听端口 (10000-65535, 建议): " input_port
        
        if ! [[ "$input_port" =~ ^[0-9]+$ ]] || (( input_port < 10000 || input_port > 65535 )); then warn "端口无效"; continue; fi
        vm_port="$input_port"
        
        if port_status "$vm_port" -ne 2; then warn "端口 $vm_port 已被系统占用或正在监听"; continue; fi
        if jq -e --argjson p "$vm_port" '.inbounds[] | select(.listen_port == $p)' "$CONFIG" >/dev/null 2>&1; then warn "端口 $vm_port 已被 Sing-box 其他节点占用"; continue; fi
        if jq -e --argjson p "$vm_port" 'to_entries[]? | select((.value.type=="argo" or .value.type=="hysteria2") and .value.port == $p)' "$META" >/dev/null 2>&1; then warn "端口 $vm_port 已被其他 Argo/Hysteria2 节点占用"; continue; fi
        if ! check_nat_allow "$vm_port" "tcp"; then warn "端口 $vm_port 不符合当前的 NAT 端口规则 (协议: tcp)"; continue; fi

        break
    done
    say "已选择本地监听端口: $vm_port"
    
    read -rp "请输入 隧道域名（例如 vps.mycf.com）: " agn_input
    [[ -z "$agn_input" ]] && { warn "域名不能为空！"; return 1; }
    
    read -rp "请输入 隧道Token (eyJh...): " agk_input
    [[ -z "$agk_input" ]] && { warn "Token 不能为空！"; return 1; }

    read -rp "请输入用户标记 (默认 CF-User): " user_tag
    user_tag=${user_tag:-CF-User}
    
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
    
    pkill -9 -f "xray run -c $config_file" >/dev/null 2>&1 || true
    pkill -9 -f "cloudflared.*${vm_port}" >/dev/null 2>&1 || true
    
    local tmpmeta; tmpmeta=$(mktemp)
    jq --arg tag "$tag" --arg port "$vm_port" --arg uuid "$uuid" --arg domain "$agn_input" --arg token "$agk_input" --arg path "$ws_path" \
        '. + {($tag): {type:"argo", subtype:"fixed", port:$port, uuid:$uuid, domain:$domain, token:$token, path:$path}}' "$META" >"$tmpmeta" && mv "$tmpmeta" "$META"

    local service_name="cf-tunnel-${vm_port}"
    
    install_cf_tunnel_service() {
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
        if [[ -d /etc/local.d ]]; then
            cat > "/etc/local.d/argo_${vm_port}.start" <<EOF
#!/bin/sh
# Auto-generated by sk5.sh for Port ${vm_port}
nohup ${ARGO_BIN_DIR}/xray run -c ${config_file} >/dev/null 2>&1 &
sleep 2
nohup ${ARGO_BIN_DIR}/cloudflared tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${agk_input} --url http://127.0.0.1:${vm_port} > ${log_file} 2>&1 &
EOF
            chmod +x "/etc/local.d/argo_${vm_port}.start"
            if command -v rc-update >/dev/null 2>&1; then rc-update add local default >/dev/null 2>&1 || true; fi
            say "   已添加 Alpine local.d 自启脚本。"
        fi

        if command -v crontab >/dev/null 2>&1; then
            if ! pgrep crond >/dev/null 2>&1 && command -v crond >/dev/null 2>&1; then nohup crond -f >/dev/null 2>&1 & fi
            local crontab_entry_xray="@reboot sleep 10 && nohup $ARGO_BIN_DIR/xray run -c $config_file >/dev/null 2>&1  # agsbx-$vm_port-xray"
            local crontab_entry_cfd="@reboot sleep 15 && nohup $ARGO_BIN_DIR/cloudflared tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${agk_input} --url http://127.0.0.1:${vm_port} > $log_file 2>&1  # agsbx-$vm_port-cfd"
            crontab -l 2>/dev/null | grep -v "# agsbx-$vm_port" > /tmp/crontab.tmp || true
            echo "$crontab_entry_xray" >> /tmp/crontab.tmp
            echo "$crontab_entry_cfd" >> /tmp/crontab.tmp
            crontab /tmp/crontab.tmp; rm -f /tmp/crontab.tmp
        fi
        
        setsid -f "$ARGO_BIN_DIR/xray" run -c "$config_file"
        sleep 2
        setsid -f "$ARGO_BIN_DIR/cloudflared" tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token "$agk_input" --url "http://127.0.0.1:${vm_port}" > "$log_file" 2>&1
        say "已配置 Fallback 自启并立即启动进程。"
    fi
    
    sleep 3
    
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

temp_tunnel_logic() {
    set +e 
    say "========== 临时隧道 (独立进程) 部署 =========="
    
    local TEMP_ARGO_DIR="/root/agsbx/temp_node"
    local ARGO_BIN_DIR="/root/agsbx"
    local TEMP_PID_FILE="$TEMP_ARGO_DIR/temp_cloudflared.pid"
    local TEMP_XRAY_PID_FILE="$TEMP_ARGO_DIR/temp_xray.pid"
    local TEMP_XRAY_LOG="$TEMP_ARGO_DIR/xray.log"
    
    mkdir -p "$TEMP_ARGO_DIR" "$ARGO_BIN_DIR"
    
    say "-> 强制终止旧的临时隧道进程..."
    pkill -9 -f "$TEMP_ARGO_DIR/xray_temp" >/dev/null 2>&1 || true
    pkill -9 -f "$TEMP_ARGO_DIR/cloudflared_temp" >/dev/null 2>&1 || true
    sleep 1

    rm -f "$TEMP_ARGO_DIR/argo.log" "$TEMP_XRAY_LOG" "$ARGO_TEMP_CACHE" "$TEMP_PID_FILE" "$TEMP_XRAY_PID_FILE"
    rm -f "$TEMP_ARGO_DIR/xray_temp" "$TEMP_ARGO_DIR/cloudflared_temp"
    
    if ! ensure_argo_deps; then read -rp "依赖安装失败，按回车返回..." _; return; fi
    
    say "-> 复制核心文件到独立目录..."
    cp "$ARGO_BIN_DIR/xray" "$TEMP_ARGO_DIR/xray_temp" || { err "复制 Xray 失败"; return; }
    cp "$ARGO_BIN_DIR/cloudflared" "$TEMP_ARGO_DIR/cloudflared_temp" || { err "复制 Cloudflared 失败"; return; }
    chmod +x "$TEMP_ARGO_DIR/xray_temp" "$TEMP_ARGO_DIR/cloudflared_temp"

    local uuid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)
    if [ -z "$uuid" ]; then uuid=$(openssl rand -hex 16 | sed 's/\(..\)/\1/g; s/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/'); fi
    
    local port=$(shuf -i 10000-60000 -n 1)
    local ws_path="/${uuid}-vm"
    local temp_config="$TEMP_ARGO_DIR/config.json"
    local temp_log="$TEMP_ARGO_DIR/argo.log"
    
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
    
    setsid bash -c "trap '' INT HUP; exec \"$TEMP_ARGO_DIR/xray_temp\" run -c \"$temp_config\" > \"$TEMP_XRAY_LOG\" 2>&1" &
    sleep 2
    
    if ! pgrep -f "$TEMP_ARGO_DIR/xray_temp" >/dev/null 2>&1; then err "Xray 启动失败！请检查日志: cat $TEMP_XRAY_LOG"; return; fi
    pgrep -f "$TEMP_ARGO_DIR/xray_temp" | head -n 1 > "$TEMP_XRAY_PID_FILE"

    say "正在申请 Argo 临时域名 (请等待约 5 秒)..."
    setsid bash -c "trap '' INT HUP; exec \"$TEMP_ARGO_DIR/cloudflared_temp\" tunnel --url \"http://127.0.0.1:${port}\" --edge-ip-version auto --no-autoupdate > \"$temp_log\" 2>&1" &
    sleep 5
    
    if ! pgrep -f "$TEMP_ARGO_DIR/cloudflared_temp" >/dev/null 2>&1; then err "Cloudflared 启动失败！请检查日志: cat $temp_log"; return; fi
    pgrep -f "$TEMP_ARGO_DIR/cloudflared_temp" | head -n 1 > "$TEMP_PID_FILE"

    local argo_url=""
    for i in {1..20}; do
        sleep 1
        argo_url=$(grep -oE 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' "$temp_log" | head -n 1 | sed 's/https:\/\///')
        if [ -n "$argo_url" ]; then break; fi
        printf "."
    done
    echo ""

    if [ -z "$argo_url" ]; then err "域名获取失败！请查看日志: cat $temp_log"; read -rp "按回车返回..." _; return; fi

    local vm_json='{
      "v": "2", "ps": "Argo-Temp-'$port'", "add": "www.visa.com.sg", "port": "443", 
      "id": "'$uuid'", "aid": "0", "scy": "auto", "net": "ws", "type": "none", 
      "host": "'$argo_url'", "path": "/'$uuid'-vm", "tls": "tls", "sni": "'$argo_url'", "alpn": ""
    }'
    local vmess_link="vmess://$(echo -n "$vm_json" | base64 -w 0)"
    echo "$vmess_link" > "$ARGO_TEMP_CACHE"

    local info="Argo 域名: ${C_CYAN}${argo_url}${C_RESET}"
    print_card "Argo 临时隧道搭建成功" "Argo-Temp-$port" "$info" "$vmess_link"

    import_argo_nodes >/dev/null 2>&1 
    read -rp "请复制上方链接，按回车返回..." _
    
    set -e
}

argo_management_menu() {
    # 依赖 view_and_del_node.sh 中的函数
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
        2) add_argo_user ;; 
        3) delete_argo_user ;; 
        4) activate_fixed_argo_nodes ;;
        5) uninstall_argo_all ;;
        0) return ;;
        *) warn "无效选项" ; read -rp "按回车继续..." _ ;;
      esac
    done
}


# ============= 主添加入口 =============
add_node() {
  install_dependencies

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

  if [[ "$proto" == "4" ]]; then
    argo_management_menu
    return
  fi

  if [[ "$proto" == "2" ]]; then
    if ! command -v sing-box >/dev/null 2>&1; then
      err "未检测到 sing-box，无法生成 Reality 密钥。请先在“脚本服务”里重装/安装。"
      return 1
    fi

    local port proto_type="tcp"
    while true; do
      if [[ -n "$nat_mode" ]] && [[ "$nat_mode" != "custom" ]] && [[ "$nat_mode" != "range" ]]; then
         say "当前NAT模式不支持端口自动挑选或检测，请手动输入。"
      fi
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
      if jq -e --argjson p "$port" '.inbounds[] | select(.listen_port == $p)' "$CONFIG" >/dev/null 2>&1; then warn "端口 $port 已存在"; continue; fi
      if jq -e --argjson p "$port" 'to_entries[]? | select(.value.type=="hysteria2" and .value.port == $p)' "$META" >/dev/null 2>&1; then warn "端口 $port 已被 Hysteria2 使用"; continue; fi
      break
    done

    local uuid fp flow server_name key_pair private_key public_key short_id tag tmpcfg
    if command -v uuidgen >/dev/null 2>&1; then
      uuid=$(uuidgen)
    else
      uuid=$(openssl rand -hex 16 | sed 's/\(..\)/\1/g; s/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
    fi

    read -rp "请输入伪装域名 (默认 www.microsoft.com): " input_sni
    server_name=${input_sni:-www.microsoft.com}
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
  
  # ============= SOCKS5 添加逻辑 =============
  local port user pass tag tmpcfg proto_type="tcp"
  while true; do
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
    if jq -e --argjson p "$port" '.inbounds[] | select(.listen_port == $p)' "$CONFIG" >/dev/null 2>&1; then warn "端口 $port 已存在"; continue; fi
    if jq -e --argjson p "$port" 'to_entries[]? | select(.value.type=="hysteria2" and .value.port == $p)' "$META" >/dev/null 2>&1; then warn "端口 $port 已被 Hysteria2 使用"; continue; fi
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