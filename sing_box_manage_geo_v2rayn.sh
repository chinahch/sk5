#!/bin/bash

# 检测系统类型
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "$ID"
    else
        echo "unknown"
    fi
}

# 安装必要依赖
install_dependencies() {
    OS=$(detect_os)
    case "$OS" in
        alpine) apk add --no-cache curl jq bash ;;
        debian|ubuntu) apt update && apt install -y curl jq ;;
        centos|rhel|fedora) yum install -y curl jq ;;
        *) echo "请手动安装 curl 和 jq" ;;
    esac
}

# 检测服务管理方式（systemd、openrc 或 fallback）
detect_init_system() {
    if pidof systemd >/dev/null 2>&1; then
        echo "systemd"
    elif [[ -x /sbin/openrc-run ]] || [[ -f /etc/init.d/softlevel ]]; then
        echo "openrc"
    else
        echo "unknown"
    fi
}

# 初始化 Sing-box（首次安装）
install_singbox_if_needed() {
    if ! command -v sing-box >/dev/null 2>&1; then
        VERSION="1.11.5"
        ARCH=$(uname -m)
        [[ "$ARCH" == "x86_64" ]] && ARCH="amd64"
        [[ "$ARCH" == "aarch64" ]] && ARCH="arm64"

        curl -LO https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box-${VERSION}-linux-${ARCH}.tar.gz
        tar -xvzf sing-box-${VERSION}-linux-${ARCH}.tar.gz
        cp sing-box-${VERSION}-linux-${ARCH}/sing-box /usr/local/bin/
        chmod +x /usr/local/bin/sing-box
        rm -rf sing-box-${VERSION}-linux-${ARCH}*
    fi

    mkdir -p /etc/sing-box
    [[ ! -f /etc/sing-box/config.json ]] && echo '{"inbounds":[],"outbounds":[{"type":"direct"}],"route":{"rules":[]}}' > /etc/sing-box/config.json

    INIT_SYS=$(detect_init_system)

    if [[ "$INIT_SYS" == "systemd" ]]; then
        cat <<EOF > /etc/systemd/system/sing-box.service
[Unit]
Description=Sing-box Service
After=network.target

[Service]
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reexec
        systemctl daemon-reload
        systemctl enable sing-box
        
if [[ "$INIT_SYS" == "systemd" ]]; then
    systemctl start sing-box
elif [[ "$INIT_SYS" == "openrc" ]]; then
    rc-service sing-box start >/dev/null 2>&1
else
    echo "⚠️ 请手动启动 sing-box 或检查其运行状态"
fi

        echo "✅ 使用 systemd 启动 Sing-box 服务"

    elif [[ "$INIT_SYS" == "openrc" ]]; then
        cat <<'EOF' > /etc/init.d/sing-box
#!/sbin/openrc-run
command="/usr/local/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
pidfile="/var/run/sing-box.pid"
name="sing-box"
depend() {
    need net
}
EOF
        chmod +x /etc/init.d/sing-box
        rc-update add sing-box default >/dev/null 2>&1
        rc-service sing-box start >/dev/null 2>&1
        echo "✅ 使用 OpenRC 启动 Sing-box 服务"

    else
        echo "⚠️ 未检测到受支持的服务管理系统，采用后台运行方式"
        nohup /usr/local/bin/sing-box run -c /etc/sing-box/config.json >/var/log/sing-box.log 2>&1 &
        echo "✅ Sing-box 已使用 nohup 在后台运行"
    fi
}

# 快捷命令 sk

setup_shortcut() {
    MAIN_CMD="/usr/local/bin/sk"
    ALT_CMD="/usr/local/bin/ck"
    SCRIPT_PATH="$(realpath "$0")"

    # sk 快捷方式（默认全功能：含 init）
    [[ -f "$MAIN_CMD" ]] || echo -e "#!/bin/bash
bash \"$SCRIPT_PATH\" --init" > "$MAIN_CMD" && chmod +x "$MAIN_CMD"

    # ck 快捷方式（仅进入菜单）
    [[ -f "$ALT_CMD" ]] || echo -e "#!/bin/bash
bash \"$SCRIPT_PATH\"" > "$ALT_CMD" && chmod +x "$ALT_CMD"
}



# 重启 sing-box 服务
restart_singbox() {
    INIT_SYS=$(detect_init_system)
    if [[ "$INIT_SYS" == "systemd" ]]; then
        systemctl restart sing-box
        echo "✅ Sing-box 已通过 systemd 重启"
    elif [[ "$INIT_SYS" == "openrc" ]]; then
        rc-service sing-box restart >/dev/null 2>&1
        echo "✅ Sing-box 已通过 OpenRC 重启"
    else
        echo "⚠️ 当前系统不支持自动服务管理，请手动重启 sing-box"
    fi
}


# 获取版本架构信息
show_version_info() {
    if command -v sing-box >/dev/null 2>&1; then
        VER=$(sing-box version | grep 'sing-box version' | awk '{print $3}')
        ARCH=$(sing-box version | grep 'Environment:' | awk '{print $3}')
        echo "Sing-box 版本: ${VER:-未知}  | 架构: ${ARCH:-未知}"
    else
        echo "Sing-box 未安装"
    fi
}

# 延迟检测
show_latency() {
    LAT=$(ping -c 3 -W 1 baidu.com 2>/dev/null | awk -F '/' 'END { print $5 }')
    [[ -z "$LAT" ]] && echo "到百度延迟: 不可达" || echo "到百度延迟: $LAT ms"
}

# 获取国家缩写
get_country_code() {
    curl -s --max-time 2 https://ipapi.co/country/ || echo "ZZ"
}

# 获取 IPv6
get_ipv6_address() {
    ip -6 addr show scope global | grep inet6 | awk '{print $2}' | cut -d/ -f1 | head -n1
}

# 添加节点
add_node() {
    read -p "请输入端口号（留空随机）: " PORT
    [[ -z "$PORT" ]] && PORT=$((RANDOM % 10000 + 40000))
    read -p "请输入用户名（默认 user）: " USER
    USER=${USER:-user}
    read -p "请输入密码（默认 pass123）: " PASS
    PASS=${PASS:-pass123}

    TAG="sk5-$(get_country_code)"
    CONFIG="/etc/sing-box/config.json"

    jq --arg port "$PORT" --arg user "$USER" --arg pass "$PASS" --arg tag "$TAG" \
    '.inbounds += [{
        "type": "socks",
        "tag": $tag,
        "listen": "::",
        "listen_port": ($port|tonumber),
        "users": [{"username": $user, "password": $pass}]
    }]' "$CONFIG" > /tmp/tmp_config && mv /tmp/tmp_config "$CONFIG"

    
INIT_SYS=$(detect_init_system)
if [[ "$INIT_SYS" == "systemd" ]]; then
    systemctl restart sing-box
elif [[ "$INIT_SYS" == "openrc" ]]; then
    rc-service sing-box restart >/dev/null 2>&1
else
    echo "⚠️ 请手动重启 sing-box 或检查其运行状态"
fi


    ENCODED=$(echo -n "$USER:$PASS" | base64)
    IPV4=$(curl -s --max-time 2 https://api.ipify.org)
    IPV6=$(get_ipv6_address)

    echo "节点已添加："
    echo "端口: $PORT | 用户名: $USER | 密码: $PASS"
    echo "节点名: $TAG"
    echo "IPv4: socks://${ENCODED}@${IPV4}:${PORT}#$TAG"
    echo "IPv6: socks://${ENCODED}@[${IPV6}]:${PORT}#$TAG"
}

# 查看节点
view_nodes() {
    jq -c '.inbounds[]' /etc/sing-box/config.json | nl -w2 -s'. ' | while read -r line; do
        INDEX=$(echo "$line" | cut -d. -f1)
        JSON=$(echo "$line" | cut -d' ' -f2-)
        PORT=$(echo "$JSON" | jq -r '.listen_port')
        USER=$(echo "$JSON" | jq -r '.users[0].username')
        PASS=$(echo "$JSON" | jq -r '.users[0].password')
        TAG=$(echo "$JSON" | jq -r '.tag')
        ENCODED=$(echo -n "$USER:$PASS" | base64)
        IPV4=$(curl -s --max-time 2 https://api.ipify.org)
        IPV6=$(get_ipv6_address)
        echo "[$INDEX] 端口: $PORT | 用户名: $USER | 名称: $TAG"
        echo "IPv4: socks://${ENCODED}@${IPV4}:${PORT}#$TAG"
        echo "IPv6: socks://${ENCODED}@[${IPV6}]:${PORT}#$TAG"
        echo "---------------------------------------------------"
    done
}

# 删除节点
delete_node() {
    CONFIG="/etc/sing-box/config.json"
    COUNT=$(jq '.inbounds | length' "$CONFIG")
    [[ $COUNT -eq 0 ]] && echo "暂无节点" && return
    view_nodes
    read -p "请输入要删除的节点序号: " IDX
    IDX=$((IDX - 1))
    jq "del(.inbounds[$IDX])" "$CONFIG" > /tmp/tmp_config && mv /tmp/tmp_config "$CONFIG"
    echo "已删除节点 [$((IDX + 1))]（无需重启）"
}

# 自动更新 Sing-box
update_singbox() {
    CUR=$(sing-box version 2>/dev/null | grep version | awk '{print $3}')
    LATEST=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep tag_name | head -n1 | sed -E 's/.*"v([^"]+)".*/\1/')
    echo "当前版本: $CUR"
    echo "最新版本: $LATEST"
    [[ "$CUR" == "$LATEST" ]] && echo "已是最新版" && return

    read -p "是否更新到 $LATEST？(y/n): " CONFIRM
    [[ "$CONFIRM" != "y" ]] && echo "已取消" && return

    ARCH=$(uname -m)
    [[ "$ARCH" == "x86_64" ]] && ARCH="amd64"
    [[ "$ARCH" == "aarch64" ]] && ARCH="arm64"

    TMP=$(mktemp -d)
    cd "$TMP" || return
    curl -LO https://github.com/SagerNet/sing-box/releases/download/v${LATEST}/sing-box-${LATEST}-linux-${ARCH}.tar.gz
    tar -xvzf sing-box-${LATEST}-linux-${ARCH}.tar.gz

    echo "正在停止 sing-box 服务以完成更新..."
    
INIT_SYS=$(detect_init_system)
if [[ "$INIT_SYS" == "systemd" ]]; then
    systemctl stop sing-box
elif [[ "$INIT_SYS" == "openrc" ]]; then
    rc-service sing-box stop >/dev/null 2>&1
else
    echo "⚠️ 请手动停止 sing-box 或检查其运行状态"
fi


    cp sing-box-${LATEST}-linux-${ARCH}/sing-box /usr/local/bin/
    chmod +x /usr/local/bin/sing-box

    echo "已更新至 v$LATEST，正在重启服务..."
    
if [[ "$INIT_SYS" == "systemd" ]]; then
    systemctl start sing-box
elif [[ "$INIT_SYS" == "openrc" ]]; then
    rc-service sing-box start >/dev/null 2>&1
else
    echo "⚠️ 请手动启动 sing-box 或检查其运行状态"
fi


    echo "更新完成为 v$LATEST"
    cd && rm -rf "$TMP"
}

# 主菜单
main_menu() {
    echo ""
    show_latency
    show_version_info
    echo "============= Sing-box 节点管理工具（IPv4 + IPv6） ============="
    echo "1) 添加节点"
    echo "2) 查看所有节点"
    echo "3) 删除用户（通过序号）"
    echo "4) 检查并更新 Sing-box 到最新版"
    echo "5) 重启 Sing-box 服务"
    echo "9) 退出"
    echo "==============================================================="
    read -p "请输入操作编号: " CHOICE
    case "$CHOICE" in
        1) add_node ;;
        2) view_nodes ;;
        3) delete_node ;;
        4) update_singbox ;;
        5) restart_singbox ;;
        9) exit 0 ;;
        *) echo "无效输入" ;;
    esac
}

# 启动逻辑
install_dependencies
install_singbox_if_needed
setup_shortcut
while true; do main_menu; done
