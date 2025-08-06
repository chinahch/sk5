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
declare -a DEPS=(curl jq)
install_dependencies() {
    for dep in "${DEPS[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            OS=$(detect_os)
            case "$OS" in
                alpine) apk add --no-cache curl jq ;;
                debian|ubuntu) apt update && apt install -y curl jq ;;
                centos|rhel|fedora) yum install -y curl jq ;;
                *) echo "⚠️ 未识别系统，请手动安装 curl 和 jq" ;;
            esac
            return
        fi
    done
    echo "✅ curl 和 jq 已安装，跳过安装步骤"
}

# 服务管理系统
detect_init_system() {
    if pidof systemd >/dev/null 2>&1; then
        echo "systemd"
    elif [[ -x /sbin/openrc-run ]] || [[ -f /etc/init.d/softlevel ]]; then
        echo "openrc"
    else
        echo "unknown"
    fi
}

# 架构映射
map_arch() {
    case $(uname -m) in
        x86_64) echo "amd64" ;;
        aarch64) echo "arm64" ;;
        armv7l) echo "armv7" ;;
        *) echo "unsupported" ;;
    esac
}

# 安装 sing-box
install_singbox_if_needed() {
    if ! command -v sing-box >/dev/null 2>&1; then
        VERSION="1.11.5"
        ARCH=$(map_arch)
        [[ "$ARCH" == "unsupported" ]] && echo "❌ 不支持的架构" && exit 1

        URL="https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box-${VERSION}-linux-${ARCH}.tar.gz"
        curl -fLO "$URL"
        tar -xvzf "sing-box-${VERSION}-linux-${ARCH}.tar.gz"
        cp "sing-box-${VERSION}-linux-${ARCH}/sing-box" /usr/local/bin/
        chmod +x /usr/local/bin/sing-box
        rm -rf "sing-box-${VERSION}-linux-${ARCH}"
        rm -f "sing-box-${VERSION}-linux-${ARCH}.tar.gz"
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
        systemctl start sing-box
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
        nohup /usr/local/bin/sing-box run -c /etc/sing-box/config.json >/var/log/sing-box.log 2>&1 &
        echo "⚠️ 未检测到受支持的服务管理系统，Sing-box 以后台运行"
    fi
}

# 快捷命令
setup_shortcut() {
    SCRIPT_PATH="$(realpath "$0")"
    echo -e "#!/bin/bash\nbash \"$SCRIPT_PATH\" --init" > /usr/local/bin/sk
    echo -e "#!/bin/bash\nbash \"$SCRIPT_PATH\"" > /usr/local/bin/ck
    chmod +x /usr/local/bin/sk /usr/local/bin/ck
}

# 重启服务
restart_singbox() {
    INIT_SYS=$(detect_init_system)
    if [[ "$INIT_SYS" == "systemd" ]]; then
        systemctl restart sing-box
        echo "✅ Sing-box 已通过 systemd 重启"
    elif [[ "$INIT_SYS" == "openrc" ]]; then
        rc-service sing-box restart >/dev/null 2>&1
        echo "✅ Sing-box 已通过 OpenRC 重启"
    else
        echo "⚠️ 当前系统不支持自动服务管理，请手动重启"
    fi
}
# 添加节点
add_node() {
    read -p "请输入端口号（留空随机）: " PORT
    [[ -z "$PORT" ]] && PORT=$((RANDOM % 10000 + 40000))
    read -p "请输入用户名（默认 user）: " USER
    USER=${USER:-user}
    read -p "请输入密码（默认 pass123）: " PASS
    PASS=${PASS:-pass123}
    TAG="sk5-$(curl -s --max-time 2 https://ipapi.co/country/ || echo ZZ)"
    CONFIG="/etc/sing-box/config.json"
    jq --arg port "$PORT" --arg user "$USER" --arg pass "$PASS" --arg tag "$TAG" \
    '.inbounds += [{"type": "socks", "tag": $tag, "listen": "::", "listen_port": ($port|tonumber), "users": [{"username": $user, "password": $pass}]}]' \
    "$CONFIG" > /tmp/tmp_config && mv /tmp/tmp_config "$CONFIG"
    restart_singbox
    ENCODED=$(echo -n "$USER:$PASS" | base64)
    IPV4=$(curl -s --max-time 2 https://api.ipify.org)
    IPV6=$(ip -6 addr show scope global | grep inet6 | awk '{print $2}' | cut -d/ -f1 | head -n1)
    echo "节点已添加："
    echo "端口: $PORT | 用户名: $USER | 密码: $PASS"
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
        IPV6=$(ip -6 addr show scope global | grep inet6 | awk '{print $2}' | cut -d/ -f1 | head -n1)
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

# 主菜单
main_menu() {
    echo ""
    echo "============= Sing-box 节点管理工具（IPv4 + IPv6） ============="
    echo "1) 添加节点"
    echo "2) 查看所有节点"
    echo "3) 删除用户（通过序号）"
    echo "4) 重启 Sing-box 服务"
    echo "9) 退出"
    echo "==============================================================="
    read -p "请输入操作编号: " CHOICE
    case "$CHOICE" in
        1) add_node ;;
        2) view_nodes ;;
        3) delete_node ;;
        4) restart_singbox ;;
        9) exit 0 ;;
        *) echo "无效输入" ;;
    esac
}

# 执行逻辑
install_dependencies
install_singbox_if_needed
setup_shortcut
while true; do main_menu; done
