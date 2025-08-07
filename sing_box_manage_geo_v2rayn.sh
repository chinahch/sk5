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

# 安装必要依赖（仅在缺失时安装）
install_dependencies() {
    if command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1 && command -v uuidgen >/dev/null 2>&1; then
        echo "✅ curl、jq 和 uuidgen 已安装，跳过安装步骤"
        return
    fi

    OS=$(detect_os)
    case "$OS" in
        alpine)
            apk add --no-cache curl jq util-linux ;;
        debian|ubuntu)
            apt update && apt install -y curl jq uuid-runtime ;;
        centos|rhel|fedora)
            yum install -y curl jq util-linux ;;
        *)
            echo "⚠️ 未识别系统，请手动安装 curl、jq 和 uuidgen"
            ;;
    esac
}

# 检测服务管理方式
detect_init_system() {
    if pidof systemd >/dev/null 2>&1; then
        echo "systemd"
    elif [[ -x /sbin/openrc-run ]] || [[ -f /etc/init.d/softlevel ]]; then
        echo "openrc"
    else
        echo "unknown"
    fi
}

# ✅ 检测“富强”状态（通过百度）
get_internal_status() {
    local success_count
    success_count=$(ping -c 5 -W 1 baidu.com 2>/dev/null | grep -c 'bytes from')
    if [[ $success_count -ge 3 ]]; then
        echo "富强：正常"
    else
        echo "富强：已墙"
    fi
}

# 安装 Sing-box
install_singbox_if_needed() {
    if command -v sing-box >/dev/null 2>&1; then
        echo "✅ Sing-box 已安装，跳过安装"
        return
    fi

    echo "⚠️ 未检测到 Sing-box，正在安装..."

    VERSION="1.12.0"
    ARCH=$(uname -m)
    [[ "$ARCH" == "x86_64" ]] && ARCH="amd64"
    [[ "$ARCH" == "aarch64" ]] && ARCH="arm64"

    TMP=$(mktemp -d)
    cd "$TMP" || exit

    echo "⬇️ 正在下载 Sing-box v$VERSION for $ARCH..."
    curl -LO https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box-${VERSION}-linux-${ARCH}.tar.gz

    echo "📦 解压中..."
    tar -xvzf sing-box-${VERSION}-linux-${ARCH}.tar.gz

    echo "⚙️ 安装中..."
    cp sing-box-${VERSION}-linux-${ARCH}/sing-box /usr/local/bin/
    chmod +x /usr/local/bin/sing-box

    echo "✅ Sing-box 已成功安装到 /usr/local/bin/sing-box"
    cd && rm -rf "$TMP"

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

# 快捷命令 sk/ck
setup_shortcut() {
    MAIN_CMD="/usr/local/bin/sk"
    ALT_CMD="/usr/local/bin/ck"
    SCRIPT_PATH="$(realpath "$0")"
    [[ -f "$MAIN_CMD" ]] || echo -e "#!/bin/bash\nbash \"$SCRIPT_PATH\" --init" > "$MAIN_CMD" && chmod +x "$MAIN_CMD"
    [[ -f "$ALT_CMD" ]] || echo -e "#!/bin/bash\nbash \"$SCRIPT_PATH\"" > "$ALT_CMD" && chmod +x "$ALT_CMD"
}

# 重启服务
restart_singbox() {
    INIT_SYS=$(detect_init_system)
    if [[ "$INIT_SYS" == "systemd" ]]; then
        systemctl restart sing-box
        sleep 1
        if systemctl is-active --quiet sing-box; then
            echo "✅ Sing-box 已通过 systemd 重启成功"
        else
            echo "❌ Sing-box 重启失败，请检查配置或日志"
            systemctl status sing-box --no-pager
        fi
    elif [[ "$INIT_SYS" == "openrc" ]]; then
        rc-service sing-box restart >/dev/null 2>&1
        sleep 1
        if rc-service sing-box status | grep -q 'started'; then
            echo "✅ Sing-box 已通过 OpenRC 重启成功"
        else
            echo "❌ Sing-box 重启失败（OpenRC），请检查配置或日志"
            rc-service sing-box status
        fi
    else
        echo "⚠️ 当前系统不支持自动服务管理，请手动重启"
    fi
}


# ✅ 修复 Sing-box 功能（增强为可选完全卸载/保留配置）
repair_singbox() {
    echo ""
    echo "=== Sing-box（完全卸载--初始化重装） ==="
    echo "0) 返回主菜单"
    echo "1) 保留节点配置重新安装"
    echo "2) 全部删除并初始化安装"
    read -p "请输入操作编号（默认 1）: " SUBCHOICE
    SUBCHOICE=${SUBCHOICE:-1}

    if [[ "$SUBCHOICE" == "0" ]]; then
        echo "🔙 返回主菜单..."
        return
    fi

    INIT_SYS=$(detect_init_system)

    echo "⚠️ 停止并清理旧服务..."
    if [[ "$INIT_SYS" == "systemd" ]]; then
        systemctl stop sing-box
        systemctl disable sing-box
        rm -f /etc/systemd/system/sing-box.service
    elif [[ "$INIT_SYS" == "openrc" ]]; then
        rc-service sing-box stop
        rc-update del sing-box default
        rm -f /etc/init.d/sing-box
    fi

    echo "⚠️ 正在卸载 Sing-box 可执行文件..."
    rm -f /usr/local/bin/sing-box
    rm -f /usr/local/bin/sk /usr/local/bin/ck

    if [[ "$SUBCHOICE" == "2" ]]; then
        echo "⚠️ 删除配置文件和所有节点信息..."
        rm -rf /etc/sing-box
    else
        echo "✅ 保留 /etc/sing-box/config.json 配置文件"
    fi

    echo "📦 开始重新安装 Sing-box..."
    sleep 2
    install_singbox_if_needed
    setup_shortcut
    echo "✅ 重装完成，Sing-box 已重新部署并启动"
}


# 显示版本
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
    if [[ -z "$LAT" ]]; then
        echo "到百度延迟: 不可达"
        CHINA_VISIBILITY="被墙"
    else
        echo "到百度延迟: $LAT ms"
        CHINA_VISIBILITY="可达"
    fi
}

# 获取国家缩写
get_country_code() {
    CODE=$(curl -s --max-time 3 https://ipinfo.io | jq -r '.country // empty')
    if [[ "$CODE" =~ ^[A-Z]{2}$ ]]; then
        echo "$CODE"
    else
        echo "ZZ"
    fi
}


# 获取 IPv6
get_ipv6_address() {
    ip -6 addr show scope global | grep inet6 | awk '{print $2}' | cut -d/ -f1 | head -n1
}

# 添加节点
add_node() {
    echo "请选择协议类型："
    echo "1) SOCKS5"
    echo "2) VLESS-REALITY"
    read -p "输入协议编号（默认 1）: " PROTO
    PROTO=${PROTO:-1}

    CONFIG="/etc/sing-box/config.json"

    if [[ "$PROTO" == "2" ]]; then
        # === 添加 VLESS + REALITY (TCP + Vision Flow) 节点 ===
        read -p "请输入端口号（默认 443）: " PORT
        PORT=${PORT:-443}

        # 自动生成 UUID
        if command -v uuidgen >/dev/null 2>&1; then
            UUID=$(uuidgen)
        else
            UUID=$(openssl rand -hex 16 | sed 's/\(..\)/\1/g; s/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
        fi

        # Reality 配置默认值
        SNI_POOL=("www.cloudflare.com" "www.google.com" "www.yahoo.com" "www.microsoft.com" "www.amazon.com" "www.bing.com")
FINGERPRINT_POOL=("chrome" "firefox" "safari" "ios" "android")

SERVER_NAME=${SNI_POOL[$RANDOM % ${#SNI_POOL[@]}]}
FINGERPRINT=${FINGERPRINT_POOL[$RANDOM % ${#FINGERPRINT_POOL[@]}]}

        FLOW="xtls-rprx-vision"
        TAG="vless-reality-$(get_country_code)"

        # 生成公私钥
        KEY_PAIR=$(sing-box generate reality-keypair 2>/dev/null)
        PRIVATE_KEY=$(echo "$KEY_PAIR" | grep 'PrivateKey' | awk '{print $2}')
        PUBLIC_KEY=$(echo "$KEY_PAIR" | grep 'PublicKey' | awk '{print $2}')

        if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
            echo "❌ 无法生成 Reality 密钥对，请确认 sing-box 支持 reality-keypair 命令"
            return 1
        fi

        SHORT_ID=$(openssl rand -hex 8)

        # 写入配置
        jq --arg port "$PORT" \
   --arg uuid "$UUID" \
   --arg prikey "$PRIVATE_KEY" \
   --arg sid "$SHORT_ID" \
   --arg server "$SERVER_NAME" \
   --arg fp "$FINGERPRINT" \
   --arg flow "$FLOW" \
   --arg tag "$TAG" \
   '
   .inbounds += [{
       "type": "vless",
       "tag": $tag,
       "listen": "0.0.0.0",
       "listen_port": ($port | tonumber),
       "users": [{ "uuid": $uuid, "flow": $flow }],
       "tls": {
           "enabled": true,
           "server_name": $server,
           "reality": {
               "enabled": true,
               "handshake": {
                   "server": $server,
                   "server_port": 443
               },
               "private_key": $prikey,
               "short_id": [$sid]
           }
       }
   }]
   ' "$CONFIG" > /tmp/tmp_config && mv /tmp/tmp_config "$CONFIG"


        # ✅ 校验配置后再重启
        echo ""
        echo "🧪 正在校验配置文件..."
        if sing-box check -c "$CONFIG" >/dev/null 2>&1; then
            echo "✅ 配置校验通过，正在重启 Sing-box 服务..."
            restart_singbox
        else
            echo "❌ 配置校验失败，Sing-box 未重启。请检查配置："
            sing-box check -c "$CONFIG"
            echo ""
            echo "提示：你可以手动修复 /etc/sing-box/config.json 后运行："
            echo "systemctl restart sing-box"
            return 1
        fi

        # 构建链接
        IPV4=$(curl -s --max-time 2 https://api.ipify.org)
        VLESS_LINK="vless://${UUID}@${IPV4}:${PORT}?encryption=none&flow=${FLOW}&type=tcp&security=reality&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&sni=${SERVER_NAME}&fp=${FINGERPRINT}#${TAG}"

        echo ""
        echo "✅ VLESS + REALITY 节点已添加："
        echo "端口: $PORT"
        echo "UUID: $UUID"
        echo "Reality 公钥: $PUBLIC_KEY"
        echo "Reality 私钥: $PRIVATE_KEY"
        echo "Short ID: $SHORT_ID"
        echo "SNI: $SERVER_NAME"
        echo "Fingerprint: $FINGERPRINT"
        echo "TAG: $TAG"
        echo ""
        echo "👉 v2rayN 节点链接（可复制导入）:"
        echo "$VLESS_LINK"
        echo ""

    else
        # === 添加 SOCKS5 节点 ===
        read -p "请输入端口号（留空随机）: " PORT
        [[ -z "$PORT" ]] && PORT=$((RANDOM % 10000 + 40000))
        read -p "请输入用户名（默认 user）: " USER
        USER=${USER:-user}
        read -p "请输入密码（默认 pass123）: " PASS
        PASS=${PASS:-pass123}
        TAG="sk5-$(get_country_code)"

        jq --arg port "$PORT" --arg user "$USER" --arg pass "$PASS" --arg tag "$TAG" \
        '.inbounds += [{
            "type": "socks",
            "tag": $tag,
            "listen": "0.0.0.0",
            "listen_port": ($port|tonumber),
            "users": [{"username": $user, "password": $pass}]
        }]' "$CONFIG" > /tmp/tmp_config && mv /tmp/tmp_config "$CONFIG"

        echo ""
        echo "🧪 正在校验配置文件..."
        if sing-box check -c "$CONFIG" >/dev/null 2>&1; then
            echo "✅ 配置校验通过，正在重启 Sing-box 服务..."
            restart_singbox
        else
            echo "❌ 配置校验失败，Sing-box 未重启。请检查配置："
            sing-box check -c "$CONFIG"
            echo ""
            echo "提示：你可以手动修复 /etc/sing-box/config.json 后运行："
            echo "systemctl restart sing-box"
            return 1
        fi

        ENCODED=$(echo -n "$USER:$PASS" | base64)
        IPV4=$(curl -s --max-time 2 https://api.ipify.org)
        IPV6=$(get_ipv6_address)

        echo "✅ SOCKS5 节点已添加："
        echo "端口: $PORT | 用户名: $USER | 密码: $PASS"
        echo "IPv4: socks://${ENCODED}@${IPV4}:${PORT}#$TAG"
        echo "IPv6: socks://${ENCODED}@[${IPV6}]:${PORT}#$TAG"
    fi
}


# 查看节点
# 查看节点（增强版：节点状态 + 外网 + 内网检测）
view_nodes() {
    CONFIG="/etc/sing-box/config.json"
    IPV4=$(curl -s --max-time 2 https://api.ipify.org)
    IPV6=$(ip -6 addr show scope global | grep inet6 | awk '{print $2}' | cut -d/ -f1 | head -n1)
    INTERNAL_STATUS=$(get_internal_status)

    jq -c '.inbounds[]' "$CONFIG" | nl -w2 -s'. ' | while read -r line; do
        INDEX=$(echo "$line" | cut -d. -f1)
        JSON=$(echo "$line" | cut -d' ' -f2-)
        PORT=$(echo "$JSON" | jq -r '.listen_port')
        TAG=$(echo "$JSON" | jq -r '.tag')
        TYPE=$(echo "$JSON" | jq -r '.type')

        # 判断节点端口是否开启（外网状态）
        timeout 2 bash -c "echo > /dev/tcp/127.0.0.1/$PORT" >/dev/null 2>&1
        [[ $? -eq 0 ]] && NODE_STATUS_LABEL="节点：正常" || NODE_STATUS_LABEL="节点：失效"

        echo "[$INDEX] 端口: $PORT | 协议: $TYPE | 名称: $TAG"
        echo "$NODE_STATUS_LABEL | $INTERNAL_STATUS"

        if [[ "$TYPE" == "socks" ]]; then
            USER=$(echo "$JSON" | jq -r '.users[0].username')
            PASS=$(echo "$JSON" | jq -r '.users[0].password')
            ENCODED=$(echo -n "$USER:$PASS" | base64)
            echo "IPv4: socks://${ENCODED}@${IPV4}:${PORT}#$TAG"
            echo "IPv6: socks://${ENCODED}@[${IPV6}]:${PORT}#$TAG"
        elif [[ "$TYPE" == "vless" ]]; then
            UUID=$(echo "$JSON" | jq -r '.users[0].uuid')
            SERVER_NAME=$(echo "$JSON" | jq -r '.tls.reality.handshake.server')
            PUBKEY=$(echo "$JSON" | jq -r '.tls.reality.public_key // empty')
            SID=$(echo "$JSON" | jq -r '.tls.reality.short_id[0] // empty')
            echo "vless://${UUID}@${IPV4}:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SERVER_NAME}&fp=chrome&pbk=${PUBKEY}&type=tcp&headerType=none&shortId=${SID}#$TAG"
        fi
        echo "---------------------------------------------------"
    done
}

# 删除节点
delete_node() {
    CONFIG="/etc/sing-box/config.json"
    COUNT=$(jq '.inbounds | length' "$CONFIG")
    [[ $COUNT -eq 0 ]] && echo "暂无节点" && return

    view_nodes

    echo "[0] 删除所有节点"
    read -p "请输入要删除的节点序号或选项编号: " IDX

    if [[ "$IDX" == "0" ]]; then
        read -p "⚠️ 确认删除全部节点？此操作不可恢复！(y/n): " CONFIRM
        [[ "$CONFIRM" != "y" ]] && echo "❌ 已取消删除" && return
        jq '.inbounds = []' "$CONFIG" > /tmp/tmp_config && mv /tmp/tmp_config "$CONFIG"
        echo "✅ 所有节点已删除（无需立即重启）"
        return
    fi

    IDX=$((IDX - 1))
    jq "del(.inbounds[$IDX])" "$CONFIG" > /tmp/tmp_config && mv /tmp/tmp_config "$CONFIG"
    echo "✅ 已删除节点 [$((IDX + 1))]（无需立即重启）"
}
# 更新 sing-box
update_singbox() {
    echo "📦 正在检查 Sing-box 更新..."

    # 获取当前版本
    CUR=$(sing-box version 2>/dev/null | grep 'version' | awk '{print $3}')
    echo "当前版本: $CUR"

    # 获取最新版本
    LATEST=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep tag_name | head -n1 | sed -E 's/.*"v([^"]+)".*/\1/')
    echo "最新版本: $LATEST"

    # 比较版本
    if [[ "$CUR" == "$LATEST" ]]; then
        echo "✅ 已是最新版，无需更新。"
        return
    fi

    read -p "是否更新到 $LATEST？(y/n): " CONFIRM
    [[ "$CONFIRM" != "y" ]] && echo "❌ 已取消更新" && return

    # 获取架构
    ARCH=$(uname -m)
    [[ "$ARCH" == "x86_64" ]] && ARCH="amd64"
    [[ "$ARCH" == "aarch64" ]] && ARCH="arm64"

    TMP=$(mktemp -d)
    cd "$TMP" || exit

    echo "⬇️ 正在下载 sing-box ${LATEST}..."
    curl -LO https://github.com/SagerNet/sing-box/releases/download/v${LATEST}/sing-box-${LATEST}-linux-${ARCH}.tar.gz

    echo "📦 解压中..."
    tar -xvzf sing-box-${LATEST}-linux-${ARCH}.tar.gz

    echo "⚙️ 替换可执行文件..."
    INIT_SYS=$(detect_init_system)
    [[ "$INIT_SYS" == "systemd" ]] && systemctl stop sing-box
    [[ "$INIT_SYS" == "openrc" ]] && rc-service sing-box stop >/dev/null 2>&1

    cp sing-box-${LATEST}-linux-${ARCH}/sing-box /usr/local/bin/
    chmod +x /usr/local/bin/sing-box

    [[ "$INIT_SYS" == "systemd" ]] && systemctl start sing-box
    [[ "$INIT_SYS" == "openrc" ]] && rc-service sing-box start >/dev/null 2>&1

    echo "✅ 已成功升级为 v${LATEST}"
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
    echo "6) 修复 Sing-box（完全卸载--初始化重装）"
    echo "9) 退出"
    echo "==============================================================="
    read -p "请输入操作编号: " CHOICE
    case "$CHOICE" in
        1) add_node ;;
        2) view_nodes ;;
        3) delete_node ;;
        4) update_singbox ;;
        5) restart_singbox ;;
        6) repair_singbox ;;
        9) exit 0 ;;
        *) echo "无效输入" ;;
    esac
}

# 执行
install_dependencies
install_singbox_if_needed
setup_shortcut
while true; do main_menu; done

