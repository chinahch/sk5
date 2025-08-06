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
        echo "⚠️ 未检测到受支持的服务管理系统，采用后台运行方式"
        nohup /usr/local/bin/sing-box run -c /etc/sing-box/config.json >/var/log/sing-box.log 2>&1 &
        echo "✅ Sing-box 已使用 nohup 在后台运行"
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

# 重启 Sing-box 服务
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

# 卸载 Sing-box（含子选项和自删除）
uninstall_singbox() {
    SCRIPT_PATH="$(realpath "$0")"

    echo ""
    echo "=========== 卸载选项 ==========="
    echo "1) 卸载 Sing-box 服务与配置"
    echo "2) 完全卸载（包括脚本与快捷方式）"
    echo "9) 返回主菜单"
    echo "================================"
    read -p "请输入操作编号: " SUB_CHOICE

    case "$SUB_CHOICE" in
        1)
            echo "⚠️ 即将卸载 Sing-box 服务与配置..."
            read -p "是否确认卸载？(y/n): " CONFIRM
            [[ "$CONFIRM" != "y" ]] && echo "❌ 已取消卸载" && return

            INIT_SYS=$(detect_init_system)
            if [[ "$INIT_SYS" == "systemd" ]]; then
                systemctl stop sing-box 2>/dev/null
                systemctl disable sing-box 2>/dev/null
                rm -f /etc/systemd/system/sing-box.service
                systemctl daemon-reload
            elif [[ "$INIT_SYS" == "openrc" ]]; then
                rc-service sing-box stop 2>/dev/null
                rc-update del sing-box default 2>/dev/null
                rm -f /etc/init.d/sing-box
            fi

            pkill -f "sing-box" 2>/dev/null
            rm -rf /usr/local/bin/sing-box /etc/sing-box
            echo "✅ Sing-box 服务与配置已卸载完成"
            ;;
        2)
            echo "⚠️ 即将执行完整卸载（包括脚本本身）..."
            read -p "是否确认彻底卸载所有组件？(y/n): " CONFIRM2
            [[ "$CONFIRM2" != "y" ]] && echo "❌ 已取消" && return

            uninstall_singbox 1
            rm -f /usr/local/bin/sk /usr/local/bin/ck

            if [[ "$SCRIPT_PATH" != /dev/fd/* ]]; then
                echo "✅ 正在删除自身: $SCRIPT_PATH"
                rm -f "$SCRIPT_PATH"
                exit 0
            else
                echo "⚠️ 当前脚本为临时执行（/dev/fd/*），无法删除自身"
            fi
            ;;
        9)
            return
            ;;
        *)
            echo "❌ 无效输入"
            ;;
    esac
}

# 显示信息
show_latency() {
    LAT=$(ping -c 3 -W 1 baidu.com 2>/dev/null | awk -F '/' 'END { print $5 }')
    [[ -z "$LAT" ]] && echo "到百度延迟: 不可达" || echo "到百度延迟: $LAT ms"
}

show_version_info() {
    if command -v sing-box >/dev/null 2>&1; then
        VER=$(sing-box version | grep 'sing-box version' | awk '{print $3}')
        ARCH=$(sing-box version | grep 'Environment:' | awk '{print $3}')
        echo "Sing-box 版本: ${VER:-未知}  | 架构: ${ARCH:-未知}"
    else
        echo "Sing-box 未安装"
    fi
}

get_country_code() { curl -s --max-time 2 https://ipapi.co/country/ || echo "ZZ"; }
get_ipv6_address() { ip -6 addr show scope global | grep inet6 | awk '{print $2}' | cut -d/ -f1 | head -n1; }

# 节点管理功能（略）
add_node() { echo "此处略，可根据你已有版本合并"; }
view_nodes() { echo "此处略，可根据你已有版本合并"; }
delete_node() { echo "此处略，可根据你已有版本合并"; }
update_singbox() { echo "此处略，可根据你已有版本合并"; }

# 主菜单
main_menu() {
    echo ""
    show_latency
    show_version_info
    echo "============= Sing-box 节点管理工具 ============="
    echo "1) 添加节点"
    echo "2) 查看所有节点"
    echo "3) 删除节点"
    echo "4) 检查并更新 Sing-box"
    echo "5) 重启 Sing-box 服务"
    echo "6) 卸载 Sing-box"
    echo "9) 退出"
    echo "=================================================="
    read -p "请输入操作编号: " CHOICE
    case "$CHOICE" in
        1) add_node ;;
        2) view_nodes ;;
        3) delete_node ;;
        4) update_singbox ;;
        5) restart_singbox ;;
        6) uninstall_singbox ;;
        9) exit 0 ;;
        *) echo "无效输入" ;;
    esac
}

# 入口
install_dependencies
install_singbox_if_needed
setup_shortcut
while true; do main_menu; done
