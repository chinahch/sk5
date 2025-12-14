#!/bin/bash
INSTALL_DIR="/root"
SCRIPT_NAME="sk5.sh"
TARGET_PATH="${INSTALL_DIR}/${SCRIPT_NAME}"

echo "📥 下载管理脚本..."
curl -Ls https://raw.githubusercontent.com/chinahch/sk5/main/sing_box_manage_geo_v2rayn.sh -o "$TARGET_PATH"
chmod +x "$TARGET_PATH"

# 启动脚本（用户会看到菜单）
echo "🚀 正在启动菜单..."
bash "$TARGET_PATH"
