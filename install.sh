#!/bin/bash
INSTALL_DIR="/root"
SCRIPT_NAME="sk5.sh"
TARGET_PATH="${INSTALL_DIR}/${SCRIPT_NAME}"

echo "📥 下载管理脚本..."
curl -Ls https://raw.githubusercontent.com/chinahch/sk5/main/sing_box_manage_geo_v2rayn.sh -o "$TARGET_PATH"
chmod +x "$TARGET_PATH"

# 设置 sk/ck 命令
echo "🔗 设置快捷方式 sk 和 ck..."
echo -e "#!/bin/bash\nbash \"$TARGET_PATH\" --init" > /usr/local/bin/sk
chmod +x /usr/local/bin/sk

echo -e "#!/bin/bash\nbash \"$TARGET_PATH\"" > /usr/local/bin/ck
chmod +x /usr/local/bin/ck

# 启动脚本（用户会看到菜单）
echo "🚀 正在启动菜单..."
bash "$TARGET_PATH"
