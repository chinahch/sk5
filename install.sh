#!/bin/bash

# 下载主脚本
INSTALL_DIR="/root"
SCRIPT_NAME="sk5.sh"
TARGET_PATH="${INSTALL_DIR}/${SCRIPT_NAME}"

echo "📥 正在下载 Sing-box 管理脚本..."
curl -Ls https://raw.githubusercontent.com/chinahch/sk5/main/sing_box_manage_geo_v2rayn.sh -o "$TARGET_PATH"

# 添加执行权限
chmod +x "$TARGET_PATH"
echo "✅ 已保存到 $TARGET_PATH"

# 设置快捷命令 sk
echo "🔗 正在创建快捷命令 /usr/local/bin/sk..."
echo -e "#!/bin/bash\nbash \"$TARGET_PATH\" --init" > /usr/local/bin/sk
chmod +x /usr/local/bin/sk

# 启动主程序
echo "🚀 正在启动脚本..."
bash "$TARGET_PATH"
