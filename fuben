#!/usr/bin/env bash
# sk5.sh — Sing-box 管理脚本（auto-detect systemd/OpenRC + 自愈守护）
# 2025-08-08

set -e

# ===================== 基础工具函数 =====================
detect_os() {
  if [[ -f /etc/os-release ]]; then . /etc/os-release; echo "$ID"; else echo "unknown"; fi
}

# 更稳的 init 检测
detect_init_system() {
  if command -v systemctl >/dev/null 2>&1 && systemctl >/dev/null 2>&1; then echo systemd && return; fi
  if command -v rc-status >/dev/null 2>&1 || [[ -d /run/openrc ]] || [[ -x /sbin/openrc-run ]]; then echo openrc && return; fi
  if pidof systemd >/dev/null 2>&1; then echo systemd && return; fi
  echo unknown
}

install_dependencies() {
  if command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1 && command -v uuidgen >/dev/null 2>&1; then
    echo "✅ curl、jq 和 uuidgen 已安装，跳过安装步骤"; return; fi
  OS=$(detect_os)
  case "$OS" in
    alpine) apk add --no-cache curl jq util-linux  iproute2;;
    debian|ubuntu) apt update && apt install -y curl jq uuid-runtime  iproute2;;
    centos|rhel|fedora) yum install -y curl jq util-linux  iproute;;
    *) echo "⚠️ 未识别系统，请手动安装 curl、jq 和 uuidgen" ;;
  esac
}

get_internal_status() {
  local c; c=$(ping -c 5 -W 1 baidu.com 2>/dev/null | grep -c 'bytes from' || true)
  [[ ${c:-0} -ge 3 ]] && echo "富强：正常" || echo "富强：已墙"
}
show_version_info() {
  if command -v sing-box >/dev/null 2>&1; then
    VER=$(sing-box version 2>/dev/null | awk '/sing-box version/{print $3}')
    ARCH=$(sing-box version 2>/dev/null | awk '/Environment:/{print $3}')
    echo "Sing-box 版本: ${VER:-未知}  | 架构: ${ARCH:-未知}"
  else echo "Sing-box 未安装"; fi
}
show_latency() {
  LAT=$(ping -c 3 -W 1 baidu.com 2>/dev/null | awk -F'/' 'END{print $5}')
  if [[ -z "$LAT" ]]; then echo "到百度延迟: 不可达"; CHINA_VISIBILITY="被墙"; else echo "到百度延迟: $LAT ms"; CHINA_VISIBILITY="可达"; fi
}
get_country_code() {
  CODE=$(curl -s --max-time 3 https://ipinfo.io | jq -r '.country // empty' 2>/dev/null || true)
  [[ "$CODE" =~ ^[A-Z]{2}$ ]] && echo "$CODE" || echo "ZZ"
}
get_ipv6_address() { ip -6 addr show scope global | awk '/inet6/ {print $2}' | cut -d/ -f1 | head -n1; }

# 生成不重复 tag（避免 jq select() 在某些环境被 shell 搞坏）
generate_unique_tag() {
  local base="vless-reality-$(get_country_code)" try=0
  while true; do
    RAND=$(tr -dc 'A-Z' </dev/urandom | head -c1)
    CANDIDATE="${base}-${RAND}"
    if ! jq -r '.inbounds[].tag // empty' /etc/sing-box/config.json | grep -Fxq "$CANDIDATE"; then
      echo "$CANDIDATE"; return; fi
    try=$((try+1))
    if [[ $try -ge 26 ]]; then echo "${base}-$(date +%s)"; return; fi
  done
}
# 从 sing-box Reality 的 private_key 推导 public_key（pbk）
# 输入：base64url 的 32 字节私钥（例如 CF045... 这种）
# 输出：base64url 的 32 字节公钥；失败返回空
derive_pbk_from_priv() {
  local priv_b64url="$1"
  [[ -z "$priv_b64url" ]] && return 1

  # base64url -> base64（替换字符并补齐 padding）
  local b64="${priv_b64url//-/+}"
  b64="${b64//_//}"
  local pad=$(( (4 - ${#b64} % 4) % 4 ))
  if [[ $pad -gt 0 ]]; then b64="${b64}$(printf '=%.0s' $(seq 1 $pad))"; fi

  # 解出原始 32 字节
  local tmpdir; tmpdir="$(mktemp -d)" || return 1
  if ! echo "$b64" | base64 -d > "$tmpdir/raw32.bin" 2>/dev/null; then
    rm -rf "$tmpdir"; return 1
  fi
  # 期望 32 字节
  if [[ $(wc -c < "$tmpdir/raw32.bin") -ne 32 ]]; then
    rm -rf "$tmpdir"; return 1
  fi

  # 组装 PKCS#8（X25519 OID = 1.3.101.110）: 302e020100300506032b656e04220420 || 32B
  {
    printf '\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x6e\x04\x22\x04\x20'
    cat "$tmpdir/raw32.bin"
  } > "$tmpdir/pkcs8.der"

  # 用 OpenSSL 导出公钥 DER（SubjectPublicKeyInfo）
  if ! openssl pkey -inform DER -in "$tmpdir/pkcs8.der" -pubout -outform DER -algorithm X25519 -quiet 2>/dev/null > "$tmpdir/pub.der"; then
    rm -rf "$tmpdir"; return 1
  fi

  # SPKI 末尾 32 字节就是公钥（header 12B: 30 2a 30 05 06 03 2b 65 6e 03 21 00）
  tail -c 32 "$tmpdir/pub.der" > "$tmpdir/pubraw.bin" 2>/dev/null || { rm -rf "$tmpdir"; return 1; }

  # 编码为 base64url（去掉 '='）
  local out; out="$(base64 -w0 < "$tmpdir/pubraw.bin")"
  out="${out//+/-}"; out="${out////_}"; out="${out%%=}"
  out="${out%%=}"; out="${out%%=}"
  echo "$out"

  rm -rf "$tmpdir"
}



# ===================== 安装与守护 =====================

# ===== SSH RTT latency (client<->server) =====
_ss_join_blocks() {
  awk '
    /^ESTAB/ { if (buf!="") print buf; buf=$0; next }
    { buf=buf " " $0 }
    END { if (buf!="") print buf }
  '
}
ssh_rtt_current() {
  command -v ss >/dev/null 2>&1 || { echo ""; return; }

  # 优先用 SSH_CLIENT 里的客户端端口，精准定位
  local cip cport out
  if [[ -n "$SSH_CLIENT" ]]; then
    cip=${SSH_CLIENT%% *}
    cport=$(echo "$SSH_CLIENT" | awk '{print $2}')
  fi

  if [[ -n "$cport" ]]; then
    # 精确筛选：本机 sport 22、对端 dport=客户端端口
    out=$(ss -ti state established "( sport = :22 and dport = :$cport )" 2>/dev/null \
        | sed -n 's/.*rtt:\([0-9.]*\).*/\1/p' | head -n1)
  fi

  if [[ -z "$out" ]]; then
    # 兜底：拿第一条已建立的 ssh 连接的 rtt
    out=$(ss -ti state established sport = :22 2>/dev/null \
      | awk '
          /^ESTAB/ { peer=$5; next }
          /rtt:/   { if (match($0, /rtt:([0-9.]+)/, m)) { print m[1]; exit } }')
  fi

  echo "$out"
}

ssh_rtt_list() {
  command -v ss >/dev/null 2>&1 || { echo "缺少 ss（iproute2）"; return; }
  ss -ti state established sport = :22 2>/dev/null \
  | awk '
      /^ESTAB/ { peer=$5; next }
      /rtt:/   { if (match($0, /rtt:([0-9.]+)/, m)) printf "%-22s  %8s ms\n", peer, m[1] }'
}

show_ssh_latency() {
  local rtt
  rtt=$(ssh_rtt_current)
  if [[ -n "$rtt" ]]; then
    echo "当前 SSH 往返延迟：${rtt} ms"
  else
    echo "当前 SSH 往返延迟：N/A"
  fi
}


# 只写入并启用“当前系统”的那一套；避免两套并存触发 update-rc.d 报错
ensure_dual_init_autoadapt() {
  local init; init=$(detect_init_system)

  case "$init" in
    systemd)
      # 清理 OpenRC 脚本，避免 systemctl 误当 SysV 脚本处理
      rm -f /etc/init.d/sing-box 2>/dev/null || true

      # 写入 systemd unit
      mkdir -p /etc/systemd/system
      cat >/etc/systemd/system/sing-box.service <<'EOF'
[Unit]
Description=Sing-box Service
After=network.target network-online.target
Wants=network-online.target
StartLimitIntervalSec=0
[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=always
RestartSec=2s
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
      systemctl daemon-reload
      systemctl enable --now sing-box
      systemctl is-active --quiet sing-box && echo "✅ systemd 已启用并运行"
      ;;
    openrc)
      # 清理 systemd unit，避免混淆
      systemctl disable --now sing-box >/dev/null 2>&1 || true
      rm -f /etc/systemd/system/sing-box.service 2>/dev/null || true
      systemctl daemon-reload >/dev/null 2>&1 || true

      # 写入 OpenRC 脚本
      mkdir -p /etc/init.d
      cat >/etc/init.d/sing-box <<'EOF'
#!/sbin/openrc-run
command="/usr/local/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
name="sing-box"
supervisor="supervise-daemon"
command_background="yes"
pidfile="/run/sing-box.pid"
respawn_delay=2
respawn_max=0
depend() { need net; }
EOF
      chmod +x /etc/init.d/sing-box || true
      rc-update add sing-box default >/dev/null 2>&1 || true
      rc-service sing-box restart || rc-service sing-box start
      rc-service sing-box status | grep -q started && echo "✅ OpenRC 已启用并运行"
      ;;
    *)
      echo "⚠️ 未检测到 systemd/OpenRC，启用守护脚本兜底"
      rm -f /etc/systemd/system/sing-box.service /etc/init.d/sing-box 2>/dev/null || true
      systemctl daemon-reload >/dev/null 2>&1 || true
      cat >/usr/local/bin/singbox-keeper.sh <<'EOF'
#!/bin/bash
CONFIG="/etc/sing-box/config.json"; BIN="/usr/local/bin/sing-box"
if ! pgrep -x sing-box >/dev/null 2>&1; then
  nohup "$BIN" run -c "$CONFIG" >/var/log/sing-box.log 2>&1 &
fi
EOF
      chmod +x /usr/local/bin/singbox-keeper.sh
      ( crontab -l 2>/dev/null | grep -q '/usr/local/bin/singbox-keeper.sh' ) || \
        ( crontab -l 2>/dev/null; echo '@reboot /usr/local/bin/singbox-keeper.sh'; echo '* * * * * /usr/local/bin/singbox-keeper.sh' ) | crontab -
      echo "✅ 已配置看门狗 + cron 兜底"
      ;;
  esac
}

install_singbox_if_needed() {
  if command -v sing-box >/dev/null 2>&1; then echo "✅ Sing-box 已安装，跳过安装"; return; fi
  echo "⚠️ 未检测到 Sing-box，正在安装..."
  VERSION="1.12.0"
  ARCH=$(uname -m); [[ "$ARCH" == "x86_64" ]] && ARCH="amd64"; [[ "$ARCH" == "aarch64" ]] && ARCH="arm64"
  TMP=$(mktemp -d); cd "$TMP" || exit 1
  echo "⬇️ 下载 Sing-box v$VERSION for $ARCH..."
  curl -fL -O "https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box-${VERSION}-linux-${ARCH}.tar.gz"
  echo "📦 解压中..."; tar -xvzf "sing-box-${VERSION}-linux-${ARCH}.tar.gz"
  echo "⚙️ 安装中..."; cp "sing-box-${VERSION}-linux-${ARCH}/sing-box" /usr/local/bin/; chmod +x /usr/local/bin/sing-box
  cd / && rm -rf "$TMP"
  mkdir -p /etc/sing-box
  [[ -f /etc/sing-box/config.json ]] || echo '{"inbounds":[],"outbounds":[{"type":"direct"}],"route":{"rules":[]}}' > /etc/sing-box/config.json
  echo "✅ Sing-box 已安装到 /usr/local/bin/sing-box"
}

restart_singbox() {
  INIT_SYS=$(detect_init_system)
  if [[ "$INIT_SYS" == "systemd" ]]; then
    systemctl restart sing-box; sleep 1
    systemctl is-active --quiet sing-box && echo "✅ Sing-box 已通过 systemd 重启成功" || { echo "❌ 重启失败"; systemctl status sing-box --no-pager || true; }
  elif [[ "$INIT_SYS" == "openrc" ]]; then
    rc-service sing-box restart >/dev/null 2>&1; sleep 1
    rc-service sing-box status | grep -q started && echo "✅ Sing-box 已通过 OpenRC 重启成功" || { echo "❌ 重启失败（OpenRC）"; rc-service sing-box status || true; }
  else echo "⚠️ 当前系统不支持自动服务管理，请手动重启"; fi
}


# 若检测到 inbounds 全部无法本地连通，则安全重启 sing-box
ensure_singbox_ready() {
  local CONFIG="/etc/sing-box/config.json"
  [[ -f "$CONFIG" ]] || return 0

  local total=0 fail=0
  while read -r p; do
    [[ -n "$p" ]] || continue
    total=$((total+1))
    timeout 1 bash -c "echo > /dev/tcp/127.0.0.1/$p" >/dev/null 2>&1 || fail=$((fail+1))
  done < <(jq -r '.inbounds[]?.listen_port // empty' "$CONFIG" 2>/dev/null)

  if [[ $total -gt 0 && $fail -eq $total ]]; then
    if sing-box check -c "$CONFIG" >/dev/null 2>&1; then
      echo "♻️ 检测到入站未就绪，正在重启 sing-box..."
      restart_singbox
    else
      echo "❌ 配置校验失败，已跳过自动重启（请先修复 /etc/sing-box/config.json）"
    fi
  fi
}

repair_singbox() {
  echo "⚠️ 卸载并清理 sing-box..."
  INIT_SYS=$(detect_init_system)
  if [[ "$INIT_SYS" == "systemd" ]]; then
    systemctl stop sing-box || true; systemctl disable sing-box || true; rm -f /etc/systemd/system/sing-box.service
  elif [[ "$INIT_SYS" == "openrc" ]]; then
    rc-service sing-box stop || true; rc-update del sing-box default || true; rm -f /etc/init.d/sing-box
  fi
  rm -f /usr/local/bin/sing-box /usr/local/bin/sk /usr/local/bin/ck
  rm -rf /etc/sing-box
  echo "✅ 已卸载，执行远程安装脚本..."
  bash <(curl -Ls https://raw.githubusercontent.com/chinahch/sk5/main/install.sh)
  echo "✅ 修复并重装完成"
  ensure_dual_init_autoadapt
}

# ===================== 节点管理 =====================
add_node() {
  echo "请选择协议类型："; echo "1) SOCKS5"; echo "2) VLESS-REALITY"
  read -p "输入协议编号（默认 1）: " PROTO; PROTO=${PROTO:-1}
  CONFIG="/etc/sing-box/config.json"

  if [[ "$PROTO" == "2" ]]; then
    # === VLESS + REALITY ===
    read -p "请输入端口号（留空自动随机 30000-39999）: " PORT
    [[ -z "$PORT" ]] && PORT=$((RANDOM % 1000 + 30000))

    # 端口是否存在（安全写法）
    if jq -r '.inbounds[].listen_port // empty' "$CONFIG" | grep -xq "$PORT"; then
      echo "⚠️ 端口 $PORT 已存在，请换一个。"; return 1; fi

    # UUID
    if command -v uuidgen >/dev/null 2>&1; then UUID=$(uuidgen)
    else RAW=$(openssl rand -hex 16); UUID="${RAW:0:8}-${RAW:8:4}-${RAW:12:4}-${RAW:16:4}-${RAW:20:12}"; fi

    SERVER_NAME="www.cloudflare.com"
    FINGERPRINT_POOL=("chrome" "firefox" "safari" "ios" "android")
    FINGERPRINT=${FINGERPRINT_POOL[$RANDOM % ${#FINGERPRINT_POOL[@]}]}
    FLOW="xtls-rprx-vision"

    KEY_PAIR=$(sing-box generate reality-keypair)
    PRIVATE_KEY=$(echo "$KEY_PAIR" | awk -F': ' '/PrivateKey/ {print $2}')
    PUBLIC_KEY=$(echo "$KEY_PAIR" | awk -F': ' '/PublicKey/ {print $2}')
    [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]] && echo "❌ 密钥对生成失败" && return 1

    SHORT_ID=$(openssl rand -hex 4)
    TAG=$(generate_unique_tag)

    # 写入配置（临时 jq 过滤器文件）
    tmpcfg=$(mktemp); tmpjq=$(mktemp)
    cat >"$tmpjq"<<'JQ'
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
      "handshake": { "server": $server, "server_port": 443 },
      "private_key": $prikey,
      "short_id": [ $sid ]
    }
  }
}]
JQ
    jq --arg port "$PORT" --arg uuid "$UUID" --arg prikey "$PRIVATE_KEY" \
       --arg sid "$SHORT_ID" --arg server "$SERVER_NAME" --arg fp "$FINGERPRINT" \
       --arg flow "$FLOW" --arg tag "$TAG" \
       -f "$tmpjq" "$CONFIG" > "$tmpcfg" && mv "$tmpcfg" "$CONFIG"
    rm -f "$tmpjq"

    echo "🧪 正在校验配置..."
    if sing-box check -c "$CONFIG" >/dev/null 2>&1; then
      echo "✅ 配置通过，正在重启 Sing-box..."; restart_singbox
      ensure_singbox_ready
    else
      echo "❌ 配置校验失败，请检查 /etc/sing-box/config.json"; sing-box check -c "$CONFIG"; return 1
    fi

    # 保存元数据
    META="/etc/sing-box/nodes_meta.json"; mkdir -p /etc/sing-box; [[ -f "$META" ]] || echo '{}' > "$META"
    tmpmeta=$(mktemp); tmpjq=$(mktemp)
    cat >"$tmpjq"<<'JQ'
. + {($tag): {pbk:$pbk, sid:$sid, sni:$sni, port:$port, fp:$fp}}
JQ
    jq --arg tag "$TAG" --arg pbk "$PUBLIC_KEY" --arg sid "$SHORT_ID" \
       --arg sni "$SERVER_NAME" --arg port "$PORT" --arg fp "$FINGERPRINT" \
       -f "$tmpjq" "$META" > "$tmpmeta" && mv "$tmpmeta" "$META"
    rm -f "$tmpjq"

    IPV4=$(curl -s --max-time 2 https://api.ipify.org)
    echo ""; echo "✅ 添加成功：VLESS Reality"
    echo "端口: $PORT"; echo "UUID: $UUID"; echo "Public Key: $PUBLIC_KEY"; echo "Short ID: $SHORT_ID"
    echo "SNI: $SERVER_NAME"; echo "Fingerprint: $FINGERPRINT"; echo "TAG: $TAG"; echo ""
    echo "👉 v2rayN / sing-box 客户端链接："
    echo "vless://${UUID}@${IPV4}:${PORT}?encryption=none&flow=${FLOW}&type=tcp&security=reality&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&sni=${SERVER_NAME}&fp=${FINGERPRINT}#${TAG}"
    echo ""

  else
    # === SOCKS5 ===
    read -p "请输入端口号（留空自动）: " PORT; [[ -z "$PORT" ]] && PORT=$((RANDOM % 10000 + 40000))
    read -p "请输入用户名（默认 user）: " USER; USER=${USER:-user}
    read -p "请输入密码（默认 pass123）: " PASS; PASS=${PASS:-pass123}
    TAG="sk5-$(get_country_code)-$(tr -dc 'A-Z' </dev/urandom | head -c1)"

    tmpcfg=$(mktemp); tmpjq=$(mktemp)
    cat >"$tmpjq"<<'JQ'
.inbounds += [{
  "type": "socks",
  "tag": $tag,
  "listen": "0.0.0.0",
  "listen_port": ($port|tonumber),
  "users": [{"username": $user, "password": $pass}]
}]
JQ
    jq --arg port "$PORT" --arg user "$USER" --arg pass "$PASS" --arg tag "$TAG" \
       -f "$tmpjq" "$CONFIG" > "$tmpcfg" && mv "$tmpcfg" "$CONFIG"
    rm -f "$tmpjq"

    echo "🧪 校验配置..."
    if sing-box check -c "$CONFIG" >/dev/null 2>&1; then
      echo "✅ 配置通过，正在重启..."; restart_singbox
      ensure_singbox_ready
    else
      echo "❌ 配置失败，Sing-box 未重启"; sing-box check -c "$CONFIG"; return 1
    fi

    ENCODED=$(echo -n "$USER:$PASS" | base64); IPV4=$(curl -s --max-time 2 https://api.ipify.org); IPV6=$(get_ipv6_address)
    echo ""; echo "✅ SOCKS5 节点已添加："
    echo "端口: $PORT | 用户: $USER | 密码: $PASS"
    echo "IPv4: socks://${ENCODED}@${IPV4}:${PORT}#$TAG"
    [[ -n "$IPV6" ]] && echo "IPv6: socks://${ENCODED}@[${IPV6}]:${PORT}#$TAG"
  fi
}

# 查看节点（增强：缺参标记 + 一键修复）
# 查看节点（增强：缺参标记 + 一键修复；回车=修复全部，0=返回）
# 查看节点（增强：缺参标记 + 一键修复；回车=修复全部，0=返回）
# 查看节点（增强：缺参标记 + 一键重建；回车=重建全部，0=返回）
# 查看节点（极速版：不做连通/延迟探测；回车=重建全部，0=返回）
view_nodes() {
  local CONFIG="/etc/sing-box/config.json"
  local META="/etc/sing-box/nodes_meta.json"
  [[ -f "$META" ]] || META="/dev/null"

  local IPV4 IPV6
  IPV4=$(curl -s --max-time 2 https://api.ipify.org)
  IPV6=$(ip -6 addr show scope global | awk '/inet6/ {print $2}' | cut -d/ -f1 | head -n1)

  # 记录需要重建的 tag（index \t tag）
  local IDXMAP
  IDXMAP=$(mktemp)

  # 仅渲染信息，不做 ping/端口探测，确保输出迅速
  jq -c '.inbounds[]' "$CONFIG" | nl -w2 -s'. ' | while read -r line; do
    INDEX=$(echo "$line" | cut -d. -f1)
    JSON=$(echo "$line" | cut -d' ' -f2-)
    PORT=$(echo "$JSON" | jq -r '.listen_port')
    TAG=$(echo "$JSON" | jq -r '.tag')
    TYPE=$(echo "$JSON" | jq -r '.type')

    echo "[$INDEX] 端口: $PORT | 协议: $TYPE | 名称: $TAG"

    if [[ "$TYPE" == "socks" ]]; then
      USER=$(echo "$JSON" | jq -r '.users[0].username')
      PASS=$(echo "$JSON" | jq -r '.users[0].password')
      ENCODED=$(echo -n "$USER:$PASS" | base64)
      echo "IPv4: socks://${ENCODED}@${IPV4}:${PORT}#$TAG"
      [[ -n "$IPV6" ]] && echo "IPv6: socks://${ENCODED}@[${IPV6}]:${PORT}#$TAG"

    elif [[ "$TYPE" == "vless" ]]; then
      UUID=$(echo "$JSON" | jq -r '.users[0].uuid')

      PBK=$(jq -r --arg tag "$TAG" '.[$tag].pbk // empty' "$META" 2>/dev/null)
      SID=$(jq -r --arg tag "$TAG" '.[$tag].sid // empty' "$META" 2>/dev/null)
      SNI_META=$(jq -r --arg tag "$TAG" '.[$tag].sni // empty' "$META" 2>/dev/null)

      SERVER_NAME=${SNI_META:-$(echo "$JSON" | jq -r '.tls.reality.handshake.server // .tls.server_name // empty')}
      [[ -z "$SID" ]] && SID=$(echo "$JSON" | jq -r '.tls.reality.short_id[0] // empty')

      if [[ -z "$PBK" || -z "$SID" || -z "$SERVER_NAME" ]]; then
        echo "⚠️ 此节点参数缺失/异常（pbk/sid/sni），可一键重建。"
        echo -e "$INDEX\t$TAG" >> "$IDXMAP"
      fi

      echo "vless://${UUID}@${IPV4}:${PORT}?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&pbk=${PBK}&sid=${SID}&sni=${SERVER_NAME}&fp=chrome#${TAG}"
    fi
    echo "---------------------------------------------------"
  done

  # 有异常则交互：回车重建全部；输入 0 跳过
  if [[ -s "$IDXMAP" ]]; then
    echo "🔧 检测到缺参/异常节点。"
    echo "   - 直接回车：重建全部缺参节点（保留原端口与标签）"
    echo "   - 输入 0：返回主菜单/跳过"
    read -r REBUILD_CHOICE

    if [[ -z "$REBUILD_CHOICE" ]]; then
      while read -r _ TAG_TO_FIX; do
        rebuild_bad_for_tag "$TAG_TO_FIX"
      done < "$IDXMAP"
      echo "♻️ 正在重启服务以应用变更..."
      restart_singbox
      ensure_singbox_ready
    elif [[ "$REBUILD_CHOICE" == "0" ]]; then
      echo "⏭️ 已跳过重建，返回主菜单"
    else
      echo "⏭️ 未识别输入：$REBUILD_CHOICE ，已跳过重建"
    fi
  fi

  rm -f "$IDXMAP"
}

# 修复指定 tag 节点缺少的 pbk/sid/sni（会写回 config 与 nodes_meta.json）
repair_missing_for_tag() {
  local TAG="$1"
  local CONFIG="/etc/sing-box/config.json"
  local META="/etc/sing-box/nodes_meta.json"
  [[ -f "$META" ]] || echo '{}' > "$META"

  # 通过 tag 找到 inbounds 的下标（避免 jq select()，用 awk 过滤）
  local IDX
  IDX=$(jq -r '.inbounds | to_entries[] | "\(.key) \(.value.tag)"' "$CONFIG" \
        | awk -v t="$TAG" '$2==t {print $1; exit}')
  if [[ -z "$IDX" ]]; then
    echo "❌ 未找到 tag=$TAG 的节点"; return 1
  fi

  # 取现有参数
  local PRIV SNI SID PBK
  PRIV=$(jq -r --argjson i "$IDX" '.inbounds[$i].tls.reality.private_key // empty' "$CONFIG")
  SNI=$(jq -r --argjson i "$IDX" '.inbounds[$i].tls.reality.handshake.server // .inbounds[$i].tls.server_name // empty' "$CONFIG")
  SID=$(jq -r --argjson i "$IDX" '.inbounds[$i].tls.reality.short_id[0] // empty' "$CONFIG")
  PBK=$(jq -r --arg tag "$TAG" '.[$tag].pbk // empty' "$META" 2>/dev/null)

  # 兜底：生成/推导
  [[ -z "$SNI" ]] && SNI="www.cloudflare.com"
  [[ -z "$SID" ]] && SID="$(openssl rand -hex 4)"
    # 兜底：从私钥推导公钥（优先用 OpenSSL；失败再试 sing-box）
  if [[ -z "$PBK" && -n "$PRIV" ]]; then
    PBK="$(derive_pbk_from_priv "$PRIV" || true)"
    if [[ -z "$PBK" ]]; then
      PBK=$(sing-box generate reality-keypair --private-key "$PRIV" 2>/dev/null | awk -F': ' '/PublicKey/ {print $2}')
    fi
  fi


  # 写回 config（使用临时 jq 过滤器文件，避免 shell 引号问题）
  local tmpcfg tmpjq
  tmpcfg=$(mktemp); tmpjq=$(mktemp)
  cat >"$tmpjq"<<'JQ'
.inbounds[$i].tls.server_name = $sni
| .inbounds[$i].tls.reality.handshake.server = $sni
| .inbounds[$i].tls.reality.handshake.server_port = 443
| .inbounds[$i].tls.reality.short_id = [ $sid ]
JQ
  jq --argjson i "$IDX" --arg sni "$SNI" --arg sid "$SID" \
     -f "$tmpjq" "$CONFIG" > "$tmpcfg" && mv "$tmpcfg" "$CONFIG"
  rm -f "$tmpjq"

  # 更新元数据
  tmpcfg=$(mktemp); tmpjq=$(mktemp)
  cat >"$tmpjq"<<'JQ'
. + {($tag): ( ( .[$tag] // {} ) + {pbk:$pbk, sid:$sid, sni:$sni} )}
JQ
  jq --arg tag "$TAG" --arg pbk "${PBK:-}" --arg sid "$SID" --arg sni "$SNI" \
     -f "$tmpjq" "$META" > "$tmpcfg" && mv "$tmpcfg" "$META"
  rm -f "$tmpjq"

  echo "🔧 已修复：$TAG  （pbk:${PBK:+OK/缺失->}$( [[ -n "$PBK" ]] && echo OK || echo "未能推导" ), sid:$SID, sni:$SNI）"
}

# 重建指定 tag 的 VLESS Reality 节点（保留原端口与原标签）
rebuild_bad_for_tag() {
  local TAG="$1"
  local CONFIG="/etc/sing-box/config.json"
  local META="/etc/sing-box/nodes_meta.json"
  [[ -f "$META" ]] || echo '{}' > "$META"

  # 定位 inbounds 下标、端口、类型（不用 select()，避免括号坑）
  local LINE IDX PORT TYPE
  LINE=$(jq -r '.inbounds | to_entries[] | "\(.key)\t\(.value.tag)\t\(.value.listen_port)\t\(.value.type)"' "$CONFIG" \
         | awk -F'\t' -v t="$TAG" '$2==t {print; exit}')
  [[ -z "$LINE" ]] && { echo "❌ 未找到节点：$TAG"; return 1; }

  IDX=$(echo "$LINE"  | awk -F'\t' '{print $1}')
  PORT=$(echo "$LINE" | awk -F'\t' '{print $3}')
  TYPE=$(echo "$LINE" | awk -F'\t' '{print $4}')
  [[ "$TYPE" != "vless" ]] && { echo "⏭️ 非 vless 节点跳过：$TAG"; return 0; }

  # 生成新参数（保持端口、标签；其余重建）
  local UUID SERVER_NAME FINGERPRINT FLOW KEY_PAIR PRIVATE_KEY PUBLIC_KEY SHORT_ID
  if command -v uuidgen >/dev/null 2>&1; then
    UUID=$(uuidgen)
  else
    RAW=$(openssl rand -hex 16); UUID="${RAW:0:8}-${RAW:8:4}-${RAW:12:4}-${RAW:16:4}-${RAW:20:12}"
  fi
  SERVER_NAME="www.cloudflare.com"
  local FINGERPRINT_POOL=("chrome" "firefox" "safari" "ios" "android")
  FINGERPRINT=${FINGERPRINT_POOL[$RANDOM % ${#FINGERPRINT_POOL[@]}]}
  FLOW="xtls-rprx-vision"

  KEY_PAIR=$(sing-box generate reality-keypair) || { echo "❌ 生成 Reality 密钥失败：$TAG"; return 1; }
  PRIVATE_KEY=$(echo "$KEY_PAIR" | awk -F': ' '/PrivateKey/ {print $2}')
  PUBLIC_KEY=$(echo "$KEY_PAIR"  | awk -F': ' '/PublicKey/  {print $2}')
  [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]] && { echo "❌ 密钥对为空：$TAG"; return 1; }

  SHORT_ID=$(openssl rand -hex 4)

  # 替换 inbounds[$IDX]
  local tmpcfg tmpjq
  tmpcfg=$(mktemp)
  tmpjq=$(mktemp)
  cat >"$tmpjq"<<'JQ'
.inbounds[$i] = {
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
      "handshake": { "server": $server, "server_port": 443 },
      "private_key": $prikey,
      "short_id": [ $sid ]
    }
  }
}
JQ
  jq --argjson i "$IDX" \
     --arg tag "$TAG" --arg port "$PORT" --arg uuid "$UUID" --arg flow "$FLOW" \
     --arg server "$SERVER_NAME" --arg prikey "$PRIVATE_KEY" --arg sid "$SHORT_ID" \
     -f "$tmpjq" "$CONFIG" > "$tmpcfg" && mv "$tmpcfg" "$CONFIG"
  rm -f "$tmpjq"

  # 同步元数据（写 pbk/sid/sni/port/fp）
  local tmpmeta
  tmpmeta=$(mktemp); tmpjq=$(mktemp)
  cat >"$tmpjq"<<'JQ'
. + {($tag): {pbk:$pbk, sid:$sid, sni:$sni, port:$port, fp:$fp}}
JQ
  jq --arg tag "$TAG" --arg pbk "$PUBLIC_KEY" --arg sid "$SHORT_ID" \
     --arg sni "$SERVER_NAME" --arg port "$PORT" --arg fp "$FINGERPRINT" \
     -f "$tmpjq" "$META" > "$tmpmeta" && mv "$tmpmeta" "$META"
  rm -f "$tmpjq"

  echo "🧱 已重建：$TAG （端口:$PORT / pbk:已更新 / sid:$SHORT_ID / sni:$SERVER_NAME）"
}


delete_node() {
  CONFIG="/etc/sing-box/config.json"; META="/etc/sing-box/nodes_meta.json"
  COUNT=$(jq -r '.inbounds | length' "$CONFIG")
  [[ $COUNT -eq 0 ]] && echo "暂无节点" && return

  view_nodes
  echo "[0] 删除所有节点"; read -p "请输入要删除的节点序号或选项编号: " IDX

  if [[ "$IDX" == "0" ]]; then
    read -p "⚠️ 确认删除全部节点？此操作不可恢复！(y/n): " CONFIRM
    [[ "$CONFIRM" != "y" ]] && echo "❌ 已取消删除" && return
    tmpcfg=$(mktemp); tmpjq=$(mktemp)
    cat >"$tmpjq"<<'JQ'
.inbounds = []
JQ
    jq -f "$tmpjq" "$CONFIG" > "$tmpcfg" && mv "$tmpcfg" "$CONFIG"; rm -f "$tmpjq"
    [[ -f "$META" ]] && echo '{}' > "$META"
    echo "✅ 所有节点已删除（无需立即重启）"; return
  fi

  IDX=$((IDX - 1))
  if [[ $IDX -lt 0 || $IDX -ge $COUNT ]]; then echo "❌ 无效序号：$((IDX + 1))"; return; fi

  TAG_TO_DELETE=$(jq -r ".inbounds[$IDX].tag // empty" "$CONFIG")
  tmpcfg=$(mktemp); jq "del(.inbounds[$IDX])" "$CONFIG" > "$tmpcfg" && mv "$tmpcfg" "$CONFIG"
  if [[ -n "$TAG_TO_DELETE" && -f "$META" ]]; then tmpmeta=$(mktemp); jq "del(.\"$TAG_TO_DELETE\")" "$META" > "$tmpmeta" && mv "$tmpmeta" "$META"; fi
  echo "✅ 已删除节点 [$((IDX + 1))]（无需立即重启）"
}

update_singbox() {
  echo "📦 正在检查 Sing-box 更新..."
  CUR=$(sing-box version 2>/dev/null | awk '/version/{print $3}')
  echo "当前版本: ${CUR:-未知}"
  LATEST=$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r '.tag_name' | sed 's/^v//')
  echo "最新版本: $LATEST"
  if [[ -n "$CUR" && -n "$LATEST" && "$CUR" == "$LATEST" ]]; then echo "✅ 已是最新版，无需更新。"; return; fi
  read -p "是否更新到 $LATEST？(y/n): " CONFIRM; [[ "$CONFIRM" != "y" ]] && echo "❌ 已取消更新" && return
  ARCH=$(uname -m); [[ "$ARCH" == "x86_64" ]] && ARCH="amd64"; [[ "$ARCH" == "aarch64" ]] && ARCH="arm64"
  TMP=$(mktemp -d); cd "$TMP" || exit 1
  echo "⬇️ 正在下载 sing-box ${LATEST}..."; curl -fL -O "https://github.com/SagerNet/sing-box/releases/download/v${LATEST}/sing-box-${LATEST}-linux-${ARCH}.tar.gz"
  echo "📦 解压中..."; tar -xvzf "sing-box-${LATEST}-linux-${ARCH}.tar.gz"
  echo "⚙️ 替换可执行文件..."; INIT_SYS=$(detect_init_system); [[ "$INIT_SYS" == "systemd" ]] && systemctl stop sing-box || true; [[ "$INIT_SYS" == "openrc" ]] && rc-service sing-box stop >/dev/null 2>&1 || true
  cp "sing-box-${LATEST}-linux-${ARCH}/sing-box" /usr/local/bin/; chmod +x /usr/local/bin/sing-box
  [[ "$INIT_SYS" == "systemd" ]] && systemctl start sing-box || true; [[ "$INIT_SYS" == "openrc" ]] && rc-service sing-box start >/dev/null 2>&1 || true
  echo "✅ 已成功升级为 v${LATEST}"; cd / && rm -rf "$TMP"
}

main_menu() {
  ensure_singbox_ready
  echo ""; show_ssh_latency; show_version_info
  echo "============= Sing-box 节点管理工具（IPv4 + IPv6） ============="
  echo "1) 添加节点"; echo "2) 查看所有节点"; echo "3) 删除用户（通过序号）"
  echo "4) 检查并更新 Sing-box 到最新版"; echo "5) 重启 Sing-box 服务"; echo "6) 修复 Sing-box（卸载并重装）"
  echo "9) 退出"; echo "==============================================================="
  read -p "请输入操作编号: " CHOICE
  case "$CHOICE" in
    1) add_node ;; 2) view_nodes ;; 3) delete_node ;; 4) update_singbox ;;
    5) restart_singbox ;; 6) repair_singbox ;; 9) exit 0 ;; *) echo "无效输入" ;;
  esac
}

# ===================== 执行 =====================
install_dependencies
install_singbox_if_needed
ensure_dual_init_autoadapt
while true; do main_menu; done
