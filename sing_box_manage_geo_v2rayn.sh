#!/usr/bin/env bash
# sk5.sh — Sing-box 管理脚本（systemd/OpenRC 自适应 + 缺参一键重建 + 修复/重装子菜单 + SSH RTT + 端口占用循环重试）
# 2025-08-08

umask 022

# ========== 工具函数 ==========

detect_os() {
  if [[ -f /etc/os-release ]]; then . /etc/os-release; echo "$ID"; else echo "unknown"; fi
}

detect_init_system() {
  if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    echo systemd
  elif command -v rc-status >/dev/null 2>&1 || [[ -d /run/openrc ]] || [[ -x /sbin/openrc-run ]]; then
    echo openrc
  else
    echo unknown
  fi
}

install_dependencies() {
  if command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1 && command -v uuidgen >/dev/null 2>&1; then
    echo "✅ curl、jq 和 uuidgen 已安装，跳过安装步骤"
    return
  fi
  local OS; OS=$(detect_os)
  case "$OS" in
    alpine) apk add --no-cache curl jq util-linux iproute2 openssl ;;
    debian|ubuntu) apt update && apt install -y curl jq uuid-runtime iproute2 openssl ;;
    centos|rhel|fedora) yum install -y curl jq util-linux iproute openssl ;;
    *) echo "⚠️ 未识别系统，请手动安装 curl、jq、uuidgen、iproute2、openssl" ;;
  esac
}

get_country_code() {
  local CODE
  CODE=$(curl -s --max-time 3 https://ipinfo.io | jq -r '.country // empty' 2>/dev/null || true)
  [[ "$CODE" =~ ^[A-Z]{2}$ ]] && echo "$CODE" || echo "ZZ"
}

get_ipv6_address() {
  ip -6 addr show scope global | awk '/inet6/ {print $2}' | cut -d/ -f1 | head -n1
}

show_version_info() {
  if command -v sing-box >/dev/null 2>&1; then
    local VER ARCH
    VER=$(sing-box version 2>/dev/null | awk '/sing-box version/{print $3}')
    ARCH=$(sing-box version 2>/dev/null | awk '/Environment:/{print $3}')
    echo "Sing-box 版本: ${VER:-未知}  | 架构: ${ARCH:-未知}"
  else
    echo "Sing-box 未安装"
  fi
}

# 当前 SSH RTT（ms）
ssh_rtt_current() {
  command -v ss >/dev/null 2>&1 || { echo ""; return; }
  local cport out
  if [[ -n "$SSH_CLIENT" ]]; then
    cport=$(echo "$SSH_CLIENT" | awk '{print $2}')
  fi
  if [[ -n "$cport" ]]; then
    out=$(ss -ti state established "( sport = :22 and dport = :$cport )" 2>/dev/null | sed -n 's/.*rtt:\([0-9.]*\).*/\1/p' | head -n1)
  fi
  if [[ -z "$out" ]]; then
    out=$(ss -ti state established sport = :22 2>/dev/null | awk '/rtt:/{if (match($0,/rtt:([0-9.]+)/,m)){print m[1]; exit}}')
  fi
  echo "$out"
}

show_ssh_latency() {
  local rtt; rtt=$(ssh_rtt_current)
  if [[ -n "$rtt" ]]; then
    echo "当前 SSH 往返延迟：${rtt} ms"
  else
    echo "当前 SSH 往返延迟：N/A"
  fi
}

# 生成不重复 tag
generate_unique_tag() {
  local base="vless-reality-$(get_country_code)"
  local try=0
  local tags
  if [[ -f /etc/sing-box/config.json ]]; then
    tags=$(jq -r '.inbounds[]?.tag // empty' /etc/sing-box/config.json 2>/dev/null)
  fi
  while true; do
    local RAND CANDIDATE
    RAND=$(tr -dc 'A-Z' </dev/urandom | head -c1)
    CANDIDATE="${base}-${RAND}"
    if ! grep -Fxq "$CANDIDATE" <<<"$tags"; then
      echo "$CANDIDATE"
      return
    fi
    try=$((try+1))
    if [[ $try -ge 26 ]]; then
      echo "${base}-$(date +%s)"
      return
    fi
  done
}

# 通用：读入唯一且合法的端口；回车=随机区间，输入0=返回
# 用法：PORT=$(read_unique_port "$CONFIG" 30000 39999 "提示语") || return
read_unique_port() {
  local CONFIG="$1" LOW="$2" HIGH="$3" PROMPT="$4"
  local PORT
  while :; do
    read -p "$PROMPT" PORT
    if [[ "$PORT" == "0" ]]; then
      echo "⏪ 已返回主菜单" >&2
      return 1
    fi
    if [[ -z "$PORT" ]]; then
      PORT=$((RANDOM % (HIGH - LOW + 1) + LOW))
      echo "（已自动选择随机端口：$PORT）" >&2
    fi
    if ! [[ "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
      echo "❌ 端口不合法：$PORT，请重试。" >&2
      continue
    fi
    if jq -e --argjson p "$PORT" '.inbounds[]? | select(.listen_port == $p)' "$CONFIG" >/dev/null 2>&1; then
      echo "⚠️ 端口 $PORT 已存在，请换一个。" >&2
      continue
    fi
    echo "$PORT"
    return 0
  done
}

# ========== 安装 / 服务自适应 ==========

install_singbox_if_needed() {
  if command -v sing-box >/dev/null 2>&1; then
    echo "✅ Sing-box 已安装，跳过安装"
    return
  fi
  echo "⚠️ 未检测到 Sing-box，正在安装..."
  local VERSION="1.12.0"
  local ARCH; ARCH=$(uname -m)
  [[ "$ARCH" == "x86_64" ]] && ARCH="amd64"
  [[ "$ARCH" == "aarch64" ]] && ARCH="arm64"
  local TMP; TMP=$(mktemp -d)
  cd "$TMP" || exit 1
  echo "⬇️ 下载 Sing-box v$VERSION ($ARCH)..."
  curl -fL -O "https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box-${VERSION}-linux-${ARCH}.tar.gz" || { echo "❌ 下载失败"; return 1; }
  echo "📦 解压中..."; tar -xzf "sing-box-${VERSION}-linux-${ARCH}.tar.gz"
  echo "⚙️ 安装中..."; cp "sing-box-${VERSION}-linux-${ARCH}/sing-box" /usr/local/bin/ && chmod +x /usr/local/bin/sing-box
  cd / && rm -rf "$TMP"
  mkdir -p /etc/sing-box
  [[ -f /etc/sing-box/config.json ]] || echo '{"inbounds":[],"outbounds":[{"type":"direct"}],"route":{"rules":[]}}' > /etc/sing-box/config.json
  echo "✅ 已安装到 /usr/local/bin/sing-box"
}

ensure_dual_init_autoadapt() {
  local INIT_SYS; INIT_SYS=$(detect_init_system)
  mkdir -p /etc/sing-box
  [[ -f /etc/sing-box/config.json ]] || echo '{"inbounds":[],"outbounds":[{"type":"direct"}],"route":{"rules":[]}}' > /etc/sing-box/config.json

  if [[ "$INIT_SYS" == "systemd" ]]; then
    rm -f /etc/init.d/sing-box 2>/dev/null || true
    cat >/etc/systemd/system/sing-box.service <<'UNIT'
[Unit]
Description=Sing-box Service
After=network.target network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable --now sing-box
    systemctl is-active --quiet sing-box && echo "✅ systemd 已启用并运行"
  elif [[ "$INIT_SYS" == "openrc" ]]; then
    systemctl disable --now sing-box >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/sing-box.service 2>/dev/null || true
    systemctl daemon-reload >/dev/null 2>&1 || true
    cat >/etc/init.d/sing-box <<'RC'
#!/sbin/openrc-run
name="sing-box"
command="/usr/local/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
pidfile="/run/sing-box.pid"
depend() { need net; }
RC
    chmod +x /etc/init.d/sing-box
    rc-update add sing-box default >/dev/null 2>&1 || true
    rc-service sing-box restart >/dev/null 2>&1 || rc-service sing-box start >/dev/null 2>&1
    rc-service sing-box status | grep -q started && echo "✅ OpenRC 已启用并运行"
  else
    cat >/usr/local/bin/singbox-keeper.sh <<'KEEP'
#!/usr/bin/env bash
CONFIG="/etc/sing-box/config.json"; BIN="/usr/local/bin/sing-box"
if ! pgrep -x sing-box >/dev/null 2>&1; then
  nohup "$BIN" run -c "$CONFIG" >/var/log/sing-box.log 2>&1 &
fi
KEEP
    chmod +x /usr/local/bin/singbox-keeper.sh
    ( crontab -l 2>/dev/null | grep -q '/usr/local/bin/singbox-keeper.sh' ) || \
      ( crontab -l 2>/dev/null; echo '@reboot /usr/local/bin/singbox-keeper.sh'; echo '* * * * * /usr/local/bin/singbox-keeper.sh' ) | crontab -
    echo "⚠️ 未检测到 systemd/OpenRC，已启用看门狗兜底。"
  fi
}

restart_singbox() {
  local INIT_SYS; INIT_SYS=$(detect_init_system)
  if [[ "$INIT_SYS" == "systemd" ]]; then
    systemctl restart sing-box
    sleep 1
    systemctl is-active --quiet sing-box && echo "✅ Sing-box 已通过 systemd 重启成功" || { echo "❌ 重启失败"; systemctl status sing-box --no-pager || true; }
  elif [[ "$INIT_SYS" == "openrc" ]]; then
    rc-service sing-box restart >/dev/null 2>&1
    sleep 1
    rc-service sing-box status | grep -q started && echo "✅ Sing-box 已通过 OpenRC 重启成功" || { echo "❌ 重启失败（OpenRC）"; rc-service sing-box status || true; }
  else
    echo "⚠️ 当前系统不支持自动服务管理，请手动重启"
  fi
}

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

# ========== 节点管理 ==========

derive_pbk_from_priv() {
  local priv="$1"
  [[ -z "$priv" ]] && return 1
  if sing-box generate reality-keypair --private-key "$priv" >/tmp/_pbk 2>/dev/null; then
    awk -F': ' '/PublicKey/ {print $2}' /tmp/_pbk
    rm -f /tmp/_pbk
    return 0
  fi
  local b64="${priv//-+/+}"; b64="${b64//_//}"
  local pad=$(( (4 - ${#b64} % 4) % 4  ))
  if [[ $pad -gt 0 ]]; then b64="${b64}$(printf '=%.0s' $(seq 1 $pad))"; fi
  local tmp; tmp=$(mktemp -d)
  echo "$b64" | base64 -d > "$tmp/raw32.bin" 2>/dev/null || { rm -rf "$tmp"; return 1; }
  if [[ $(wc -c < "$tmp/raw32.bin") -ne 32 ]]; then rm -rf "$tmp"; return 1; fi
  { printf '\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x6e\x04\x22\x04\x20'; cat "$tmp/raw32.bin"; } > "$tmp/pkcs8.der"
  openssl pkey -inform DER -in "$tmp/pkcs8.der" -pubout -outform DER -algorithm X25519 -quiet 2>/dev/null > "$tmp/pub.der" || { rm -rf "$tmp"; return 1; }
  tail -c 32 "$tmp/pub.der" > "$tmp/pubraw.bin"
  local out; out="$(base64 -w0 < "$tmp/pubraw.bin")"
  out="${out//+/-}"; out="${out////_}"; out="${out%%=}"; out="${out%%=}"; out="${out%%=}"
  echo "$out"
  rm -rf "$tmp"
}

rebuild_bad_for_tag() {
  local TAG="$1"
  local CONFIG="/etc/sing-box/config.json"
  local META="/etc/sing-box/nodes_meta.json"
  [[ -z "$TAG" ]] && return 1

  local IDX; IDX=$(jq -r --arg t "$TAG" '[(.inbounds // []) | to_entries[] | select(.value.tag==$t) | .key][0] // empty' "$CONFIG")
  [[ -z "$IDX" ]] && { echo "❌ 未找到节点：$TAG"; return 1; }

  local PORT UUID
  PORT=$(jq -r --arg t "$TAG" '.inbounds[] | select(.tag==$t) | .listen_port' "$CONFIG")
  UUID=$(jq -r --arg t "$TAG" '.inbounds[] | select(.tag==$t) | .users[0].uuid' "$CONFIG")

  local KEY_PAIR PRIVATE_KEY PUBLIC_KEY SHORT_ID SERVER_NAME FLOW
  KEY_PAIR=$(sing-box generate reality-keypair) || { echo "❌ 重建失败：生成密钥失败"; return 1; }
  PRIVATE_KEY=$(echo "$KEY_PAIR" | awk -F': ' '/PrivateKey/ {print $2}')
  PUBLIC_KEY=$(echo "$KEY_PAIR"  | awk -F': ' '/PublicKey/  {print $2}')
  SHORT_ID=$(openssl rand -hex 4)
  SERVER_NAME="www.cloudflare.com"
  FLOW="xtls-rprx-vision"

  local tmpcfg; tmpcfg=$(mktemp)
  jq --argjson idx "$IDX" \
     --arg port "$PORT" \
     --arg uuid "$UUID" \
     --arg prikey "$PRIVATE_KEY" \
     --arg sid "$SHORT_ID" \
     --arg server "$SERVER_NAME" \
     --arg flow "$FLOW" \
     --arg tag "$TAG" '
     .inbounds[$idx] = {
       "type": "vless",
       "tag": $tag,
       "listen": "0.0.0.0",
       "listen_port": ($port|tonumber),
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
     }' "$CONFIG" > "$tmpcfg" && mv "$tmpcfg" "$CONFIG"

  mkdir -p /etc/sing-box
  [[ -f "$META" ]] || echo '{}' > "$META"
  local tmpmeta; tmpmeta=$(mktemp)
  jq --arg tag "$TAG" \
     --arg pbk "$PUBLIC_KEY" \
     --arg sid "$SHORT_ID" \
     --arg sni "$SERVER_NAME" \
     --arg port "$PORT" \
     '. + {($tag): {pbk:$pbk, sid:$sid, sni:$sni, port:$port}}' \
     "$META" > "$tmpmeta" && mv "$tmpmeta" "$META"

  echo "🔧 已重建：$TAG"
}

# 添加节点
add_node() {
  echo "请选择协议类型："
  echo "0) 返回主菜单"
  echo "1) SOCKS5"
  echo "2) VLESS-REALITY"
  read -p "输入协议编号（默认 1，输入 0 返回）: " PROTO
  PROTO=${PROTO:-1}
  [[ "$PROTO" == "0" ]] && echo "⏪ 已返回主菜单" && return

  local CONFIG="/etc/sing-box/config.json"
  mkdir -p /etc/sing-box

  if [[ "$PROTO" == "2" ]]; then
    # 确认 sing-box 可用（防止刚刚“完全卸载”后直接来添加节点）
    if ! command -v sing-box >/dev/null 2>&1; then
      echo "❌ 未检测到 sing-box（可能你刚执行了“完全卸载”）。"
      echo "   可选择："
      echo "     1) 立即自动安装并初始化服务（推荐）"
      echo "     0) 返回主菜单"
      read -p "请选择: " _ai
      if [[ "$_ai" == "1" ]]; then
        install_singbox_if_needed || { echo "❌ 安装失败"; return 1; }
        ensure_dual_init_autoadapt
      else
        echo "⏪ 已返回主菜单"; return
      fi
    fi
    local PORT
    PORT=$(read_unique_port "$CONFIG" 30000 39999 "请输入端口号（留空自动随机 30000-39999；输入 0 返回）: ") || return

    local UUID
    if command -v uuidgen >/dev/null 2>&1; then UUID=$(uuidgen); else
      local RAW; RAW=$(openssl rand -hex 16); UUID="${RAW:0:8}-${RAW:8:4}-${RAW:12:4}-${RAW:16:4}-${RAW:20:12}"
    fi

    local SERVER_NAME="www.cloudflare.com"
    local FLOW="xtls-rprx-vision"
    local FINGERPRINT="chrome"
    local KEY_PAIR PRIVATE_KEY PUBLIC_KEY SHORT_ID
    KEY_PAIR=$(sing-box generate reality-keypair) || { echo "❌ 生成 Reality 密钥失败（未检测到 sing-box 或二进制损坏）。请先在菜单 6→2 重装，或选择自动安装后重试。"; return 1; }
    PRIVATE_KEY=$(echo "$KEY_PAIR" | awk -F': ' '/PrivateKey/ {print $2}')
    PUBLIC_KEY=$(echo "$KEY_PAIR"  | awk -F': ' '/PublicKey/  {print $2}')
    SHORT_ID=$(openssl rand -hex 4)
    local TAG; TAG=$(generate_unique_tag)

    local tmpcfg; tmpcfg=$(mktemp)
    jq --arg port "$PORT" --arg uuid "$UUID" --arg prikey "$PRIVATE_KEY" --arg sid "$SHORT_ID" --arg server "$SERVER_NAME" --arg flow "$FLOW" --arg tag "$TAG" '
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
      }]' "$CONFIG" > "$tmpcfg" && mv "$tmpcfg" "$CONFIG" || { echo "❌ 写入配置失败"; return 1; }

    echo "🧪 正在校验配置..."
    if sing-box check -c "$CONFIG" >/dev/null 2>&1; then
      echo "✅ 配置通过，正在重启 Sing-box..."
      restart_singbox
      ensure_singbox_ready
    else
      echo "❌ 配置校验失败，请检查 /etc/sing-box/config.json"
      sing-box check -c "$CONFIG"
      return 1
    fi

    local META="/etc/sing-box/nodes_meta.json"
    [[ -f "$META" ]] || echo '{}' > "$META"
    local tmpmeta; tmpmeta=$(mktemp)
    jq --arg tag "$TAG" --arg pbk "$PUBLIC_KEY" --arg sid "$SHORT_ID" --arg sni "$SERVER_NAME" --arg port "$PORT" --arg fp "$FINGERPRINT" \
      '. + {($tag): {pbk:$pbk, sid:$sid, sni:$sni, port:$port, fp:$fp}}' \
      "$META" > "$tmpmeta" && mv "$tmpmeta" "$META"

    local IPV4; IPV4=$(curl -s --max-time 2 https://api.ipify.org)
    echo ""
    echo "✅ 添加成功：VLESS Reality"
    echo "端口: $PORT"
    echo "UUID: $UUID"
    echo "Public Key: $PUBLIC_KEY"
    echo "Short ID: $SHORT_ID"
    echo "SNI: $SERVER_NAME"
    echo "Fingerprint: $FINGERPRINT"
    echo "TAG: $TAG"
    echo ""
    echo "👉 客户端链接："
    echo "vless://${UUID}@${IPV4}:${PORT}?encryption=none&flow=${FLOW}&type=tcp&security=reality&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&sni=${SERVER_NAME}&fp=${FINGERPRINT}#${TAG}"
    echo ""
  else
    local PORT USER PASS TAG
    PORT=$(read_unique_port "$CONFIG" 40000 49999 "请输入端口号（留空自动；输入 0 返回）: ") || return
    read -p "请输入用户名（默认 user；输入 0 返回）: " USER; [[ "$USER" == "0" ]] && echo "⏪ 已返回主菜单" && return; USER=${USER:-user}
    read -p "请输入密码（默认 pass123；输入 0 返回）: " PASS; [[ "$PASS" == "0" ]] && echo "⏪ 已返回主菜单" && return; PASS=${PASS:-pass123}
    TAG="sk5-$(get_country_code)-$(tr -dc 'A-Z' </dev/urandom | head -c1)"

    local tmpcfg; tmpcfg=$(mktemp)
    jq --arg port "$PORT" --arg user "$USER" --arg pass "$PASS" --arg tag "$TAG" \
      '.inbounds += [{
        "type": "socks",
        "tag": $tag,
        "listen": "0.0.0.0",
        "listen_port": ($port|tonumber),
        "users": [{"username": $user, "password": $pass}]
      }]' "$CONFIG" > "$tmpcfg" && mv "$tmpcfg" "$CONFIG" || { echo "❌ 写入配置失败"; return 1; }

    echo "🧪 校验配置..."
    if sing-box check -c "$CONFIG" >/dev/null 2>&1; then
      echo "✅ 配置通过，正在重启..."
      restart_singbox
      ensure_singbox_ready
    else
      echo "❌ 配置失败，Sing-box 未重启"
      sing-box check -c "$CONFIG"
      return 1
    fi

    local ENCODED IPV4 IPV6
    ENCODED=$(printf '%s' "$USER:$PASS" | base64)
    IPV4=$(curl -s --max-time 2 https://api.ipify.org)
    IPV6=$(get_ipv6_address)
    echo ""
    echo "✅ SOCKS5 节点已添加："
    echo "端口: $PORT | 用户: $USER | 密码: $PASS"
    echo "IPv4: socks://${ENCODED}@${IPV4}:${PORT}#$TAG"
    [[ -n "$IPV6" ]] && echo "IPv6: socks://${ENCODED}@[${IPV6}]:${PORT}#$TAG"
  fi
}

# 查看节点（异常体检 + 缺参一键重建；回车=重建全部，0=返回）
view_nodes() {
  local CONFIG="/etc/sing-box/config.json"
  local META="/etc/sing-box/nodes_meta.json"
  [[ -f "$META" ]] || META="/dev/null"

  local IPV4 IPV6
  IPV4=$(curl -s --max-time 2 https://api.ipify.org)
  IPV6=$(ip -6 addr show scope global | awk '/inet6/ {print $2}' | cut -d/ -f1 | head -n1)

  local ALL_PORTS; ALL_PORTS="$(jq -r '.inbounds[]?.listen_port // empty' "$CONFIG" 2>/dev/null | sort)"
  local IDXMAP; IDXMAP="$(mktemp)"

  _sid_ok() {
    local s="$1"
    [[ "$s" =~ ^[0-9a-fA-F]{2,16}$ ]] && (( ${#s} % 2 == 0 ))
  }

  jq -c '.inbounds[]' "$CONFIG" | nl -w2 -s'. ' | while read -r line; do
    local INDEX JSON PORT TAG TYPE LISTEN
    INDEX=$(echo "$line" | cut -d. -f1)
    JSON=$(echo "$line" | cut -d' ' -f2-)
    PORT=$(echo "$JSON" | jq -r '.listen_port')
    TAG=$(echo "$JSON" | jq -r '.tag')
    TYPE=$(echo "$JSON" | jq -r '.type')
    LISTEN=$(echo "$JSON" | jq -r '.listen // "0.0.0.0"')

    echo "[$INDEX] 端口: $PORT | 协议: $TYPE | 名称: $TAG"

    if [[ "$TYPE" == "socks" ]]; then
      local USER PASS ENCODED
      USER=$(echo "$JSON" | jq -r '.users[0].username // empty')
      PASS=$(echo "$JSON" | jq -r '.users[0].password // empty')
      ENCODED=$(printf '%s' "$USER:$PASS" | base64)
      if command -v ss >/dev/null 2>&1; then
        ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":$PORT$" || echo "⚠️ 本机端口未监听：$PORT（服务未重载或异常）"
      else
        timeout 1 bash -c "echo > /dev/tcp/127.0.0.1/$PORT" >/dev/null 2>&1 || echo "⚠️ 本机端口未监听：$PORT（服务未重载或异常）"
      fi
      [[ "$LISTEN" != "0.0.0.0" ]] && echo "⚠️ 仅监听 $LISTEN，外网可能无法连接"
      if [[ -n "$PORT" ]] && [[ $(printf '%s\n' "$ALL_PORTS" | grep -c -x "$PORT") -gt 1 ]]; then
        echo "⚠️ 端口与其他节点重复：$PORT"
      fi
      echo "IPv4: socks://${ENCODED}@${IPV4}:${PORT}#$TAG"
      [[ -n "$IPV6" ]] && echo "IPv6: socks://${ENCODED}@[${IPV6}]:${PORT}#$TAG"
      echo "---------------------------------------------------"
      continue
    fi

    local UUID FLOW TLS_ENABLED REALITY_ENABLED SERVER_NAME_CFG HANDSHAKE_SNI PRIV SID
    UUID=$(echo "$JSON" | jq -r '.users[0].uuid // empty')
    FLOW=$(echo "$JSON" | jq -r '.users[0].flow // empty')
    TLS_ENABLED=$(echo "$JSON" | jq -r '.tls.enabled // false')
    REALITY_ENABLED=$(echo "$JSON" | jq -r '.tls.reality.enabled // false')
    SERVER_NAME_CFG=$(echo "$JSON" | jq -r '.tls.server_name // empty')
    HANDSHAKE_SNI=$(echo "$JSON" | jq -r '.tls.reality.handshake.server // empty')
    PRIV=$(echo "$JSON" | jq -r '.tls.reality.private_key // empty')
    SID=$(echo "$JSON" | jq -r '.tls.reality.short_id[0] // empty')

    local PBK SID_META SNI_META FP_META SERVER_NAME FINGERPRINT
    PBK=$(jq -r --arg tag "$TAG" '.[$tag].pbk // empty' "$META" 2>/dev/null)
    SID_META=$(jq -r --arg tag "$TAG" '.[$tag].sid // empty' "$META" 2>/dev/null)
    SNI_META=$(jq -r --arg tag "$TAG" '.[$tag].sni // empty' "$META" 2>/dev/null)
    FP_META=$(jq -r --arg tag "$TAG" '.[$tag].fp  // empty' "$META" 2>/dev/null)

    [[ -z "$SID" && -n "$SID_META" ]] && SID="$SID_META"
    SERVER_NAME="${SNI_META:-${HANDSHAKE_SNI:-$SERVER_NAME_CFG}}"
    FINGERPRINT="${FP_META:-chrome}"

    if [[ -z "$PBK" || -z "$SID" || -z "$SERVER_NAME" ]]; then
      echo "⚠️ 此节点参数缺失/异常（pbk/sid/sni），可一键重建。"
      printf '%s\t%s\n' "$INDEX" "$TAG" >> "$IDXMAP"
    fi
    if [[ -n "$SID" ]] && ! _sid_ok "$SID"; then
      echo "⚠️ short_id 异常：$SID（需为偶数长度 2–16 位十六进制）"
    fi
    [[ "$TLS_ENABLED" != "true" ]] && echo "⚠️ TLS 未启用（应为 true）"
    [[ "$REALITY_ENABLED" != "true" ]] && echo "⚠️ Reality 未启用（应为 true）"
    if [[ -n "$SERVER_NAME_CFG" && -n "$HANDSHAKE_SNI" && "$SERVER_NAME_CFG" != "$HANDSHAKE_SNI" ]]; then
      echo "⚠️ SNI 不一致：tls.server_name=$SERVER_NAME_CFG，handshake.server=$HANDSHAKE_SNI"
    fi
    [[ "$FLOW" != "xtls-rprx-vision" ]] && echo "⚠️ flow 异常：$FLOW（应为 xtls-rprx-vision）"
    if [[ -n "$UUID" ]] && ! echo "$UUID" | grep -Eq '^[0-9a-fA-F-]{36}$'; then
      echo "⚠️ UUID 格式可能异常：$UUID"
    fi
    if command -v ss >/dev/null 2>&1; then
      ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":$PORT$" || echo "⚠️ 本机端口未监听：$PORT（服务未重载或异常）"
    else
      timeout 1 bash -c "echo > /dev/tcp/127.0.0.1/$PORT" >/dev/null 2>&1 || echo "⚠️ 本机端口未监听：$PORT（服务未重载或异常）"
    fi
    [[ "$LISTEN" != "0.0.0.0" ]] && echo "⚠️ 仅监听 $LISTEN，外网可能无法连接"
    if [[ -n "$PORT" ]] && [[ $(printf '%s\n' "$ALL_PORTS" | grep -c -x "$PORT") -gt 1 ]]; then
      echo "⚠️ 端口与其他节点重复：$PORT"
    fi
    if [[ -n "$PRIV" && -n "$PBK" ]] && command -v sing-box >/dev/null 2>&1; then
      local PBK_FROM_PRIV
      PBK_FROM_PRIV=$(sing-box generate reality-keypair --private-key "$PRIV" 2>/dev/null | awk -F': ' '/PublicKey/ {print $2}')
      if [[ -n "$PBK_FROM_PRIV" && "$PBK_FROM_PRIV" != "$PBK" ]]; then
        echo "⚠️ 公钥与私钥不匹配（pbk 缓存可能过期），建议重建"
      fi
    fi

    echo "vless://${UUID}@${IPV4}:${PORT}?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&pbk=${PBK}&sid=${SID}&sni=${SERVER_NAME}&fp=${FINGERPRINT}#${TAG}"
    echo "---------------------------------------------------"
  done

  if [[ -s "$IDXMAP" ]]; then
    echo "🔧 检测到缺参/异常节点。"
    echo "   - 直接回车：重建全部缺参节点（保留原端口与标签）"
    echo "   - 输入 0：跳过并返回主菜单"
    local REBUILD_CHOICE
    read -r REBUILD_CHOICE
    if [[ -z "$REBUILD_CHOICE" ]]; then
      while IFS=$'\t' read -r _ TAG_TO_FIX; do
        rebuild_bad_for_tag "$TAG_TO_FIX"
      done < "$IDXMAP"
      echo "♻️ 正在重启服务以应用变更..."
      restart_singbox
      ensure_singbox_ready
    else
      echo "⏭️ 已跳过重建"
    fi
  fi

  rm -f "$IDXMAP"
}

# 删除节点（含返回与“删除全部”）
delete_node() {
  local CONFIG="/etc/sing-box/config.json"
  local META="/etc/sing-box/nodes_meta.json"
  local COUNT; COUNT=$(jq '.inbounds | length' "$CONFIG" 2>/dev/null)
  if [[ -z "$COUNT" || "$COUNT" -eq 0 ]]; then
    echo "暂无节点"; return
  fi

  view_nodes

  echo "[0 ] 返回主菜单"
  echo "[00] 删除所有节点"
  read -p "请输入要删除的节点序号，或以上选项: " IDX

  if [[ "$IDX" == "0" ]]; then
    echo "⏪ 已返回主菜单"; return
  fi
  if [[ "$IDX" == "00" ]]; then
    read -p "⚠️ 确认删除全部节点？此操作不可恢复！(y/n): " CONFIRM
    [[ "$CONFIRM" != "y" ]] && { echo "❌ 已取消删除"; return; }
    local tmpcfg; tmpcfg=$(mktemp)
    jq '.inbounds = []' "$CONFIG" > "$tmpcfg" && mv "$tmpcfg" "$CONFIG"
    [[ -f "$META" ]] && echo '{}' > "$META"
    echo "✅ 所有节点已删除（无需立即重启）"
    return
  fi

  if ! [[ "$IDX" =~ ^[0-9]+$ ]]; then echo "❌ 无效输入"; return; fi
  local ZERO=$((IDX - 1))
  if (( ZERO < 0 || ZERO >= COUNT )); then echo "❌ 无效序号：$IDX"; return; fi

  local TAG_TO_DELETE tmpcfg
  TAG_TO_DELETE=$(jq -r ".inbounds[$ZERO].tag // empty" "$CONFIG")
  tmpcfg=$(mktemp)
  jq "del(.inbounds[$ZERO])" "$CONFIG" > "$tmpcfg" && mv "$tmpcfg" "$CONFIG"

  if [[ -n "$TAG_TO_DELETE" && -f "$META" ]]; then
    local tmpmeta; tmpmeta=$(mktemp)
    jq "del(.\"$TAG_TO_DELETE\")" "$META" > "$tmpmeta" && mv "$tmpmeta" "$META"
  fi

  echo "✅ 已删除节点 [$IDX]（无需立即重启）"
}

# 检查并更新 Sing-box
update_singbox() {
  echo "📦 正在检查 Sing-box 更新..."
  local CUR; CUR=$(sing-box version 2>/dev/null | awk '/version/{print $3}')
  echo "当前版本: ${CUR:-未知}"
  local LATEST
  LATEST=$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r '.tag_name' 2>/dev/null)
  LATEST="${LATEST#v}"
  echo "最新版本: ${LATEST:-获取失败}"
  if [[ -z "$LATEST" || "$LATEST" == "null" ]]; then
    echo "⚠️ 获取最新版本失败"; return
  fi
  if [[ "$CUR" == "$LATEST" ]]; then
    echo "✅ 已是最新版，无需更新。"; return
  fi
  read -p "是否更新到 $LATEST？(y/n): " CONFIRM
  [[ "$CONFIRM" != "y" ]] && { echo "❌ 已取消更新"; return; }

  local ARCH; ARCH=$(uname -m)
  [[ "$ARCH" == "x86_64" ]] && ARCH="amd64"
  [[ "$ARCH" == "aarch64" ]] && ARCH="arm64"
  local TMP; TMP=$(mktemp -d); cd "$TMP" || exit 1
  echo "⬇️ 正在下载 sing-box ${LATEST}..."
  curl -fL -O "https://github.com/SagerNet/sing-box/releases/download/v${LATEST}/sing-box-${LATEST}-linux-${ARCH}.tar.gz" || { echo "❌ 下载失败"; cd /; rm -rf "$TMP"; return 1; }
  echo "📦 解压中..."; tar -xzf "sing-box-${LATEST}-linux-${ARCH}.tar.gz"
  echo "⚙️ 替换可执行文件..."
  local INIT_SYS; INIT_SYS=$(detect_init_system)
  [[ "$INIT_SYS" == "systemd" ]] && systemctl stop sing-box 2>/dev/null || true
  [[ "$INIT_SYS" == "openrc" ]] && rc-service sing-box stop >/dev/null 2>&1 || true
  cp "sing-box-${LATEST}-linux-${ARCH}/sing-box" /usr/local/bin/ && chmod +x /usr/local/bin/sing-box
  [[ "$INIT_SYS" == "systemd" ]] && systemctl start sing-box 2>/dev/null || true
  [[ "$INIT_SYS" == "openrc" ]] && rc-service sing-box start >/dev/null 2>&1 || true
  echo "✅ 已成功升级为 v${LATEST}"
  cd / && rm -rf "$TMP"
}

# 修复 / 重装 子菜单
repair_menu() {
  echo ""
  echo "=== 修复 / 重装 Sing-box ==="
  echo "1) 完全卸载（删除程序与全部节点配置）"
  echo "2) 重装（保留节点与配置，重新初始化服务脚本）"
  echo "0) 返回主菜单"
  read -p "请选择: " _r
  case "$_r" in
    1) uninstall_full ;;
    2) reinstall_keep_nodes ;;
    0|"") echo "返回主菜单" ;;
    *) echo "无效输入" ;;
  esac
}

uninstall_full() {
  echo "⚠️ 开始完全卸载 Sing-box..."
  local INIT_SYS; INIT_SYS=$(detect_init_system)
  if [[ "$INIT_SYS" == "systemd" ]]; then
    systemctl stop sing-box 2>/dev/null || true
    systemctl disable sing-box 2>/dev/null || true
    rm -f /etc/systemd/system/sing-box.service
    systemctl daemon-reload 2>/dev/null || true
  elif [[ "$INIT_SYS" == "openrc" ]]; then
    rc-service sing-box stop 2>/dev/null || true
    rc-update del sing-box default 2>/dev/null || true
    rm -f /etc/init.d/sing-box
  fi
  rm -f /usr/local/bin/sing-box /usr/local/bin/sk /usr/local/bin/ck
  rm -rf /etc/sing-box
  echo "✅ 已完成完全卸载。"
}

autofix_config_if_check_fails() {
  local CONFIG="$1"
  local META="$2"

  jq . "$CONFIG" >/dev/null 2>&1 || { echo "⚠️ 配置 JSON 无法解析，跳过自动修复"; return 1; }

  local idxs
  idxs=$(jq -r '(.inbounds // []) | to_entries[] | .key' "$CONFIG" 2>/dev/null) || return 1
  for idx in $idxs; do
    local TYPE
    TYPE=$(jq -r ".inbounds[$idx].type // empty" "$CONFIG")

    if [[ "$TYPE" == "vless" ]]; then
      local PORT TAG UUID SERVER_NAME PRIV SID
      PORT=$(jq -r ".inbounds[$idx].listen_port // empty" "$CONFIG")
      TAG=$(jq -r ".inbounds[$idx].tag // empty" "$CONFIG")
      UUID=$(jq -r ".inbounds[$idx].users[0].uuid // empty" "$CONFIG")
      [[ -z "$UUID" ]] && UUID=$(uuidgen 2>/dev/null || echo "00000000-0000-4000-8000-000000000000")

      SERVER_NAME=$(jq -r ".inbounds[$idx].tls.reality.handshake.server // .inbounds[$idx].tls.server_name // empty" "$CONFIG")
      [[ -z "$SERVER_NAME" ]] && SERVER_NAME="www.cloudflare.com"

      PRIV=$(jq -r ".inbounds[$idx].tls.reality.private_key // empty" "$CONFIG")
      SID=$(jq -r ".inbounds[$idx].tls.reality.short_id[0] // empty" "$CONFIG")

      local need_regen=0
      if [[ -z "$PRIV" ]]; then need_regen=1; fi
      if [[ -z "$SID" || ! "$SID" =~ ^[0-9a-fA-F]{2,16}$ || $(( ${#SID} % 2 )) -ne 0 ]]; then need_regen=1; fi

      local PRIV_NEW="" PBK_NEW="" SID_NEW=""
      if (( need_regen )); then
        local KP; KP=$(sing-box generate reality-keypair 2>/dev/null)
        PRIV_NEW=$(awk -F': ' '/PrivateKey/ {print $2}' <<<"$KP")
        PBK_NEW=$(awk -F': ' '/PublicKey/ {print $2}' <<<"$KP")
        [[ -z "$PRIV_NEW" ]] && continue
        SID_NEW=$(openssl rand -hex 4)

        local tmp; tmp=$(mktemp)
        jq --argjson i "$idx" --arg sni "$SERVER_NAME" --arg uuid "$UUID" --arg priv "$PRIV_NEW" --arg sid "$SID_NEW" '
          .inbounds[$i].tls.enabled = true
          | .inbounds[$i].tls.server_name = $sni
          | .inbounds[$i].tls.reality.enabled = true
          | .inbounds[$i].tls.reality.handshake.server = $sni
          | .inbounds[$i].tls.reality.handshake.server_port = 443
          | .inbounds[$i].tls.reality.private_key = $priv
          | .inbounds[$i].tls.reality.short_id = [ $sid ]
          | .inbounds[$i].users[0].uuid = (.inbounds[$i].users[0].uuid // $uuid)
          | .inbounds[$i].users[0].flow = "xtls-rprx-vision"
        ' "$CONFIG" > "$tmp" && mv "$tmp" "$CONFIG"

        if [[ -n "$META" ]]; then
          mkdir -p "$(dirname "$META")"; [[ -f "$META" ]] || echo '{}' > "$META"
          local tmpm; tmpm=$(mktemp)
          jq --arg tag "$TAG" --arg pbk "$PBK_NEW" --arg sid "$SID_NEW" --arg sni "$SERVER_NAME" --arg port "$PORT" \
            '. + {($tag): {pbk:$pbk, sid:$sid, sni:$sni, port:$port}}' \
            "$META" > "$tmpm" && mv "$tmpm" "$META"
        fi
      else
        local tmp; tmp=$(mktemp)
        jq --argjson i "$idx" --arg sni "$SERVER_NAME" --arg uuid "$UUID" '
          .inbounds[$i].tls.enabled = true
          | .inbounds[$i].tls.server_name = $sni
          | .inbounds[$i].tls.reality.enabled = true
          | .inbounds[$i].tls.reality.handshake.server = $sni
          | .inbounds[$i].tls.reality.handshake.server_port = 443
          | .inbounds[$i].users[0].uuid = (.inbounds[$i].users[0].uuid // $uuid)
          | .inbounds[$i].users[0].flow = "xtls-rprx-vision"
        ' "$CONFIG" > "$tmp" && mv "$tmp" "$CONFIG"
      fi

    elif [[ "$TYPE" == "socks" ]]; then
      local tmp; tmp=$(mktemp)
      jq --argjson i "$idx" '
        .inbounds[$i].listen = (.inbounds[$i].listen // "0.0.0.0")
      ' "$CONFIG" > "$tmp" && mv "$tmp" "$CONFIG"
    fi
  done
  return 0
}

reinstall_keep_nodes() {
  echo "🔧 开始重装（保留节点）..."
  mkdir -p /etc/sing-box
  local CONFIG="/etc/sing-box/config.json"
  local META="/etc/sing-box/nodes_meta.json"
  local BKDIR="/etc/sing-box.bak-$(date +%s)"
  mkdir -p "$BKDIR"
  [[ -f "$CONFIG" ]] && cp -a "$CONFIG" "$BKDIR/config.json"
  [[ -f "$META" ]] && cp -a "$META" "$BKDIR/nodes_meta.json"

  local INIT_SYS; INIT_SYS=$(detect_init_system)
  [[ "$INIT_SYS" == "systemd" ]] && systemctl stop sing-box 2>/dev/null || true
  [[ "$INIT_SYS" == "openrc" ]] && rc-service sing-box stop 2>/dev/null || true

  rm -f /usr/local/bin/sing-box /usr/local/bin/sk /usr/local/bin/ck
  rm -f /etc/systemd/system/sing-box.service /etc/init.d/sing-box
  systemctl daemon-reload 2>/dev/null || true

  install_singbox_if_needed

  [[ -f "$BKDIR/config.json" ]] && cp -a "$BKDIR/config.json" "$CONFIG"
  [[ -f "$BKDIR/nodes_meta.json" ]] && cp -a "$BKDIR/nodes_meta.json" "$META"

  if sing-box check -c "$CONFIG" >/dev/null 2>&1; then
    ensure_dual_init_autoadapt
    restart_singbox
    ensure_singbox_ready
    echo "✅ 重装完成（已保留节点与配置）。备份目录：$BKDIR"
  else
    echo "⚠️ 配置校验失败，尝试自动修复..."
    if autofix_config_if_check_fails "$CONFIG" "$META"; then
      if sing-box check -c "$CONFIG" >/dev/null 2>&1; then
        ensure_dual_init_autoadapt
        restart_singbox
        ensure_singbox_ready
        echo "✅ 自动修复成功并完成重装。备份目录：$BKDIR"
      else
        echo "❌ 自动修复后仍然校验失败，已保留备份：$BKDIR"
      fi
    else
      echo "❌ 无法自动修复配置，已保留备份：$BKDIR"
    fi
  fi
}

# 快捷命令 sk/ck
setup_shortcut() {
  local MAIN_CMD="/usr/local/bin/sk"
  local ALT_CMD="/usr/local/bin/ck"
  local SCRIPT_PATH; SCRIPT_PATH="$(realpath "$0" 2>/dev/null || readlink -f "$0")"
  [[ -f "$MAIN_CMD" ]] || { echo -e "#!/usr/bin/env bash\nbash \"$SCRIPT_PATH\"" > "$MAIN_CMD"; chmod +x "$MAIN_CMD"; }
  [[ -f "$ALT_CMD" ]] || { echo -e "#!/usr/bin/env bash\nbash \"$SCRIPT_PATH\"" > "$ALT_CMD"; chmod +x "$ALT_CMD"; }
}

# 主菜单
main_menu() {
  echo ""
  show_ssh_latency
  show_version_info
  echo "============= Sing-box 节点管理工具（IPv4 + IPv6） ============="
  echo "1) 添加节点"
  echo "2) 查看所有节点"
  echo "3) 删除用户（通过序号）"
  echo "4) 检查并更新 Sing-box 到最新版"
  echo "5) 重启 Sing-box 服务"
  echo "6) 修复 / 重装（完全卸载 / 保留节点重装）"
  echo "9) 退出"
  echo "==============================================================="
  read -p "请输入操作编号: " CHOICE
  case "$CHOICE" in
    1) add_node ;;
    2) view_nodes ;;
    3) delete_node ;;
    4) update_singbox ;;
    5) restart_singbox ;;
    6) repair_menu ;;
    9) exit 0 ;;
    *) echo "无效输入" ;;
  esac
}

# ========== 入口 ==========
install_dependencies
install_singbox_if_needed
ensure_dual_init_autoadapt
setup_shortcut

while true; do main_menu; done
