#!/usr/bin/env bash
# sk5.sh — Sing-box Node Manager (VLESS Reality + SOCKS5)
# Features:
# - Add nodes (VLESS-REALITY or SOCKS5) with safe jq writes
# - View nodes with health check: param loss, invalid sid, port listening/occupied
# - One-key rebuild invalid VLESS nodes on the same port
# - Delete nodes (by index or all), keep meta in sync
# - Update sing-box to latest release
# - Repair menu: full uninstall OR reinstall (keep nodes), with auto-fix if check fails
# - Service auto-adapt: systemd / OpenRC
# - Robust quoting, heredocs, and syntax checked
set -Eeuo pipefail

CONFIG="/etc/sing-box/config.json"
META="/etc/sing-box/nodes_meta.json"

ensure_config_dir() {
  mkdir -p /etc/sing-box
  if [[ ! -f "$CONFIG" ]]; then
    echo '{"inbounds":[],"outbounds":[{"type":"direct"}],"route":{"rules":[]}}' > "$CONFIG"
  fi
  [[ -f "$META" ]] || echo '{}' > "$META"
}

detect_os() {
  if [[ -f /etc/os-release ]]; then . /etc/os-release; echo "$ID"; else echo "unknown"; fi
}

install_dependencies() {
  local need=0
  for cmd in curl jq uuidgen openssl; do
    command -v "$cmd" >/dev/null 2>&1 || need=1
  done
  # we try to provide ss/lsof if possible
  for cmd in ss lsof; do
    command -v "$cmd" >/dev/null 2>&1 || need=1
  done
  if [[ $need -eq 0 ]]; then
    echo "✅ 依赖已满足（curl/jq/uuidgen/openssl/ss/lsof）"
    return
  fi
  local OS; OS=$(detect_os)
  case "$OS" in
    alpine)
      apk add --no-cache curl jq util-linux openssl lsof iproute2 >/dev/null ;;
    debian|ubuntu)
      apt-get update -y >/dev/null
      apt-get install -y curl jq uuid-runtime openssl lsof iproute2 >/dev/null ;;
    centos|rhel|fedora)
      yum install -y curl jq util-linux openssl lsof iproute >/dev/null || true ;;
    *)
      echo "⚠️ 未识别系统，请自行安装：curl jq uuidgen openssl（可选：ss 或 lsof）"
      ;;
  esac
}

detect_init_system() {
  if pidof systemd >/dev/null 2>&1; then
    echo "systemd"
  elif [[ -x /sbin/openrc-run ]] || [[ -f /etc/init.d/softlevel ]]; then
    echo "openrc"
  else
    echo "unknown"
  fi
}

ensure_service_systemd() {
  # write unit file
  cat <<'EOF' >/etc/systemd/system/sing-box.service
[Unit]
Description=Sing-box Service
After=network.target network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable sing-box >/dev/null 2>&1 || true
  systemctl restart sing-box || true
}

ensure_service_openrc() {
  cat <<'EOF' >/etc/init.d/sing-box
#!/sbin/openrc-run
command="/usr/local/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
name="sing-box"
pidfile="/var/run/sing-box.pid"
depend() { need net; }
start() { ebegin "Starting sing-box"; start-stop-daemon --start --exec "$command" -- $command_args; eend $?; }
stop()  { ebegin "Stopping sing-box"; start-stop-daemon --stop --exec "$command"; eend $?; }
EOF
  chmod +x /etc/init.d/sing-box
  rc-update add sing-box default >/dev/null 2>&1 || true
  rc-service sing-box restart >/dev/null 2>&1 || rc-service sing-box start >/dev/null 2>&1 || true
}

ensure_dual_init_autoadapt() {
  local init; init=$(detect_init_system)
  if [[ "$init" == "systemd" ]]; then
    ensure_service_systemd
  elif [[ "$init" == "openrc" ]]; then
    ensure_service_openrc
  else
    echo "⚠️ 未检测到 systemd/OpenRC；将以后台方式运行（不建议）。"
    nohup /usr/local/bin/sing-box run -c "$CONFIG" >/var/log/sing-box.log 2>&1 &
  fi
}

# Install sing-box if missing (latest)
install_singbox_if_needed() {
  if command -v sing-box >/dev/null 2>&1; then
    echo "✅ Sing-box 已安装，跳过安装"
    return 0
  fi
  echo "⬇️ 正在安装 Sing-box（最新版本）..."
  local arch uname; uname=$(uname -m)
  case "$uname" in
    x86_64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) echo "❌ 不支持的架构：$uname"; return 1 ;;
  esac
  local latest
  latest=$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name | sed 's/^v//')
  [[ -z "$latest" || "$latest" == "null" ]] && latest="1.12.0"
  local tmp; tmp=$(mktemp -d)
  ( cd "$tmp" && curl -fsSLO "https://github.com/SagerNet/sing-box/releases/download/v${latest}/sing-box-${latest}-linux-${arch}.tar.gz" \
    && tar -xzf "sing-box-${latest}-linux-${arch}.tar.gz" \
    && cp "sing-box-${latest}-linux-${arch}/sing-box" /usr/local/bin/ \
    && chmod +x /usr/local/bin/sing-box )
  rm -rf "$tmp"
  ensure_config_dir
  ensure_dual_init_autoadapt
  echo "✅ Sing-box 已安装并初始化服务"
}

restart_singbox() {
  local init; init=$(detect_init_system)
  if [[ "$init" == "systemd" ]]; then
    systemctl restart sing-box || true
    sleep 1
    if systemctl is-active --quiet sing-box; then
      echo "✅ Sing-box 已通过 systemd 重启成功"
    else
      echo "❌ Sing-box 重启失败（systemd）"
    fi
  elif [[ "$init" == "openrc" ]]; then
    rc-service sing-box restart >/dev/null 2>&1 || true
    sleep 1
    if rc-service sing-box status 2>/dev/null | grep -q started; then
      echo "✅ Sing-box 已通过 OpenRC 重启成功"
    else
      echo "❌ Sing-box 重启失败（OpenRC）"
    fi
  else
    echo "⚠️ 无服务管理，尝试后台运行"
    nohup /usr/local/bin/sing-box run -c "$CONFIG" >/var/log/sing-box.log 2>&1 &
  fi
}

show_version_info() {
  if command -v sing-box >/dev/null 2>&1; then
    local ver arch
    ver=$(sing-box version 2>/dev/null | awk '/sing-box version/{print $3}')
    arch=$(sing-box version 2>/dev/null | awk -F': ' '/Environment/{print $2}')
    echo "Sing-box 版本: ${ver:-未知}  | 架构: ${arch:-未知}"
  else
    echo "Sing-box 版本: 未知  | 架构: 未知"
  fi
}

get_country_code() {
  local code
  code=$(curl -s --max-time 3 https://ipinfo.io | jq -r '.country // empty' 2>/dev/null || echo "")
  if [[ "$code" =~ ^[A-Z]{2}$ ]]; then echo "$code"; else echo "ZZ"; fi
}

get_ipv6_address() {
  ip -6 addr show scope global | awk '/inet6/{print $2}' | cut -d/ -f1 | head -n1
}

generate_unique_tag() {
  local base="vless-reality-$(get_country_code)"
  local try=0
  ensure_config_dir
  while true; do
    local rand candidate
    rand=$(tr -dc 'A-Z' </dev/urandom | head -c1)
    candidate="${base}-${rand}"
    if ! jq -e --arg t "$candidate" '.inbounds[]? | select(.tag == $t)' "$CONFIG" >/dev/null 2>&1; then
      echo "$candidate"; return
    fi
    try=$((try+1))
    if [[ $try -ge 26 ]]; then
      echo "${base}-$(date +%s)"; return
    fi
  done
}

# ---- Port & param diagnostics helpers ----
check_port_state() {
  local PORT="$1"
  local line owner name pid
  if command -v ss >/dev/null 2>&1; then
    line=$(ss -ltnp 2>/dev/null | awk -v p=":$PORT" '$4 ~ p {print; exit}')
    if [[ -n "$line" ]]; then
      owner=$(sed -n 's/.*users:(("\([^"]\+\)",pid=\([0-9]\+\).*/\1 \2/p' <<<"$line")
      if [[ -n "$owner" ]]; then
        name=$(awk '{print $1}' <<<"$owner")
        pid=$(awk '{print $2}' <<<"$owner")
        if [[ "$name" == "sing-box" ]]; then
          echo "LISTEN_SING|$pid"; return 0
        else
          echo "LISTEN_OTHER|$name $pid"; return 0
        fi
      fi
    fi
  fi
  if command -v lsof >/dev/null 2>&1; then
    owner=$(lsof -nP -iTCP:"$PORT" -sTCP:LISTEN -Fpcn 2>/dev/null | paste - - - | sed -n 's/^p\([0-9]\+\)c\([^|]*\)n.*/\2 \1/p' | head -n1 || true)
    if [[ -n "$owner" ]]; then
      name=$(awk '{print $1}' <<<"$owner")
      pid=$(awk '{print $2}' <<<"$owner")
      if [[ "$name" == "sing-box" ]]; then
        echo "LISTEN_SING|$pid"; return 0
      else
        echo "LISTEN_OTHER|$name $pid"; return 0
      fi
    fi
  fi
  timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$PORT" >/dev/null 2>&1 && { echo "UNKNOWN|"; return 0; }
  echo "NOT_LISTENING|"; return 0
}

valid_sid() {
  local SID="$1"
  [[ "$SID" =~ ^[0-9a-fA-F]{2,16}$ ]] && (( ${#SID} % 2 == 0 ))
}

# ---- View nodes with diagnostics & rebuild ----
rebuild_invalid_nodes() {
  local LIST="${1:-/tmp/sk5_invalid.list}"
  ensure_config_dir
  [[ ! -s "$LIST" ]] && echo "没有异常节点需要重建。" && return 0
  if ! command -v sing-box >/dev/null 2>&1; then
    echo "❌ 未检测到 sing-box，请先安装/重装后再试。"; return 1
  fi
  while IFS='|' read -r TAG PORT UUID SNI; do
    [[ -z "$TAG" ]] && continue
    [[ -z "$SNI" ]] && SNI="www.cloudflare.com"
    [[ -z "$UUID" ]] && UUID=$(uuidgen 2>/dev/null || echo "00000000-0000-4000-8000-000000000000")
    local KP PRIV PBK SID tmpcfg tmpmeta
    KP=$(sing-box generate reality-keypair 2>/dev/null) || { echo "❌ 生成密钥失败：$TAG"; continue; }
    PRIV=$(awk -F': ' '/PrivateKey/ {print $2}' <<<"$KP")
    PBK=$( awk -F': ' '/PublicKey/  {print $2}' <<<"$KP")
    SID=$(openssl rand -hex 4)
    tmpcfg=$(mktemp)
    jq --arg tag "$TAG" --arg uuid "$UUID" --arg sni "$SNI" --arg priv "$PRIV" --arg sid "$SID" --argjson port "$PORT" '
      .inbounds |= (map(
        if .tag==$tag then
          .type="vless" |
          .listen="0.0.0.0" |
          .listen_port=$port |
          .users=[{uuid:$uuid, flow:"xtls-rprx-vision"}] |
          .tls.enabled=true |
          .tls.server_name=$sni |
          .tls.reality.enabled=true |
          .tls.reality.handshake.server=$sni |
          .tls.reality.handshake.server_port=443 |
          .tls.reality.private_key=$priv |
          .tls.reality.short_id=[ $sid ]
        else . end
      ))
    ' "$CONFIG" > "$tmpcfg" && mv "$tmpcfg" "$CONFIG"
    mkdir -p /etc/sing-box
    [[ -f "$META" ]] || echo '{}' > "$META"
    tmpmeta=$(mktemp)
    jq --arg tag "$TAG" --arg pbk "$PBK" --arg sid "$SID" --arg sni "$SNI" --arg port "$PORT" \
      '. + {($tag): {pbk:$pbk, sid:$sid, sni:$sni, port:$port}}' \
      "$META" > "$tmpmeta" && mv "$tmpmeta" "$META"
    echo "🔧 已重建：$TAG（端口 $PORT）"
  done < "$LIST"
  if sing-box check -c "$CONFIG" >/dev/null 2>&1; then
    restart_singbox
    echo "✅ 异常节点已重建并重启完成"
  else
    echo "❌ 重建后校验失败，请检查 $CONFIG"
  fi
}

view_nodes() {
  ensure_config_dir
  local IPV4; IPV4=$(curl -s --max-time 2 https://api.ipify.org || echo "")
  local INVALID="/tmp/sk5_invalid.list"; : > "$INVALID"
  jq -c '.inbounds[]' "$CONFIG" | nl -w2 -s'. ' | while read -r line; do
    local INDEX JSON PORT TAG TYPE
    INDEX=$(echo "$line" | cut -d. -f1)
    JSON=$(echo "$line"  | cut -d' ' -f2-)
    PORT=$(echo "$JSON"  | jq -r '.listen_port')
    TAG=$(echo "$JSON"   | jq -r '.tag')
    TYPE=$(echo "$JSON"  | jq -r '.type')
    echo "[$INDEX] 端口: $PORT | 协议: $TYPE | 名称: $TAG"
    if [[ "$TYPE" == "socks" ]]; then
      local USER PASS ENCODED
      USER=$(echo "$JSON" | jq -r '.users[0].username // empty')
      PASS=$(echo "$JSON" | jq -r '.users[0].password // empty')
      ENCODED=$(echo -n "$USER:$PASS" | base64)
      [[ -n "$IPV4" ]] && echo "socks://${ENCODED}@${IPV4}:${PORT}#${TAG}"
      echo "---------------------------------------------------"
      continue
    fi
    if [[ "$TYPE" == "vless" ]]; then
      local UUID SNI PRIV SID PBK PBK_META
      UUID=$(echo "$JSON" | jq -r '.users[0].uuid // empty')
      SNI=$( echo "$JSON" | jq -r '.tls.reality.handshake.server // .tls.server_name // empty')
      PRIV=$(echo "$JSON" | jq -r '.tls.reality.private_key // empty')
      SID=$( echo "$JSON" | jq -r '.tls.reality.short_id[0]   // empty')
      PBK_META=$(jq -r --arg tag "$TAG" '.[$tag].pbk // empty' "$META" 2>/dev/null || echo "")
      PBK="$PBK_META"
      if [[ -z "$PBK" && -n "$PRIV" ]] && command -v sing-box >/dev/null 2>&1; then
        PBK=$(sing-box generate reality-keypair --private-key "$PRIV" 2>/dev/null | awk -F': ' '/PublicKey/ {print $2}')
      fi
      local invalid=0 reasons=()
      [[ -z "$SNI" ]] && invalid=1 && reasons+=("sni缺失")
      if ! valid_sid "$SID"; then invalid=1; reasons+=("sid非法"); fi
      if [[ -z "$PBK" ]]; then invalid=1; reasons+=("pbk缺失"); fi
      local PST DET; IFS='|' read -r PST DET < <(check_port_state "$PORT")
      case "$PST" in
        LISTEN_SING) ;;
        LISTEN_OTHER) invalid=1; reasons+=("端口被占用:$DET");;
        NOT_LISTENING) invalid=1; reasons+=("端口未监听");;
        *) ;;
      esac
      if (( invalid )); then
        echo "⚠️ 节点异常：$(IFS=','; echo "${reasons[*]}")。可一键重建（同端口）。"
        echo "${TAG}|${PORT}|${UUID}|${SNI}" >> "$INVALID"
      fi
      [[ -n "$IPV4" ]] && echo "vless://${UUID}@${IPV4}:${PORT}?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&pbk=${PBK}&sid=${SID}&sni=${SNI}&fp=chrome#${TAG}"
      echo "---------------------------------------------------"
    fi
  done
  if [[ -s "$INVALID" ]]; then
    echo "=== 异常节点处理 ==="
    echo "r) 一键重建全部异常节点（同端口）"
    echo "0) 返回主菜单"
    read -p "请选择: " _opt
    case "$_opt" in
      r|R) rebuild_invalid_nodes "$INVALID" ;;
      0|"") : ;;
      *) echo "无效选项，已返回主菜单" ;;
    esac
  fi
}

# ---- Delete nodes (with Return option) ----
delete_node() {
  ensure_config_dir
  local COUNT; COUNT=$(jq '(.inbounds // []) | length' "$CONFIG")
  [[ $COUNT -eq 0 ]] && echo "暂无节点" && return

  # 先给用户看一眼当前节点（带体检/重建入口）
  view_nodes

  echo "a) 删除所有节点"
  echo "0) 返回主菜单"
  read -p "请输入要删除的节点序号（或 a 全部，0 返回）: " CHOICE

  case "$CHOICE" in
    0|"")
      echo "⏪ 已返回主菜单"
      return
      ;;
    a|A|all|ALL)
      read -p "⚠️ 确认删除全部节点？此操作不可恢复！(y/n): " CONFIRM
      [[ "$CONFIRM" != "y" ]] && echo "❌ 已取消删除" && return
      local tmpcfg; tmpcfg=$(mktemp)
      jq '.inbounds = []' "$CONFIG" > "$tmpcfg" && mv "$tmpcfg" "$CONFIG"
      echo '{}' > "$META"
      echo "✅ 所有节点已删除（无需立即重启）"
      return
      ;;
  esac

  # 单个删除：必须是纯数字
  if ! [[ "$CHOICE" =~ ^[0-9]+$ ]]; then
    echo "❌ 无效输入：$CHOICE"
    return
  fi

  local IDX=$((CHOICE - 1))
  if (( IDX < 0 || IDX >= COUNT )); then
    echo "❌ 无效序号：$CHOICE"
    return
  fi

  # 取出 tag，用于同步清理 META
  local TAG_TO_DELETE
  TAG_TO_DELETE=$(jq -r ".inbounds[$IDX].tag // empty" "$CONFIG")

  # 删 config 中对应入站
  local tmpcfg; tmpcfg=$(mktemp)
  jq "del(.inbounds[$IDX])" "$CONFIG" > "$tmpcfg" && mv "$tmpcfg" "$CONFIG"

  # 删 META 对应条目
  if [[ -n "$TAG_TO_DELETE" ]]; then
    local tmpmeta; tmpmeta=$(mktemp)
    jq "del(.\"$TAG_TO_DELETE\")" "$META" > "$tmpmeta" && mv "$tmpmeta" "$META"
  fi

  echo "✅ 已删除节点 [$CHOICE]（无需立即重启）"
}

# ---- Update sing-box ----
update_singbox() {
  echo "📦 正在检查 Sing-box 更新..."
  local CUR LATEST arch uname tmp init
  CUR=$(sing-box version 2>/dev/null | awk '/version/{print $3}')
  echo "当前版本: ${CUR:-未知}"
  LATEST=$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name | sed 's/^v//')
  echo "最新版本: ${LATEST:-未知}"
  if [[ -n "$CUR" && -n "$LATEST" && "$CUR" == "$LATEST" ]]; then
    echo "✅ 已是最新版，无需更新。"; return
  fi
  read -p "是否更新到 $LATEST？(y/n): " CONFIRM
  [[ "$CONFIRM" != "y" ]] && echo "❌ 已取消更新" && return
  uname=$(uname -m)
  case "$uname" in
    x86_64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) echo "❌ 不支持的架构：$uname"; return ;;
  esac
  tmp=$(mktemp -d); init=$(detect_init_system)
  [[ "$init" == "systemd" ]] && systemctl stop sing-box || true
  [[ "$init" == "openrc"  ]] && rc-service sing-box stop >/dev/null 2>&1 || true
  ( cd "$tmp" && curl -fsSLO "https://github.com/SagerNet/sing-box/releases/download/v${LATEST}/sing-box-${LATEST}-linux-${arch}.tar.gz" \
    && tar -xzf "sing-box-${LATEST}-linux-${arch}.tar.gz" \
    && cp "sing-box-${LATEST}-linux-${arch}/sing-box" /usr/local/bin/ \
    && chmod +x /usr/local/bin/sing-box )
  rm -rf "$tmp"
  [[ "$init" == "systemd" ]] && systemctl start sing-box || true
  [[ "$init" == "openrc"  ]] && rc-service sing-box start  >/dev/null 2>&1 || true
  echo "✅ 已成功升级为 v${LATEST}"
}

# ---- Autofix for reinstall keep-nodes ----
autofix_config_if_check_fails() {
  ensure_config_dir
  jq . "$CONFIG" >/dev/null 2>&1 || { echo "⚠️ 配置 JSON 无法解析，跳过自动修复"; return 1; }
  local idxs; idxs=$(jq -r '(.inbounds // []) | to_entries[] | .key' "$CONFIG" 2>/dev/null) || return 1
  for idx in $idxs; do
    local TYPE; TYPE=$(jq -r ".inbounds[$idx].type // empty" "$CONFIG")
    if [[ "$TYPE" == "vless" ]]; then
      local PORT TAG UUID SNI PRIV SID
      PORT=$(jq -r ".inbounds[$idx].listen_port // empty" "$CONFIG")
      TAG=$(jq -r ".inbounds[$idx].tag // empty" "$CONFIG")
      UUID=$(jq -r ".inbounds[$idx].users[0].uuid // empty" "$CONFIG")
      [[ -z "$UUID" ]] && UUID=$(uuidgen 2>/dev/null || echo "00000000-0000-4000-8000-000000000000")
      SNI=$(jq -r ".inbounds[$idx].tls.reality.handshake.server // .inbounds[$idx].tls.server_name // empty" "$CONFIG")
      [[ -z "$SNI" ]] && SNI="www.cloudflare.com"
      PRIV=$(jq -r ".inbounds[$idx].tls.reality.private_key // empty" "$CONFIG")
      SID=$(jq -r ".inbounds[$idx].tls.reality.short_id[0] // empty" "$CONFIG")
      local need_regen=0
      if [[ -z "$PRIV" ]]; then need_regen=1; fi
      if [[ -z "$SID" || ! "$SID" =~ ^[0-9a-fA-F]{2,16}$ || $(( ${#SID} % 2 )) -ne 0 ]]; then need_regen=1; fi
      if (( need_regen )); then
        local KP PRIV_NEW PBK_NEW SID_NEW tmp tmpm
        KP=$(sing-box generate reality-keypair 2>/dev/null) || continue
        PRIV_NEW=$(awk -F': ' '/PrivateKey/ {print $2}' <<<"$KP")
        PBK_NEW=$( awk -F': ' '/PublicKey/  {print $2}' <<<"$KP")
        SID_NEW=$(openssl rand -hex 4)
        tmp=$(mktemp)
        jq --argjson i "$idx" --arg sni "$SNI" --arg uuid "$UUID" --arg priv "$PRIV_NEW" --arg sid "$SID_NEW" '
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
        [[ -f "$META" ]] || echo '{}' > "$META"
        tmpm=$(mktemp)
        jq --arg tag "$TAG" --arg pbk "$PBK_NEW" --arg sid "$SID_NEW" --arg sni "$SNI" --arg port "$PORT" \
          '. + {($tag): {pbk:$pbk, sid:$sid, sni:$sni, port:$port}}' \
          "$META" > "$tmpm" && mv "$tmpm" "$META"
      else
        local tmp
        tmp=$(mktemp)
        jq --argjson i "$idx" --arg sni "$SNI" --arg uuid "$UUID" '
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

# ---- Repair / reinstall ----
full_uninstall() {
  echo "⚠️ 开始完全卸载 Sing-box..."
  local init; init=$(detect_init_system)
  if [[ "$init" == "systemd" ]]; then
    systemctl stop sing-box || true
    systemctl disable sing-box || true
    rm -f /etc/systemd/system/sing-box.service
    systemctl daemon-reload || true
  elif [[ "$init" == "openrc" ]]; then
    rc-service sing-box stop >/dev/null 2>&1 || true
    rc-update del sing-box default >/dev/null 2>&1 || true
    rm -f /etc/init.d/sing-box
  fi
  rm -f /usr/local/bin/sing-box /usr/local/bin/sk /usr/local/bin/ck || true
  rm -rf /etc/sing-box || true
  echo "✅ 已完成完全卸载。"
}

reinstall_keep_nodes() {
  echo "🔧 开始重装（保留节点）..."
  ensure_config_dir
  install_singbox_if_needed || { echo "❌ 安装 Sing-box 失败"; return 1; }
  ensure_dual_init_autoadapt
  if sing-box check -c "$CONFIG" >/dev/null 2>&1; then
    echo "✅ 配置校验通过"; restart_singbox; return 0
  fi
  echo "⚠️ 配置校验失败，尝试自动修复..."
  local bak="/etc/sing-box.bak-$(date +%s)"
  mkdir -p "$bak"
  cp "$CONFIG" "$bak/config.json"
  cp "$META"   "$bak/nodes_meta.json" 2>/dev/null || true
  autofix_config_if_check_fails
  if sing-box check -c "$CONFIG" >/dev/null 2>&1; then
    echo "✅ 自动修复成功"; restart_singbox; return 0
  else
    echo "❌ 自动修复后仍然校验失败，已保留备份：$bak"; return 1
  fi
}

# ---- Add node ----
add_node() {
  ensure_config_dir
  echo "请选择协议类型："
  echo "0) 返回主菜单"
  echo "1) SOCKS5"
  echo "2) VLESS-REALITY"
  read -p "输入协议编号（默认 1，输入 0 返回）: " PROTO
  PROTO=${PROTO:-1}
  [[ "$PROTO" == "0" ]] && return

  if [[ "$PROTO" == "2" ]]; then
    if ! command -v sing-box >/dev/null 2>&1; then
      echo "❌ 未检测到 sing-box。"
      echo "   1) 立即自动安装并初始化服务"
      echo "   0) 返回主菜单"
      read -p "请选择: " _ai
      if [[ "$_ai" == "1" ]]; then
        install_singbox_if_needed || { echo "❌ 安装失败"; return; }
        ensure_dual_init_autoadapt
      else
        echo "⏪ 已返回主菜单"; return
      fi
    fi

    local PORT
    while true; do
      read -p "请输入端口号（留空自动随机 30000-39999；输入 0 返回）: " PORT
      if [[ -z "${PORT:-}" ]]; then PORT=$((RANDOM % 1000 + 30000)); echo "（已自动选择随机端口：$PORT）"; fi
      [[ "$PORT" == "0" ]] && return
      if ! [[ "$PORT" =~ ^[0-9]{2,5}$ ]] || (( PORT < 1024 || PORT > 65535 )); then
        echo "❌ 端口无效，请重新输入。"; continue
      fi
      # conflict with config?
      if jq -e --argjson p "$PORT" '.inbounds[]? | select(.listen_port == $p)' "$CONFIG" >/dev/null 2>&1; then
        echo "⚠️ 端口 $PORT 已存在于配置，请换一个。"; continue
      fi
      # occupied by other process?
      local PST DET; IFS='|' read -r PST DET < <(check_port_state "$PORT")
      if [[ "$PST" == "LISTEN_OTHER" ]]; then
        echo "⚠️ 端口 $PORT 正被其他进程占用（$DET），请换一个。"; continue
      fi
      break
    done

    local UUID; if command -v uuidgen >/dev/null 2>&1; then UUID=$(uuidgen); else UUID=$(openssl rand -hex 16 | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/'); fi
    local FLOW="xtls-rprx-vision"
    local SERVER_NAME="www.cloudflare.com"
    local FINGERPRINTS=("chrome" "firefox" "safari" "ios" "android")
    local FINGERPRINT="${FINGERPRINTS[$RANDOM % ${#FINGERPRINTS[@]}]}"

    local KEY_PAIR; KEY_PAIR=$(sing-box generate reality-keypair) || { echo "❌ 生成 Reality 密钥失败（未安装或二进制异常）。"; return; }
    local PRIVATE_KEY PUBLIC_KEY SHORT_ID
    PRIVATE_KEY=$(awk -F': ' '/PrivateKey/ {print $2}' <<<"$KEY_PAIR")
    PUBLIC_KEY=$( awk -F': ' '/PublicKey/  {print $2}' <<<"$KEY_PAIR")
    SHORT_ID=$(openssl rand -hex 4)

    local TAG; TAG=$(generate_unique_tag)

    local tmpcfg; tmpcfg=$(mktemp)
    jq --arg port "$PORT" \
       --arg uuid "$UUID" \
       --arg prikey "$PRIVATE_KEY" \
       --arg sid "$SHORT_ID" \
       --arg server "$SERVER_NAME" \
       --arg flow "$FLOW" \
       --arg tag "$TAG" \
      '
      .inbounds += [{
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
      }]
      ' "$CONFIG" > "$tmpcfg" && mv "$tmpcfg" "$CONFIG"

    # write META
    local tmpmeta; tmpmeta=$(mktemp)
    jq --arg tag "$TAG" --arg pbk "$PUBLIC_KEY" --arg sid "$SHORT_ID" --arg sni "$SERVER_NAME" --arg port "$PORT" \
      '. + {($tag): {pbk:$pbk, sid:$sid, sni:$sni, port:$port}}' \
      "$META" > "$tmpmeta" && mv "$tmpmeta" "$META"

    echo "🧪 正在校验配置..."
    if sing-box check -c "$CONFIG" >/dev/null 2>&1; then
      echo "✅ 配置通过，正在重启 Sing-box..."
      restart_singbox
    else
      echo "❌ 配置校验失败，请检查 $CONFIG"
      sing-box check -c "$CONFIG" || true
      return
    fi

    local IPV4; IPV4=$(curl -s --max-time 2 https://api.ipify.org || echo "")
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
    [[ -n "$IPV4" ]] && echo "👉 客户端链接："
    [[ -n "$IPV4" ]] && echo "vless://${UUID}@${IPV4}:${PORT}?encryption=none&flow=${FLOW}&type=tcp&security=reality&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&sni=${SERVER_NAME}&fp=${FINGERPRINT}#${TAG}"
    echo ""

    post_add_diagnose "$PORT" "$TAG" "vless"

  else
    # SOCKS5
    local PORT USER PASS TAG
    while true; do
      read -p "请输入端口号（留空自动；输入 0 返回）: " PORT
      if [[ -z "${PORT:-}" ]]; then PORT=$((RANDOM % 10000 + 40000)); echo "（已自动选择随机端口：$PORT）"; fi
      [[ "$PORT" == "0" ]] && return
      if ! [[ "$PORT" =~ ^[0-9]{2,5}$ ]] || (( PORT < 1024 || PORT > 65535 )); then
        echo "❌ 端口无效，请重新输入。"; continue
      fi
      if jq -e --argjson p "$PORT" '.inbounds[]? | select(.listen_port == $p)' "$CONFIG" >/dev/null 2>&1; then
        echo "⚠️ 端口 $PORT 已存在于配置，请换一个。"; continue
      fi
      local PST DET; IFS='|' read -r PST DET < <(check_port_state "$PORT")
      if [[ "$PST" == "LISTEN_OTHER" ]]; then
        echo "⚠️ 端口 $PORT 正被其他进程占用（$DET），请换一个。"; continue
      fi
      break
    done
    read -p "请输入用户名（默认 user；输入 0 返回）: " USER; USER=${USER:-user}; [[ "$USER" == "0" ]] && return
    read -p "请输入密码（默认 pass123；输入 0 返回）: " PASS; PASS=${PASS:-pass123}; [[ "$PASS" == "0" ]] && return
    TAG="sk5-$(get_country_code)-$(tr -dc 'A-Z' </dev/urandom | head -c1)"
    local tmpcfg; tmpcfg=$(mktemp)
    jq --arg port "$PORT" --arg user "$USER" --arg pass "$PASS" --arg tag "$TAG" '
      .inbounds += [{
        "type": "socks",
        "tag": $tag,
        "listen": "0.0.0.0",
        "listen_port": ($port|tonumber),
        "users": [{"username": $user, "password": $pass}]
      }]
    ' "$CONFIG" > "$tmpcfg" && mv "$tmpcfg" "$CONFIG"

    echo "🧪 校验配置..."
    if command -v sing-box >/dev/null 2>&1 && sing-box check -c "$CONFIG" >/dev/null 2>&1; then
      echo "✅ 配置通过，正在重启..."
      restart_singbox
    else
      echo "❌ 配置失败，Sing-box 未重启"
      command -v sing-box >/dev/null 2>&1 && sing-box check -c "$CONFIG" || true
      return
    fi

    local ENCODED IPV4 IPV6
    ENCODED=$(echo -n "$USER:$PASS" | base64)
    IPV4=$(curl -s --max-time 2 https://api.ipify.org || echo "")
    IPV6=$(get_ipv6_address || echo "")
    echo ""
    echo "✅ SOCKS5 节点已添加："
    echo "端口: $PORT | 用户: $USER | 密码: $PASS"
    [[ -n "$IPV4" ]] && echo "IPv4: socks://${ENCODED}@${IPV4}:${PORT}#$TAG"
    [[ -n "$IPV6" ]] && echo "IPv6: socks://${ENCODED}@[${IPV6}]:${PORT}#$TAG"

    post_add_diagnose "$PORT" "$TAG" "socks"
  fi
}

# ---- Post-add diagnose ----
post_add_diagnose() {
  local PORT="$1" TAG="$2" TYPE="$3"
  echo ""
  echo "🩺 正在对新节点进行即时诊断（端口 $PORT）..."
  local PST DET; IFS='|' read -r PST DET < <(check_port_state "$PORT")
  local issues=()
  case "$PST" in
    LISTEN_SING)  echo "✅ 端口 $PORT 已由 sing-box 监听。";;
    LISTEN_OTHER) echo "⚠️ 端口 $PORT 被其他进程占用：$DET"; issues+=("OTHER");;
    NOT_LISTENING) echo "⚠️ 端口 $PORT 未被监听（可能重启未生效或端口冲突）。"; issues+=("DOWN");;
    *) echo "⚠️ 端口 $PORT 状态未知。";;
  esac
  if [[ "$TYPE" == "vless" ]]; then
    local JSON PRIV SID SNI
    JSON=$(jq -c --arg tag "$TAG" '.inbounds[]|select(.tag==$tag)' "$CONFIG")
    PRIV=$(echo "$JSON" | jq -r '.tls.reality.private_key // empty')
    SID=$( echo "$JSON" | jq -r '.tls.reality.short_id[0]   // empty')
    SNI=$( echo "$JSON" | jq -r '.tls.reality.handshake.server // .tls.server_name // empty')
    if ! valid_sid "${SID:-}"; then issues+=("PARAM"); fi
    [[ -z "${SNI:-}" ]] && issues+=("PARAM")
  fi
  echo "=== 处理选项 ==="
  local has=0
  for it in "${issues[@]}"; do
    case "$it" in
      OTHER)
        has=1
        echo "1) 查看占用进程详情"
        echo "2) 结束占用进程（危险）"
        echo "3) 换一个端口重新添加（自动删除当前入站）"
        ;;
      DOWN)
        has=1
        echo "4) 再次重启 sing-box"
        echo "5) 查看最近日志"
        echo "6) 回滚刚才的改动（删除该入站）"
        ;;
      PARAM)
        has=1
        echo "7) 一键重建（同端口，重新生成 reality 私钥与 short_id）"
        ;;
    esac
  done
  echo "0) 返回主菜单"
  if [[ $has -eq 0 ]]; then echo "无异常；按 0 返回主菜单。"; fi
  read -p "请选择: " opt
  case "$opt" in
    1)
      if command -v ss >/dev/null 2>&1; then
        ss -ltnp 2>/dev/null | awk -v p=":$PORT" '$4 ~ p'
      elif command -v lsof >/dev/null 2>&1; then
        lsof -nP -iTCP:"$PORT" -sTCP:LISTEN
      else
        echo "无 ss/lsof，无法显示详细占用信息。"
      fi
      ;;
    2)
      if [[ "$PST" == "LISTEN_OTHER" ]]; then
        local name pid; name=$(awk '{print $1}' <<<"$DET"); pid=$(awk '{print $2}' <<<"$DET")
        read -p "确认结束 $name (PID $pid)？(y/N): " y
        [[ "$y" == "y" ]] && kill -9 "$pid" && echo "已结束 $pid" || echo "已取消"
      else
        echo "当前不处于“被其他进程占用”状态。"
      fi
      ;;
    3)
      local tmpcfg; tmpcfg=$(mktemp)
      jq --arg tag "$TAG" 'del(.inbounds[]|select(.tag==$tag))' "$CONFIG" > "$tmpcfg" && mv "$tmpcfg" "$CONFIG"
      restart_singbox
      echo "✅ 已删除该入站，请重新添加并选择新端口。"
      ;;
    4) restart_singbox ;;
    5)
      if pidof systemd >/dev/null 2>&1; then
        journalctl -u sing-box --since -2min --no-pager | tail -n 80
      else
        echo "请查看 /var/log/sing-box.log 或相应日志。"
      fi
      ;;
    6)
      local tmpcfg; tmpcfg=$(mktemp)
      jq --arg tag "$TAG" 'del(.inbounds[]|select(.tag==$tag))' "$CONFIG" > "$tmpcfg" && mv "$tmpcfg" "$CONFIG"
      restart_singbox
      echo "✅ 已回滚：删除该入站。"
      ;;
    7)
      echo "${TAG}|${PORT}|$(uuidgen 2>/dev/null || echo "")|$(jq -r --arg tag "$TAG" '.inbounds[]|select(.tag==$tag)|.tls.reality.handshake.server // .tls.server_name // "www.cloudflare.com"' "$CONFIG")" > /tmp/sk5_invalid.single
      rebuild_invalid_nodes /tmp/sk5_invalid.single
      ;;
    0|"") : ;;
    *) echo "无效选项";;
  esac
}

# ---- Main menu ----
main_menu() {
  echo ""
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
    6)
      echo "=== 修复 / 重装 Sing-box ==="
      echo "1) 完全卸载（删除程序与全部节点配置）"
      echo "2) 重装（保留节点与配置，重新初始化服务脚本）"
      echo "0) 返回主菜单"
      read -p "请选择: " sub
      case "$sub" in
        1) full_uninstall ;;
        2) reinstall_keep_nodes ;;
        0|"") : ;;
        *) echo "无效选项" ;;
      esac
      ;;
    9) exit 0 ;;
    *) echo "无效输入" ;;
  esac
}

setup_shortcut() {
  local MAIN_CMD="/usr/local/bin/sk" ALT_CMD="/usr/local/bin/ck"
  local SCRIPT_PATH; SCRIPT_PATH="$(realpath "$0")"
  [[ -f "$MAIN_CMD" ]] || { printf '#!/usr/bin/env bash\nbash "%s"\n' "$SCRIPT_PATH" > "$MAIN_CMD"; chmod +x "$MAIN_CMD"; }
  [[ -f "$ALT_CMD"  ]] || { printf '#!/usr/bin/env bash\nbash "%s"\n' "$SCRIPT_PATH" > "$ALT_CMD";  chmod +x "$ALT_CMD";  }
}

# ---- Entry ----
install_dependencies
ensure_config_dir
setup_shortcut
while true; do main_menu; done
