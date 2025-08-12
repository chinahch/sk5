#!/bin/sh
# sing-box one-key installer with Alpine (OpenRC) support
# Compatible: Alpine, Debian/Ubuntu, RHEL/CentOS/Rocky/Alma
# Usage:
#   chmod +x install.sh
#   ./install.sh install      # 安装/升级到最新版本
#   ./install.sh install v1.10.0   # 指定版本
#   ./install.sh uninstall
#   ./install.sh start|stop|restart|status|enable|disable
#   SING_BOX_VERSION=v1.10.0 ./install.sh install  # 也可用环境变量

set -eu

APP_NAME="sing-box"
REPO="SagerNet/sing-box"
BIN_DIR="/usr/local/bin"
BIN_PATH="$BIN_DIR/$APP_NAME"
ETC_DIR="/etc/$APP_NAME"
CONF_PATH="$ETC_DIR/config.json"
SYSTEMD_UNIT="/etc/systemd/system/$APP_NAME.service"
OPENRC_INIT="/etc/init.d/$APP_NAME"
SB_USER="sing-box"
TMP_DIR=""

log() { printf "\033[1;32m[+]\033[0m %s\n" "$*"; }
err() { printf "\033[1;31m[!]\033[0m %s\n" "$*" 1>&2; }
abort() { err "$*"; exit 1; }

die_on_nonroot() {
  if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
      exec sudo -E "$0" "$@"
    else
      abort "请以 root 运行，或安装 sudo 后重试。"
    fi
  fi
}

cleanup() {
  [ -n "$TMP_DIR" ] && rm -rf "$TMP_DIR" || true
}
trap cleanup EXIT INT TERM

# -------- OS / PKG manager detection --------
OS_ID=""
OS_FAMILY=""
PKG_MGR=""
SERVICE_MGR=""

os_detect() {
  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID=${ID:-}
    case "$OS_ID" in
      alpine) OS_FAMILY="alpine" ;;
      debian|ubuntu) OS_FAMILY="debian" ;;
      centos|rhel|rocky|almalinux|fedora) OS_FAMILY="rhel" ;;
      *) OS_FAMILY="unknown" ;;
    esac
  fi

  case "$OS_FAMILY" in
    alpine) PKG_MGR="apk" ;;
    debian) PKG_MGR="apt" ;;
    rhel)
      if command -v dnf >/dev/null 2>&1; then PKG_MGR="dnf"; else PKG_MGR="yum"; fi ;;
    *) abort "不支持的发行版，无法检测到包管理器。" ;;
  esac

  if command -v systemctl >/dev/null 2>&1; then
    SERVICE_MGR="systemd"
  elif command -v rc-update >/dev/null 2>&1; then
    SERVICE_MGR="openrc"
  else
    SERVICE_MGR="none"
  fi
}

install_deps() {
  # 基本依赖：curl 或 wget 至少一个，tar、xz、unzip、jq、ca-certificates
  case "$PKG_MGR" in
    apk)
      log "安装依赖 (apk) ..."
      apk update
      apk add --no-cache bash curl wget tar xz unzip jq ca-certificates coreutils openrc
      update-ca-certificates || true
      ;;
    apt)
      log "安装依赖 (apt) ..."
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y
      apt-get install -y bash curl wget tar xz-utils unzip jq ca-certificates
      update-ca-certificates || true
      ;;
    dnf)
      log "安装依赖 (dnf) ..."
      dnf -y install bash curl wget tar xz unzip jq ca-certificates
      ;;
    yum)
      log "安装依赖 (yum) ..."
      yum -y install bash curl wget tar xz unzip jq ca-certificates
      ;;
    *) abort "未知包管理器：$PKG_MGR" ;;
  esac
}

ensure_user() {
  if id "$SB_USER" >/dev/null 2>&1; then return; fi
  case "$OS_FAMILY" in
    alpine) adduser -S -H -s /sbin/nologin "$SB_USER" || true ;;
    debian) adduser --system --no-create-home --shell /usr/sbin/nologin "$SB_USER" || true ;;
    rhel)   useradd -r -s /sbin/nologin "$SB_USER" || true ;;
  esac
}

# -------- arch detection & download URL selection --------
arch_detect() {
  GOARCHv3=""  # 为 x86_64/amd64 提供可选的 amd64v3 变体；其他架构留空
  UNAME_M=$(uname -m)
  case "$UNAME_M" in
    x86_64|amd64)  GOARCH="amd64" ; GOARCHv3="amd64v3" ;;
    aarch64|arm64) GOARCH="arm64" ;;
    armv7l|armv7)  GOARCH="armv7" ;;
    armv6l|armv6)  GOARCH="armv6" ;;
    i386|i686)     GOARCH="386" ;;
    riscv64)       GOARCH="riscv64" ;;
    *) abort "不支持的架构：$UNAME_M" ;;
  esac
}

# 从 GitHub Releases 解析出合适的下载链接。优先选择 musl (在 Alpine)。
get_download_url() {
  VERSION_TAG="$1"  # vX.Y.Z 或 latest

  # 可选：自定义镜像/反代前缀，例如 https://ghproxy.net 或你自建的反代
  GH_PROXY_PREFIX="${GH_PROXY_PREFIX:-}"

  ghcurl() {
    # $1: URL
    local URL="$1"
    case "$URL" in
      https://api.github.com/*|https://github.com/*)
        [ -n "$GH_PROXY_PREFIX" ] && URL="${GH_PROXY_PREFIX%/}/$URL"
        ;;
    esac
    curl -fsSL --retry 3 --connect-timeout 8 \
      -H 'Accept: application/vnd.github+json' \
      -H 'User-Agent: curl-sing-box-installer' \
      "$URL"
  }

  local API_BASE="https://api.github.com/repos/$REPO/releases"
  local JSON TAG

  if [ "$VERSION_TAG" = "latest" ]; then
    JSON="$(ghcurl "$API_BASE/latest" || true)"
    TAG="$(printf '%s' "$JSON" | jq -r '.tag_name' 2>/dev/null || true)"
  else
    case "$VERSION_TAG" in v*) ;; * ) VERSION_TAG="v$VERSION_TAG" ;; esac
    JSON="$(ghcurl "$API_BASE/tags/$VERSION_TAG" || true)"
    TAG="$VERSION_TAG"
  fi

  # 需要 GOARCH/GOARCHv3
  arch_detect
  local CAND1="linux-$GOARCH-musl.tar.gz"
  local CAND2="linux-$GOARCH.tar.gz"
  local CAND3="linux-${GOARCHv3:-none}.tar.gz"

  pick_from_json() {
    printf '%s' "$JSON" | jq -r \
      --arg c1 "$1" --arg c2 "$2" --arg c3 "$3" \
      'try (.assets[].browser_download_url) // empty
       | select( test($c1) or test($c2) or ($c3 != "none" and test($c3)) )' \
      2>/dev/null | head -n1 || true
  }

  local URL=""
  if [ -n "$JSON" ] && printf '%s' "$JSON" | jq -e . >/dev/null 2>&1; then
    URL="$(pick_from_json "$CAND1" "$CAND2" "$CAND3")"
  fi

  # HTML 兜底
  if [ -z "$URL" ]; then
    local PAGE_URL
    if [ -n "$TAG" ]; then
      PAGE_URL="https://github.com/$REPO/releases/tag/$TAG"
    elif [ "$VERSION_TAG" = "latest" ]; then
      PAGE_URL="https://github.com/$REPO/releases/latest"
    else
      PAGE_URL="https://github.com/$REPO/releases"
    fi
    local PAGE="$(ghcurl "$PAGE_URL" || true)"
    for cand in "$CAND1" "$CAND2" "$CAND3"; do
      [ "$cand" = "linux-none.tar.gz" ] && continue
      local U
      U="$(printf '%s' "$PAGE" \
        | sed -n "s#href=\\\"\\(/$REPO/releases/download/[^\\\"]*${cand}\\)\\\"#https://github.com\\1#p" \
        | head -n1)"
      [ -n "$U" ] && URL="$U" && break
    done
  fi

  [ -n "$URL" ] || abort "无法确定下载地址。可设置 GH_PROXY_PREFIX 走镜像后重试。"
  echo "$URL"
}


install_binary() {
  VERSION_TAG=${1:-"${SING_BOX_VERSION:-latest}"}
  arch_detect
  URL=$(get_download_url "$VERSION_TAG")
  log "下载: $URL"
  TMP_DIR=$(mktemp -d)
  TARBALL="$TMP_DIR/sb.tgz"
  curl -fsSL "$URL" -o "$TARBALL"
  tar -xzf "$TARBALL" -C "$TMP_DIR"
  # 目录名类似 sing-box-<ver>-linux-amd64
  EXTRACT_DIR=$(find "$TMP_DIR" -maxdepth 1 -type d -name "sing-box-*" | head -n1)
  [ -n "$EXTRACT_DIR" ] || abort "解压失败。"
  mkdir -p "$BIN_DIR"
  install -m 0755 "$EXTRACT_DIR/$APP_NAME" "$BIN_PATH"
  log "已安装二进制到 $BIN_PATH"
}

install_config() {
  mkdir -p "$ETC_DIR"
  if [ ! -f "$CONF_PATH" ]; then
    cat >"$CONF_PATH" <<'JSON'
{
  "log": { "level": "info" },
  "inbounds": [
    { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 },
    { "type": "http",  "tag": "http-in",  "listen": "127.0.0.1", "listen_port": 8080 }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" },
    { "type": "block",  "tag": "block" }
  ]
}
JSON
    log "已生成默认配置: $CONF_PATH (请按需修改)"
  fi
  chown -R "$SB_USER":"$SB_USER" "$ETC_DIR" || true
}

install_service_systemd() {
  cat >"$SYSTEMD_UNIT" <<EOF
[Unit]
Description=$APP_NAME service
After=network-online.target
Wants=network-online.target

[Service]
User=$SB_USER
Group=$SB_USER
Type=simple
ExecStart=$BIN_PATH run -c $CONF_PATH
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "$APP_NAME"
}

install_service_openrc() {
  cat >"$OPENRC_INIT" <<'EOF'
#!/sbin/openrc-run
name="sing-box"
description="sing-box service"
command="/usr/local/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_user="sing-box:sing-box"
command_background=yes
pidfile="/run/sing-box.pid"

depend() { need net after firewall }

start() {
  ebegin "Starting sing-box"
  start-stop-daemon --start --make-pidfile --pidfile "$pidfile" --exec "$command" -- $command_args
  eend $?
}

stop() {
  ebegin "Stopping sing-box"
  start-stop-daemon --stop --pidfile "$pidfile"
  eend $?
}
EOF
  chmod +x "$OPENRC_INIT"
  rc-update add "$APP_NAME" default || true
}

start_service() {
  case "$SERVICE_MGR" in
    systemd) systemctl restart "$APP_NAME" ;;
    openrc)  rc-service "$APP_NAME" restart || rc-service "$APP_NAME" start ;;
    none)    err "未检测到 systemd/OpenRC。你可以手动运行: $BIN_PATH run -c $CONF_PATH" ;;
  esac
}

cmd_install() {
  die_on_nonroot "$@"
  os_detect
  log "检测到系统：$OS_FAMILY (pkg: $PKG_MGR, svc: $SERVICE_MGR)"
  install_deps
  ensure_user
  install_binary "$1"
  install_config
  case "$SERVICE_MGR" in
    systemd) install_service_systemd ;;
    openrc)  install_service_openrc ;;
    none)    : ;;
  esac
  start_service
  log "安装完成。可编辑 $CONF_PATH 后执行 '$0 restart' 生效。"
}

cmd_uninstall() {
  die_on_nonroot "$@"
  os_detect
  case "$SERVICE_MGR" in
    systemd) systemctl disable "$APP_NAME" || true; systemctl stop "$APP_NAME" || true; rm -f "$SYSTEMD_UNIT"; systemctl daemon-reload || true ;;
    openrc)  rc-service "$APP_NAME" stop || true; rc-update del "$APP_NAME" default || true; rm -f "$OPENRC_INIT" ;;
  esac
  rm -f "$BIN_PATH"
  log "保留配置目录：$ETC_DIR (如需一起删除请手动 rm -rf)"
}

cmd_service() {
  os_detect
  case "$1" in
    start)
      [ "$SERVICE_MGR" = systemd ] && exec systemctl start "$APP_NAME" || exec rc-service "$APP_NAME" start ;;
    stop)
      [ "$SERVICE_MGR" = systemd ] && exec systemctl stop "$APP_NAME" || exec rc-service "$APP_NAME" stop ;;
    restart)
      [ "$SERVICE_MGR" = systemd ] && exec systemctl restart "$APP_NAME" || exec rc-service "$APP_NAME" restart ;;
    status)
      if [ "$SERVICE_MGR" = systemd ]; then exec systemctl status "$APP_NAME"; else exec rc-service "$APP_NAME" status; fi ;;
    enable)
      [ "$SERVICE_MGR" = systemd ] && exec systemctl enable "$APP_NAME" || exec rc-update add "$APP_NAME" default ;;
    disable)
      [ "$SERVICE_MGR" = systemd ] && exec systemctl disable "$APP_NAME" || exec rc-update del "$APP_NAME" default ;;
    *) abort "未知服务命令：$1" ;;
  esac
}

main() {
  CMD=${1:-}
  ARG=${2:-}
  case "$CMD" in
    install)   cmd_install "$ARG" ;;
    uninstall) cmd_uninstall ;;
    start|stop|restart|status|enable|disable) cmd_service "$CMD" ;;
    *)
      cat <<USAGE
用法：
  $0 install [version]   安装/升级（version 可为 vX.Y.Z 或留空表示 latest）
  $0 uninstall           卸载（保留 /etc/$APP_NAME 配置）
  $0 start|stop|restart|status|enable|disable  管理服务

示例：
  $0 install
  $0 install v1.10.0
  SING_BOX_VERSION=v1.10.0 $0 install
USAGE
      ;;
  esac
}

main "$@"
