#!/usr/bin/env bash
# sk5.sh 模块: NAT 端口管理

# 依赖: main.sh 中的全局变量和辅助函数，以及 deps_and_util.sh 中的 port_status

# 全局变量 nat_mode, nat_ranges, nat_tcp, nat_udp 需要在 main.sh 中声明，并在 load_nat_data 中填充

load_nat_data() {
  if [[ -f "$NAT_FILE" ]]; then
    nat_mode=$(jq -r '.mode // "custom"' "$NAT_FILE")
    mapfile -t nat_ranges < <(jq -r '.ranges[]?' "$NAT_FILE")
    mapfile -t nat_tcp < <(jq -r '.custom_tcp[]?' "$NAT_FILE" | sort -n -u)
    mapfile -t nat_udp < <(jq -r '.custom_udp[]?' "$NAT_FILE" | sort -n -u)
  else
    nat_mode=""
    nat_ranges=()
    nat_tcp=()
    nat_udp=()
  fi
}

get_random_allowed_port() {
  local proto="$1"
  local -a used=()
  mapfile -t used < <(jq -r '.inbounds[].listen_port' "$CONFIG" 2>/dev/null | grep -E '^[0-9]+$' || true)
  mapfile -t hy2u < <(jq -r 'to_entries[]? | select(.value.type=="hysteria2") | .value.port' "$META" 2>/dev/null || true)
  used+=("${hy2u[@]}")

  local -a candidates=()
  if [[ -n "$nat_mode" ]]; then
    if [[ "$nat_mode" == "range" ]]; then
      for range in "${nat_ranges[@]}"; do
        local s=${range%-*} e=${range#*-} p
        for ((p=s; p<=e; p++)); do candidates+=("$p"); done
      done
    else
      if [[ "$proto" == "tcp" ]]; then
        candidates=("${nat_tcp[@]}")
      elif [[ "$proto" == "udp" ]]; then
        candidates=("${nat_udp[@]}")
      else
        candidates=("${nat_tcp[@]}" "${nat_udp[@]}")
      fi
    fi
    local free=() usedset=" ${used[*]} "
    for c in "${candidates[@]}"; do
      [[ "$usedset" == *" $c "* ]] && continue
      free+=("$c")
    done
    if ((${#free[@]}==0)); then echo "NO_PORT"; return 1; fi
    echo "${free[RANDOM % ${#free[@]}]}"; return 0
  else
    if [[ "$proto" == "tcp" ]]; then
      echo $((RANDOM%10000 + 30000))
    elif [[ "$proto" == "udp" ]]; then
      echo $((RANDOM%10000 + 50000))
    else
      echo $((RANDOM%1000 + 30000))
    fi
  fi
}

check_nat_allow() {
  local port="$1" proto="$2"
  if [[ -z "$nat_mode" ]]; then return 0; fi
  if [[ "$nat_mode" == "range" ]]; then
    for range in "${nat_ranges[@]}"; do
      local s=${range%-*} e=${range#*-}
      if (( port >= s && port <= e )); then return 0; fi
    done
    return 1
  elif [[ "$nat_mode" == "custom" ]]; then
    local arr=()
    if [[ "$proto" == "tcp" ]]; then arr=("${nat_tcp[@]}")
    elif [[ "$proto" == "udp" ]]; then arr=("${nat_udp[@]}")
    else arr=("${nat_tcp[@]}" "${nat_udp[@]}")
    fi
    printf '%s\n' "${arr[@]}" | grep -qx "$port"; return $?
  else
    return 0
  fi
}

view_nat_ports() {
  if [[ ! -f "$NAT_FILE" ]]; then
    warn "当前未设置 NAT 模式规则"
    return
  fi

  local BOLD="" C_END="" C_CYAN="" C_GRN="" C_YLW=""
  if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && [[ $(tput colors 2>/dev/null) -ge 8 ]]; then
    BOLD=$'\033[1m'; C_END=$'\033[0m'
    C_CYAN=$'\033[36m'; C_GRN=$'\033[32m'; C_YLW=$'\033[33m'
  fi

  _print_grid() {
    local cols="$1" cellw="$2"; shift 2
    local i=0 item
    for item in "$@"; do
      printf "%-*s" "$cellw" "$item"
      i=$((i+1))
      if (( i % cols == 0 )); then printf "\n"; else printf " "; fi
    done
    (( i % cols != 0 )) && printf "\n"
  }

  local mode; mode="$nat_mode"
  printf "%s" "$BOLD"; printf "%s" "当前 NAT 模式:"; printf "%s" "$C_END"; printf " %s\n\n" "$mode"

  if ((${#nat_ranges[@]})); then
    printf "%s%s范围端口:%s\n" "$BOLD" "$C_CYAN" "$C_END"
    _print_grid 4 13 "${nat_ranges[@]}"
    printf "\n"
  fi

  if ((${#nat_tcp[@]})); then
    printf "%s%s自定义 TCP 端口:%s\n" "$BOLD" "$C_GRN" "$C_END"
    _print_grid 8 6 "${nat_tcp[@]}"; printf "\n"
  fi

  if ((${#nat_udp[@]})); then
    printf "%s%s自定义 UDP 端口:%s\n" "$BOLD" "$C_YLW" "$C_END"
    _print_grid 8 6 "${nat_udp[@]}"; printf "\n"
  fi

  local w_left=34
  printf '%s\n' "------ 端口规则管理 ------"
  printf "%-*s %s\n" "$w_left" "1) 添加范围端口"                      "2) 删除范围端口"
  printf "%-*s %s\n" "$w_left" "3) 添加自定义TCP端口"                 "4) 删除自定义TCP端口"
  printf "%-*s %s\n" "$w_left" "5) 添加自定义UDP端口"                 "6) 删除自定义UDP端口"
  printf "%s\n" "0) 返回"
  printf "%s\n\n" "提示：空格分隔"

  read -rp "选择: " op
  case "$op" in
    1)
      read -rp "输入范围段: " ranges_in
      [[ -z "$ranges_in" ]] && { warn "未输入"; return; }
      local tmp; tmp=$(mktemp)
      trap 'rm -f "$tmp"' EXIT
      jq --argjson arr "$(printf '%s\n' "$ranges_in" | jq -R 'split(" ")')" \
         '.mode="range"|.ranges=((.ranges//[])+$arr)|.custom_tcp=(.custom_tcp//[])|.custom_udp=(.custom_udp//[])' \
         "$NAT_FILE" >"$tmp" && mv "$tmp" "$NAT_FILE"
      load_nat_data
      ok "已添加范围段"
      ;;
    2)
      read -rp "输入要删除的范围段（完全匹配）: " seg
      [[ -z "$seg" ]] && { warn "未输入"; return; }
      local tmp; tmp=$(mktemp)
      trap 'rm -f "$tmp"' EXIT
      jq --arg seg "$seg" '.ranges=((.ranges//[])|map(select(.!=$seg)))' "$NAT_FILE" >"$tmp" && mv "$tmp" "$NAT_FILE"
      load_nat_data
      ok "已删除范围段"
      ;;
    3)
      read -rp "输入要添加的TCP端口（空格分隔）: " ports
      local tmp; tmp=$(mktemp)
      trap 'rm -f "$tmp"' EXIT
      jq --argjson add "$(printf '%s\n' "$ports" | jq -R 'split(" ")|map(tonumber)')" \
         '.mode="custom"|.custom_tcp=((.custom_tcp//[])+$add)|.custom_udp=(.custom_udp//[])|.ranges=[]' \
         "$NAT_FILE" >"$tmp" && mv "$tmp" "$NAT_FILE"
      load_nat_data
      ok "已添加TCP端口"
      ;;
    4)
      read -rp "输入要删除的TCP端口（空格分隔）: " ports
      local tmp; tmp=$(mktemp)
      trap 'rm -f "$tmp"' EXIT
      jq --argjson del "$(printf '%s\n' "$ports" | jq -R 'split(" ")|map(tonumber)')" \
         '.custom_tcp=((.custom_tcp//[])|map(select(( $del|index(.) )|not )))' \
         "$NAT_FILE" >"$tmp" && mv "$tmp" "$NAT_FILE"
      load_nat_data
      ok "已删除TCP端口"
      ;;
    5)
      read -rp "输入要添加的UDP端口（空格分隔）: " ports
      local tmp; tmp=$(mktemp)
      trap 'rm -f "$tmp"' EXIT
      jq --argjson add "$(printf '%s\n' "$ports" | jq -R 'split(" ")|map(tonumber)')" \
         '.mode="custom"|.custom_udp=((.custom_udp//[])+$add)|.custom_tcp=(.custom_tcp//[])|.ranges=[]' \
         "$NAT_FILE" >"$tmp" && mv "$tmp" "$NAT_FILE"
      load_nat_data
      ok "已添加UDP端口"
      ;;
    6)
      read -rp "输入要删除的UDP端口（空格分隔）: " ports
      local tmp; tmp=$(mktemp)
      trap 'rm -f "$tmp"' EXIT
      jq --argjson del "$(printf '%s\n' "$ports" | jq -R 'split(" ")|map(tonumber)')" \
         '.custom_udp=((.custom_udp//[])|map(select(( $del|index(.) )|not )))' \
         "$NAT_FILE" >"$tmp" && mv "$tmp" "$NAT_FILE"
      load_nat_data
      ok "已删除UDP端口"
      ;;
    0) return ;;
    *) warn "无效输入" ;;
  esac
}

disable_nat_mode() {
  if [[ -f "$NAT_FILE" ]]; then rm -f "$NAT_FILE"; load_nat_data; ok "NAT 模式已关闭（规则已清除）"
  else warn "当前未启用 NAT 模式"; fi
}

set_nat_range() {
  read -rp "请输入范围端口（多个用空格分隔，如 12000-12020 34050-34070）: " ranges
  local tmp; tmp=$(mktemp)
  trap 'rm -f "$tmp"' EXIT
  jq -n --argjson arr "$(printf '%s\n' "$ranges" | jq -R 'split(" ")')" \
    '{"mode":"range","ranges":$arr,"custom_tcp":[],"custom_udp":[]}' > "$tmp"
  mv "$tmp" "$NAT_FILE"
  load_nat_data
  ok "范围端口已保存"
}
set_nat_custom_tcp() {
  read -rp "请输入自定义TCP端口（空格分隔）: " ports
  local tmp; tmp=$(mktemp)
  trap 'rm -f "$tmp"' EXIT
  if [[ -f "$NAT_FILE" ]]; then
    jq --argjson arr "$(printf '%s\n' "$ports" | jq -R 'split(" ") | map(tonumber)')" '.mode="custom"|.ranges=[]|.custom_tcp = $arr' "$NAT_FILE" > "$tmp"
  else
    jq -n --argjson arr "$(printf '%s\n' "$ports" | jq -R 'split(" ") | map(tonumber)')" '{"mode":"custom","ranges":[],"custom_tcp":$arr,"custom_udp":[]}' > "$tmp"
  fi
  mv "$tmp" "$NAT_FILE"
  load_nat_data
  ok "自定义TCP端口已保存"
}

set_nat_custom_udp() {
  read -rp "请输入自定义UDP端口（空格分隔）: " ports
  local tmp; tmp=$(mktemp)
  trap 'rm -f "$tmp"' EXIT
  if [[ -f "$NAT_FILE" ]]; then
    jq --argjson arr "$(printf '%s\n' "$ports" | jq -R 'split(" ") | map(tonumber)')" '.mode="custom"|.ranges=[]|.custom_udp = $arr' "$NAT_FILE" > "$tmp"
  else
    jq -n --argjson arr "$(printf '%s\n' "$ports" | jq -R 'split(" ") | map(tonumber)')" '{"mode":"custom","ranges":[],"custom_tcp":[],"custom_udp":$arr}' > "$tmp"
  fi
  mv "$tmp" "$NAT_FILE"
  load_nat_data
  ok "自定义UDP端口已保存"
}

nat_mode_menu() {
  while true; do
    load_nat_data
    say "====== NAT 模式设置 ======"
    say "1) 设置范围端口"
    say "2) 设置自定义TCP端口"
    say "3) 设置自定义UDP端口"
    say "4) 查看当前NAT端口规则"
    say "5) 退出 NAT 模式"
    say "0) 返回主菜单"
    read -rp "请选择: " opt
    case "$opt" in
      1) set_nat_range ;;
      2) set_nat_custom_tcp ;;
      3) set_nat_custom_udp ;;
      4) view_nat_ports ;;
      5) disable_nat_mode ;;
      0) return ;;
      *) warn "无效输入" ;;
    esac
  done
}