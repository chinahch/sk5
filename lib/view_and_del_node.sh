#!/usr/bin/env bash
# sk5.sh 模块: 节点查看与删除

# 依赖: main.sh/deps_and_util.sh/add_node.sh 中的函数和变量

# ============= CF Tunnel 管理函数 (独立进程) =============
ARGO_NODES_DIR="/etc/sing-box/argo_users"
ARGO_BIN_DIR="/root/agsbx"

delete_argo_user() {
    set +e
    say "========== 删除 CF Tunnel 用户 =========="
    local nodes
    nodes=$(jq -r 'to_entries[] | select(.value.type == "argo") | "\(.key) \(.value.port // "null") \(.value.domain // "null")"' "$META" 2>/dev/null || true)
    if [ -z "$nodes" ]; then say "当前无 CF Tunnel 节点可删除。"; read -rp "按回车返回..." _; return; fi

    local idx=1 tags=() ports=()
    while IFS= read -r line; do
        local tag port domain
        read -r tag port domain <<< "$line"
        tags[$idx]="$tag"
        ports[$idx]="$port"
        echo "[${idx}] ${tag} (端口: ${port}, 域名: ${domain})"
        ((idx++))
    done <<< "$nodes"

    say "[0] 返回"
    read -rp "请输入要删除的节点序号（1-$((idx-1))）: " del_idx
    [[ "$del_idx" == "0" || -z "$del_idx" ]] && return
    if ! [[ "$del_idx" =~ ^[0-9]+$ ]] || (( del_idx < 1 || del_idx >= idx )); then warn "无效序号。"; return; fi 

    local tag_to_del="${tags[$del_idx]}"
    local port_to_del="${ports[$del_idx]}"
    read -rp "确认删除节点 ${tag_to_del} ？(y/N): " confirm
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && { say "已取消"; return; }
    
    say "-> 正在处理节点 ${tag_to_del}..."

    if [[ "$port_to_del" == "null" ]]; then
        pkill -f "/root/agsbx/temp_node/xray_temp" >/dev/null 2>&1 || true
        pkill -f "/root/agsbx/temp_node/cloudflared_temp" >/dev/null 2>&1 || true
        rm -f "$ARGO_TEMP_CACHE"
        local tmpmeta; tmpmeta=$(mktemp)
        jq "del(.\"$tag_to_del\")" "$META" > "$tmpmeta" && mv "$tmpmeta" "$META"
        ok "已删除临时节点 ${tag_to_del} 的元数据。"
    elif [[ -n "$port_to_del" ]]; then
        local service_name="cf-tunnel-${port_to_del}"
        if [[ -n "$_SYSTEMCTL_CMD" ]]; then
            "$_SYSTEMCTL_CMD" disable --now "${service_name}-xray.service" >/dev/null 2>&1 || true
            "$_SYSTEMCTL_CMD" disable --now "${service_name}-cfd.service" >/dev/null 2>&1 || true
            rm -f "/etc/systemd/system/${service_name}-xray.service"
            rm -f "/etc/systemd/system/${service_name}-cfd.service"
            "$_SYSTEMCTL_CMD" daemon-reload >/dev/null 2>&1 || true
        else
            pkill -9 -f "xray run -c ${ARGO_NODES_DIR}/${port_to_del}.json" >/dev/null 2>&1 || true
            pkill -9 -f "cloudflared.*${port_to_del}" >/dev/null 2>&1 || true
            rm -f "/etc/local.d/argo_${port_to_del}.start"
            crontab -l 2>/dev/null | grep -v "# agsbx-${port_to_del}" > /tmp/crontab.tmp || true
            if [[ -s /tmp/crontab.tmp ]]; then crontab /tmp/crontab.tmp; else crontab -r >/dev/null 2>&1; fi; rm -f /tmp/crontab.tmp
        fi
        rm -f "${ARGO_NODES_DIR}/${port_to_del}.json" "${ARGO_NODES_DIR}/${port_to_del}.log"
        local tmpmeta; tmpmeta=$(mktemp)
        jq "del(.\"$tag_to_del\")" "$META" > "$tmpmeta" && mv "$tmpmeta" "$META"
        ok "已删除固定 CF Tunnel 用户 ${tag_to_del} (进程已停止)"
    fi
    read -rp "按回车返回..." _
    set -e
}

activate_fixed_argo_nodes() {
    set +e
    say "========== 激活/重启固定 CF Tunnel 节点 =========="
    
    local nodes_to_restart=()
    local nodes
    nodes=$(jq -r 'to_entries[] | select(.value.type == "argo" and .value.port != "null") | "\(.key) \(.value.port) \(.value.domain) \(.value.token) \(.value.uuid)"' "$META" 2>/dev/null || true)
    
    if [ -z "$nodes" ]; then say "当前没有已配置的固定 CF Tunnel 用户可供激活。"; read -rp "按回车返回..." _; return; fi
    
    say "检测到以下固定 CF Tunnel 用户："
    local idx=1
    while IFS= read -r line; do
        local tag port domain token uuid is_running=0 service_name="cf-tunnel-${port}"
        read -r tag port domain token uuid <<< "$line"
        
        if [[ -n "$_SYSTEMCTL_CMD" ]]; then
            if "$_SYSTEMCTL_CMD" is-active --quiet "${service_name}-cfd.service"; then is_running=1; fi
        else
            if pgrep -f "cloudflared.*${port}" >/dev/null; then is_running=1; fi
        fi

        if (( is_running == 1 )); then
            say "[${idx}] ${tag} (端口: ${port}) - ${C_GREEN}已运行${C_RESET}，跳过。"
        else
            say "[${idx}] ${tag} (端口: ${port}) - ${C_RED}停止中${C_RESET}，将重启..."
            nodes_to_restart+=("$line")
        fi
        ((idx++))
    done <<< "$nodes"
    
    if ((${#nodes_to_restart[@]} == 0)); then ok "所有固定 CF Tunnel 节点均已运行。"; read -rp "按回车返回..." _; return; fi
    
    say ""; say "正在尝试重启 ${#nodes_to_restart[@]} 个停止中的 CF Tunnel 用户..."
    
    local restart_count=0
    for node_line in "${nodes_to_restart[@]}"; do
        local tag port domain token uuid config_file log_file service_name
        read -r tag port domain token uuid <<< "$node_line"
        
        config_file="$ARGO_NODES_DIR/${port}.json"; log_file="$ARGO_NODES_DIR/${port}.log"; service_name="cf-tunnel-${port}"
        say "-> 重启用户 ${tag} (端口 ${port})..."

        if [[ -n "$_SYSTEMCTL_CMD" ]]; then
            "$_SYSTEMCTL_CMD" daemon-reload >/dev/null 2>&1 || true
            "$_SYSTEMCTL_CMD" restart "${service_name}-xray.service" >/dev/null 2>&1 || true
            sleep 1
            "$_SYSTEMCTL_CMD" restart "${service_name}-cfd.service" >/dev/null 2>&1 || true
            sleep 2

            if "$_SYSTEMCTL_CMD" is-active --quiet "${service_name}-cfd.service"; then ok "   用户 ${tag} 启动成功 (Systemd)。"; ((restart_count++));
            else err "   用户 ${tag} 启动失败，请检查日志: sudo journalctl -u ${service_name}-cfd.service"; fi
            
        else
            say "   非Systemd环境，使用nohup重启..."
            pkill -9 -f "xray run -c $config_file" >/dev/null 2>&1 || true
            pkill -9 -f "cloudflared.*${port}" >/dev/null 2>&1 || true
            sleep 1
            (nohup "$ARGO_BIN_DIR/xray" run -c "$config_file" >/dev/null 2>&1 &); sleep 1
            (nohup "$ARGO_BIN_DIR/cloudflared" tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token "$token" --url "http://127.0.0.1:${port}" > "$log_file" 2>&1 &); sleep 2
            
            if pgrep -f "cloudflared.*${port}" >/dev/null; then ok "   用户 ${tag} 启动成功 (Fallback)。"; ((restart_count++));
            else err "   用户 ${tag} 启动失败，请检查日志: cat ${log_file}"; fi
        fi
    done
    
    say ""; ok "重启操作完成。成功启动 ${restart_count} 个用户。"; read -rp "按回车返回..." _; set -e
}

uninstall_argo_all() {
    set +e
    say "========== 卸载所有 CF Tunnel 相关组件及进程 =========="
    read -rp "确认卸载所有 CF Tunnel 用户及其核心组件 (Xray/Cloudflared)？(y/N): " confirm
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && { say "已取消"; return; }
    
    say "正在停止所有 CF Tunnel 进程..."
    pkill -9 -f "${ARGO_BIN_DIR}/xray" >/dev/null 2>&1 || true
    pkill -9 -f "${ARGO_BIN_DIR}/cloudflared" >/dev/null 2>&1 || true
    pkill -9 -f "/root/agsbx/temp_node/xray_temp" >/dev/null 2>&1 || true
    pkill -9 -f "/root/agsbx/temp_node/cloudflared_temp" >/dev/null 2>&1 || true
    
    say "正在清理服务文件和自启配置..."
    if [[ -n "$_SYSTEMCTL_CMD" ]]; then
        shopt -s nullglob
        for f in /etc/systemd/system/cf-tunnel-*.service; do
          "$_SYSTEMCTL_CMD" disable --now "$(basename "$f" .service)" >/dev/null 2>&1 || true; rm -f "$f"
        done
        shopt -u nullglob
        "$_SYSTEMCTL_CMD" daemon-reload >/dev/null 2>&1 || true
    fi

    rm -f /etc/local.d/argo_*.start
    rm -rf "$ARGO_NODES_DIR"
    rm -rf "$ARGO_BIN_DIR"
    rm -rf "/root/agsbx/temp_node"
    rm -f "$ARGO_TEMP_CACHE" "$ARGO_FIXED_CACHE"
    
    if [[ -f "$META" ]]; then
        jq 'to_entries | map(select(.value.type != "argo")) | from_entries' "$META" > "${META}.tmp" && mv "${META}.tmp" "$META"
    fi
    
    crontab -l 2>/dev/null | grep -v "# agsbx-" > /tmp/crontab.tmp || true
    if [[ -s /tmp/crontab.tmp ]]; then crontab /tmp/crontab.tmp; else crontab -r >/dev/null 2>&1; fi
    rm -f /tmp/crontab.tmp
    
    ok "所有 CF Tunnel 组件及用户已彻底卸载。"; read -rp "按回车返回..." _; set -e
}

# ============= 节点导入（用于清理旧临时节点和重启服务） =============
import_argo_nodes() {
    set +e
    local imported=0
    local tmpmeta_file=$(mktemp)

    say "-> 清理旧的临时隧道元数据..."
    if [[ -f "$META" ]]; then
        jq 'to_entries | map(select(.value.type != "argo" or .value.subtype != "temp")) | from_entries' "$META" > "$tmpmeta_file"
    else
        echo "{}" > "$tmpmeta_file"
    fi
    mv "$tmpmeta_file" "$META"

    if [[ -f "$ARGO_FIXED_CACHE" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
            if [[ "$line" =~ ^(vmess|vless|trojan|ss):// ]]; then
                tag="${ARGO_META_TAG_PREFIX}Fixed-$(date +%s)"
                jq --arg t "$tag" --arg url "$line" \
                   '.[$t] = {type:"argo", subtype:"fixed", raw:$url}' "$META" > "$META.tmp" && mv "$META.tmp" "$META"
                ((imported++))
            fi
        done < "$ARGO_FIXED_CACHE"
    fi

    if [[ -f "$ARGO_TEMP_CACHE" ]]; then
        say "-> 导入新的临时隧道节点..."
        while IFS= read -r line || [[ -n "$line" ]]; do
          [[ "$line" =~ ^[[:space:]]*# ]] && continue
            if [[ "$line" =~ ^(vmess|vless|trojan|ss):// ]]; then
                tag="${ARGO_META_TAG_PREFIX}Temp-$(date +%s)"
                jq --arg t "$tag" --arg url "$line" \
                   '.[$t] = {type:"argo", subtype:"temp", raw:$url}' "$META" > "$META.tmp" && mv "$META.tmp" "$META"
                ((imported++))
                break 
            fi
        done < "$ARGO_TEMP_CACHE"
    fi

    rm -f "$tmpmeta_file" "$META.tmp"
    
    if (( imported > 0 )); then
        say "导入 $imported 个 CF Tunnel 节点，正在重启 Sing-box..."
        restart_singbox >/dev/null 2>&1
    fi
    set -e
    return 0
}

# ============= 节点查看与删除逻辑 =============
view_nodes() {
  local filter_mode="$1" 
  set +e

  local total ext_count
  if [[ "$filter_mode" == "normal" ]]; then
    total=$(jq '[.inbounds[] | select(.type=="socks" or .type=="vless")] | length' "$CONFIG" 2>/dev/null || echo "0")
    ext_count=$(jq '[to_entries[] | select(.value.type=="hysteria2")] | length' "$META" 2>/dev/null || echo "0")
  fi

  declare -A node_ports node_types node_tags node_raws node_domains node_uuids
  local idx=0

  if [[ "$filter_mode" == "normal" ]]; then
    while read -r line; do
      local tag port type
      tag=$(jq -r '.tag' <<<"$line"); port=$(jq -r '.listen_port // empty' <<<"$line"); type=$(jq -r '.type' <<<"$line")
      node_tags[$idx]="$tag"; node_ports[$idx]="${port:-未知}"; node_types[$idx]="$type"; node_raws[$idx]=""
      ((idx++))
    done < <(jq -c '.inbounds[] | select(.type=="socks" or .type=="vless")' "$CONFIG" 2>/dev/null)

    if (( ext_count > 0 )); then
      while read -r key; do
        local tag port
        tag="$key"; port=$(jq -r --arg t "$tag" '.[$t].port // "未知"' "$META")
        node_tags[$idx]="$tag"; node_ports[$idx]="$port"; node_types[$idx]="hysteria2"; node_raws[$idx]=""
        ((idx++))
      done < <(jq -r 'to_entries[] | select(.value.type=="hysteria2") | .key' "$META")
    fi
  fi

  if [[ "$filter_mode" == "argo" ]]; then
    say "正在从元数据中读取 CF Tunnel 节点..."
    while read -r key; do
        local tag raw port domain uuid subtype path
        tag="$key"; raw=$(jq -r --arg t "$tag" '.[$t].raw // empty' "$META"); subtype=$(jq -r --arg t "$tag" '.[$t].subtype // "fixed"' "$META")
        
        if [[ "$subtype" == "temp" ]]; then
            local b64_str="${raw#vmess://}"; local remainder=$(( ${#b64_str} % 4 ))
            if [[ $remainder -gt 0 ]]; then b64_str="${b64_str}$(printf '%0.s=' $(seq 1 $((4 - remainder))))"; fi
            local decoded_json=$(echo "$b64_str" | base64 -d 2>/dev/null)
            if [[ -n "$decoded_json" ]]; then
                domain=$(jq -r '.host // empty' <<<"$decoded_json"); port=$(jq -r '.port // "443"' <<<"$decoded_json")
                local ps_name=$(jq -r '.ps // empty' <<<"$decoded_json"); tag=${ps_name:-$tag}
            else
                domain="解码失败/Base64错误"; port="443"
            fi
        else
            port=$(jq -r --arg t "$tag" '.[$t].port // "443"' "$META")
            domain=$(jq -r --arg t "$tag" '.[$t].domain // empty' "$META")
        fi
        
        node_tags[$idx]="${tag}"; node_ports[$idx]="${port}"; node_types[$idx]="ARGO-${subtype^^}"; node_raws[$idx]="$raw"; node_domains[$idx]="$domain";
        ((idx++))

    done < <(jq -r 'to_entries[] | select(.value.type=="argo") | .key' "$META")
  fi

  if (( idx == 0 )); then say "当前分类下暂无节点"; unset node_tags node_ports node_types node_raws node_domains; set -e; return; fi

  local ss_tcp="" ss_udp=""
  if [[ "$filter_mode" == "normal" ]]; then ss_tcp=$(ss -ltnp 2>/dev/null || true); ss_udp=$(ss -lunp 2>/dev/null || true); fi

  echo ""; echo -e "${C_GREEN}序号  协议        端口         名称${C_RESET}"
  echo "---------------------------------------------------------"

  local -a sort_map; local k
  for ((k=0; k<idx; k++)); do
    local p_str="${node_ports[$k]}"; local p_val
    if [[ "$p_str" =~ [0-9]+ ]]; then p_val="${BASH_REMATCH[0]}"; else p_val=999999; fi
    sort_map+=("$p_val:$k")
  done

  local -a sorted_indices; IFS=$'\n' sorted_indices=($(sort -n <<<"${sort_map[*]}")); unset IFS

  local display_seq=1
  for item in "${sorted_indices[@]}"; do
    local i="${item#*:}" ; local tag="${node_tags[$i]}"; local port="${node_ports[$i]}"; local type="${node_types[$i]}"; local raw="${node_raws[$i]}"; local domain="${node_domains[$i]}"; local display_link="$raw"; local status_mark=""
    
    if [[ "$type" =~ ARGO ]]; then
      local port_num="${port}"
      if [[ "$type" == "ARGO-TEMP" ]]; then
        if pgrep -f "/root/agsbx/temp_node/cloudflared_temp" >/dev/null; then status_mark="${C_GREEN}[运行中 (临时)]${C_RESET}"; else status_mark="${C_RED}[停止/失效 (临时)]${C_RESET}"; fi
        printf "[%2d] ${C_GREEN}%-10s${C_RESET} | ${C_CYAN}%-10s${C_RESET} | ${C_CYAN}域名: %s${C_RESET} %s\n" "$display_seq" "TEMP" "443" "${domain}" "${status_mark}"
      else
        local s_name="cf-tunnel-${port_num}"
        if [[ -n "$_SYSTEMCTL_CMD" ]] && "$_SYSTEMCTL_CMD" is-active --quiet "${s_name}-cfd.service"; then status_mark="${C_GREEN}[运行中 (Systemd)]${C_RESET}";
        elif pgrep -f "cloudflared.*${port_num}" >/dev/null; then status_mark="${C_GREEN}[运行中 (Fallback)]${C_RESET}";
        else status_mark="${C_RED}[停止 (Fallback)]${C_RESET}"; fi
        printf "[%2d] ${C_GREEN}%-10s${C_RESET} | ${C_CYAN}%-10s${C_RESET} | ${C_CYAN}域名: %s${C_RESET} %s\n" "$display_seq" "FIXED" "443" "${domain}" "${status_mark}"
      fi
    else
      if [[ "$port" =~ ^[0-9]+$ ]] && ! grep -q ":$port " <<<"$ss_tcp$ss_udp" &>/dev/null; then status_mark="${C_RED}[未运行]${C_RESET}"; fi
      
      case "$type" in
        vless)
          local uuid=$(jq -r --arg t "$tag" '.inbounds[] | select(.tag==$t) | .users[0].uuid // empty' "$CONFIG")
          local pbk=$(jq -r --arg t "$tag" '.[$t].pbk // empty' "$META")
          local sid=$(jq -r --arg t "$tag" '.[$t].sid // empty' "$META")
          local sni=$(jq -r --arg t "$tag" '.[$t].sni // "www.cloudflare.com"' "$META")
          local fp=$(jq -r --arg t "$tag" '.[$t].fp // "chrome"' "$META")
          [[ -n "$uuid" && -n "$pbk" ]] && display_link="vless://${uuid}@${GLOBAL_IPV4}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&pbk=${pbk}&sid=${sid}&sni=${sni}&fp=${fp}#${tag}"
          ;;
        socks)
          local info=$(jq -r --arg t "$tag" '.inbounds[] | select(.tag==$t) | "\(.users[0].username):\(.users[0].password)"' "$CONFIG")
          local creds=$(printf "%s" "$info" | base64 -w0)
          display_link="socks://${creds}@${GLOBAL_IPV4}:${port}#${tag}"
          ;;
        hysteria2)
          local auth=$(jq -r --arg t "$tag" '.[$t].auth // empty' "$META")
          local obfs=$(jq -r --arg t "$tag" '.[$t].obfs // empty' "$META")
          local sni=$(jq -r --arg t "$tag" '.[$t].sni // "bing.com"' "$META")
          [[ -n "$auth" ]] && display_link="hysteria2://${auth}@${GLOBAL_IPV4}:${port}?obfs=salamander&obfs-password=${obfs}&sni=${sni}&insecure=1#${tag}"
          ;;
        *) display_link="[链接生成失败]";;
      esac

      printf "[%2d] ${C_GREEN}%-10s${C_RESET} | ${C_CYAN}%-10s${C_RESET} | ${C_CYAN}%s${C_RESET} %s\n" \
             "$display_seq" "${type^^}" "${port}" "${tag}" "${status_mark}"
      
    fi

    echo -e "     ${C_YELLOW}${display_link}${C_RESET}"
    echo -e "${C_RESET}---------------------------------------------------------${C_RESET}"
    
    ((display_seq++))
  done
  
  unset node_tags node_ports node_types node_raws sorted_indices sort_map node_domains
  set -e
}

view_nodes_menu() {
  while true; do
    say ""
    say "========== 查看节点 =========="
    say "1) 普通节点 (SOCKS5 / VLESS / Hysteria2)"
    say "2) 隧道节点 (Argo 临时 / 固定)"
    say "0) 返回主菜单"
    read -rp "请选择查看类型: " v_opt
    case "$v_opt" in
      1) 
        say "--- 普通节点列表 ---"
        view_nodes "normal" 
        read -rp "按回车继续..." _
        ;;
      2) 
        say "--- 隧道节点列表 ---"
        view_nodes "argo"
        read -rp "按回车继续..." _
        ;;
      0) return ;;
      *) warn "无效输入" ;;
    esac
  done
}

delete_node() {
  local total ext_count real_count
  total=$(jq '.inbounds | length' "$CONFIG" 2>/dev/null || echo "0")
  ext_count=$(jq '[to_entries[] | select(.value.type=="hysteria2")] | length' "$META" 2>/dev/null || echo "0")
  real_count=$((total + ext_count))

  if (( real_count == 0 )); then
    say "暂无本地节点可删除（Argo 节点请通过 CF 隧道管理菜单删除）"
    return
  fi

  say "================= 可删除的本地节点 =================="
  view_nodes "normal"   
  say "===================================================="
  say "提示：隧道节点（Argo）请在【1 添加节点 → 4 CF Tunnel 隧道】中管理。"
  say "===================================================="

  say "[0] 返回主菜单"
  say "[ss] 删除所有本地节点"
  read -rp "请输入要删除的本地节点序号（1-$real_count）: " idx

  [[ "$idx" == "0" || -z "$idx" ]] && return

  if [[ "$idx" == "ss" ]]; then
    read -rp "确认删除所有本地节点？(y/N): " c
    [[ "$c" != "y" && "$c" != "Y" ]] && { say "已取消"; return; }
    
    jq '.inbounds = []' "$CONFIG" > "${CONFIG}.tmp" && mv "${CONFIG}.tmp" "$CONFIG"
    
    if [[ -f "$META" ]]; then
        jq 'to_entries | map(select(.value.type == "argo")) | from_entries' "$META" > "${META}.tmp" && mv "${META}.tmp" "$META"
    else
        printf '{}' > "$META"
    fi
    
    shopt -s nullglob
    for f in /etc/systemd/system/hysteria2*.service; do
      "$(_SYSTEMCTL_CMD)" disable --now "$(basename "$f" .service)" &>/dev/null || true
      rm -f "$f"
    done
    shopt -u nullglob
    "$(_SYSTEMCTL_CMD)" daemon-reload &>/dev/null || true
    rm -rf /etc/hysteria2
    
    restart_singbox >/dev/null 2>&1
    ok "所有本地节点已删除（Argo 节点不受影响）"
    return
  fi

  if ! [[ "$idx" =~ ^[0-9]+$ ]] || (( idx < 1 || idx > real_count )); then
    warn "只能输入 1~$real_count 的序号"
    return
  fi

  local n=$((idx - 1))
  local total_internal=$(jq '[.inbounds[] | select(.type=="socks" or .type=="vless")] | length' "$CONFIG" 2>/dev/null || echo "0")


  if (( n < total_internal )); then
    # 删除 Sing-box 内部节点 (SOCKS5/VLESS)
    local tag=$(jq -r ".inbounds[$n].tag // empty" "$CONFIG")
    jq "del(.inbounds[$n])" "$CONFIG" > "${CONFIG}.tmp" && mv "${CONFIG}.tmp" "$CONFIG"
    [[ -n "$tag" && "$tag" != "null" ]] && jq "del(.\"$tag\")" "$META" > "${META}.tmp" && mv "${META}.tmp" "$META"
    restart_singbox >/dev/null 2>&1
    ok "已删除本地节点 [$idx]"
  else
    # 删除 Hysteria2 节点 (外部节点)
    n=$((n - total_internal))
    local tag=$(jq -r --argjson i "$n" 'to_entries | map(select(.value.type=="hysteria2")) | .[$i].key' "$META")
    local port=$(jq -r --arg t "$tag" '.[$t].port // empty' "$META")
    
    jq "del(.\"$tag\")" "$META" > "${META}.tmp" && mv "${META}.tmp" "$META"
    
    if [[ -n "$port" ]]; then
      if [[ -n "$_SYSTEMCTL_CMD" ]]; then
        "$(_SYSTEMCTL_CMD)" disable --now "hysteria2-${port}" &>/dev/null || true
        rm -f "/etc/systemd/system/hysteria2-${port}.service" 
      elif [[ -n "$_RCSERVICE_CMD" ]]; then
        "$(_RCSERVICE_CMD)" hysteria2-${port} stop &>/dev/null || true
        rm -f "/etc/init.d/hysteria2-${port}"
      fi
      rm -f "/etc/hysteria2/${port}".{yaml,key,crt}
    fi
    "$(_SYSTEMCTL_CMD)" daemon-reload &>/dev/null || true
    ok "已删除 Hysteria2 节点 [$idx]"
  fi
}