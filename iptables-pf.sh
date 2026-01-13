#!/usr/bin/env bash
# iptables 端口转发一键管理脚本（极简可控版）
# 设计目标：
# 1) 删除/清空只影响“本脚本管理的规则”，绝不影响系统其他 iptables 规则
# 2) 删除不会导致其他规则“失效”（通过独立自建链 + 挂钩实现）
# 3) 添加可重复（会提示已存在，但不阻止；你要重复就重复）
# 4) 删除时选一个编号，会连带删除同 dport + 同 to-destination 的 DNAT（通常 TCP/UDP 两条）以及对应 SNAT
# 5) 添加时可选择：使用内网 IP 或 公网 IP 作为 SNAT 源地址；公网可回车自动探测（ipify/ifconfig.me 兜底）
# 6) 添加/删除后自动保存，重启仍生效（自动识别 netfilter-persistent / iptables-services）

set -euo pipefail

VERSION="v2.0.0"
TITLE="iptables 端口转发一键管理脚本 [${VERSION}]"
AUTHOR="-- for XiaoYu (简化可控版) --"

# ===== 可改：默认外网网卡（通常 eth0）=====
DEFAULT_WAN_IF="eth0"

# ===== 本脚本专用链（关键：不动系统其他规则）=====
CHAIN_PRE="IPTPF_PREROUTING"
CHAIN_POST="IPTPF_POSTROUTING"

# ===== 小工具 =====
color() { local c="$1"; shift; printf "\033[%sm%s\033[0m" "$c" "$*"; }
ok()    { echo -e "$(color 32 '[OK]') $*"; }
warn()  { echo -e "$(color 33 '[WARN]') $*"; }
err()   { echo -e "$(color 31 '[ERR]') $*" >&2; }
die()   { err "$*"; exit 1; }

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "请用 root 运行：sudo -i 或 sudo bash $0"
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

pause() { read -r -p "回车继续..." _; }

trim() {
  local s="$*"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  echo -n "$s"
}

detect_wan_if() {
  # 优先用 DEFAULT_WAN_IF，其次自动探测默认路由的出口网卡
  if ip link show "$DEFAULT_WAN_IF" >/dev/null 2>&1; then
    echo "$DEFAULT_WAN_IF"
    return
  fi
  ip route show default 0.0.0.0/0 2>/dev/null | awk '/default/ {print $5; exit}' || true
}

detect_public_ip() {
  local ip=""
  # ipify
  ip="$(curl -fsSL --max-time 3 https://api.ipify.org 2>/dev/null || true)"
  ip="$(trim "$ip")"
  if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "$ip"; return 0
  fi
  # ifconfig.me
  ip="$(curl -fsSL --max-time 3 https://ifconfig.me 2>/dev/null || true)"
  ip="$(trim "$ip")"
  if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "$ip"; return 0
  fi
  return 1
}

ensure_sysctl_ip_forward() {
  sysctl -w net.ipv4.ip_forward=1 >/dev/null || true
  mkdir -p /etc/sysctl.d
  cat >/etc/sysctl.d/99-iptpf-ipforward.conf <<'EOF'
net.ipv4.ip_forward=1
EOF
  sysctl --system >/dev/null 2>&1 || true
}

# ===== 规则持久化 =====
save_rules() {
  # 优先 netfilter-persistent
  if have_cmd netfilter-persistent; then
    netfilter-persistent save >/dev/null 2>&1 || true
    ok "已保存规则（netfilter-persistent）"
    return 0
  fi
  # Debian/Ubuntu: iptables-persistent
  if [[ -d /etc/iptables ]]; then
    iptables-save > /etc/iptables/rules.v4
    ok "已保存规则（/etc/iptables/rules.v4）"
    return 0
  fi
  # RHEL系：iptables-services
  if have_cmd service && service iptables status >/dev/null 2>&1; then
    service iptables save >/dev/null 2>&1 || true
    ok "已保存规则（iptables-services）"
    return 0
  fi
  # fallback：尽量落盘一份
  mkdir -p /etc/iptables
  iptables-save > /etc/iptables/rules.v4
  warn "未检测到持久化服务，已落盘到 /etc/iptables/rules.v4（你可能需要自己设置开机恢复）"
  return 0
}

# ===== 安装依赖 =====
install_deps() {
  local os_id=""
  os_id="$(. /etc/os-release 2>/dev/null; echo "${ID:-}")" || true

  ok "启用 IP 转发..."
  ensure_sysctl_ip_forward

  # 安装 curl（探测公网IP用）
  if ! have_cmd curl; then
    warn "curl 不存在，准备安装..."
    if have_cmd apt-get; then apt-get update -y && apt-get install -y curl
    elif have_cmd dnf; then dnf install -y curl
    elif have_cmd yum; then yum install -y curl
    elif have_cmd apk; then apk add --no-cache curl
    else warn "无法自动安装 curl，请手动安装。"
    fi
  fi

  # 安装 iptables
  if ! have_cmd iptables; then
    warn "iptables 不存在，准备安装..."
    if have_cmd apt-get; then apt-get update -y && apt-get install -y iptables
    elif have_cmd dnf; then dnf install -y iptables
    elif have_cmd yum; then yum install -y iptables
    elif have_cmd apk; then apk add --no-cache iptables
    else die "无法自动安装 iptables，请手动安装。"
    fi
  fi

  # 安装持久化（尽量）
  if have_cmd apt-get; then
    # Debian/Ubuntu
    DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent netfilter-persistent >/dev/null 2>&1 || true
    systemctl enable netfilter-persistent >/dev/null 2>&1 || true
  elif have_cmd dnf || have_cmd yum; then
    # RHEL/CentOS/Alma/Rocky
    (dnf install -y iptables-services >/dev/null 2>&1 || yum install -y iptables-services >/dev/null 2>&1) || true
    systemctl enable iptables >/dev/null 2>&1 || true
    systemctl start iptables >/dev/null 2>&1 || true
  fi

  ok "依赖安装/配置完成。"
}

# ===== 专用链初始化（最关键：不动别的规则）=====
ensure_chains() {
  # 创建链（已存在则跳过）
  iptables -t nat -N "$CHAIN_PRE" 2>/dev/null || true
  iptables -t nat -N "$CHAIN_POST" 2>/dev/null || true

  # 确保挂钩存在：PREROUTING -> CHAIN_PRE
  if ! iptables -t nat -C PREROUTING -j "$CHAIN_PRE" >/dev/null 2>&1; then
    # 放到最前面，保证优先匹配
    iptables -t nat -I PREROUTING 1 -j "$CHAIN_PRE"
  fi

  # 确保挂钩存在：POSTROUTING -> CHAIN_POST
  if ! iptables -t nat -C POSTROUTING -j "$CHAIN_POST" >/dev/null 2>&1; then
    iptables -t nat -I POSTROUTING 1 -j "$CHAIN_POST"
  fi

  ok "专用链已就绪：$CHAIN_PRE / $CHAIN_POST（并已挂钩到 PREROUTING/POSTROUTING）"
}

# ===== 展示规则（按“可理解的编号”列出来）=====
list_rules() {
  ensure_chains
  echo
  echo "当前由本脚本管理的转发（来自链：$CHAIN_PRE）："
  echo "------------------------------------------------------------"
  local i=0
  # 解析：-A IPTPF_PREROUTING -p tcp -m tcp --dport 10007 -j DNAT --to-destination 1.1.1.1:1111
  iptables -t nat -S "$CHAIN_PRE" | grep -E '\-j DNAT' | while read -r line; do
    i=$((i+1))
    local proto dport toip toport
    proto="$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i=="-p"){print $(i+1); exit}}')"
    dport="$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i=="--dport"){print $(i+1); exit}}')"
    # --to-destination IP:PORT
    local to
    to="$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i ~ /--to-destination/){print $(i+1); exit}}')"
    toip="${to%:*}"; toport="${to##*:}"
    printf "%2d. 类型: %-3s  本地监听端口: %-5s  转发到: %s:%s\n" "$i" "$proto" "$dport" "$toip" "$toport"
  done

  local count
  count="$(iptables -t nat -S "$CHAIN_PRE" | grep -c '\-j DNAT' || true)"
  echo "------------------------------------------------------------"
  echo "总计：${count} 条 DNAT 规则（注意：TCP/UDP 分开计数）"
  echo
}

# ===== 添加规则 =====
read_port_or_range() {
  # 允许单端口或端口段：2333-6666
  local p="$1"
  if [[ "$p" =~ ^[0-9]{1,5}$ ]]; then
    (( p>=1 && p<=65535 )) || return 1
    return 0
  fi
  if [[ "$p" =~ ^([0-9]{1,5})-([0-9]{1,5})$ ]]; then
    local a="${BASH_REMATCH[1]}" b="${BASH_REMATCH[2]}"
    (( a>=1 && a<=65535 && b>=1 && b<=65535 && a<=b )) || return 1
    return 0
  fi
  return 1
}

add_one_rule() {
  local proto="$1" local_port="$2" remote_ip="$3" remote_port="$4" snat_ip="$5" wan_if="$6"

  # DNAT
  iptables -t nat -A "$CHAIN_PRE" -p "$proto" --dport "$local_port" -j DNAT --to-destination "${remote_ip}:${remote_port}"

  # SNAT：仅对 DNAT 连接做 SNAT（避免误伤）
  # 注意：这里 match 远端目的IP+目的端口，配合 --ctstate DNAT
  iptables -t nat -A "$CHAIN_POST" -o "$wan_if" -p "$proto" -d "$remote_ip" --dport "$remote_port" -m conntrack --ctstate DNAT -j SNAT --to-source "$snat_ip"
}

add_rules() {
  ensure_chains
  local wan_if
  wan_if="$(detect_wan_if)"
  [[ -n "$wan_if" ]] || wan_if="$DEFAULT_WAN_IF"

  echo
  read -r -p "请输入 转发目标端口(远程端口) [1-65535] (支持端口段 2333-6666): " remote_port
  remote_port="$(trim "$remote_port")"
  read_port_or_range "$remote_port" || die "远程端口格式不合法。"

  read -r -p "请输入 转发目标IP(被转发服务器IP): " remote_ip
  remote_ip="$(trim "$remote_ip")"
  [[ "$remote_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "IP 格式不合法。"

  read -r -p "请输入 本机监听端口 [1-65535] (支持端口段，默认=远程端口): " local_port
  local_port="$(trim "$local_port")"
  [[ -z "$local_port" ]] && local_port="$remote_port"
  read_port_or_range "$local_port" || die "本机监听端口格式不合法。"

  echo
  echo "请选择 SNAT 源IP："
  echo " 1) 使用内网IP（你手动输入，例如 10.83.66.46）"
  echo " 2) 使用公网IP（回车自动探测；也可手动输入）"
  read -r -p "请选择 [1-2] (默认 1): " snat_mode
  snat_mode="$(trim "$snat_mode")"
  [[ -z "$snat_mode" ]] && snat_mode="1"

  local snat_ip=""
  if [[ "$snat_mode" == "1" ]]; then
    read -r -p "请输入内网IP(用于SNAT): " snat_ip
    snat_ip="$(trim "$snat_ip")"
    [[ "$snat_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "内网IP格式不合法。"
  elif [[ "$snat_mode" == "2" ]]; then
    read -r -p "请输入公网IP(回车自动探测): " snat_ip
    snat_ip="$(trim "$snat_ip")"
    if [[ -z "$snat_ip" ]]; then
      snat_ip="$(detect_public_ip || true)"
      [[ -n "$snat_ip" ]] || die "自动探测公网IP失败，请手动输入公网IP。"
      ok "探测到公网IP：$snat_ip"
    else
      [[ "$snat_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "公网IP格式不合法。"
    fi
  else
    die "选择不合法。"
  fi

  echo
  echo "请选择转发类型："
  echo " 1) TCP"
  echo " 2) UDP"
  echo " 3) TCP+UDP"
  read -r -p "请选择 [1-3] (默认 3): " t
  t="$(trim "$t")"
  [[ -z "$t" ]] && t="3"

  # 端口段处理：local_port / remote_port 都可能是 a-b
  # 规则：端口段必须“同长度映射”，比如 2000-2005 -> 3000-3005
  # 如果只给了一个端口段，另一个不是段，则用同段（默认=远程端口时已经一致）
  local r_a r_b l_a l_b
  if [[ "$remote_port" =~ ^([0-9]{1,5})-([0-9]{1,5})$ ]]; then
    r_a="${BASH_REMATCH[1]}"; r_b="${BASH_REMATCH[2]}"
  else
    r_a="$remote_port"; r_b="$remote_port"
  fi
  if [[ "$local_port" =~ ^([0-9]{1,5})-([0-9]{1,5})$ ]]; then
    l_a="${BASH_REMATCH[1]}"; l_b="${BASH_REMATCH[2]}"
  else
    l_a="$local_port"; l_b="$local_port"
  fi

  local r_len=$((r_b - r_a))
  local l_len=$((l_b - l_a))
  [[ "$r_len" -eq "$l_len" ]] || die "端口段长度不一致：远程(${remote_port}) vs 本地(${local_port})，请保持同长度。"

  local idx=0
  local lp rp
  for ((idx=0; idx<=r_len; idx++)); do
    rp=$((r_a + idx))
    lp=$((l_a + idx))

    if [[ "$t" == "1" || "$t" == "3" ]]; then
      add_one_rule "tcp" "$lp" "$remote_ip" "$rp" "$snat_ip" "$wan_if"
    fi
    if [[ "$t" == "2" || "$t" == "3" ]]; then
      add_one_rule "udp" "$lp" "$remote_ip" "$rp" "$snat_ip" "$wan_if"
    fi

    echo "已添加：本机 ${lp}  ->  目标 ${remote_ip}:${rp}  （SNAT源IP=${snat_ip}，网卡=${wan_if}，类型=$( [[ "$t"=="1" ]] && echo TCP || ([[ "$t"=="2" ]] && echo UDP || echo TCP+UDP) ))"
  done

  save_rules
  ok "添加完成，并已保存（重启生效）。"
}

# ===== 删除规则：选编号 -> 删除同 dport + 同 to-destination 的所有 DNAT + 对应 SNAT =====
delete_rules_loop() {
  ensure_chains

  while true; do
    list_rules
    echo "输入要删除的编号（例如 63），输入 q 退出删除："
    read -r -p "> " choice
    choice="$(trim "$choice")"
    [[ -z "$choice" ]] && continue
    [[ "$choice" =~ ^[qQ]$ ]] && break
    [[ "$choice" =~ ^[0-9]+$ ]] || { warn "请输入数字编号或 q"; continue; }

    local target_line=""
    target_line="$(iptables -t nat -S "$CHAIN_PRE" | grep -E '\-j DNAT' | sed -n "${choice}p" || true)"
    [[ -n "$target_line" ]] || { warn "编号不存在：$choice"; continue; }

    local proto dport to remote_ip remote_port
    proto="$(echo "$target_line" | awk '{for(i=1;i<=NF;i++) if($i=="-p"){print $(i+1); exit}}')"
    dport="$(echo "$target_line" | awk '{for(i=1;i<=NF;i++) if($i=="--dport"){print $(i+1); exit}}')"
    to="$(echo "$target_line" | awk '{for(i=1;i<=NF;i++) if($i ~ /--to-destination/){print $(i+1); exit}}')"
    remote_ip="${to%:*}"; remote_port="${to##*:}"

    echo
    echo "将删除：协议=${proto}  本地端口=${dport}  ->  ${remote_ip}:${remote_port}"
    read -r -p "确认删除？[y/N]: " yn
    yn="$(trim "$yn")"
    [[ "$yn" =~ ^[yY]$ ]] || { warn "已取消。"; continue; }

    # 删除 DNAT：同 proto + 同 dport + 同 to-destination
    # 用 while 循环删除直到不存在（避免重复规则删不干净）
    while iptables -t nat -C "$CHAIN_PRE" -p "$proto" --dport "$dport" -j DNAT --to-destination "${remote_ip}:${remote_port}" >/dev/null 2>&1; do
      iptables -t nat -D "$CHAIN_PRE" -p "$proto" --dport "$dport" -j DNAT --to-destination "${remote_ip}:${remote_port}"
    done

    # 删除 SNAT：同 proto + 远端 ip+port + ctstate DNAT 的规则（不关心源IP）
    # 先抓出所有匹配的规则，再逐条删
    local snat_rules
    snat_rules="$(iptables -t nat -S "$CHAIN_POST" | grep -E "\-p ${proto} .* -d ${remote_ip}(/32)? .* --dport ${remote_port} .* --ctstate DNAT .* -j SNAT" || true)"
    if [[ -n "$snat_rules" ]]; then
      while read -r r; do
        [[ -z "$r" ]] && continue
        # 把 -A CHAIN_POST 替换为 -D CHAIN_POST
        iptables -t nat ${r/-A/-D} || true
      done <<< "$snat_rules"
    fi

    save_rules
    ok "删除完成，并已保存（重启生效）。"
    echo
  done
}

# ===== 清空（只清本脚本链内规则，不影响系统其他规则）=====
clear_all() {
  ensure_chains
  echo
  read -r -p "确认清空本脚本管理的全部转发规则？（只清 $CHAIN_PRE/$CHAIN_POST，不影响系统其他规则）[y/N]: " yn
  yn="$(trim "$yn")"
  [[ "$yn" =~ ^[yY]$ ]] || { warn "已取消。"; return; }

  iptables -t nat -F "$CHAIN_PRE"
  iptables -t nat -F "$CHAIN_POST"
  save_rules
  ok "已清空本脚本管理的全部转发规则，并已保存。"
}

# ===== 升级（可选：如果你是 git clone 下来的，直接 git pull）=====
upgrade_self() {
  if [[ -d .git ]] && have_cmd git; then
    git pull --rebase || true
    ok "已尝试升级（git pull）。"
  else
    warn "当前目录不是 git 仓库（或未安装 git），无法自动升级。你可以：重新 git clone 或手动覆盖脚本。"
  fi
}

# ===== 菜单 =====
menu() {
  clear || true
  echo
  echo " ${TITLE}"
  echo "  ${AUTHOR}"
  echo
  echo " 0. 升级脚本（git pull）"
  echo "————————————"
  echo " 1. 安装/初始化（iptables + 持久化 + 专用链 + 开启转发）"
  echo " 2. 清空 本脚本管理的全部端口转发"
  echo "————————————"
  echo " 3. 查看 本脚本管理的端口转发"
  echo " 4. 添加 端口转发"
  echo " 5. 删除 端口转发（循环删除，直到你退出）"
  echo "————————————"
  echo "注意：本脚本只管理专用链 ${CHAIN_PRE}/${CHAIN_POST}，不会动系统其他规则。"
  echo
}

main() {
  need_root

  while true; do
    menu
    read -r -p "请输入数字 [0-5] (q退出): " n
    n="$(trim "$n")"
    case "$n" in
      q|Q) exit 0 ;;
      0) upgrade_self; pause ;;
      1) install_deps; ensure_chains; save_rules; pause ;;
      2) clear_all; pause ;;
      3) list_rules; pause ;;
      4) add_rules; pause ;;
      5) delete_rules_loop; pause ;;
      *) warn "请输入 0-5 或 q"; sleep 1 ;;
    esac
  done
}

main "$@"
