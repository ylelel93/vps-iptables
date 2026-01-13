#!/usr/bin/env bash
set -euo pipefail

VERSION="v2.0.0"
CHAIN_PRE="IPTPF_PREROUTING"
CHAIN_POST="IPTPF_POSTROUTING"

# ---------------- 基础保障 ----------------

ensure_root() {
  if [[ ${EUID:-999} -ne 0 ]]; then
    echo "❌ 请使用 root 运行"
    exit 1
  fi
}

# 防止 curl | bash / 非交互导致 read 没反应
ensure_tty() {
  if [[ ! -t 0 ]]; then
    exec </dev/tty >/dev/tty 2>/dev/tty
  fi
}

has_cmd() { command -v "$1" >/dev/null 2>&1; }

# ---------------- 系统识别 ----------------

is_debian_like() { has_cmd apt-get; }
is_rhel_like() { has_cmd yum || has_cmd dnf; }

# ---------------- 安装/初始化相关 ----------------

install_iptables_and_persist() {
  echo "==> [1/4] 检查/安装 iptables & 持久化组件"

  if has_cmd iptables; then
    echo "[OK] iptables 已存在：$(iptables --version 2>/dev/null || true)"
  else
    echo "[*] 未检测到 iptables，开始安装..."
    if is_debian_like; then
      apt-get update -y
      apt-get install -y iptables
    elif has_cmd yum; then
      yum install -y iptables
    elif has_cmd dnf; then
      dnf install -y iptables
    else
      echo "❌ 不支持的系统（找不到 apt/yum/dnf）"
      exit 1
    fi
    echo "[OK] iptables 安装完成"
  fi

  # 持久化：Debian/Ubuntu 用 netfilter-persistent；RHEL 系用 iptables-services
  if is_debian_like; then
    if has_cmd netfilter-persistent; then
      echo "[OK] netfilter-persistent 已存在"
    else
      echo "[*] 安装 netfilter-persistent..."
      apt-get install -y iptables-persistent netfilter-persistent
      echo "[OK] netfilter-persistent 安装完成"
    fi
    systemctl enable netfilter-persistent >/dev/null 2>&1 || true
    systemctl enable netfilter-persistent.service >/dev/null 2>&1 || true
    echo "[OK] 已启用 netfilter-persistent 开机加载"
  else
    # RHEL-like
    if systemctl list-unit-files 2>/dev/null | grep -q '^iptables\.service'; then
      echo "[OK] iptables.service 已存在"
    else
      echo "[*] 尝试安装 iptables-services..."
      if has_cmd yum; then yum install -y iptables-services; fi
      if has_cmd dnf; then dnf install -y iptables-services; fi
      echo "[OK] iptables-services 处理完成（若仓库不含也不致命）"
    fi
    systemctl enable iptables >/dev/null 2>&1 || true
    echo "[OK] 已尝试启用 iptables.service 开机加载"
  fi
}

enable_ip_forward_persist() {
  echo "==> [2/4] 开启 IPv4 转发（ip_forward）并持久化"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  echo "[OK] 已开启：net.ipv4.ip_forward=1（当前即时生效）"

  local conf="/etc/sysctl.d/99-iptpf.conf"
  if [[ -f "$conf" ]]; then
    # 确保存在那一行
    if grep -q '^net\.ipv4\.ip_forward=1' "$conf"; then
      echo "[OK] 持久化已存在：$conf"
    else
      echo "net.ipv4.ip_forward=1" >> "$conf"
      echo "[OK] 已写入持久化：$conf"
    fi
  else
    echo "net.ipv4.ip_forward=1" > "$conf"
    echo "[OK] 已创建持久化：$conf"
  fi

  sysctl --system >/dev/null 2>&1 || true
}

ensure_chains_and_hooks() {
  echo "==> [3/4] 初始化专用链 + 挂钩（不碰系统其他规则）"

  iptables -t nat -N "$CHAIN_PRE" 2>/dev/null || true
  iptables -t nat -N "$CHAIN_POST" 2>/dev/null || true

  # 确保挂钩存在（只添加一次）
  iptables -t nat -C PREROUTING -j "$CHAIN_PRE" 2>/dev/null || \
    iptables -t nat -A PREROUTING -j "$CHAIN_PRE"

  iptables -t nat -C POSTROUTING -j "$CHAIN_POST" 2>/dev/null || \
    iptables -t nat -A POSTROUTING -j "$CHAIN_POST"

  echo "[OK] 专用链就绪：$CHAIN_PRE / $CHAIN_POST（已挂钩到 PREROUTING/POSTROUTING）"
}

save_rules_persist() {
  echo "==> [4/4] 保存规则（重启生效）"
  if has_cmd netfilter-persistent; then
    netfilter-persistent save >/dev/null 2>&1 || true
    echo "[OK] 已保存（netfilter-persistent）"
  elif has_cmd service; then
    service iptables save >/dev/null 2>&1 || true
    echo "[OK] 已保存（service iptables save）"
  else
    echo "[WARN] 未找到持久化保存命令（但当前规则已生效）"
  fi
}

init_all() {
  install_iptables_and_persist
  enable_ip_forward_persist
  ensure_chains_and_hooks
  save_rules_persist
  echo "✅ 初始化完成：iptables/持久化/专用链/转发 已就绪"
}

# ---------------- IP 探测 ----------------

detect_lan_ip() {
  ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}'
}

detect_wan_ip() {
  # 两个兜底，5 秒超时
  curl -s --max-time 5 ifconfig.me || curl -s --max-time 5 api.ipify.org
}

# ---------------- 规则管理（只动专用链） ----------------

add_rule() {
  ensure_chains_and_hooks

  read -rp "转发目标端口(远程端口) [1-65535] (支持端口段 2333-6666): " RPORT
  read -rp "转发目标IP(被转发服务器IP): " RIP
  read -rp "本机监听端口 [1-65535] (回车默认=$RPORT): " LPORT
  [[ -z "${LPORT}" ]] && LPORT="$RPORT"

  # SNAT 源IP：你要“自动检测 + 也可手动填”，并且要“确认输出简洁”
  echo
  echo "SNAT 源IP选择："
  echo " 1) 内网IP（回车自动检测）"
  echo " 2) 公网IP（回车自动检测）"
  read -rp "请选择 [1-2] (默认 1): " MODE
  [[ -z "${MODE}" ]] && MODE="1"

  local SNAT_IP=""
  if [[ "$MODE" == "2" ]]; then
    local auto_wan
    auto_wan="$(detect_wan_ip || true)"
    read -rp "公网IP (回车自动=${auto_wan}): " SNAT_IP
    [[ -z "${SNAT_IP}" ]] && SNAT_IP="${auto_wan}"
  else
    local auto_lan
    auto_lan="$(detect_lan_ip || true)"
    read -rp "内网IP (回车自动=${auto_lan}): " SNAT_IP
    [[ -z "${SNAT_IP}" ]] && SNAT_IP="${auto_lan}"
  fi

  if [[ -z "${SNAT_IP}" ]]; then
    echo "❌ 未获取到 SNAT 源IP（你可以手动输入一个）"
    return
  fi

  echo
  echo "协议类型："
  echo " 1) TCP"
  echo " 2) UDP"
  echo " 3) TCP + UDP"
  read -rp "请选择 [1-3] (默认 3): " PTYPE
  [[ -z "${PTYPE}" ]] && PTYPE="3"

  # 你要的极简确认输出
  echo
  echo "目标地址 : ${RIP}:${RPORT}"
  echo "本机     : ${SNAT_IP}:${LPORT}"
  case "$PTYPE" in
    1) echo "协议类型 : TCP" ;;
    2) echo "协议类型 : UDP" ;;
    *) echo "协议类型 : TCP + UDP" ;;
  esac
  read -rp "确认添加？ [y/N]: " OK
  [[ "${OK}" != "y" && "${OK}" != "Y" ]] && return

  # 添加：允许重复（不做去重），你说你会人工维护
  if [[ "$PTYPE" == "1" || "$PTYPE" == "3" ]]; then
    iptables -t nat -A "$CHAIN_PRE"  -p tcp --dport "$LPORT" -j DNAT --to-destination "$RIP:$RPORT"
    iptables -t nat -A "$CHAIN_POST" -p tcp -d "$RIP" --dport "$RPORT" -j SNAT --to-source "$SNAT_IP"
  fi
  if [[ "$PTYPE" == "2" || "$PTYPE" == "3" ]]; then
    iptables -t nat -A "$CHAIN_PRE"  -p udp --dport "$LPORT" -j DNAT --to-destination "$RIP:$RPORT"
    iptables -t nat -A "$CHAIN_POST" -p udp -d "$RIP" --dport "$RPORT" -j SNAT --to-source "$SNAT_IP"
  fi

  save_rules_persist
  echo "✅ 已添加并保存（重启生效）"
}

list_rules() {
  ensure_chains_and_hooks
  echo
  echo "当前规则（仅本脚本专用链）："
  # 用 -S 更像你原脚本那种“类型/端口/IP:port”的感觉
  iptables -t nat -S "$CHAIN_PRE" | nl -ba
}

# 删除：循环删除直到你退出；选择一个编号 -> 联动删同 dport + 同 to-destination 的 DNAT
delete_rules_loop() {
  ensure_chains_and_hooks

  while true; do
    echo
    echo "当前规则（仅本脚本专用链）："
    iptables -t nat -S "$CHAIN_PRE" | nl -ba

    echo
    read -rp "请输入要删除的编号 (q退出): " IDX
    [[ "$IDX" == "q" ]] && break
    [[ -z "$IDX" ]] && continue

    # 取第 IDX 行（注意：nl 从 1 开始）
    local RULE
    RULE="$(iptables -t nat -S "$CHAIN_PRE" | sed -n "${IDX}p")" || true
    if [[ -z "${RULE}" ]]; then
      echo "[WARN] 编号无效"
      continue
    fi

    # 提取 dport / to-destination
    local DPORT TO
    DPORT="$(echo "$RULE" | sed -n 's/.*--dport \([0-9]\+\).*/\1/p')" || true
    TO="$(echo "$RULE" | sed -n 's/.*--to-destination \([^ ]\+\).*/\1/p')" || true

    if [[ -z "${DPORT}" || -z "${TO}" ]]; then
      echo "[WARN] 解析失败，跳过"
      continue
    fi

    # 1) 删除所有同 dport + 同 to-destination 的 DNAT（通常 tcp/udp 两条）
    iptables -t nat -S "$CHAIN_PRE" | grep -- "--dport ${DPORT}" | grep "$TO" | while read -r r; do
      iptables -t nat -D "$CHAIN_PRE" ${r#*-A $CHAIN_PRE }
    done

    # 2) 删除对应 POSTROUTING 中所有指向该 TO 的 SNAT（tcp/udp 两条）
    iptables -t nat -S "$CHAIN_POST" | grep "$TO" | while read -r r; do
      iptables -t nat -D "$CHAIN_POST" ${r#*-A $CHAIN_POST }
    done

    save_rules_persist
    echo "✅ 已删除：$TO（dport=$DPORT）"
  done
}

clear_all() {
  ensure_chains_and_hooks
  iptables -t nat -F "$CHAIN_PRE" || true
  iptables -t nat -F "$CHAIN_POST" || true
  save_rules_persist
  echo "✅ 已清空：本脚本管理的全部转发规则（仅专用链，不影响系统其他规则）"
}

# ---------------- 升级（git pull） ----------------

upgrade_via_git_pull() {
  echo "==> 升级脚本（git pull）"
  if has_cmd git && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "[*] 检测到 git 仓库，执行 git pull..."
    git pull --rebase || git pull
    echo "[OK] git pull 完成。建议你重新运行脚本以加载最新版本。"
  else
    echo "[WARN] 当前目录不是 git 仓库，无法 git pull。"
    echo "      你可以用“curl 下载并运行”的一键命令重新拉取最新脚本。"
  fi
}

# ---------------- UI 菜单 ----------------

menu() {
  echo
  echo " iptables 端口转发一键管理脚本 [${VERSION}]"
  echo "  -- for XiaoYu (简化可控版) --"
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
  echo
}

main() {
  ensure_root
  ensure_tty

  while true; do
    menu
    read -rp "请输入数字 [0-5] (q退出): " C || true
    case "${C:-}" in
      0) upgrade_via_git_pull ;;
      1) init_all ;;
      2) clear_all ;;
      3) list_rules ;;
      4) add_rule ;;
      5) delete_rules_loop ;;
      q) exit 0 ;;
      *) echo "[WARN] 无效输入" ;;
    esac
  done
}

main
