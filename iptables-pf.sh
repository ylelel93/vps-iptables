#!/usr/bin/env bash
set -euo pipefail

VERSION="v2.0.1"
CHAIN_PRE="IPTPF_PREROUTING"
CHAIN_POST="IPTPF_POSTROUTING"

ensure_root() {
  [[ ${EUID:-999} -ne 0 ]] && echo "请使用 root 运行" && exit 1
}

ensure_tty() {
  [[ ! -t 0 ]] && exec </dev/tty >/dev/tty 2>/dev/tty
}

has_cmd() { command -v "$1" >/dev/null 2>&1; }

# ---------- 安装 / 初始化 ----------

init_all() {
  echo "==> 初始化 / 更新环境"

  if ! has_cmd iptables; then
    echo "[*] 安装 iptables..."
    if has_cmd apt-get; then
      apt-get update -y && apt-get install -y iptables iptables-persistent
    elif has_cmd yum; then
      yum install -y iptables iptables-services
    elif has_cmd dnf; then
      dnf install -y iptables iptables-services
    else
      echo "不支持的系统"; exit 1
    fi
  else
    echo "[OK] iptables 已存在"
  fi

  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-iptpf.conf
  sysctl --system >/dev/null 2>&1 || true

  iptables -t nat -N "$CHAIN_PRE" 2>/dev/null || true
  iptables -t nat -N "$CHAIN_POST" 2>/dev/null || true
  iptables -t nat -C PREROUTING -j "$CHAIN_PRE" 2>/dev/null || iptables -t nat -A PREROUTING -j "$CHAIN_PRE"
  iptables -t nat -C POSTROUTING -j "$CHAIN_POST" 2>/dev/null || iptables -t nat -A POSTROUTING -j "$CHAIN_POST"

  has_cmd netfilter-persistent && netfilter-persistent save >/dev/null 2>&1 || true

  echo "✅ 初始化 / 更新完成（iptables / 转发 / 专用链 已确认）"
}

# ---------- 查看规则（极简输出） ----------

list_rules() {
  echo
  local i=1
  iptables -t nat -S "$CHAIN_PRE" | grep -- '-A' | while read -r r; do
    proto=$(echo "$r" | grep -oP '-p \K(tcp|udp)')
    dport=$(echo "$r" | grep -oP '--dport \K[0-9]+')
    to=$(echo "$r" | grep -oP '--to-destination \K[^ ]+')
    echo "$i. 类型: $proto  本地监听端口: $dport  转发到: $to"
    i=$((i+1))
  done
}

# ---------- 添加规则 ----------

detect_lan_ip() { ip route get 1.1.1.1 | awk '/src/ {print $NF}'; }
detect_wan_ip() { curl -s ifconfig.me || curl -s api.ipify.org; }

add_rule() {
  read -rp "转发目标端口(远程端口): " RPORT
  read -rp "转发目标IP: " RIP
  read -rp "本机监听端口 (回车默认=$RPORT): " LPORT
  [[ -z "$LPORT" ]] && LPORT="$RPORT"

  echo "1) 内网IP  2) 公网IP"
  read -rp "SNAT 源IP选择 [1-2] (默认1): " MODE
  [[ -z "$MODE" ]] && MODE=1

  if [[ "$MODE" == "2" ]]; then
    auto=$(detect_wan_ip)
  else
    auto=$(detect_lan_ip)
  fi
  read -rp "SNAT IP (回车默认=$auto): " SNAT
  [[ -z "$SNAT" ]] && SNAT="$auto"

  read -rp "协议 1)TCP 2)UDP 3)TCP+UDP (默认3): " P
  [[ -z "$P" ]] && P=3

  echo
  echo "目标地址 : $RIP:$RPORT"
  echo "本机     : $SNAT:$LPORT"
  echo "协议类型 : $([[ "$P" == 1 ]] && echo TCP || [[ "$P" == 2 ]] && echo UDP || echo TCP+UDP)"
  read -rp "确认添加？ [Y/n]: " OK
  [[ "$OK" == "n" || "$OK" == "N" ]] && return

  [[ "$P" == 1 || "$P" == 3 ]] && {
    iptables -t nat -A "$CHAIN_PRE" -p tcp --dport "$LPORT" -j DNAT --to "$RIP:$RPORT"
    iptables -t nat -A "$CHAIN_POST" -p tcp -d "$RIP" --dport "$RPORT" -j SNAT --to-source "$SNAT"
  }
  [[ "$P" == 2 || "$P" == 3 ]] && {
    iptables -t nat -A "$CHAIN_PRE" -p udp --dport "$LPORT" -j DNAT --to "$RIP:$RPORT"
    iptables -t nat -A "$CHAIN_POST" -p udp -d "$RIP" --dport "$RPORT" -j SNAT --to-source "$SNAT"
  }

  has_cmd netfilter-persistent && netfilter-persistent save >/dev/null 2>&1 || true
  echo "✅ 添加完成并已保存"
}

# ---------- 删除规则（单条删除，循环） ----------

delete_rules_loop() {
  while true; do
    list_rules
    read -rp "请输入要删除的编号 (q退出): " IDX
    [[ "$IDX" == "q" ]] && break

    RULE=$(iptables -t nat -S "$CHAIN_PRE" | grep -- '-A' | sed -n "${IDX}p")
    [[ -z "$RULE" ]] && echo "编号无效" && continue

    iptables -t nat -D "$CHAIN_PRE" ${RULE#*-A $CHAIN_PRE }

    proto=$(echo "$RULE" | grep -oP '-p \K(tcp|udp)')
    dport=$(echo "$RULE" | grep -oP '--dport \K[0-9]+')
    to=$(echo "$RULE" | grep -oP '--to-destination \K[^ ]+')

    POST=$(iptables -t nat -S "$CHAIN_POST" | grep "$to" | grep "$proto" | head -n1 || true)
    [[ -n "$POST" ]] && iptables -t nat -D "$CHAIN_POST" ${POST#*-A $CHAIN_POST }

    has_cmd netfilter-persistent && netfilter-persistent save >/dev/null 2>&1 || true
    echo "✅ 已删除：$proto $dport -> $to"
  done
}

clear_all() {
  iptables -t nat -F "$CHAIN_PRE"
  iptables -t nat -F "$CHAIN_POST"
  has_cmd netfilter-persistent && netfilter-persistent save >/dev/null 2>&1 || true
  echo "✅ 已清空本脚本管理的所有规则"
}

menu() {
  echo
  echo " iptables 端口转发一键管理脚本 [$VERSION]"
  echo " 0. 升级脚本（git pull）"
  echo "————————————"
  echo " 1. 安装/初始化（iptables + 持久化 + 专用链 + 开启转发）"
  echo " 2. 清空 本脚本管理的全部端口转发"
  echo "————————————"
  echo " 3. 查看 本脚本管理的端口转发"
  echo " 4. 添加 端口转发"
  echo " 5. 删除 端口转发（循环删除，直到你退出）"
  echo "————————————"
}

main() {
  ensure_root
  ensure_tty
  while true; do
    menu
    read -rp "请输入数字 [0-5] (q退出): " C
    case "$C" in
      1) init_all ;;
      2) clear_all ;;
      3) list_rules ;;
      4) add_rule ;;
      5) delete_rules_loop ;;
      q) exit 0 ;;
    esac
  done
}

main
