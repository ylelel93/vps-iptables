#!/usr/bin/env bash
set -e

CHAIN_PRE="IPTPF_PREROUTING"
CHAIN_POST="IPTPF_POSTROUTING"

ensure_root() {
  [[ $EUID -ne 0 ]] && echo "请使用 root 运行" && exit 1
}

ensure_iptables() {
  if ! command -v iptables >/dev/null 2>&1; then
    echo "[*] 安装 iptables..."
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update -y
      apt-get install -y iptables iptables-persistent
    elif command -v yum >/dev/null 2>&1; then
      yum install -y iptables-services
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y iptables-services
    else
      echo "不支持的系统"
      exit 1
    fi
  fi
}

ensure_chains() {
  iptables -t nat -N $CHAIN_PRE 2>/dev/null || true
  iptables -t nat -N $CHAIN_POST 2>/dev/null || true

  iptables -t nat -C PREROUTING -j $CHAIN_PRE 2>/dev/null || \
    iptables -t nat -A PREROUTING -j $CHAIN_PRE

  iptables -t nat -C POSTROUTING -j $CHAIN_POST 2>/dev/null || \
    iptables -t nat -A POSTROUTING -j $CHAIN_POST
}

detect_lan_ip() {
  ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}'
}

detect_wan_ip() {
  curl -s ifconfig.me || curl -s api.ipify.org
}

save_rules() {
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1
  elif command -v service >/dev/null 2>&1; then
    service iptables save >/dev/null 2>&1 || true
  fi
}

add_rule() {
  ensure_chains

  read -rp "请输入 转发目标端口(远程端口): " RPORT
  read -rp "请输入 转发目标IP: " RIP
  read -rp "请输入 本机监听端口 (回车默认=$RPORT): " LPORT
  [[ -z "$LPORT" ]] && LPORT="$RPORT"

  echo
  echo "SNAT 源IP："
  echo " 1) 内网IP（回车自动检测）"
  echo " 2) 公网IP（回车自动检测）"
  read -rp "请选择 [1-2] (默认 1): " MODE
  [[ -z "$MODE" ]] && MODE=1

  if [[ "$MODE" == "2" ]]; then
    read -rp "请输入公网IP (回车自动): " SNAT_IP
    [[ -z "$SNAT_IP" ]] && SNAT_IP=$(detect_wan_ip)
  else
    read -rp "请输入内网IP (回车自动): " SNAT_IP
    [[ -z "$SNAT_IP" ]] && SNAT_IP=$(detect_lan_ip)
  fi

  echo
  echo "协议类型："
  echo " 1) TCP"
  echo " 2) UDP"
  echo " 3) TCP + UDP"
  read -rp "请选择 [1-3] (默认 3): " PTYPE
  [[ -z "$PTYPE" ]] && PTYPE=3

  echo
  echo "目标地址 : $RIP:$RPORT"
  echo "本机     : $SNAT_IP:$LPORT"
  case $PTYPE in
    1) echo "协议类型 : TCP" ;;
    2) echo "协议类型 : UDP" ;;
    3) echo "协议类型 : TCP + UDP" ;;
  esac
  echo
  read -rp "确认添加？ [y/N]: " OK
  [[ "$OK" != "y" && "$OK" != "Y" ]] && return

  [[ "$PTYPE" == "1" || "$PTYPE" == "3" ]] && {
    iptables -t nat -A $CHAIN_PRE  -p tcp --dport $LPORT -j DNAT --to $RIP:$RPORT
    iptables -t nat -A $CHAIN_POST -p tcp -d $RIP --dport $RPORT -j SNAT --to-source $SNAT_IP
  }

  [[ "$PTYPE" == "2" || "$PTYPE" == "3" ]] && {
    iptables -t nat -A $CHAIN_PRE  -p udp --dport $LPORT -j DNAT --to $RIP:$RPORT
    iptables -t nat -A $CHAIN_POST -p udp -d $RIP --dport $RPORT -j SNAT --to-source $SNAT_IP
  }

  save_rules
  echo "[OK] 添加完成（已保存）"
}

list_rules() {
  iptables -t nat -L $CHAIN_PRE -n --line-numbers
}

delete_rules() {
  while true; do
    echo
    iptables -t nat -L $CHAIN_PRE -n --line-numbers
    echo
    read -rp "请输入要删除的编号 (q退出): " IDX
    [[ "$IDX" == "q" ]] && break

    RULE=$(iptables -t nat -S $CHAIN_PRE | sed -n "${IDX}p")
    [[ -z "$RULE" ]] && continue

    DPORT=$(echo "$RULE" | sed -n 's/.*--dport \([0-9]*\).*/\1/p')
    TO=$(echo "$RULE" | sed -n 's/.*--to-destination \([^ ]*\).*/\1/p')

    iptables -t nat -S $CHAIN_PRE | grep -- "--dport $DPORT" | grep "$TO" | while read -r r; do
      iptables -t nat -D $CHAIN_PRE ${r#*-A $CHAIN_PRE }
    done

    iptables -t nat -S $CHAIN_POST | grep "$TO" | while read -r r; do
      iptables -t nat -D $CHAIN_POST ${r#*-A $CHAIN_POST }
    done

    save_rules
    echo "[OK] 已删除：$TO (端口 $DPORT)"
  done
}

clear_all() {
  iptables -t nat -F $CHAIN_PRE || true
  iptables -t nat -F $CHAIN_POST || true
  save_rules
  echo "[OK] 已清空专用链规则"
}

menu() {
  echo
  echo "iptables 端口转发管理脚本"
  echo "----------------------------"
  echo "1. 安装 iptables"
  echo "2. 清空所有转发规则"
  echo "3. 查看转发规则"
  echo "4. 添加端口转发"
  echo "5. 删除端口转发"
  echo "q. 退出"
  echo
}

main() {
  ensure_root
  while true; do
    menu
    read -rp "请选择: " C
    case "$C" in
      1) ensure_iptables ;;
      2) clear_all ;;
      3) list_rules ;;
      4) add_rule ;;
      5) delete_rules ;;
      q) exit 0 ;;
    esac
  done
}

main
