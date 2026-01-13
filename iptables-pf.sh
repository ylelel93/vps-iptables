#!/usr/bin/env bash
set -e

VERSION="v2.0.4-fixed"
CHAIN_PRE="IPTPF_PREROUTING"
CHAIN_POST="IPTPF_POSTROUTING"

### ---------- 基础 ----------
require_root() {
  [[ $EUID -ne 0 ]] && echo "请使用 root 运行" && exit 1
}

detect_lan_ip() {
  ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || echo "127.0.0.1"
}

detect_wan_ip() {
  curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || curl -s --connect-timeout 5 api.ipify.org 2>/dev/null || echo "0.0.0.0"
}

save_rules() {
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1
  elif command -v service >/dev/null 2>&1; then
    service iptables save >/dev/null 2>&1 || true
  fi
}

### ---------- 检查是否已安装 ----------
check_installed() {
  iptables -t nat -L $CHAIN_PRE >/dev/null 2>&1 && return 0
  return 1
}

### ---------- 初始化 ----------
install_and_init() {
  echo "==> [1/4] 检查 / 安装 iptables"
  if ! command -v iptables >/dev/null 2>&1; then
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
  echo "[OK] iptables 已就绪"

  echo "==> [2/4] 开启 IPv4 转发"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-iptpf.conf
  echo "[OK] 转发已开启并持久化"

  echo "==> [3/4] 初始化专用链（不影响系统其它规则）"
  iptables -t nat -N $CHAIN_PRE 2>/dev/null || true
  iptables -t nat -N $CHAIN_POST 2>/dev/null || true

  iptables -t nat -C PREROUTING -j $CHAIN_PRE 2>/dev/null || \
    iptables -t nat -A PREROUTING -j $CHAIN_PRE
  iptables -t nat -C POSTROUTING -j $CHAIN_POST 2>/dev/null || \
    iptables -t nat -A POSTROUTING -j $CHAIN_POST
  echo "[OK] 专用链已挂钩"

  echo "==> [4/4] 保存规则"
  save_rules
  echo "✅ 初始化 / 更新完成"
}

### ---------- 查看 ----------
list_rules() {
  echo
  echo "当前转发规则："
  echo "------------------------------------------"
  local i=1
  iptables -t nat -S $CHAIN_PRE | grep DNAT | while read -r r; do
    proto=$(echo "$r" | grep -oE "-p (tcp|udp)" | awk '{print toupper($2)}')
    dport=$(echo "$r" | sed -n 's/.*--dport \([0-9]*\).*/\1/p')
    to=$(echo "$r" | sed -n 's/.*--to-destination \([^ ]*\).*/\1/p')
    printf "%2d. 类型: %-4s 本地端口: %-6s 转发到: %s\n" "$i" "$proto" "$dport" "$to"
    i=$((i+1))
  done
  [[ $i -eq 1 ]] && echo "（暂无规则）"
}

### ---------- 添加 ----------
add_rule() {
  read -rp "转发目标端口(远程端口): " RPORT
  read -rp "转发目标IP: " RIP
  read -rp "本机监听端口 (回车=$RPORT): " LPORT
  [[ -z "$LPORT" ]] && LPORT="$RPORT"

  echo "SNAT 源IP："
  echo " 1) 内网IP（回车自动）"
  echo " 2) 公网IP（回车自动）"
  read -rp "请选择 [1-2] (默认1): " MODE
  [[ -z "$MODE" ]] && MODE=1

  if [[ "$MODE" == "2" ]]; then
    read -rp "公网IP (回车自动): " SNAT_IP
    [[ -z "$SNAT_IP" ]] && SNAT_IP=$(detect_wan_ip)
  else
    read -rp "内网IP (回车自动): " SNAT_IP
    [[ -z "$SNAT_IP" ]] && SNAT_IP=$(detect_lan_ip)
  fi

  read -rp "协议类型 [1 TCP / 2 UDP / 3 TCP+UDP] (默认3): " PTYPE
  [[ -z "$PTYPE" ]] && PTYPE=3

  echo
  echo "目标地址 : $RIP:$RPORT"
  echo "本机     : $SNAT_IP:$LPORT"
  case $PTYPE in
    1) echo "协议类型 : TCP" ;;
    2) echo "协议类型 : UDP" ;;
    *) echo "协议类型 : TCP + UDP" ;;
  esac

  read -rp "确认添加？ [Y/n]: " OK
  [[ "$OK" == "n" || "$OK" == "N" ]] && return

  [[ "$PTYPE" == "1" || "$PTYPE" == "3" ]] && {
    iptables -t nat -A $CHAIN_PRE -p tcp --dport $LPORT -j DNAT --to $RIP:$RPORT
    iptables -t nat -A $CHAIN_POST -p tcp -d $RIP --dport $RPORT -j SNAT --to-source $SNAT_IP
  }
  [[ "$PTYPE" == "2" || "$PTYPE" == "3" ]] && {
    iptables -t nat -A $CHAIN_PRE -p udp --dport $LPORT -j DNAT --to $RIP:$RPORT
    iptables -t nat -A $CHAIN_POST -p udp -d $RIP --dport $RPORT -j SNAT --to-source $SNAT_IP
  }

  save_rules
  echo "✅ 已添加并保存"
}

### ---------- 删除 ----------
delete_rule() {
  while true; do
    list_rules
    echo
    read -rp "请输入要删除的编号 (q退出): " IDX
    [[ "$IDX" == "q" ]] && break

    RULE=$(iptables -t nat -S $CHAIN_PRE | grep DNAT | sed -n "${IDX}p")
    [[ -z "$RULE" ]] && continue

    DPORT=$(echo "$RULE" | sed -n 's/.*--dport \([0-9]*\).*/\1/p')
    TO=$(echo "$RULE" | sed -n 's/.*--to-destination \([^ ]*\).*/\1/p')

    iptables -t nat -S $CHAIN_PRE | grep "--dport $DPORT" | grep "$TO" | while read -r r; do
      iptables -t nat -D $CHAIN_PRE ${r#*-A $CHAIN_PRE }
    done
    iptables -t nat -S $CHAIN_POST | grep "$TO" | while read -r r; do
      iptables -t nat -D $CHAIN_POST ${r#*-A $CHAIN_POST }
    done

    save_rules
    echo "✅ 已删除：$TO"
  done
}

### ---------- 清空 ----------
clear_all() {
  iptables -t nat -F $CHAIN_PRE || true
  iptables -t nat -F $CHAIN_POST || true
  save_rules
  echo "✅ 已清空本脚本管理的所有规则"
}

### ---------- 显示菜单 ----------
show_menu() {
  clear 2>/dev/null || echo -e "\n\n"
  echo
  echo "iptables 端口转发一键管理脚本 [$VERSION]"
  echo " -- for XiaoYu (简化可控版) --"
  echo
  echo "0. 升级脚本（重新下载并覆盖）"
  echo "————————————"
  echo "1. 安装 / 初始化"
  echo "2. 清空 所有转发"
  echo "————————————"
  echo "3. 查看 转发"
  echo "4. 添加 转发"
  echo "5. 删除 转发（循环）"
  echo "————————————"
  echo "q. 退出"
  echo
}

### ---------- 主循环 ----------
main() {
  require_root
  
  # 检查是否已安装
  if check_installed; then
    echo "✅ 检测到已安装，直接进入管理界面..."
    sleep 1
  else
    echo "⚠️  检测到未安装，需要先初始化..."
    echo "是否现在安装初始化？ [Y/n]"
    read -rp "> " answer
    if [[ "$answer" != "n" && "$answer" != "N" ]]; then
      install_and_init
      echo "✅ 安装完成，进入管理界面..."
      sleep 1
    else
      echo "取消安装，退出脚本"
      exit 0
    fi
  fi
  
  # 主菜单循环
  while true; do
    show_menu
    read -rp "请选择 [0-5] (q退出): " C
    case "$C" in
      0) echo "请使用原安装链接重新执行以升级"; read -rp "按回车继续...";;
      1) install_and_init ;;
      2) clear_all ;;
      3) list_rules; read -rp "按回车返回菜单...";;
      4) add_rule ;;
      5) delete_rule ;;
      q) echo "再见！"; exit 0 ;;
      *) echo "无效选项，请重新选择"; sleep 1 ;;
    esac
  done
}

### ---------- 脚本入口 ----------
# 强制设置脚本为交互模式
if [[ -t 0 ]]; then
  # 有终端，直接运行
  main
else
  # 没有终端（比如通过 bash <(...) 运行）
  # 先保存到临时文件，然后用 bash 执行
  SCRIPT_URL="https://raw.githubusercontent.com/ylelel93/vps-iptables/main/iptables-pf.sh"
  TEMP_FILE="/tmp/iptables-pf-$(date +%s).sh"
  
  echo "正在准备交互式环境..."
  
  # 下载脚本到临时文件
  if command -v wget >/dev/null 2>&1; then
    wget --no-check-certificate -q "$SCRIPT_URL" -O "$TEMP_FILE"
  elif command -v curl >/dev/null 2>&1; then
    curl -kfsSL "$SCRIPT_URL" -o "$TEMP_FILE"
  else
    echo "错误：需要 wget 或 curl 下载脚本"
    exit 1
  fi
  
  # 使脚本可执行并运行
  chmod +x "$TEMP_FILE"
  
  # 用 exec 替换当前进程，保持交互性
  exec bash "$TEMP_FILE"
fi
