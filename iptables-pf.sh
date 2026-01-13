#!/bin/bash
# ============================================
# iptables端口转发管理脚本 - 修复版
# GitHub: https://github.com/ylelel93/vps-iptables
# ============================================

set -euo pipefail

VERSION="v2.0.2"
CHAIN_PRE="IPTPF_PREROUTING"
CHAIN_POST="IPTPF_POSTROUTING"

# 颜色定义
Green_font_prefix="\033[32m"
Red_font_prefix="\033[31m"
Yellow_font_prefix="\033[33m"
Blue_font_prefix="\033[34m"
Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
Tip="${Yellow_font_prefix}[注意]${Font_color_suffix}"
Question="${Blue_font_prefix}[?]${Font_color_suffix}"

### ---------- 基础 ----------
require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo -e "${Error} 请使用 root 运行此脚本！"
    exit 1
  fi
}

detect_lan_ip() {
  local ip
  ip=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' 2>/dev/null || true)
  
  if [[ -z "$ip" ]]; then
    ip=$(hostname -I | awk '{print $1}' 2>/dev/null || true)
  fi
  
  echo "${ip:-未知}"
}

detect_wan_ip() {
  local ip
  ip=$(curl -s --connect-timeout 3 ifconfig.me 2>/dev/null || 
       curl -s --connect-timeout 3 api.ipify.org 2>/dev/null ||
       echo "未知")
  echo "$ip"
}

save_rules() {
  echo -e "${Tip} 正在保存规则..."
  
  # 尝试多种保存方式
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 && echo -e "${Info} 使用netfilter-persistent保存"
  elif command -v iptables-save >/dev/null 2>&1; then
    iptables-save > /etc/iptables/rules.v4 2>/dev/null && echo -e "${Info} 保存到/etc/iptables/rules.v4"
  elif command -v service >/dev/null 2>&1; then
    service iptables save >/dev/null 2>&1 && echo -e "${Info} 使用service iptables save保存"
  else
    echo -e "${Error} 无法保存规则，请手动保存"
  fi
}

### ---------- 初始化 ----------
install_and_init() {
  echo -e "${Info} ==> [1/4] 检查/安装iptables"
  
  # 检查系统类型
  if [[ -f /etc/redhat-release ]]; then
    # CentOS/RHEL
    if ! command -v iptables >/dev/null 2>&1; then
      yum install -y iptables iptables-services 2>/dev/null || true
    fi
  elif [[ -f /etc/debian_version ]]; then
    # Debian/Ubuntu
    if ! command -v iptables >/dev/null 2>&1; then
      apt-get update -y
      apt-get install -y iptables iptables-persistent 2>/dev/null || true
    fi
  else
    echo -e "${Error} 不支持的系统类型"
    exit 1
  fi
  
  echo -e "${Info} [OK] iptables已就绪"

  echo -e "${Info} ==> [2/4] 开启IPv4转发"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
  echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-iptpf.conf 2>/dev/null || true
  sysctl -p /etc/sysctl.d/99-iptpf.conf 2>/dev/null || true
  echo -e "${Info} [OK] 转发已开启并持久化"

  echo -e "${Info} ==> [3/4] 初始化专用链"
  iptables -t nat -N "$CHAIN_PRE" 2>/dev/null || true
  iptables -t nat -N "$CHAIN_POST" 2>/dev/null || true

  iptables -t nat -C PREROUTING -j "$CHAIN_PRE" 2>/dev/null || \
    iptables -t nat -A PREROUTING -j "$CHAIN_PRE"
  iptables -t nat -C POSTROUTING -j "$CHAIN_POST" 2>/dev/null || \
    iptables -t nat -A POSTROUTING -j "$CHAIN_POST"
  echo -e "${Info} [OK] 专用链已挂钩"

  echo -e "${Info} ==> [4/4] 保存规则"
  save_rules
  echo -e "${Info} ✅ 初始化/更新完成"
}

### ---------- 查看 ----------
list_rules() {
  echo -e "\n${Info} 当前转发规则："
  echo "------------------------------------------"
  local i=1
  iptables -t nat -S "$CHAIN_PRE" 2>/dev/null | grep DNAT | while read -r r; do
    proto=$(echo "$r" | grep -oE "-p (tcp|udp)" | awk '{print toupper($2)}' || echo "TCP/UDP")
    dport=$(echo "$r" | sed -n 's/.*--dport \([0-9]*\).*/\1/p')
    to=$(echo "$r" | sed -n 's/.*--to-destination \([^ ]*\).*/\1/p')
    printf "%2d. 类型: %-6s 本地端口: %-6s 转发到: %s\n" "$i" "$proto" "$dport" "$to"
    i=$((i+1))
  done
  
  if [[ $i -eq 1 ]]; then
    echo -e "${Tip} （暂无规则）"
  fi
  echo "------------------------------------------"
}

### ---------- 添加 ----------
add_rule() {
  echo -e "${Info} 添加端口转发规则"
  echo "------------------------------------------"
  
  read -rp "$(echo -e ${Question}) 转发目标端口(远程端口): " RPORT
  read -rp "$(echo -e ${Question}) 转发目标IP: " RIP
  read -rp "$(echo -e ${Question}) 本机监听端口 (回车=$RPORT): " LPORT
  [[ -z "$LPORT" ]] && LPORT="$RPORT"

  echo -e "\n${Tip} SNAT源IP："
  echo " 1) 内网IP（回车自动）"
  echo " 2) 公网IP（回车自动）"
  read -rp "$(echo -e ${Question}) 请选择 [1-2] (默认1): " MODE
  [[ -z "$MODE" ]] && MODE=1

  if [[ "$MODE" == "2" ]]; then
    read -rp "$(echo -e ${Question}) 公网IP (回车自动): " SNAT_IP
    [[ -z "$SNAT_IP" ]] && SNAT_IP=$(detect_wan_ip)
  else
    read -rp "$(echo -e ${Question}) 内网IP (回车自动): " SNAT_IP
    [[ -z "$SNAT_IP" ]] && SNAT_IP=$(detect_lan_ip)
  fi

  read -rp "$(echo -e ${Question}) 协议类型 [1 TCP / 2 UDP / 3 TCP+UDP] (默认3): " PTYPE
  [[ -z "$PTYPE" ]] && PTYPE=3

  echo -e "\n${Info} 配置摘要:"
  echo " 目标地址 : $RIP:$RPORT"
  echo " 本机监听 : $SNAT_IP:$LPORT"
  case $PTYPE in
    1) echo " 协议类型 : TCP" ;;
    2) echo " 协议类型 : UDP" ;;
    *) echo " 协议类型 : TCP + UDP" ;;
  esac

  read -rp "$(echo -e ${Question}) 确认添加？ [Y/n]: " OK
  [[ "$OK" == "n" || "$OK" == "N" ]] && echo -e "${Tip} 已取消" && return

  if [[ "$PTYPE" == "1" || "$PTYPE" == "3" ]]; then
    iptables -t nat -A "$CHAIN_PRE" -p tcp --dport "$LPORT" -j DNAT --to "$RIP:$RPORT"
    iptables -t nat -A "$CHAIN_POST" -p tcp -d "$RIP" --dport "$RPORT" -j SNAT --to-source "$SNAT_IP"
  fi
  
  if [[ "$PTYPE" == "2" || "$PTYPE" == "3" ]]; then
    iptables -t nat -A "$CHAIN_PRE" -p udp --dport "$LPORT" -j DNAT --to "$RIP:$RPORT"
    iptables -t nat -A "$CHAIN_POST" -p udp -d "$RIP" --dport "$RPORT" -j SNAT --to-source "$SNAT_IP"
  fi

  save_rules
  echo -e "${Info} ✅ 已添加并保存"
}

### ---------- 删除 ----------
delete_rule() {
  while true; do
    list_rules
    echo
    read -rp "$(echo -e ${Question}) 请输入要删除的编号 (q退出): " IDX
    [[ "$IDX" == "q" ]] && break

    RULE=$(iptables -t nat -S "$CHAIN_PRE" 2>/dev/null | grep DNAT | sed -n "${IDX}p")
    [[ -z "$RULE" ]] && echo -e "${Error} 编号无效" && continue

    DPORT=$(echo "$RULE" | sed -n 's/.*--dport \([0-9]*\).*/\1/p')
    TO=$(echo "$RULE" | sed -n 's/.*--to-destination \([^ ]*\).*/\1/p')

    echo -e "${Tip} 正在删除规则: $DPORT -> $TO"
    
    # 删除PREROUTING链中的规则
    iptables -t nat -S "$CHAIN_PRE" 2>/dev/null | grep "--dport $DPORT" | grep "$TO" | while read -r r; do
      iptables -t nat -D "$CHAIN_PRE" ${r#*-A $CHAIN_PRE }
    done
    
    # 删除POSTROUTING链中的规则
    iptables -t nat -S "$CHAIN_POST" 2>/dev/null | grep "$TO" | while read -r r; do
      iptables -t nat -D "$CHAIN_POST" ${r#*-A $CHAIN_POST }
    done

    save_rules
    echo -e "${Info} ✅ 已删除：$TO"
  done
}

### ---------- 清空 ----------
clear_all() {
  echo -e "${Warning} 警告：这将清空所有转发规则！"
  read -rp "$(echo -e ${Question}) 确认清空？ [y/N]: " CONFIRM
  [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]] && echo -e "${Tip} 已取消" && return
  
  iptables -t nat -F "$CHAIN_PRE" 2>/dev/null || true
  iptables -t nat -F "$CHAIN_POST" 2>/dev/null || true
  save_rules
  echo -e "${Info} ✅ 已清空本脚本管理的所有规则"
}

### ---------- 菜单 ----------
show_menu() {
  clear
  echo -e "=========================================="
  echo -e " iptables端口转发管理脚本 [$VERSION]"
  echo -e " GitHub: ylelel93/vps-iptables"
  echo -e "=========================================="
  echo -e " ${Green_font_prefix}1.${Font_color_suffix} 安装/初始化"
  echo -e " ${Green_font_prefix}2.${Font_color_suffix} 清空所有转发"
  echo -e " ${Green_font_prefix}3.${Font_color_suffix} 查看转发"
  echo -e " ${Green_font_prefix}4.${Font_color_suffix} 添加转发"
  echo -e " ${Green_font_prefix}5.${Font_color_suffix} 删除转发"
  echo -e " ${Green_font_prefix}6.${Font_color_suffix} 系统信息"
  echo -e " ${Green_font_prefix}7.${Font_color_suffix} 退出脚本"
  echo -e "=========================================="
}

### ---------- 系统信息 ----------
show_info() {
  echo -e "\n${Info} 系统信息："
  echo "------------------------------------------"
  echo " 内网IP: $(detect_lan_ip)"
  echo " 公网IP: $(detect_wan_ip)"
  echo " IPv4转发状态: $(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo '未知')"
  echo "------------------------------------------"
}

### ---------- 主循环 ----------
main() {
  require_root
  
  while true; do
    show_menu
    read -rp "$(echo -e ${Question}) 请选择 [1-7] (q退出): " C
    case "$C" in
      1) install_and_init ;;
      2) clear_all ;;
      3) list_rules ;;
      4) add_rule ;;
      5) delete_rule ;;
      6) show_info ;;
      7|q) echo -e "${Info} 感谢使用！"; exit 0 ;;
      *) echo -e "${Error} 无效选择";;
    esac
    
    echo -e "\n${Tip} 按回车继续..."
    read -r
  done
}

# 启动脚本
main
