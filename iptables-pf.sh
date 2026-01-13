#!/usr/bin/env bash
set -e

VERSION="v2.0.7-interactive"
CHAIN_PRE="IPTPF_PREROUTING"
CHAIN_POST="IPTPF_POSTROUTING"

# 颜色定义
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[0;34m'
magenta='\033[0;35m'
cyan='\033[0;36m'
reset='\033[0m'

### ---------- 基础 ----------
require_root() {
  [[ $EUID -ne 0 ]] && echo -e "${red}请使用 root 运行${reset}" && exit 1
}

detect_lan_ip() {
  ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}'
}

detect_wan_ip() {
  curl -s --connect-timeout 3 ifconfig.me 2>/dev/null || curl -s --connect-timeout 3 api.ipify.org 2>/dev/null || echo "自动获取失败"
}

save_rules() {
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1
  elif command -v service >/dev/null 2>&1; then
    service iptables save >/dev/null 2>&1 || true
  fi
}

### ---------- 初始化 ----------
install_and_init() {
  clear
  echo -e "${cyan}==> [1/4] 检查 / 安装 iptables${reset}"
  if ! command -v iptables >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update -y
      apt-get install -y iptables iptables-persistent
    elif command -v yum >/dev/null 2>&1; then
      yum install -y iptables-services
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y iptables-services
    else
      echo -e "${red}不支持的系统${reset}"
      exit 1
    fi
  fi
  echo -e "${green}[OK] iptables 已就绪${reset}"

  echo -e "${cyan}==> [2/4] 开启 IPv4 转发${reset}"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-iptpf.conf
  echo -e "${green}[OK] 转发已开启并持久化${reset}"

  echo -e "${cyan}==> [3/4] 初始化专用链（不影响系统其它规则）${reset}"
  iptables -t nat -N $CHAIN_PRE 2>/dev/null || true
  iptables -t nat -N $CHAIN_POST 2>/dev/null || true

  iptables -t nat -C PREROUTING -j $CHAIN_PRE 2>/dev/null || \
    iptables -t nat -A PREROUTING -j $CHAIN_PRE
  iptables -t nat -C POSTROUTING -j $CHAIN_POST 2>/dev/null || \
    iptables -t nat -A POSTROUTING -j $CHAIN_POST
  echo -e "${green}[OK] 专用链已挂钩${reset}"

  echo -e "${cyan}==> [4/4] 保存规则${reset}"
  save_rules
  echo -e "${green}✅ 初始化 / 更新完成${reset}"
  echo ""
  read -n 1 -s -r -p "按任意键返回主菜单..."
}

### ---------- 查看 ----------
list_rules() {
  clear
  echo ""
  echo -e "${cyan}当前转发规则：${reset}"
  echo "------------------------------------------"
  local i=1
  iptables -t nat -S $CHAIN_PRE | grep DNAT | while read -r r; do
    proto=$(echo "$r" | grep -oE "-p (tcp|udp)" | awk '{print toupper($2)}')
    dport=$(echo "$r" | sed -n 's/.*--dport \([0-9]*\).*/\1/p')
    to=$(echo "$r" | sed -n 's/.*--to-destination \([^ ]*\).*/\1/p')
    printf "%2d. 类型: %-4s 本地端口: %-6s 转发到: %s\n" "$i" "$proto" "$dport" "$to"
    i=$((i+1))
  done
  [[ $i -eq 1 ]] && echo -e "${yellow}（暂无规则）${reset}"
  echo "------------------------------------------"
  echo ""
  read -n 1 -s -r -p "按任意键返回主菜单..."
}

### ---------- 添加 ----------
add_rule() {
  clear
  echo -e "${cyan}=== 添加端口转发 ===${reset}"
  echo ""
  
  while true; do
    read -rp "转发目标端口(远程端口): " RPORT
    [[ -n "$RPORT" ]] && break
    echo -e "${red}端口不能为空，请重新输入${reset}"
  done
  
  while true; do
    read -rp "转发目标IP: " RIP
    [[ -n "$RIP" ]] && break
    echo -e "${red}IP不能为空，请重新输入${reset}"
  done
  
  read -rp "本机监听端口 (回车=$RPORT): " LPORT
  [[ -z "$LPORT" ]] && LPORT="$RPORT"

  echo ""
  echo -e "${cyan}SNAT 源IP：${reset}"
  echo " 1) 内网IP（回车自动）"
  echo " 2) 公网IP（回车自动）"
  while true; do
    read -rp "请选择 [1-2] (默认1): " MODE
    [[ -z "$MODE" ]] && MODE=1
    [[ "$MODE" == "1" || "$MODE" == "2" ]] && break
    echo -e "${red}请选择 1 或 2${reset}"
  done

  if [[ "$MODE" == "2" ]]; then
    SNAT_IP=$(detect_wan_ip)
    read -rp "公网IP (回车自动=$SNAT_IP): " USER_SNAT_IP
    [[ -n "$USER_SNAT_IP" ]] && SNAT_IP="$USER_SNAT_IP"
  else
    SNAT_IP=$(detect_lan_ip)
    read -rp "内网IP (回车自动=$SNAT_IP): " USER_SNAT_IP
    [[ -n "$USER_SNAT_IP" ]] && SNAT_IP="$USER_SNAT_IP"
  fi

  echo ""
  echo -e "${cyan}协议类型：${reset}"
  echo " 1) TCP"
  echo " 2) UDP"
  echo " 3) TCP+UDP"
  while true; do
    read -rp "请选择 [1-3] (默认3): " PTYPE
    [[ -z "$PTYPE" ]] && PTYPE=3
    [[ "$PTYPE" =~ ^[123]$ ]] && break
    echo -e "${red}请选择 1, 2 或 3${reset}"
  done

  clear
  echo -e "${cyan}=== 确认信息 ===${reset}"
  echo ""
  echo "目标地址 : $RIP:$RPORT"
  echo "本机监听 : $LPORT"
  echo "SNAT IP  : $SNAT_IP"
  case $PTYPE in
    1) echo "协议类型 : TCP" ;;
    2) echo "协议类型 : UDP" ;;
    3) echo "协议类型 : TCP + UDP" ;;
  esac
  echo ""
  
  read -rp "确认添加？ [Y/n]: " OK
  [[ "$OK" == "n" || "$OK" == "N" ]] && {
    echo -e "${yellow}已取消添加${reset}"
    sleep 1
    return
  }

  [[ "$PTYPE" == "1" || "$PTYPE" == "3" ]] && {
    iptables -t nat -A $CHAIN_PRE -p tcp --dport $LPORT -j DNAT --to $RIP:$RPORT
    iptables -t nat -A $CHAIN_POST -p tcp -d $RIP --dport $RPORT -j SNAT --to-source $SNAT_IP
  }
  [[ "$PTYPE" == "2" || "$PTYPE" == "3" ]] && {
    iptables -t nat -A $CHAIN_PRE -p udp --dport $LPORT -j DNAT --to $RIP:$RPORT
    iptables -t nat -A $CHAIN_POST -p udp -d $RIP --dport $RPORT -j SNAT --to-source $SNAT_IP
  }

  save_rules
  echo -e "${green}✅ 已添加并保存${reset}"
  echo ""
  read -n 1 -s -r -p "按任意键返回主菜单..."
}

### ---------- 删除 ----------
delete_rule() {
  while true; do
    clear
    echo ""
    echo -e "${cyan}当前转发规则：${reset}"
    echo "------------------------------------------"
    local i=1
    iptables -t nat -S $CHAIN_PRE | grep DNAT | while read -r r; do
      proto=$(echo "$r" | grep -oE "-p (tcp|udp)" | awk '{print toupper($2)}')
      dport=$(echo "$r" | sed -n 's/.*--dport \([0-9]*\).*/\1/p')
      to=$(echo "$r" | sed -n 's/.*--to-destination \([^ ]*\).*/\1/p')
      printf "%2d. 类型: %-4s 本地端口: %-6s 转发到: %s\n" "$i" "$proto" "$dport" "$to"
      i=$((i+1))
    done
    [[ $i -eq 1 ]] && {
      echo -e "${yellow}（暂无规则）${reset}"
      echo "------------------------------------------"
      echo ""
      read -n 1 -s -r -p "按任意键返回主菜单..."
      break
    }
    echo "------------------------------------------"
    echo ""
    read -rp "请输入要删除的编号 (q返回主菜单): " IDX
    
    [[ "$IDX" == "q" ]] && break
    
    if ! [[ "$IDX" =~ ^[0-9]+$ ]]; then
      echo -e "${red}请输入有效的数字${reset}"
      sleep 1
      continue
    fi
    
    RULE=$(iptables -t nat -S $CHAIN_PRE | grep DNAT | sed -n "${IDX}p")
    if [[ -z "$RULE" ]]; then
      echo -e "${red}编号不存在${reset}"
      sleep 1
      continue
    fi

    DPORT=$(echo "$RULE" | sed -n 's/.*--dport \([0-9]*\).*/\1/p')
    TO=$(echo "$RULE" | sed -n 's/.*--to-destination \([^ ]*\).*/\1/p')
    
    echo ""
    echo -e "${yellow}即将删除：端口 $DPORT -> $TO${reset}"
    read -rp "确认删除？ [y/N]: " CONFIRM
    
    if [[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]]; then
      # 删除PREROUTING链中的规则
      iptables -t nat -S $CHAIN_PRE | grep "--dport $DPORT" | grep "$TO" | while read -r r; do
        iptables -t nat -D $CHAIN_PRE ${r#*-A $CHAIN_PRE }
      done
      
      # 删除POSTROUTING链中的对应规则
      iptables -t nat -S $CHAIN_POST | grep "$TO" | while read -r r; do
        iptables -t nat -D $CHAIN_POST ${r#*-A $CHAIN_POST }
      done

      save_rules
      echo -e "${green}✅ 已删除：$TO${reset}"
      sleep 1
    else
      echo -e "${yellow}已取消删除${reset}"
      sleep 1
    fi
  done
}

### ---------- 清空 ----------
clear_all() {
  clear
  echo -e "${red}=== 警告 ===${reset}"
  echo ""
  echo "此操作将清空本脚本管理的所有转发规则！"
  echo ""
  read -rp "确定要清空所有转发规则？ [y/N]: " CONFIRM
  
  if [[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]]; then
    iptables -t nat -F $CHAIN_PRE || true
    iptables -t nat -F $CHAIN_POST || true
    save_rules
    echo -e "${green}✅ 已清空本脚本管理的所有规则${reset}"
  else
    echo -e "${yellow}已取消清空${reset}"
  fi
  
  echo ""
  read -n 1 -s -r -p "按任意键返回主菜单..."
}

### ---------- 菜单 ----------
show_menu() {
  clear
  echo ""
  echo "╔════════════════════════════════════════════╗"
  echo "║                                            ║"
  echo "║    iptables 端口转发一键管理脚本           ║"
  echo "║              [$VERSION]                    ║"
  echo "║                                            ║"
  echo "║    -- for XiaoYu (简化可控版) --           ║"
  echo "║                                            ║"
  echo "╠════════════════════════════════════════════╣"
  echo "║                                            ║"
  echo "║  0. 升级脚本（重新下载并覆盖）             ║"
  echo "║  ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄  ║"
  echo "║  1. 安装 / 初始化                          ║"
  echo "║  2. 清空 所有转发                          ║"
  echo "║  ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄  ║"
  echo "║  3. 查看 转发                              ║"
  echo "║  4. 添加 转发                              ║"
  echo "║  5. 删除 转发（循环）                      ║"
  echo "║  ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄  ║"
  echo "║  q. 退出                                   ║"
  echo "║                                            ║"
  echo "╚════════════════════════════════════════════╝"
  echo ""
}

### ---------- 主循环 ----------
main() {
  require_root
  
  # 检查是否已安装
  if ! iptables -t nat -L $CHAIN_PRE &>/dev/null; then
    clear
    echo -e "${yellow}检测到未安装 iptables 转发规则${reset}"
    echo ""
    echo "是否现在安装初始化？"
    read -rp "输入 y 安装，其他键跳过: " answer
    if [[ "$answer" == "y" || "$answer" == "Y" ]]; then
      install_and_init
    fi
  fi
  
  while true; do
    show_menu
    read -rp "请选择 [0-5] (q退出): " C
    case "$C" in
      0) 
        clear
        echo -e "${cyan}升级脚本${reset}"
        echo ""
        echo "请使用原安装链接重新下载运行以升级"
        echo ""
        read -n 1 -s -r -p "按任意键返回主菜单..."
        ;;
      1) install_and_init ;;
      2) clear_all ;;
      3) list_rules ;;
      4) add_rule ;;
      5) delete_rule ;;
      q|Q) 
        clear
        echo ""
        echo -e "${green}感谢使用，再见！${reset}"
        echo ""
        exit 0 
        ;;
      *) 
        echo -e "${red}无效选项，请重新选择${reset}"
        sleep 1
        ;;
    esac
  done
}

# 确保有交互式终端
if [[ -t 0 ]] && [[ -t 1 ]]; then
  main
else
  # 如果没有交互式终端，提示用户下载到本地运行
  echo -e "${red}错误：需要在交互式终端中运行此脚本${reset}"
  echo ""
  echo "请使用以下方式："
  echo "1. 下载脚本："
  echo "   wget --no-check-certificate https://raw.githubusercontent.com/ylelel93/vps-iptables/main/iptables-pf.sh -O iptables.sh"
  echo "2. 添加权限："
  echo "   chmod +x iptables.sh"
  echo "3. 运行脚本："
  echo "   ./iptables.sh"
  exit 1
fi
