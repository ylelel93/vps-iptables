#!/bin/bash
# ============================================
# Name: iptables 端口转发管理脚本
# Author: XiaoYu
# Modified: 2024-01-01
# ============================================

set -euo pipefail

VERSION="v1.1.1"
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
    echo -e "${Error} 请使用 root 用户运行此脚本！"
    exit 1
  fi
}

# 只获取IPv4地址
detect_lan_ip() {
  local ip
  ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' 2>/dev/null || true)
  
  if [[ -z "$ip" ]]; then
    ip=$(hostname -I 2>/dev/null | awk '{print $1}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
  fi
  
  if [[ -z "$ip" ]]; then
    ip=$(ip addr show 2>/dev/null | grep -E 'inet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | grep -v '127.0.0.1' | head -1 | awk '{print $2}' | cut -d'/' -f1 || true)
  fi
  
  echo "${ip:-未知}"
}

# 只获取IPv4公网地址
detect_wan_ip() {
  local ip
  ip=$(curl -4 -s --connect-timeout 3 ifconfig.me 2>/dev/null || 
       curl -4 -s --connect-timeout 3 api.ipify.org 2>/dev/null ||
       curl -4 -s --connect-timeout 3 ipinfo.io/ip 2>/dev/null ||
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
  
  # 使用临时文件处理iptables输出，避免管道问题
  local temp_file
  temp_file=$(mktemp)
  iptables -t nat -S "$CHAIN_PRE" 2>/dev/null > "$temp_file"
  
  local i=0
  while read -r line; do
    if echo "$line" | grep -q "DNAT"; then
      i=$((i+1))
      
      # 提取协议类型
      local proto="TCP/UDP"
      if echo "$line" | grep -q " -p tcp "; then
        proto="TCP"
      elif echo "$line" | grep -q " -p udp "; then
        proto="UDP"
      fi
      
      # 提取端口和目标地址
      local dport=""
      local to=""
      
      # 使用更安全的方式提取端口和地址
      dport=$(echo "$line" | sed 's/.*--dport \([0-9]*\).*/\1/')
      to=$(echo "$line" | sed 's/.*--to-destination \([^ ]*\).*/\1/')
      
      # 如果提取失败，尝试其他格式
      if [[ "$dport" == "$line" ]]; then
        dport=$(echo "$line" | sed 's/.*:\([0-9]*\) .*/\1/')
      fi
      
      if [[ -n "$dport" && -n "$to" ]]; then
        printf "%2d. 类型: %-4s 监听端口: %-6s 转发IP和端口: %s\n" "$i" "$proto" "$dport" "$to"
      fi
    fi
  done < "$temp_file"
  
  rm -f "$temp_file"
  
  if [[ $i -eq 0 ]]; then
    echo -e "${Tip} （暂无规则）"
  else
    echo -e "\n${Info} 当前有 $i 个 iptables 端口转发规则。"
  fi
  echo "------------------------------------------"
  
  # 等待用户按回车键返回主菜单
  echo ""
  read -rp "$(echo -e ${Tip}) 按回车键返回主菜单... " enter
}

### ---------- 添加 ----------
add_rule() {
  echo -e "${Info} 添加端口转发规则"
  echo "------------------------------------------"
  
  read -rp "$(echo -e ${Question}) 转发目标IP: " RIP
  [[ -z "$RIP" ]] && echo -e "${Error} 目标IP不能为空" && return 1
  
  read -rp "$(echo -e ${Question}) 转发目标端口: " RPORT
  [[ -z "$RPORT" ]] && echo -e "${Error} 目标端口不能为空" && return 1
  
  read -rp "$(echo -e ${Question}) 本机监听端口 (回车默认=${RPORT}): " LPORT
  [[ -z "$LPORT" ]] && LPORT="$RPORT"
  
  # SNAT选择
  echo -e "\n${Tip} SNAT源IP："
  echo " 1) 内网IP（回车自动）"
  echo " 2) 公网IP（回车自动）"
  read -rp "$(echo -e ${Question}) 请选择 [1-2] (默认1): " MODE
  [[ -z "$MODE" ]] && MODE=1

  if [[ "$MODE" == "2" ]]; then
    SNAT_IP=$(detect_wan_ip)
    echo -e "${Info} 检测到的公网IP: $SNAT_IP"
    read -rp "$(echo -e ${Question}) 公网IP (回车使用检测到的IP): " USER_SNAT_IP
    [[ -n "$USER_SNAT_IP" ]] && SNAT_IP="$USER_SNAT_IP"
  else
    SNAT_IP=$(detect_lan_ip)
    echo -e "${Info} 检测到的内网IP: $SNAT_IP"
    read -rp "$(echo -e ${Question}) 内网IP (回车使用检测到的IP): " USER_SNAT_IP
    [[ -n "$USER_SNAT_IP" ]] && SNAT_IP="$USER_SNAT_IP"
  fi

  read -rp "$(echo -e ${Question}) 协议类型 [1 TCP / 2 UDP / 3 TCP+UDP] (默认3): " PTYPE
  [[ -z "$PTYPE" ]] && PTYPE=3

  # 验证IP是否为IPv4
  if ! [[ "$SNAT_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo -e "${Error} 检测到的IP '$SNAT_IP' 不是有效的IPv4地址"
    return 1
  fi

  echo -e "\n${Info} 配置摘要:"
  echo " 目标地址 : $RIP:$RPORT"
  echo " 本机监听 : $SNAT_IP:$LPORT"
  case $PTYPE in
    1) echo " 协议类型 : TCP" ;;
    2) echo " 协议类型 : UDP" ;;
    *) echo " 协议类型 : TCP + UDP" ;;
  esac

  read -rp "$(echo -e ${Question}) 确认添加？ [Y/n]: " OK
  # 默认按回车或输入y/Y确认，输入n/N取消
  [[ "$OK" == "n" || "$OK" == "N" ]] && echo -e "${Tip} 已取消" && return

  if [[ "$PTYPE" == "1" || "$PTYPE" == "3" ]]; then
    iptables -t nat -A "$CHAIN_PRE" -p tcp --dport "$LPORT" -j DNAT --to-destination "$RIP:$RPORT"
    iptables -t nat -A "$CHAIN_POST" -p tcp -d "$RIP" --dport "$RPORT" -j SNAT --to-source "$SNAT_IP"
  fi
  
  if [[ "$PTYPE" == "2" || "$PTYPE" == "3" ]]; then
    iptables -t nat -A "$CHAIN_PRE" -p udp --dport "$LPORT" -j DNAT --to-destination "$RIP:$RPORT"
    iptables -t nat -A "$CHAIN_POST" -p udp -d "$RIP" --dport "$RPORT" -j SNAT --to-source "$SNAT_IP"
  fi

  save_rules
  echo -e "${Info} ✅ 已添加并保存"
}

### ---------- 删除 ----------
# 使用原脚本的删除逻辑，避免删除中间编号导致的问题
delete_rule() {
  while true; do
    echo -e "\n${Info} 删除端口转发规则"
    
    # 显示规则
    list_rules_no_wait
    
    echo ""
    read -rp "$(echo -e ${Question}) 请输入要删除的编号 (q退出): " IDX
    [[ "$IDX" == "q" ]] && break

    if [[ -z "$IDX" || ! "$IDX" =~ ^[0-9]+$ ]]; then
      echo -e "${Error} 请输入有效的数字编号"
      continue
    fi
    
    # 获取对应编号的规则
    local rule_found=false
    local rule_line=""
    local temp_file=$(mktemp)
    iptables -t nat -S "$CHAIN_PRE" 2>/dev/null > "$temp_file"
    
    local i=0
    while read -r line; do
      if echo "$line" | grep -q "DNAT"; then
        i=$((i+1))
        if [[ $i -eq $IDX ]]; then
          rule_found=true
          rule_line="$line"
          break
        fi
      fi
    done < "$temp_file"
    
    rm -f "$temp_file"
    
    if [[ "$rule_found" == false ]]; then
      echo -e "${Error} 未找到编号为 $IDX 的规则"
      continue
    fi
    
    # 解析规则内容
    local dport=$(echo "$rule_line" | sed -n 's/.*--dport \([0-9]*\).*/\1/p')
    local to=$(echo "$rule_line" | sed -n 's/.*--to-destination \([^ ]*\).*/\1/p')
    local rip=$(echo "$to" | cut -d: -f1)
    local rport=$(echo "$to" | cut -d: -f2)
    
    # 检查是否是TCP、UDP还是两者
    local is_tcp=false
    local is_udp=false
    
    if echo "$rule_line" | grep -q " -p tcp "; then
      is_tcp=true
    elif echo "$rule_line" | grep -q " -p udp "; then
      is_udp=true
    else
      # 没有指定协议，则同时删除TCP和UDP
      is_tcp=true
      is_udp=true
    fi
    
    echo -e "${Tip} 正在删除规则: $dport -> $rip:$rport"
    
    # 使用原脚本的删除逻辑，通过逐条匹配删除
    if [[ "$is_tcp" == true ]]; then
      # 删除PREROUTING链中的TCP规则
      iptables -t nat -S "$CHAIN_PRE" 2>/dev/null | grep "DNAT" | grep "tcp" | grep "dport $dport" | grep "$to" | while read -r r; do
        # 使用原脚本的方法删除规则
        local delete_cmd="${r#*-A $CHAIN_PRE }"
        iptables -t nat -D "$CHAIN_PRE" $delete_cmd 2>/dev/null || true
      done
      
      # 删除POSTROUTING链中的TCP规则
      iptables -t nat -S "$CHAIN_POST" 2>/dev/null | grep "tcp" | grep "$rip" | grep "dport $rport" | while read -r r; do
        local delete_cmd="${r#*-A $CHAIN_POST }"
        iptables -t nat -D "$CHAIN_POST" $delete_cmd 2>/dev/null || true
      done
    fi
    
    if [[ "$is_udp" == true ]]; then
      # 删除PREROUTING链中的UDP规则
      iptables -t nat -S "$CHAIN_PRE" 2>/dev/null | grep "DNAT" | grep "udp" | grep "dport $dport" | grep "$to" | while read -r r; do
        local delete_cmd="${r#*-A $CHAIN_PRE }"
        iptables -t nat -D "$CHAIN_PRE" $delete_cmd 2>/dev/null || true
      done
      
      # 删除POSTROUTING链中的UDP规则
      iptables -t nat -S "$CHAIN_POST" 2>/dev/null | grep "udp" | grep "$rip" | grep "dport $rport" | while read -r r; do
        local delete_cmd="${r#*-A $CHAIN_POST }"
        iptables -t nat -D "$CHAIN_POST" $delete_cmd 2>/dev/null || true
      done
    fi

    save_rules
    echo -e "${Info} ✅ 已删除：$to"
  done
}

# 查看规则但不等待回车（供删除函数使用）
list_rules_no_wait() {
  echo -e "\n${Info} 当前转发规则："
  echo "------------------------------------------"
  
  # 使用临时文件处理iptables输出，避免管道问题
  local temp_file
  temp_file=$(mktemp)
  iptables -t nat -S "$CHAIN_PRE" 2>/dev/null > "$temp_file"
  
  local i=0
  while read -r line; do
    if echo "$line" | grep -q "DNAT"; then
      i=$((i+1))
      
      # 提取协议类型
      local proto="TCP/UDP"
      if echo "$line" | grep -q " -p tcp "; then
        proto="TCP"
      elif echo "$line" | grep -q " -p udp "; then
        proto="UDP"
      fi
      
      # 提取端口和目标地址
      local dport=""
      local to=""
      
      # 使用更安全的方式提取端口和地址
      dport=$(echo "$line" | sed 's/.*--dport \([0-9]*\).*/\1/')
      to=$(echo "$line" | sed 's/.*--to-destination \([^ ]*\).*/\1/')
      
      # 如果提取失败，尝试其他格式
      if [[ "$dport" == "$line" ]]; then
        dport=$(echo "$line" | sed 's/.*:\([0-9]*\) .*/\1/')
      fi
      
      if [[ -n "$dport" && -n "$to" ]]; then
        printf "%2d. 类型: %-4s 监听端口: %-6s 转发IP和端口: %s\n" "$i" "$proto" "$dport" "$to"
      fi
    fi
  done < "$temp_file"
  
  rm -f "$temp_file"
  
  if [[ $i -eq 0 ]]; then
    echo -e "${Tip} （暂无规则）"
  else
    echo -e "\n${Info} 当前有 $i 个 iptables 端口转发规则。"
  fi
  echo "------------------------------------------"
}

### ---------- 清空 ----------
clear_all() {
  echo -e "${Error} 警告：这将清空所有转发规则！"
  read -rp "$(echo -e ${Question}) 确认清空？ [y/N]: " CONFIRM
  [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]] && echo -e "${Tip} 已取消" && return
  
  iptables -t nat -F "$CHAIN_PRE" 2>/dev/null || true
  iptables -t nat -F "$CHAIN_POST" 2>/dev/null || true
  save_rules
  echo -e "${Info} ✅ 已清空所有转发规则"
}

### ---------- 菜单 ----------
show_menu() {
  clear
  echo -e " iptables 端口转发一键管理脚本 [${VERSION}]"
  echo -e "  -- Toyo | doub.io/wlzy-202 --"
  echo ""
  echo -e " 0. 升级脚本"
  echo -e "————————————"
  echo -e " 1. 安装 iptables"
  echo -e " 2. 清空 iptables 端口转发"
  echo -e "————————————"
  echo -e " 3. 查看 iptables 端口转发"
  echo -e " 4. 添加 iptables 端口转发"
  echo -e " 5. 删除 iptables 端口转发"
  echo -e "————————————"
  echo -e "${Tip} 注意：初次使用前请务必执行 1. 安装 iptables(不仅仅是安装)"
  echo ""
}

### ---------- 系统信息 ----------
show_info() {
  echo -e "\n${Info} 系统信息："
  echo "------------------------------------------"
  echo -e " 内网IPv4: $(detect_lan_ip)"
  echo -e " 公网IPv4: $(detect_wan_ip)"
  echo -e " IPv4转发状态: $(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo '未知')"
  echo "------------------------------------------"
}

### ---------- 主循环 ----------
main() {
  require_root
  
  while true; do
    show_menu
    read -rp "$(echo -e ${Question}) 请输入数字 [0-5]: " C
    
    case "$C" in
      0) 
        echo -e "${Info} 请使用原安装链接重新执行以升级"
        echo -e "${Info} wget -N --no-check-certificate https://raw.githubusercontent.com/ylelel93/vps-iptables/main/iptables-pf.sh && chmod +x iptables-pf.sh && bash iptables-pf.sh"
        echo ""
        read -rp "$(echo -e ${Tip}) 按回车键返回主菜单... " enter
        ;;
      1) 
        install_and_init
        echo ""
        read -rp "$(echo -e ${Tip}) 按回车键返回主菜单... " enter
        ;;
      2) 
        clear_all
        echo ""
        read -rp "$(echo -e ${Tip}) 按回车键返回主菜单... " enter
        ;;
      3) 
        list_rules
        ;;
      4) 
        add_rule
        echo ""
        read -rp "$(echo -e ${Tip}) 按回车键返回主菜单... " enter
        ;;
      5) 
        delete_rule
        ;;
      q) 
        echo -e "${Info} 感谢使用！"
        exit 0 
        ;;
      *) 
        echo -e "${Error} 无效选择，请重新输入"
        echo ""
        read -rp "$(echo -e ${Tip}) 按回车键继续... " enter
        ;;
    esac
  done
}

# 启动脚本
main
