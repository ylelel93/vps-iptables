#!/bin/bash
# ============================================
# Name: iptables 端口转发管理脚本 (改进版)
# Version: v2.1.0
# 结合了两个脚本的优点，修复了兼容性问题
# ============================================

set -e
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# 版本和配置
VERSION="v2.1.0"
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

# ============================================
# 工具函数
# ============================================

# 检查root权限
require_root() {
    [[ $EUID -ne 0 ]] && echo -e "${Error} 请使用 root 用户运行此脚本！" && exit 1
}

# 检测系统类型
check_sys() {
    if [[ -f /etc/redhat-release ]]; then
        release="centos"
    elif cat /etc/issue | grep -q -E -i "debian"; then
        release="debian"
    elif cat /etc/issue | grep -q -E -i "ubuntu"; then
        release="ubuntu"
    elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
        release="centos"
    elif cat /proc/version | grep -q -E -i "debian"; then
        release="debian"
    elif cat /proc/version | grep -q -E -i "ubuntu"; then
        release="ubuntu"
    elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
        release="centos"
    else
        release="unknown"
    fi
}

# 检测内网IP
detect_lan_ip() {
    local ip
    ip=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
    if [[ -z "$ip" ]]; then
        ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi
    echo "$ip"
}

# 检测公网IP
detect_wan_ip() {
    local ip
    ip=$(curl -s --connect-timeout 3 ifconfig.me 2>/dev/null || 
         curl -s --connect-timeout 3 api.ipify.org 2>/dev/null ||
         curl -s --connect-timeout 3 ipinfo.io/ip 2>/dev/null ||
         curl -s --connect-timeout 3 ip.sb 2>/dev/null ||
         echo "未知")
    echo "$ip"
}

# 保存iptables规则
save_rules() {
    echo -e "${Tip} 正在保存iptables规则..."
    
    case "$release" in
        centos)
            if command -v iptables-save >/dev/null 2>&1; then
                iptables-save > /etc/sysconfig/iptables 2>/dev/null
                echo -e "${Info} 规则已保存到 /etc/sysconfig/iptables"
            fi
            if systemctl is-active iptables >/dev/null 2>&1; then
                systemctl restart iptables >/dev/null 2>&1
            fi
            ;;
        debian|ubuntu)
            # 尝试多种保存方式
            if command -v iptables-save >/dev/null 2>&1; then
                iptables-save > /etc/iptables/rules.v4 2>/dev/null && \
                echo -e "${Info} 规则已保存到 /etc/iptables/rules.v4"
                
                # 创建恢复脚本
                mkdir -p /etc/network/if-pre-up.d
                cat > /etc/network/if-pre-up.d/iptables << 'EOF'
#!/bin/sh
/sbin/iptables-restore < /etc/iptables/rules.v4
EOF
                chmod +x /etc/network/if-pre-up.d/iptables
            fi
            
            # 尝试使用netfilter-persistent
            if command -v netfilter-persistent >/dev/null 2>&1; then
                netfilter-persistent save >/dev/null 2>&1
            fi
            ;;
        *)
            echo -e "${Error} 未知系统类型，无法自动保存规则"
            echo -e "${Tip} 请手动运行 'iptables-save > /路径/规则文件' 保存规则"
            ;;
    esac
}

# ============================================
# 核心功能
# ============================================

# 安装和初始化
install_and_init() {
    echo -e "${Info} 开始安装和初始化..."
    
    # 检查系统并安装iptables
    check_sys
    echo -e "${Info} 检测到系统: ${release}"
    
    case "$release" in
        centos)
            echo -e "${Info} 正在安装 iptables..."
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y iptables iptables-services 2>/dev/null || yum install -y iptables iptables-services
            else
                yum install -y iptables iptables-services
            fi
            ;;
        debian|ubuntu)
            echo -e "${Info} 正在更新包列表并安装 iptables..."
            apt-get update
            apt-get install -y iptables iptables-persistent
            ;;
        *)
            echo -e "${Error} 不支持的系统类型: ${release}"
            echo -e "${Tip} 请手动安装 iptables 后再运行此脚本"
            exit 1
            ;;
    esac
    
    # 开启IP转发
    echo -e "${Info} 开启IPv4转发..."
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    if [[ -d /etc/sysctl.d ]]; then
        echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-iptables-forward.conf
    fi
    sysctl -p >/dev/null 2>&1
    sysctl -p /etc/sysctl.d/99-iptables-forward.conf 2>/dev/null || true
    
    # 创建自定义链
    echo -e "${Info} 创建自定义链..."
    iptables -t nat -N $CHAIN_PRE 2>/dev/null || true
    iptables -t nat -N $CHAIN_POST 2>/dev/null || true
    
    # 将自定义链挂接到系统链
    if ! iptables -t nat -C PREROUTING -j $CHAIN_PRE 2>/dev/null; then
        iptables -t nat -I PREROUTING 1 -j $CHAIN_PRE
    fi
    if ! iptables -t nat -C POSTROUTING -j $CHAIN_POST 2>/dev/null; then
        iptables -t nat -I POSTROUTING 1 -j $CHAIN_POST
    fi
    
    # 保存规则
    save_rules
    
    echo -e "${Info} ✅ 安装和初始化完成！"
    echo -e "${Tip} 当前系统IP: 内网 $(detect_lan_ip) | 公网 $(detect_wan_ip)"
}

# 列出规则
list_rules() {
    echo -e "\n${Info} 当前转发规则："
    echo "=========================================="
    
    local count=0
    # 获取DNAT规则
    iptables -t nat -vnL $CHAIN_PRE --line-numbers 2>/dev/null | while read -r line; do
        if echo "$line" | grep -q "DNAT"; then
            count=$((count+1))
            num=$(echo "$line" | awk '{print $1}')
            proto=$(echo "$line" | grep -o "tcp\|udp" | head -1 | tr 'a-z' 'A-Z')
            dport=$(echo "$line" | grep -o "dpts\?[=:][0-9]\+" | grep -o "[0-9]\+" || echo "$line" | grep -o "dport [0-9]\+" | awk '{print $2}')
            to=$(echo "$line" | grep -o "to:[0-9.]\+:[0-9]\+" | cut -d: -f2-3 | tr ':' '/')
            
            if [[ -n "$dport" && -n "$to" ]]; then
                echo -e " ${Green_font_prefix}$count${Font_color_suffix}. 类型: ${proto:-TCP+UDP} | 本地端口: ${dport} | 转发到: ${to}"
            fi
        fi
    done
    
    if [[ $count -eq 0 ]]; then
        echo -e " ${Tip} 暂无转发规则"
    fi
    
    echo "=========================================="
}

# 添加规则
add_rule() {
    echo -e "${Info} 添加端口转发规则"
    echo "------------------------------------------"
    
    # 获取输入
    read -rp "$(echo -e ${Question}) 转发目标IP: " RIP
    [[ -z "$RIP" ]] && echo -e "${Error} 目标IP不能为空" && return 1
    
    read -rp "$(echo -e ${Question}) 转发目标端口: " RPORT
    [[ -z "$RPORT" ]] && echo -e "${Error} 目标端口不能为空" && return 1
    
    read -rp "$(echo -e ${Question}) 本机监听端口 (回车默认=${RPORT}): " LPORT
    [[ -z "$LPORT" ]] && LPORT="$RPORT"
    
    # SNAT选择
    echo -e "\n${Tip} 选择SNAT源地址:"
    echo "  1) 使用内网IP (默认)"
    echo "  2) 使用公网IP"
    echo "  3) 使用MASQUERADE (自动)"
    read -rp "$(echo -e ${Question}) 请选择 [1-3] (默认1): " SNAT_MODE
    [[ -z "$SNAT_MODE" ]] && SNAT_MODE=1
    
    case $SNAT_MODE in
        1)
            SNAT_IP=$(detect_lan_ip)
            SNAT_TYPE="SNAT"
            ;;
        2)
            SNAT_IP=$(detect_wan_ip)
            SNAT_TYPE="SNAT"
            ;;
        3)
            SNAT_IP=""
            SNAT_TYPE="MASQUERADE"
            ;;
        *)
            echo -e "${Error} 无效选择，使用默认(内网IP)"
            SNAT_IP=$(detect_lan_ip)
            SNAT_TYPE="SNAT"
            ;;
    esac
    
    # 协议选择
    echo -e "\n${Tip} 选择协议类型:"
    echo "  1) TCP (默认)"
    echo "  2) UDP"
    echo "  3) TCP+UDP"
    read -rp "$(echo -e ${Question}) 请选择 [1-3] (默认1): " PROTO_MODE
    [[ -z "$PROTO_MODE" ]] && PROTO_MODE=1
    
    # 显示配置摘要
    echo -e "\n${Info} 配置摘要:"
    echo "  ┌──────────────────────────────────────┐"
    echo "  │  目标地址  : $RIP:$RPORT"
    echo "  │  本机端口  : $LPORT"
    echo "  │  SNAT模式  : $SNAT_TYPE ${SNAT_IP:+($SNAT_IP)}"
    case $PROTO_MODE in
        1) echo "  │  协议类型  : TCP" ;;
        2) echo "  │  协议类型  : UDP" ;;
        3) echo "  │  协议类型  : TCP + UDP" ;;
    esac
    echo "  └──────────────────────────────────────┘"
    
    # 确认
    read -rp "$(echo -e ${Question}) 确认添加此规则？[Y/n]: " CONFIRM
    [[ "$CONFIRM" == "n" || "$CONFIRM" == "N" ]] && echo -e "${Tip} 已取消" && return
    
    # 添加规则
    case $PROTO_MODE in
        1)  # TCP
            iptables -t nat -A $CHAIN_PRE -p tcp --dport $LPORT -j DNAT --to-destination $RIP:$RPORT
            if [[ "$SNAT_TYPE" == "SNAT" ]]; then
                iptables -t nat -A $CHAIN_POST -p tcp -d $RIP --dport $RPORT -j SNAT --to-source $SNAT_IP
            else
                iptables -t nat -A $CHAIN_POST -p tcp -d $RIP --dport $RPORT -j MASQUERADE
            fi
            ;;
        2)  # UDP
            iptables -t nat -A $CHAIN_PRE -p udp --dport $LPORT -j DNAT --to-destination $RIP:$RPORT
            if [[ "$SNAT_TYPE" == "SNAT" ]]; then
                iptables -t nat -A $CHAIN_POST -p udp -d $RIP --dport $RPORT -j SNAT --to-source $SNAT_IP
            else
                iptables -t nat -A $CHAIN_POST -p udp -d $RIP --dport $RPORT -j MASQUERADE
            fi
            ;;
        3)  # TCP+UDP
            iptables -t nat -A $CHAIN_PRE -p tcp --dport $LPORT -j DNAT --to-destination $RIP:$RPORT
            iptables -t nat -A $CHAIN_PRE -p udp --dport $LPORT -j DNAT --to-destination $RIP:$RPORT
            if [[ "$SNAT_TYPE" == "SNAT" ]]; then
                iptables -t nat -A $CHAIN_POST -p tcp -d $RIP --dport $RPORT -j SNAT --to-source $SNAT_IP
                iptables -t nat -A $CHAIN_POST -p udp -d $RIP --dport $RPORT -j SNAT --to-source $SNAT_IP
            else
                iptables -t nat -A $CHAIN_POST -p tcp -d $RIP --dport $RPORT -j MASQUERADE
                iptables -t nat -A $CHAIN_POST -p udp -d $RIP --dport $RPORT -j MASQUERADE
            fi
            ;;
    esac
    
    # 保存规则
    save_rules
    echo -e "${Info} ✅ 规则添加成功！"
}

# 删除规则
delete_rule() {
    while true; do
        echo -e "\n${Info} 删除端口转发规则"
        echo "=========================================="
        
        # 显示规则并编号
        local index=1
        declare -A rule_map
        
        iptables -t nat -vnL $CHAIN_PRE --line-numbers 2>/dev/null | while read -r line; do
            if echo "$line" | grep -q "DNAT"; then
                num=$(echo "$line" | awk '{print $1}')
                proto=$(echo "$line" | grep -o "tcp\|udp" | head -1 | tr 'a-z' 'A-Z')
                dport=$(echo "$line" | grep -o "dpts\?[=:][0-9]\+" | grep -o "[0-9]\+" || echo "$line" | grep -o "dport [0-9]\+" | awk '{print $2}')
                to=$(echo "$line" | grep -o "to:[0-9.]\+:[0-9]\+" | cut -d: -f2-3 | tr ':' '/')
                
                if [[ -n "$dport" && -n "$to" ]]; then
                    rule_map[$index]="$num:$dport:$to"
                    echo -e " ${Green_font_prefix}$index${Font_color_suffix}. 类型: ${proto:-TCP+UDP} | 本地端口: $dport | 转发到: $to"
                    index=$((index+1))
                fi
            fi
        done
        
        if [[ $index -eq 1 ]]; then
            echo -e " ${Tip} 暂无规则可删除"
            return
        fi
        
        echo "=========================================="
        
        # 获取用户选择
        read -rp "$(echo -e ${Question}) 输入要删除的规则编号 (q退出): " choice
        [[ "$choice" == "q" ]] && break
        
        if [[ -n "${rule_map[$choice]}" ]]; then
            IFS=':' read -r rule_num dport dest <<< "${rule_map[$choice]}"
            rip=$(echo "$dest" | cut -d'/' -f1)
            rport=$(echo "$dest" | cut -d'/' -f2)
            
            echo -e "${Tip} 正在删除规则: $dport -> $rip:$rport"
            
            # 删除PREROUTING链中的规则
            while iptables -t nat -C $CHAIN_PRE -p tcp --dport $dport -j DNAT --to-destination $rip:$rport 2>/dev/null; do
                iptables -t nat -D $CHAIN_PRE -p tcp --dport $dport -j DNAT --to-destination $rip:$rport
            done
            
            while iptables -t nat -C $CHAIN_PRE -p udp --dport $dport -j DNAT --to-destination $rip:$rport 2>/dev/null; do
                iptables -t nat -D $CHAIN_PRE -p udp --dport $dport -j DNAT --to-destination $rip:$rport
            done
            
            # 删除POSTROUTING链中的规则
            while iptables -t nat -C $CHAIN_POST -p tcp -d $rip --dport $rport -j SNAT 2>/dev/null; do
                iptables -t nat -D $CHAIN_POST -p tcp -d $rip --dport $rport -j SNAT
            done
            
            while iptables -t nat -C $CHAIN_POST -p udp -d $rip --dport $rport -j SNAT 2>/dev/null; do
                iptables -t nat -D $CHAIN_POST -p udp -d $rip --dport $rport -j SNAT
            done
            
            while iptables -t nat -C $CHAIN_POST -p tcp -d $rip --dport $rport -j MASQUERADE 2>/dev/null; do
                iptables -t nat -D $CHAIN_POST -p tcp -d $rip --dport $rport -j MASQUERADE
            done
            
            while iptables -t nat -C $CHAIN_POST -p udp -d $rip --dport $rport -j MASQUERADE 2>/dev/null; do
                iptables -t nat -D $CHAIN_POST -p udp -d $rip --dport $rport -j MASQUERADE
            done
            
            save_rules
            echo -e "${Info} ✅ 规则删除成功！"
        else
            echo -e "${Error} 无效的编号"
        fi
    done
}

# 清空所有规则
clear_all() {
    echo -e "${Tip} 正在清空所有转发规则..."
    
    read -rp "$(echo -e ${Question}) 确认清空所有规则？[y/N]: " CONFIRM
    [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]] && echo -e "${Tip} 已取消" && return
    
    # 清空自定义链
    iptables -t nat -F $CHAIN_PRE 2>/dev/null
    iptables -t nat -F $CHAIN_POST 2>/dev/null
    
    # 从系统链中删除跳转
    iptables -t nat -D PREROUTING -j $CHAIN_PRE 2>/dev/null || true
    iptables -t nat -D POSTROUTING -j $CHAIN_POST 2>/dev/null || true
    
    # 删除自定义链
    iptables -t nat -X $CHAIN_PRE 2>/dev/null || true
    iptables -t nat -X $CHAIN_POST 2>/dev/null || true
    
    save_rules
    echo -e "${Info} ✅ 所有规则已清空！"
}

# 显示系统信息
show_info() {
    echo -e "\n${Info} 系统信息:"
    echo "=========================================="
    echo -e " 脚本版本 : ${VERSION}"
    echo -e " 系统类型 : ${release}"
    echo -e " 内网IP   : $(detect_lan_ip)"
    echo -e " 公网IP   : $(detect_wan_ip)"
    echo -e " IPv4转发 : $(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo '未知')"
    echo "=========================================="
}

# 主菜单
show_menu() {
    clear
    echo -e "==============================================="
    echo -e "   iptables 端口转发管理脚本 ${Green_font_prefix}${VERSION}${Font_color_suffix}"
    echo -e "==============================================="
    echo -e " ${Green_font_prefix}1.${Font_color_suffix} 安装 / 初始化"
    echo -e " ${Green_font_prefix}2.${Font_color_suffix} 查看转发规则"
    echo -e " ${Green_font_prefix}3.${Font_color_suffix} 添加转发规则"
    echo -e " ${Green_font_prefix}4.${Font_color_suffix} 删除转发规则"
    echo -e " ${Green_font_prefix}5.${Font_color_suffix} 清空所有规则"
    echo -e " ${Green_font_prefix}6.${Font_color_suffix} 系统信息"
    echo -e " ${Green_font_prefix}7.${Font_color_suffix} 退出脚本"
    echo -e "==============================================="
}

# 主函数
main() {
    require_root
    check_sys
    
    while true; do
        show_menu
        echo -e "\n${Question} 请选择操作 [1-7]: "
        read -r choice
        
        case $choice in
            1)
                install_and_init
                ;;
            2)
                list_rules
                ;;
            3)
                add_rule
                ;;
            4)
                delete_rule
                ;;
            5)
                clear_all
                ;;
            6)
                show_info
                ;;
            7)
                echo -e "${Info} 感谢使用，再见！"
                exit 0
                ;;
            *)
                echo -e "${Error} 无效的选择，请重新输入"
                ;;
        esac
        
        echo -e "\n${Tip} 按回车键继续..."
        read -r
    done
}

# 启动脚本
main
