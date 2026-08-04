#!/bin/bash
# ============================================
# iptables 端口转发管理脚本 v3.0
# 2006-8-4
# ============================================

set -euo pipefail

VERSION="v3.0"
CHAIN_PRE="IPTPF_PREROUTING"
CHAIN_POST="IPTPF_POSTROUTING"
COMMENT_TAG="IPTPF"
LOCK_FILE="/var/lock/iptpf.lock"
LOG_FILE="/var/log/iptpf.log"
CMD_NAME="yangtian"
INSTALL_DIR="/usr/local/bin"

# 颜色
G="\033[32m"; R="\033[31m"; Y="\033[33m"; B="\033[34m"; N="\033[0m"
Info="${G}[信息]${N}"
Error="${R}[错误]${N}"
Warn="${Y}[警告]${N}"
Tip="${Y}[注意]${N}"
Ask="${B}[?]${N}"

### ---------- 日志 ----------
_LOG_INITED=0
_init_log() {
  (( _LOG_INITED == 1 )) && return 0
  mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
  touch "$LOG_FILE" 2>/dev/null || true
  _LOG_INITED=1
}

log()  {
  echo -e "$1"
  _init_log
  echo "$(date '+%F %T') $(echo -e "$1" | sed 's/\x1b\[[0-9;]*m//g')" >> "$LOG_FILE" 2>/dev/null || true
}
warn() { log "${Warn} $*"; }
die()  { log "${Error} $*"; exit 1; }

### ---------- iptables 包装 (含锁等待) ----------
ipt() { iptables -w 5 "$@"; }

### ---------- 基础检查 ----------
require_root() {
  [[ $EUID -eq 0 ]] || die "请使用 root 用户运行此脚本"
}

acquire_lock() {
  exec 9>"$LOCK_FILE" 2>/dev/null || exec 9>/tmp/iptpf.lock
  if ! flock -n 9; then
    die "已有另一个 iptpf 实例在运行 (锁: $LOCK_FILE)"
  fi
}

### ---------- 输入校验 ----------
validate_ip() {
  local ip="$1" o
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  for o in ${ip//./ }; do
    # 拒绝前导零 (01, 001) —— Linux 会解析成八进制，容易踩坑；"0" 本身仍允许
    [[ "$o" =~ ^0[0-9]+$ ]] && return 1
    (( o >= 0 && o <= 255 )) || return 1
  done
  return 0
}

# 单端口 1-65535 (不支持范围: _add_one 的 --to-destination 语法与 --dport 冒号写法冲突)
validate_port() {
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || return 1
  # 拒绝前导零 (080/007) —— bash 算术会当八进制解析踩坑
  [[ "$p" =~ ^0[0-9]+$ ]] && return 1
  (( p >= 1 && p <= 65535 ))
}

validate_proto() {
  case "$1" in tcp|udp|both) return 0;; *) return 1;; esac
}

### ---------- 环境检测 ----------
detect_lan_ip() {
  local ip
  ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}') || true
  [[ -z "${ip:-}" ]] && ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  echo "${ip:-}"
}

detect_wan_ip() {
  local ip u
  for u in ifconfig.me api.ipify.org ipinfo.io/ip; do
    ip=$(curl -4 -s --connect-timeout 2 --max-time 3 "$u" 2>/dev/null || true)
    [[ -n "$ip" ]] && { echo "$ip"; return; }
  done
  echo ""
}

detect_backend() {
  local v
  v=$(iptables -V 2>/dev/null | head -1)
  case "$v" in
    *nf_tables*) echo "nft" ;;
    *legacy*)    echo "legacy" ;;
    *)           echo "unknown" ;;
  esac
}

detect_conflicts() {
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    warn "检测到 firewalld 正在运行，直接操作 iptables 会与其冲突"
    warn "  建议: systemctl stop firewalld && systemctl disable firewalld"
  fi
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "Status: active"; then
    warn "检测到 ufw 已启用，本脚本添加的规则可能被 ufw 重写"
    warn "  建议: ufw disable"
  fi
  local nics
  nics=$(ip -4 -o addr show scope global 2>/dev/null | grep -v ' lo ' | wc -l)
  if (( nics > 1 )); then
    warn "检测到 ${nics} 个公网/内网 IP：多网卡环境请确认回包路由，"
    warn "  必要时对 SNAT 源 IP 添加策略路由以避免非对称路由"
  fi

  local backend; backend=$(detect_backend)
  if [[ "$backend" == "nft" ]] && command -v update-alternatives >/dev/null 2>&1; then
    warn "当前 iptables 后端为 nft；如遇重启后规则不生效，可切换后端:"
    warn "  update-alternatives --config iptables"
  fi

  # FORWARD 策略检测: DNAT 后的包必须过 FORWARD 链
  # 若装了 Docker 或用户手工加固, 策略可能是 DROP, 中转会静默失败
  local fwd_policy
  fwd_policy=$(ipt -L FORWARD -n 2>/dev/null | head -1 | sed -n 's/.*policy \([A-Z]*\).*/\1/p')
  if [[ "$fwd_policy" == "DROP" ]]; then
    warn "FORWARD 链默认策略为 DROP (常见于装了 Docker 或手工加固的系统)"
    warn "  DNAT 后的中转流量会被 FORWARD 拒绝，需要放行:"
    warn "    iptables -I FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    warn "    iptables -I FORWARD -m conntrack --ctstate DNAT -j ACCEPT"
    warn "  (本脚本不主动改 FORWARD 以免与其它工具冲突)"
  fi
}

ensure_modules() {
  local m failed=()
  for m in iptable_nat nf_conntrack; do
    lsmod 2>/dev/null | grep -q "^${m} " && continue
    if ! modprobe "$m" 2>/dev/null; then failed+=("$m"); fi
  done
  (( ${#failed[@]} > 0 )) && warn "无法加载内核模块: ${failed[*]}（可能是容器环境或已静态编译进内核，可忽略）"
  return 0
}

### ---------- 规则持久化 ----------
# 返回: enabled | installed_not_enabled | not_installed
_persistence_status() {
  # Debian/Ubuntu: netfilter-persistent (提供 iptables-persistent 服务)
  if command -v netfilter-persistent >/dev/null 2>&1; then
    if systemctl is-enabled netfilter-persistent >/dev/null 2>&1; then
      echo "enabled:netfilter-persistent"; return
    fi
    echo "installed_not_enabled:netfilter-persistent"; return
  fi
  # RHEL/CentOS: iptables-services 提供的 iptables.service
  if [[ -f /etc/redhat-release ]] && rpm -q iptables-services >/dev/null 2>&1; then
    if systemctl is-enabled iptables >/dev/null 2>&1; then
      echo "enabled:iptables-services"; return
    fi
    echo "installed_not_enabled:iptables-services"; return
  fi
  echo "not_installed:"
}

save_rules() {
  local st svc
  st=$(_persistence_status)
  svc="${st#*:}"; st="${st%%:*}"

  case "$st" in
    enabled)
      if [[ "$svc" == "netfilter-persistent" ]]; then
        netfilter-persistent save >/dev/null 2>&1 \
          && { log "${Info} 已持久化 (netfilter-persistent)"; return 0; } \
          || warn "netfilter-persistent save 执行失败"
      else
        service iptables save >/dev/null 2>&1 \
          && { log "${Info} 已持久化 (iptables-services)"; return 0; } \
          || warn "service iptables save 执行失败"
      fi
      return 1
      ;;
    installed_not_enabled)
      warn "持久化服务 $svc 已安装但未启用；本次规则已生效，重启后会丢失"
      warn "  修复: sudo systemctl enable --now $svc"
      # 尝试写文件，reboot 时若手工 restore 至少还在
      mkdir -p /etc/iptables 2>/dev/null || true
      iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
      return 1
      ;;
    not_installed)
      warn "未安装任何持久化服务；本次规则已生效，重启后会丢失"
      warn "  修复: sudo ${CMD_NAME} init  会自动安装 iptables-persistent / iptables-services"
      return 1
      ;;
  esac
}

### ---------- 初始化 ----------
install_and_init() {
  log "${Info} [1/5] 检查/安装 iptables + 持久化服务"

  local distro=""
  if   [[ -f /etc/redhat-release ]]; then distro=rhel
  elif [[ -f /etc/debian_version ]]; then distro=debian
  else die "不支持的系统类型 (需要 RHEL/CentOS 或 Debian/Ubuntu 系)"
  fi

  # (a) 装 iptables 本体 (预装的话跳过)
  if ! command -v iptables >/dev/null 2>&1; then
    log "${Info}   安装 iptables..."
    case "$distro" in
      rhel)   yum install -y iptables || die "iptables 安装失败" ;;
      debian) apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y iptables \
                || die "iptables 安装失败" ;;
    esac
  fi

  # (b) 装持久化服务 —— 独立于 (a)，因为 iptables 通常预装但持久化服务不装
  case "$distro" in
    rhel)
      if ! rpm -q iptables-services >/dev/null 2>&1; then
        log "${Info}   安装 iptables-services..."
        yum install -y iptables-services || warn "iptables-services 安装失败，规则将无法自动持久化"
      fi
      systemctl enable iptables >/dev/null 2>&1 || true
      ;;
    debian)
      if ! dpkg -s iptables-persistent >/dev/null 2>&1; then
        log "${Info}   安装 iptables-persistent..."
        # 预置 debconf，避免弹交互框
        echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
        echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
        DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent \
          || warn "iptables-persistent 安装失败，规则将无法自动持久化"
      fi
      systemctl enable netfilter-persistent >/dev/null 2>&1 || true
      ;;
  esac

  log "${Info}   iptables 后端: $(detect_backend)"
  log "${Info}   持久化状态: $(_persistence_status | cut -d: -f1)"

  log "${Info} [2/5] 加载内核模块"
  ensure_modules

  log "${Info} [3/5] 开启 IPv4 转发"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null || die "开启 ip_forward 失败"
  echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-iptpf.conf
  sysctl -p /etc/sysctl.d/99-iptpf.conf >/dev/null 2>&1 || true

  log "${Info} [4/5] 初始化专用链"
  ipt -t nat -N "$CHAIN_PRE"  2>/dev/null || true
  ipt -t nat -N "$CHAIN_POST" 2>/dev/null || true
  ipt -t nat -C PREROUTING  -j "$CHAIN_PRE"  2>/dev/null || ipt -t nat -A PREROUTING  -j "$CHAIN_PRE"
  ipt -t nat -C POSTROUTING -j "$CHAIN_POST" 2>/dev/null || ipt -t nat -A POSTROUTING -j "$CHAIN_POST"

  log "${Info} [5/5] 环境冲突检测"
  detect_conflicts

  save_rules
  log "${Info} 初始化完成"
}

### ---------- 规则 tag 编解码 ----------
# tag 格式:  IPTPF|<lport>|<proto>|<rip>|<rport>|<snat>|<remark>
_sanitize_remark() {
  # 剥掉会破坏 comment/shell 上下文的字符
  local s="$1"
  s="${s//\"/}"     # 引号 → 截断 comment
  s="${s//\`/}"     # 反引号 → 命令替换
  s="${s//\$/}"     # 美元 → 变量展开
  s="${s//\\/}"     # 反斜杠 → 转义
  s="${s//|/_}"     # tag 分隔符
  s="${s//$'\r'/}"; s="${s//$'\n'/ }"; s="${s//$'\t'/ }"

  # 按 byte 截断: iptables comment 上限 256 byte, tag 前缀最多 ~55 byte, remark 最多 200 byte
  # bash `${s:0:N}` 在 UTF-8 环境是按字符计数, 100 中文 = 300 byte 会撑爆
  # 用 wc -c (byte) 循环裁末尾字符 (${s%?} 按字符裁, 保证不切开多字节)
  local max_bytes=200
  while (( $(printf '%s' "$s" | wc -c) > max_bytes )); do
    s="${s%?}"
  done
  printf '%s' "$s"
}

_make_tag() {
  local lport="$1" proto="$2" rip="$3" rport="$4" snat="$5" remark="$6"
  remark=$(_sanitize_remark "$remark")
  echo "${COMMENT_TAG}|${lport}|${proto}|${rip}|${rport}|${snat}|${remark}"
}

# 输入 tag，输出 (lport proto rip rport snat remark) TAB 分隔
_parse_tag() {
  local tag_head lport proto rip rport snat remark
  IFS='|' read -r tag_head lport proto rip rport snat remark <<< "$1"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$lport" "$proto" "$rip" "$rport" "$snat" "${remark:-}"
}

# 拿 CHAIN_PRE 里所有规则的原文（用 iptables-save 而非 -S，输出更 canonical）
_dump_pre_rules() {
  if command -v iptables-save >/dev/null 2>&1; then
    iptables-save -t nat 2>/dev/null | grep -E "^-A ${CHAIN_PRE}( |$)" || true
  else
    ipt -t nat -S "$CHAIN_PRE" 2>/dev/null | grep -E "^-A ${CHAIN_PRE}( |$)" || true
  fi
}

_list_tags() {
  # 三种 comment 格式都能匹配: "IPTPF|..." / 'IPTPF|...' / IPTPF|...
  # (少数 iptables-nft 版本据说会输出单引号，双 sed 表达式代价极低)
  _dump_pre_rules | sed -n \
    -e 's/.*--comment "\(IPTPF|[^"]*\)".*/\1/p' \
    -e "s/.*--comment '\(IPTPF|[^']*\)'.*/\1/p" \
    -e 's/.*--comment \(IPTPF|[^ ]*\).*/\1/p' \
    | awk 'NF && !seen[$0]++'
}

_count_legacy_rules() {
  local total tagged
  total=$(_dump_pre_rules | grep -c -- '-j DNAT' || true)
  tagged=$(_list_tags | wc -l | tr -d ' ')
  echo $(( total - tagged ))
}

### ---------- 添加 ----------
_dnat_exists() {
  local lport="$1" proto="$2" rip="$3" rport="$4" tag="$5"
  ipt -t nat -C "$CHAIN_PRE" -p "$proto" --dport "$lport" \
    -m comment --comment "$tag" -j DNAT --to-destination "${rip}:${rport}" 2>/dev/null
}

_add_one() {
  # 返回码: 0=新增成功  1=错误  2=重复(已存在，跳过)
  local lport="$1" proto="$2" rip="$3" rport="$4" snat="$5" remark="$6"
  local tag; tag=$(_make_tag "$lport" "$proto" "$rip" "$rport" "$snat" "$remark")

  local existing
  existing=$(_list_tags | awk -F'|' -v l="$lport" -v p="$proto" '$2==l && $3==p' | head -1)
  if [[ -n "$existing" ]]; then
    warn "已存在 ${proto}/${lport} 规则: $existing"
    warn "  如需变更目标，请先删除: sudo ${CMD_NAME} del ${lport} ${proto}"
    return 2
  fi

  ipt -t nat -A "$CHAIN_PRE" \
    -p "$proto" --dport "$lport" \
    -m comment --comment "$tag" \
    -j DNAT --to-destination "${rip}:${rport}"

  # SNAT 加 --ctstate DNAT: 只对经过 DNAT 的中转连接生效，
  # 避免 VPS 自身访问 $rip:$rport 时被误 SNAT
  ipt -t nat -A "$CHAIN_POST" \
    -p "$proto" -d "$rip" --dport "$rport" \
    -m conntrack --ctstate DNAT \
    -m comment --comment "$tag" \
    -j SNAT --to-source "$snat"

  log "${Info} 添加: $proto ${lport} -> ${rip}:${rport} (SNAT ${snat})${remark:+ [$remark]}"
}

_validate_rule() {
  local lport="$1" proto="$2" rip="$3" rport="$4" snat="$5"
  validate_port  "$lport" || { warn "本机端口非法: $lport"; return 1; }
  validate_port  "$rport" || { warn "目标端口非法: $rport"; return 1; }
  validate_ip    "$rip"   || { warn "目标 IP 非法: $rip"; return 1; }
  validate_ip    "$snat"  || { warn "SNAT IP 非法: $snat"; return 1; }
  validate_proto "$proto" || { warn "协议非法: $proto (支持 tcp/udp/both)"; return 1; }
}

# 对外主接口：一条规则 (proto 可为 tcp/udp/both；both 展开为两条)
# 返回码: 0=全部新增  2=全部重复  3=部分新增(both 时一新一旧)  1=错误
add_rules_multi_proto() {
  local lport="$1" proto="$2" rip="$3" rport="$4" snat="$5" remark="${6:-}"
  _validate_rule "$lport" "$proto" "$rip" "$rport" "$snat" || return 1

  local r1=0 r2=0 rc=0
  if [[ "$proto" == "both" ]]; then
    _add_one "$lport" tcp "$rip" "$rport" "$snat" "$remark" || r1=$?
    _add_one "$lport" udp "$rip" "$rport" "$snat" "$remark" || r2=$?
    if   (( r1 == 1 || r2 == 1 )); then return 1
    elif (( r1 == 0 && r2 == 0 )); then return 0
    elif (( r1 == 2 && r2 == 2 )); then return 2
    else return 3   # 一个新增一个重复
    fi
  else
    _add_one "$lport" "$proto" "$rip" "$rport" "$snat" "$remark" || rc=$?
    return $rc
  fi
}

interactive_add() {
  echo -e "\n${Info} 添加端口转发规则"
  echo "------------------------------------------"

  local RIP RPORT LPORT MODE SNAT_IP PTYPE REMARK proto USER_IP OK

  read -rp "$(echo -e ${Ask}) 转发目标 IP: " RIP
  validate_ip "$RIP" || { log "${Error} IP 格式错误"; return 1; }

  read -rp "$(echo -e ${Ask}) 转发目标端口: " RPORT
  validate_port "$RPORT" || { log "${Error} 端口非法"; return 1; }

  read -rp "$(echo -e ${Ask}) 本机监听端口 (默认=$RPORT): " LPORT
  LPORT="${LPORT:-$RPORT}"
  validate_port "$LPORT" || { log "${Error} 端口非法"; return 1; }

  echo -e "\n${Tip} SNAT 源 IP:"
  echo "  1) 内网 IP (自动检测)"
  echo "  2) 公网 IP (自动检测)"
  read -rp "$(echo -e ${Ask}) 选择 [1-2] (默认 1): " MODE
  MODE="${MODE:-1}"
  if [[ "$MODE" == "2" ]]; then
    SNAT_IP=$(detect_wan_ip)
    if [[ -z "$SNAT_IP" ]]; then
      warn "自动获取公网 IP 失败 (可能 DNS 异常或 443 出口被墙)"
      warn "  请手工输入公网 IP，或按 Ctrl+C 取消后重新选模式 1 (用内网 IP)"
    else
      echo -e "${Info} 检测到公网 IP: $SNAT_IP"
    fi
  else
    SNAT_IP=$(detect_lan_ip)
    if [[ -z "$SNAT_IP" ]]; then
      warn "自动获取内网 IP 失败 (可能无默认路由)"
      warn "  请手工输入本机内网 IP"
    else
      echo -e "${Info} 检测到内网 IP: $SNAT_IP"
    fi
  fi
  read -rp "$(echo -e ${Ask}) SNAT IP (回车使用上面的值): " USER_IP
  [[ -n "$USER_IP" ]] && SNAT_IP="$USER_IP"
  validate_ip "$SNAT_IP" || { log "${Error} SNAT IP 非法: '${SNAT_IP:-空}'"; return 1; }

  read -rp "$(echo -e ${Ask}) 协议 [1=TCP  2=UDP  3=TCP+UDP] (默认 3): " PTYPE
  PTYPE="${PTYPE:-3}"
  case "$PTYPE" in 1) proto=tcp;; 2) proto=udp;; 3) proto=both;; *) log "${Error} 协议选择非法"; return 1;; esac

  read -rp "$(echo -e ${Ask}) 备注 (可选，用于识别用途): " REMARK

  echo -e "\n${Info} 配置摘要:"
  echo "  监听 : $SNAT_IP:$LPORT  ($proto)"
  echo "  目标 : $RIP:$RPORT"
  echo "  备注 : ${REMARK:-<无>}"
  read -rp "$(echo -e ${Ask}) 确认添加? [Y/n]: " OK
  [[ "$OK" == "n" || "$OK" == "N" ]] && { log "${Tip} 已取消"; return; }

  local _rc=0
  add_rules_multi_proto "$LPORT" "$proto" "$RIP" "$RPORT" "$SNAT_IP" "$REMARK" || _rc=$?
  case "$_rc" in
    0) save_rules ;;
    2) log "${Tip} 规则已存在，未做修改" ;;
    3) save_rules; log "${Info} 部分协议已存在，其余已新增并保存" ;;
    *) log "${Error} 添加失败"; return 1 ;;
  esac
}

interactive_batch_add() {
  echo -e "\n${Info} 批量添加"
  echo "------------------------------------------"
  echo -e "${Tip} 格式:  本机IP:端口=目标IP:端口"
  echo -e "${Tip} 例如:  1.1.1.1:11=2.2.2.2:22"
  echo -e "${Tip} 空行结束; 输入 q 返回"
  echo "------------------------------------------"

  local rules=() rule i=1
  local _lip _lport _rip _rport _rest
  while true; do
    read -rp "$(echo -e ${Ask}) 规则 ${i}: " rule
    [[ "$rule" == "q" || "$rule" == "Q" ]] && return 1
    [[ -z "$rule" ]] && break
    if ! [[ "$rule" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]+=([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]+$ ]]; then
      log "${Error} 格式错误 (应为 本机IP:端口=目标IP:端口)"
      continue
    fi
    # 逐行深度校验：拦下 999.999.999.999 / 端口 > 65535 / 前导零之类
    _lip="${rule%%:*}"; _rest="${rule#*:}"
    _lport="${_rest%%=*}"; _rest="${_rest#*=}"
    _rip="${_rest%%:*}"; _rport="${_rest#*:}"
    if   ! validate_ip   "$_lip";   then log "${Error} 本机 IP 非法: $_lip";       continue
    elif ! validate_ip   "$_rip";   then log "${Error} 目标 IP 非法: $_rip";       continue
    elif ! validate_port "$_lport"; then log "${Error} 本机端口非法: $_lport";     continue
    elif ! validate_port "$_rport"; then log "${Error} 目标端口非法: $_rport";     continue
    fi
    rules+=("$rule")
    i=$((i+1))
  done
  (( ${#rules[@]} == 0 )) && { log "${Tip} 未输入任何规则"; return; }

  local PTYPE proto REMARK OK
  read -rp "$(echo -e ${Ask}) 协议 [1=TCP 2=UDP 3=TCP+UDP] (默认 3): " PTYPE
  PTYPE="${PTYPE:-3}"
  case "$PTYPE" in 1) proto=tcp;; 2) proto=udp;; 3) proto=both;; *) log "${Error} 协议选择非法"; return 1;; esac

  read -rp "$(echo -e ${Ask}) 统一备注 (可选): " REMARK

  echo -e "\n${Info} 即将添加 ${#rules[@]} 条规则 (协议: $proto):"
  local r lip lport rest rip rport
  for r in "${rules[@]}"; do
    lip="${r%%:*}"; rest="${r#*:}"
    lport="${rest%%=*}"; rest="${rest#*=}"
    rip="${rest%%:*}"; rport="${rest#*:}"
    echo "  $lip:$lport  ->  $rip:$rport"
  done
  read -rp "$(echo -e ${Ask}) 确认添加所有规则? [Y/n]: " OK
  [[ "$OK" == "n" || "$OK" == "N" ]] && { log "${Tip} 已取消"; return; }

  local added=0 dup=0 partial=0 fail=0 rc
  for r in "${rules[@]}"; do
    lip="${r%%:*}"; rest="${r#*:}"
    lport="${rest%%=*}"; rest="${rest#*=}"
    rip="${rest%%:*}"; rport="${rest#*:}"
    # 关键: 每条规则用它自己的本机 IP 作 SNAT 源
    rc=0
    add_rules_multi_proto "$lport" "$proto" "$rip" "$rport" "$lip" "$REMARK" || rc=$?
    case "$rc" in
      0) added=$((added+1)) ;;
      2) dup=$((dup+1)) ;;
      3) partial=$((partial+1)) ;;
      *) fail=$((fail+1)) ;;
    esac
  done
  save_rules
  log "${Info} 完成: 新增 $added / 部分新增 $partial / 全部重复 $dup / 失败 $fail"
}

### ---------- 列表 ----------
_print_rules_table() {
  local tags=() tag
  while IFS= read -r tag; do tags+=("$tag"); done < <(_list_tags)

  if (( ${#tags[@]} == 0 )); then
    echo -e "${Tip} （暂无规则）"
    return 1
  fi

  printf "%-4s %-6s %-24s %-24s %-16s %s\n" "序号" "协议" "监听" "目标" "SNAT" "备注"
  echo "----------------------------------------------------------------------------------------------"
  local i=0 lport proto rip rport snat remark
  for tag in "${tags[@]}"; do
    i=$((i+1))
    IFS=$'\t' read -r lport proto rip rport snat remark < <(_parse_tag "$tag")
    printf "%-4d %-6s %-24s %-24s %-16s %s\n" \
      "$i" "$proto" "0.0.0.0:${lport}" "${rip}:${rport}" "$snat" "${remark:-}"
  done
  return 0
}

list_rules() {
  echo -e "\n${Info} 当前转发规则:"
  echo "----------------------------------------------------------------------------------------------"
  _print_rules_table || true
  echo "----------------------------------------------------------------------------------------------"

  local legacy; legacy=$(_count_legacy_rules)
  if (( legacy > 0 )); then
    warn "另有 ${legacy} 条旧格式规则 (无 comment 标签)，本工具无法安全管理"
    warn "  建议: 执行菜单 [清空] 后重新添加，或手工用 iptables -D 清理"
  fi
}

### ---------- 删除 ----------
_delete_by_tag() {
  local tag="$1"
  IFS=$'\t' read -r lport proto rip rport snat remark < <(_parse_tag "$tag")

  # max=100: 正常应只有 1 条; 上调兜底以防手工/旧脚本残留大量同 tag 副本
  local n=0 max=100 removed=0

  # 底层规则应各只有 1 条，用 while+iptables -C 兜底重复
  while (( n++ < max )) && ipt -t nat -C "$CHAIN_PRE" -p "$proto" --dport "$lport" \
       -m comment --comment "$tag" -j DNAT --to-destination "${rip}:${rport}" 2>/dev/null; do
    ipt -t nat -D "$CHAIN_PRE" -p "$proto" --dport "$lport" \
       -m comment --comment "$tag" -j DNAT --to-destination "${rip}:${rport}"
    removed=$((removed+1))
  done

  n=0
  while (( n++ < max )) && ipt -t nat -C "$CHAIN_POST" -p "$proto" -d "$rip" --dport "$rport" \
       -m conntrack --ctstate DNAT \
       -m comment --comment "$tag" -j SNAT --to-source "$snat" 2>/dev/null; do
    ipt -t nat -D "$CHAIN_POST" -p "$proto" -d "$rip" --dport "$rport" \
       -m conntrack --ctstate DNAT \
       -m comment --comment "$tag" -j SNAT --to-source "$snat"
    removed=$((removed+1))
  done

  # 兼容旧版添加的 SNAT (没有 --ctstate DNAT)
  n=0
  while (( n++ < max )) && ipt -t nat -C "$CHAIN_POST" -p "$proto" -d "$rip" --dport "$rport" \
       -m comment --comment "$tag" -j SNAT --to-source "$snat" 2>/dev/null; do
    ipt -t nat -D "$CHAIN_POST" -p "$proto" -d "$rip" --dport "$rport" \
       -m comment --comment "$tag" -j SNAT --to-source "$snat"
    removed=$((removed+1))
  done

  log "${Info} 已删除: $proto $lport -> $rip:$rport${remark:+ [$remark]} (共 $removed 条)"
}

# 解析 "1,3,5-8,all" 类的编号表达式，输出编号列表(去重升序)
_expand_indices() {
  local expr="$1" total="$2"
  local -a parts out=()
  local part start end i
  IFS=',' read -ra parts <<< "$expr"
  for part in "${parts[@]}"; do
    part="${part// /}"
    [[ -z "$part" ]] && continue
    if [[ "$part" == "all" || "$part" == "ALL" ]]; then
      for ((i=1; i<=total; i++)); do out+=("$i"); done
    elif [[ "$part" =~ ^([0-9]+)-([0-9]+)$ ]]; then
      start="${BASH_REMATCH[1]}"; end="${BASH_REMATCH[2]}"
      (( start >= 1 && end <= total && start <= end )) || return 1
      for ((i=start; i<=end; i++)); do out+=("$i"); done
    elif [[ "$part" =~ ^[0-9]+$ ]]; then
      (( part >= 1 && part <= total )) || return 1
      out+=("$part")
    else
      return 1
    fi
  done
  (( ${#out[@]} == 0 )) && return 1
  printf '%s\n' "${out[@]}" | sort -un
}

interactive_delete() {
  local IDX tags nums n tag
  while true; do
    echo ""
    _print_rules_table || { echo ""; return; }
    echo ""
    echo -e "${Tip} 支持: 单个(3) / 范围(1-3) / 组合(1,3,5-8) / all / q 退出"
    read -rp "$(echo -e ${Ask}) 删除编号: " IDX
    [[ "$IDX" == "q" || "$IDX" == "Q" ]] && break
    [[ -z "$IDX" ]] && continue

    tags=()
    while IFS= read -r tag; do tags+=("$tag"); done < <(_list_tags)
    local total="${#tags[@]}"
    (( total == 0 )) && break

    if ! nums=$(_expand_indices "$IDX" "$total"); then
      log "${Error} 编号格式错误或越界 (当前共 $total 条)"
      continue
    fi

    # 危险操作二次确认：输入含 all 或选中了全部规则
    local sel_count C2
    sel_count=$(echo "$nums" | grep -c .)
    if [[ "$IDX" =~ [aA][lL][lL] ]] || (( sel_count == total )); then
      echo -e "${Warn} 即将删除全部 ${total} 条规则！"
      read -rp "$(echo -e ${Ask}) 确认? [y/N]: " C2
      if [[ "$C2" != "y" && "$C2" != "Y" ]]; then
        log "${Tip} 已取消"
        continue
      fi
    fi

    # 从大到小删除，避免影响序号（此处按 tag 数组下标不受影响，但保持惯例）
    local nums_desc
    nums_desc=$(echo "$nums" | sort -rn)
    while IFS= read -r n; do
      [[ -z "$n" ]] && continue
      _delete_by_tag "${tags[n-1]}"
    done <<< "$nums_desc"

    save_rules
  done
}

### ---------- 清空 ----------
clear_all() {
  local count; count=$(_list_tags | wc -l | tr -d ' ')
  echo -e "${Warn} 这将清空所有由本脚本添加的转发规则！(当前共 ${count} 条)"
  echo -e "${Warn} 为防手滑，请完整输入 'yes' 确认；其它任何输入均取消。"
  local CONFIRM
  read -rp "$(echo -e ${Ask}) 输入 yes 确认: " CONFIRM
  if [[ "$CONFIRM" != "yes" ]]; then
    log "${Tip} 已取消"
    return
  fi

  ipt -t nat -F "$CHAIN_PRE"  2>/dev/null || true
  ipt -t nat -F "$CHAIN_POST" 2>/dev/null || true
  log "${Info} 已清空专用链内所有规则"

  local RM_HOOK
  read -rp "$(echo -e ${Ask}) 是否同时移除主链钩子(-j $CHAIN_PRE / $CHAIN_POST)? [y/N]: " RM_HOOK
  if [[ "$RM_HOOK" == "y" || "$RM_HOOK" == "Y" ]]; then
    while ipt -t nat -C PREROUTING  -j "$CHAIN_PRE"  2>/dev/null; do
      ipt -t nat -D PREROUTING  -j "$CHAIN_PRE"
    done
    while ipt -t nat -C POSTROUTING -j "$CHAIN_POST" 2>/dev/null; do
      ipt -t nat -D POSTROUTING -j "$CHAIN_POST"
    done
    ipt -t nat -X "$CHAIN_PRE"  2>/dev/null || true
    ipt -t nat -X "$CHAIN_POST" 2>/dev/null || true
    log "${Info} 已移除主链钩子并删除专用链"
  else
    log "${Tip} 已保留主链钩子（下次直接添加规则仍会生效）"
  fi

  save_rules
}

### ---------- 导入导出 ----------
export_rules() {
  local file="${1:-/root/iptpf-rules.txt}"
  {
    echo "# iptpf 规则导出"
    echo "# version:  ${VERSION}"
    echo "# backend:  $(detect_backend)"
    echo "# hostname: $(hostname 2>/dev/null || echo unknown)"
    echo "# date:     $(date '+%F %T')"
    echo "# 格式:     lport|proto|rip|rport|snat|remark"
  } > "$file"

  local tag lport proto rip rport snat remark n=0
  while IFS= read -r tag; do
    IFS=$'\t' read -r lport proto rip rport snat remark < <(_parse_tag "$tag")
    printf '%s|%s|%s|%s|%s|%s\n' "$lport" "$proto" "$rip" "$rport" "$snat" "$remark" >> "$file"
    n=$((n+1))
  done < <(_list_tags)
  log "${Info} 已导出 ${n} 条到 $file"
}

import_rules() {
  local file="${1:?请指定导入文件}"
  [[ -f "$file" ]] || die "文件不存在: $file"

  local lport proto rip rport snat remark lineno=0 errors=0

  # 第 1 遍：全量校验（含格式和 IP/端口/协议合法性）
  log "${Info} 校验中..."
  while IFS='|' read -r lport proto rip rport snat remark; do
    lineno=$((lineno+1))
    [[ -z "${lport:-}" ]] && continue
    [[ "$lport" =~ ^[[:space:]]*# ]] && continue
    if ! _validate_rule "$lport" "$proto" "$rip" "$rport" "$snat" 2>/dev/null; then
      warn "第 $lineno 行校验失败: ${lport}|${proto}|${rip}|${rport}|${snat}"
      errors=$((errors+1))
    fi
  done < "$file"

  if (( errors > 0 )); then
    die "共 $errors 处校验失败，未导入任何规则；请先修正文件再重试"
  fi

  # 第 2 遍：实际添加
  log "${Info} 校验通过，开始导入..."
  local added=0 dup=0 partial=0 fail=0 rc
  while IFS='|' read -r lport proto rip rport snat remark; do
    [[ -z "${lport:-}" ]] && continue
    [[ "$lport" =~ ^[[:space:]]*# ]] && continue
    rc=0
    add_rules_multi_proto "$lport" "$proto" "$rip" "$rport" "$snat" "${remark:-}" || rc=$?
    case "$rc" in
      0) added=$((added+1)) ;;
      2) dup=$((dup+1)) ;;
      3) partial=$((partial+1)) ;;
      *) fail=$((fail+1)) ;;
    esac
  done < "$file"

  save_rules
  log "${Info} 导入完成: 新增 $added / 部分新增 $partial / 全部重复 $dup / 失败 $fail"
}

### ---------- IPv6 开关 ----------
IPV6_CONF_FILE="/etc/sysctl.d/99-disable-ipv6.conf"

_ipv6_status() {
  local v
  v=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "?")
  case "$v" in
    0) echo "启用" ;;
    1) echo "已禁用" ;;
    *) echo "未知" ;;
  esac
}

disable_ipv6() {
  echo -e "${Warn} 将从内核禁用 IPv6，并清除所有网卡上的 IPv6 地址"
  echo -e "${Tip} 当前状态: $(_ipv6_status)"
  local C
  read -rp "$(echo -e ${Ask}) 确认禁用? [y/N]: " C
  [[ "$C" != "y" && "$C" != "Y" ]] && { log "${Tip} 已取消"; return; }

  # 1. 立即从内核生效
  sysctl -w net.ipv6.conf.all.disable_ipv6=1     >/dev/null || die "sysctl 写入失败"
  sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null || die "sysctl 写入失败"
  sysctl -w net.ipv6.conf.lo.disable_ipv6=1      >/dev/null || die "sysctl 写入失败"

  # 2. 清掉旧脚本可能写入 /etc/sysctl.conf 的重复条目，避免冲突
  if [[ -f /etc/sysctl.conf ]]; then
    sed -i.bak '/net\.ipv6\.conf\.\(all\|default\|lo\)\.disable_ipv6/d' /etc/sysctl.conf
  fi

  # 3. 写入独立配置文件（与主 sysctl.conf 隔离，便于卸载）
  mkdir -p /etc/sysctl.d
  cat > "$IPV6_CONF_FILE" <<EOF
# 由 ${CMD_NAME} 管理；启用 IPv6 请运行: sudo ${CMD_NAME} enable-ipv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
  sysctl -p "$IPV6_CONF_FILE" >/dev/null 2>&1 || true

  # 4. 清除所有网卡（除 lo）上现存的 IPv6 地址；不只 eth0
  local ifn ifname flushed=0
  for ifn in /sys/class/net/*; do
    ifname=$(basename "$ifn")
    [[ "$ifname" == "lo" ]] && continue
    ip -6 addr flush dev "$ifname" 2>/dev/null && flushed=$((flushed+1)) || true
  done
  log "${Info} 已刷新 ${flushed} 张网卡的 IPv6 地址"

  # 5. 验证 (只看 global scope，link-local 是正常的)
  local remain
  remain=$(ip -6 addr show scope global 2>/dev/null | grep -c inet6 || true)
  if (( remain == 0 )); then
    log "${Info} IPv6 已彻底禁用 (配置: $IPV6_CONF_FILE)"
  else
    warn "IPv6 仍有 ${remain} 条全局地址残留，可能需要重启网卡或系统"
  fi
}

check_ipv6() {
  echo -e "\n${Info} ============ IPv6 状态复核 ============"
  local issues=0

  # [1] sysctl 三个关键值
  echo -e "\n${Info} [1] 内核 sysctl:"
  local k v
  for k in net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.default.disable_ipv6 net.ipv6.conf.lo.disable_ipv6; do
    v=$(sysctl -n "$k" 2>/dev/null || echo "?")
    if [[ "$v" == "1" ]]; then
      printf "     [OK]   %-45s = %s\n" "$k" "$v"
    else
      printf "     [WARN] %-45s = %s   <-- 未禁用\n" "$k" "$v"
      issues=$((issues+1))
    fi
  done

  # [2] 持久化配置
  echo -e "\n${Info} [2] 持久化配置文件:"
  if [[ -f "$IPV6_CONF_FILE" ]]; then
    echo "     [OK]   $IPV6_CONF_FILE 存在"
  else
    echo "     [WARN] $IPV6_CONF_FILE 不存在 —— 重启后 IPv6 会恢复！"
    issues=$((issues+1))
  fi

  # [3] 现存全局 IPv6 地址
  echo -e "\n${Info} [3] 现存 IPv6 全局地址 (link-local fe80:: 是正常的，不列出):"
  local addrs
  addrs=$(ip -6 addr show scope global 2>/dev/null | grep -E "^\s+inet6" || true)
  if [[ -z "$addrs" ]]; then
    echo "     [OK]   无全局 IPv6 地址"
  else
    echo "     [WARN] 仍有以下地址残留:"
    echo "$addrs" | sed 's/^/            /'
    issues=$((issues+1))
  fi

  # [4] IPv6 路由
  echo -e "\n${Info} [4] IPv6 路由 (link-local / 回环除外):"
  local routes
  routes=$(ip -6 route show 2>/dev/null | grep -v -E "^fe80|^::1|^unreachable" || true)
  if [[ -z "$routes" ]]; then
    echo "     [OK]   无 IPv6 全局路由"
  else
    echo "     [WARN] 仍有以下路由:"
    echo "$routes" | sed 's/^/            /'
    issues=$((issues+1))
  fi

  # [5] IPv6 socket 监听
  echo -e "\n${Info} [5] 监听 IPv6 socket 的服务:"
  if command -v ss >/dev/null 2>&1; then
    local listeners
    listeners=$(ss -tuln6 2>/dev/null | awk 'NR>1 {printf "%-6s %s\n", $1, $5}' | sort -u)
    if [[ -z "$listeners" ]]; then
      echo "     [OK]   无服务监听 IPv6"
    else
      echo "     [TIP]  以下服务仍占用 IPv6 socket (无流量进来，但 socket 未释放；"
      echo "            如需清理请 systemctl restart 对应服务):"
      echo "$listeners" | sed 's/^/            /'
    fi
  else
    echo "     [SKIP] 缺少 ss 命令"
  fi

  # [6] 内核模块
  echo -e "\n${Info} [6] ipv6 内核模块:"
  if lsmod 2>/dev/null | grep -q "^ipv6 "; then
    echo "     [TIP]  ipv6 模块仍加载 (sysctl 禁用不卸载模块，属于正常现象)"
    echo "            如需彻底卸载: 编辑 /etc/default/grub，GRUB_CMDLINE_LINUX 加 ipv6.disable=1"
    echo "            然后 update-grub (或 grub2-mkconfig) 并重启"
  else
    echo "     [OK]   ipv6 模块未加载 (最彻底状态)"
  fi

  # [7] GRUB 参数
  echo -e "\n${Info} [7] GRUB 内核参数:"
  if grep -q "ipv6.disable=1" /proc/cmdline 2>/dev/null; then
    echo "     [OK]   /proc/cmdline 含 ipv6.disable=1"
  else
    echo "     [TIP]  未通过 GRUB 禁用 (对本脚本的中转功能无影响)"
  fi

  # 结论
  echo -e "\n${Info} ============ 结论 ============"
  if (( issues == 0 )); then
    log "${Info} IPv6 已成功禁用，对网络转发功能已完全足够；无需重启"
    log "${Tip} 如上面 [5] 列出了 IPv6 socket，重启对应服务可清理"
  else
    warn "发现 ${issues} 项问题，建议重新执行: sudo ${CMD_NAME} disable-ipv6"
  fi
  echo ""
}

enable_ipv6() {
  echo -e "${Info} 将启用 IPv6"
  echo -e "${Tip} 当前状态: $(_ipv6_status)"
  local C
  read -rp "$(echo -e ${Ask}) 确认启用? [y/N]: " C
  [[ "$C" != "y" && "$C" != "Y" ]] && { log "${Tip} 已取消"; return; }

  sysctl -w net.ipv6.conf.all.disable_ipv6=0     >/dev/null || die "sysctl 写入失败"
  sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null || die "sysctl 写入失败"
  sysctl -w net.ipv6.conf.lo.disable_ipv6=0      >/dev/null || die "sysctl 写入失败"

  rm -f "$IPV6_CONF_FILE"

  if [[ -f /etc/sysctl.conf ]]; then
    sed -i.bak '/net\.ipv6\.conf\.\(all\|default\|lo\)\.disable_ipv6/d' /etc/sysctl.conf
  fi

  log "${Info} IPv6 已启用 (删除配置: $IPV6_CONF_FILE)"
  log "${Tip} 网卡可能需要重启或执行 'dhclient -6 <网卡名>' 才会获取新的 IPv6 地址"
}

### ---------- 安装到系统 ----------
install_self() {
  local name="${1:-$CMD_NAME}"
  local dst="${INSTALL_DIR}/${name}"
  local src
  src=$(readlink -f "$0" 2>/dev/null || echo "$0")
  [[ -f "$src" ]] || die "找不到脚本源文件: $src"
  mkdir -p "$INSTALL_DIR"
  cp -f "$src" "$dst" || die "复制失败: $dst"
  chmod +x "$dst"
  log "${Info} 已安装到 $dst"
  log "${Info} 之后可直接使用: sudo $name           (进菜单)"
  log "${Info}                  sudo $name list      (查规则)"
  log "${Info}                  sudo $name add ...   (加规则)"
}

uninstall_self() {
  local name="${1:-$CMD_NAME}"
  local dst="${INSTALL_DIR}/${name}"
  if [[ -f "$dst" ]]; then
    rm -f "$dst" && log "${Info} 已移除 $dst"
  else
    warn "未找到 $dst"
  fi
}

### ---------- CLI ----------
usage() {
  cat <<EOF
用法: $0 <子命令> [参数...]

子命令:
  install [name]                      安装为系统命令 (默认: $CMD_NAME)
  uninstall [name]                    卸载系统命令 (默认: $CMD_NAME)
  init                                初始化 (安装 iptables / 开转发 / 建链)
  list | ls                           列出所有规则
  add <lport> <proto> <rip:rport> <snat> [remark]
                                      添加规则；proto = tcp | udp | both
  del <lport> <proto> [rip:rport] [--dry-run]
                                      删除规则；只给 lport+proto 会删中该端口的规则，
                                      带 rip:rport 更精确；--dry-run 仅预览不删除
  clear                               清空所有规则 (交互确认)
  export [file]                       导出规则 (默认 /root/iptpf-rules.txt)
  import <file>                       从文件导入规则
  disable-ipv6                        禁用 IPv6 (含持久化，无需重启)
  enable-ipv6                         恢复启用 IPv6
  check-ipv6                          复核 IPv6 状态 (sysctl / 地址 / 路由 / 监听 / 模块)
  menu                                进入交互菜单 (无参数时默认)

首次使用:
  sudo bash $0 install                # 装成系统命令
  sudo $CMD_NAME init                 # 完成初始化 (装 iptables、开转发、建链)

添加规则示例:
  sudo $CMD_NAME add 10022 tcp  1.2.3.4:22   192.168.1.10  my-vps-ssh
  sudo $CMD_NAME add 20000 both 2.3.4.5:443  10.0.0.5      web-relay
  sudo $CMD_NAME add 30000 udp  8.8.8.8:53   10.0.0.5      dns
  sudo $CMD_NAME add 40000 tcp  5.6.7.8:80   10.0.0.5      客户A 反代 nginx     # 备注可带空格/中文

删除规则示例:
  sudo $CMD_NAME del 10022 tcp                # 删掉所有 tcp/10022 规则
  sudo $CMD_NAME del 10022 tcp  1.2.3.4:22    # 精确删 (端口相同、目标不同才需要)
  sudo $CMD_NAME del 20000 both               # both = 同时删 tcp+udp
  sudo $CMD_NAME del 10022 tcp  --dry-run     # 预览会删掉哪些，不实际删

查询与备份:
  sudo $CMD_NAME list
  sudo $CMD_NAME export /root/pf-\$(date +%F).txt
  sudo $CMD_NAME import /root/pf-2026-08-04.txt
EOF
}

cli_add() {
  local lport="${1:-}" proto="${2:-}" target="${3:-}" snat="${4:-}"
  [[ -z "$lport" || -z "$proto" || -z "$target" || -z "$snat" ]] && { usage; exit 1; }

  # 前 4 个是定位参数，剩余全部拼成 remark（支持带空格的备注不加引号）
  shift 4
  local remark="${*:-}"

  local rip rport
  if [[ "$target" == *:* ]]; then
    rip="${target%:*}"
    rport="${target##*:}"
  else
    die "目标格式错误，应为 rip:rport (如 1.2.3.4:22)，当前: $target"
  fi
  [[ -z "$rip" || -z "$rport" ]] && die "目标格式错误: $target"

  local _rc=0
  add_rules_multi_proto "$lport" "$proto" "$rip" "$rport" "$snat" "$remark" || _rc=$?
  case "$_rc" in
    0) save_rules ;;
    2) log "${Tip} 规则已存在，未做修改"; exit 0 ;;
    3) save_rules; log "${Info} 部分协议已存在，其余已新增" ;;
    *) exit 1 ;;
  esac
}

cli_del() {
  # 从参数中剥离 --dry-run（可以出现在任何位置）
  local dry_run=0
  local -a args=()
  local a
  for a in "$@"; do
    if [[ "$a" == "--dry-run" || "$a" == "-n" ]]; then
      dry_run=1
    else
      args+=("$a")
    fi
  done
  set -- "${args[@]}"

  local lport="${1:-}" proto="${2:-}" target="${3:-}"
  [[ -z "$lport" || -z "$proto" ]] && { usage; exit 1; }

  local rip="" rport=""
  if [[ -n "$target" ]]; then
    if [[ "$target" == *:* ]]; then
      rip="${target%:*}"; rport="${target##*:}"
    else
      die "目标格式错误，应为 rip:rport (如 1.2.3.4:22)"
    fi
  fi

  local protos
  case "$proto" in
    both) protos="tcp udp" ;;
    tcp|udp) protos="$proto" ;;
    *) die "协议非法: $proto (支持 tcp/udp/both)" ;;
  esac

  (( dry_run )) && log "${Tip} [dry-run] 仅预览，不实际删除"

  local tag matched=0 p_lport p_proto p_rip p_rport p_snat p_remark p
  while IFS= read -r tag; do
    IFS=$'\t' read -r p_lport p_proto p_rip p_rport p_snat p_remark < <(_parse_tag "$tag")
    [[ "$p_lport" != "$lport" ]] && continue
    for p in $protos; do
      if [[ "$p_proto" == "$p" ]] \
         && [[ -z "$rip"   || "$p_rip"   == "$rip"   ]] \
         && [[ -z "$rport" || "$p_rport" == "$rport" ]]; then
        if (( dry_run )); then
          log "${Info} [dry-run] 匹配: ${p_proto} ${p_lport} -> ${p_rip}:${p_rport} (SNAT ${p_snat})${p_remark:+ [$p_remark]}"
        else
          _delete_by_tag "$tag"
        fi
        matched=$((matched+1))
        break
      fi
    done
  done < <(_list_tags)

  if (( matched == 0 )); then
    warn "未匹配到任何规则"
    return 1
  fi
  if (( dry_run )); then
    log "${Info} [dry-run] 共匹配 ${matched} 条 (未删除)"
  else
    save_rules
  fi
}

### ---------- 菜单 ----------
_menu_status() {
  local backend fwd fwd_v ipv6 persist count
  backend=$(detect_backend)
  fwd_v=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "?")
  case "$fwd_v" in 1) fwd="ON";; 0) fwd="OFF";; *) fwd="?";; esac
  ipv6=$(_ipv6_status)
  persist=$(_persistence_status | cut -d: -f1)
  count=$(_list_tags | wc -l | tr -d ' ')

  printf "   %-14s : %s\n" "iptables 后端" "$backend"
  printf "   %-14s : %s\n" "IPv4 转发"     "$fwd"
  printf "   %-14s : %s\n" "IPv6"          "$ipv6"
  printf "   %-14s : %s\n" "持久化服务"    "$persist"
  printf "   %-14s : %s\n" "已管理规则"    "$count 条"
}

show_menu() {
  local installed_hint=""
  [[ -x "${INSTALL_DIR}/${CMD_NAME}" ]] && installed_hint="  (cmd: ${CMD_NAME})"
  echo ""
  echo -e "  iptables 端口转发管理  [${VERSION}]${installed_hint}"
  echo -e "  =========================================="
  _menu_status
  echo -e "  ------------------------------------------"
  echo -e "   1. 安装 / 初始化 iptables"
  echo -e "   2. 查看规则"
  echo -e "   3. 添加规则"
  echo -e "   4. 批量添加"
  echo -e "   5. 删除规则  (支持批量: 1,3,5-8)"
  echo -e "   6. 清空所有规则"
  echo -e "   7. 导出规则"
  echo -e "   8. 导入规则"
  echo -e "   9. 安装为系统命令 (${CMD_NAME})"
  echo -e "  ------------------------------------------  (较少用)"
  echo -e "  10. 禁用 IPv6"
  echo -e "  11. 启用 IPv6 (恢复)"
  echo -e "  12. 检查 IPv6 状态"
  echo -e "   q. 退出"
  echo ""
}

menu_loop() {
  local C f
  while true; do
    show_menu
    read -rp "$(echo -e ${Ask}) 选择: " C
    case "$C" in
      1) install_and_init ;;
      2) list_rules ;;
      3) interactive_add ;;
      4) interactive_batch_add ;;
      5) interactive_delete ;;
      6) clear_all ;;
      7) read -rp "导出文件路径 (默认 /root/iptpf-rules.txt): " f
         export_rules "${f:-/root/iptpf-rules.txt}" ;;
      8) read -rp "导入文件路径: " f
         [[ -n "$f" ]] && import_rules "$f" ;;
      9) local nm
         read -rp "命令名 (回车用默认 $CMD_NAME): " nm
         install_self "${nm:-$CMD_NAME}" ;;
      10) disable_ipv6 ;;
      11) enable_ipv6 ;;
      12) check_ipv6 ;;
      q|Q) log "${Info} 再见"; exit 0 ;;
      *) log "${Error} 无效选择" ;;
    esac
    echo ""
    read -rp "$(echo -e ${Tip}) 回车返回菜单..." _
  done
}

### ---------- 入口 ----------
main() {
  require_root

  local sub="${1:-menu}"
  # install/uninstall/help 不需要抢锁
  case "$sub" in
    install)        shift; install_self   "${1:-}"; exit 0 ;;
    uninstall)      shift; uninstall_self "${1:-}"; exit 0 ;;
    -h|--help|help) usage; exit 0 ;;
  esac

  acquire_lock
  case "$sub" in
    init)           install_and_init ;;
    list|ls)        list_rules ;;
    add)            shift; cli_add "$@" ;;
    del|rm|delete)  shift; cli_del "$@" ;;
    clear|flush)    clear_all ;;
    export)         shift; export_rules "${1:-/root/iptpf-rules.txt}" ;;
    import)         shift; import_rules "${1:-}" ;;
    disable-ipv6)   disable_ipv6 ;;
    enable-ipv6)    enable_ipv6 ;;
    check-ipv6)     check_ipv6 ;;
    menu|"")        menu_loop ;;
    *) usage; exit 1 ;;
  esac
}

main "$@"
