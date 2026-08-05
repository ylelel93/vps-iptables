#!/bin/bash
# ============================================
# iptables 端口转发管理脚本 v3.0
# 主要改进:
#   [bug]  基于 comment 标签的 DNAT/SNAT 精确配对 (根治跨规则误删)
#   [bug]  批量添加使用每条规则自己的本机 IP 作 SNAT
#   [bug]  重复添加检测 (iptables -C)
#   [新增] 输入校验 / 备注 / 批量删除(1,3,5-8) / 导入导出
#   [新增] firewalld / ufw 冲突检测；多网卡提示
#   [新增] flock 并发锁；iptables -w 等待 xtables lock
#   [新增] iptables backend (legacy/nft) 检测
#   [新增] 内核模块自动加载
#   [新增] 操作日志 /var/log/iptpf.log
#   [新增] 命令行子命令模式 (add / del / list / import / export / init)
#   [新增] clear_all 可选移除主链钩子
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

### ---------- 交互输入通用助手 ----------
# 与 read -rp 行为等价，但显式处理 EOF 避免 set -e 意外退出
_ask() {
  local __prompt="$1" __var="$2" __in=""
  # 与 read -rp 等价，但 || true 保证 set -e 下不会因 EOF 退出
  printf '%s' "$__prompt" >&2 || true
  IFS= read -r __in || __in=""
  printf -v "$__var" '%s' "$__in" || true
}

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
  echo ""
  echo "  ═══════════════════════════════════════════════════════════"
  echo "     添加端口转发规则  (共 6 步，可随时按 Ctrl+C 取消)"
  echo "  ═══════════════════════════════════════════════════════════"

  local RIP RPORT LPORT MODE SNAT_IP PTYPE REMARK proto USER_IP OK

  # ── 步骤 1/6 ──
  echo ""
  echo "  [步骤 1/6]  转发目标 IP  (要转到哪台机器? 例: 1.2.3.4)"
  _ask "  >>> 请输入目标 IP: " RIP
  validate_ip "$RIP" || { log "${Error} IP 格式错误: '${RIP}'"; return 0; }

  # ── 步骤 2/6 ──
  echo ""
  echo "  [步骤 2/6]  转发目标端口  (对方服务端口，例: 22 / 80 / 443)"
  _ask "  >>> 请输入目标端口: " RPORT
  validate_port "$RPORT" || { log "${Error} 端口非法: '${RPORT}'"; return 1; }

  # ── 步骤 3/6 ──
  echo ""
  echo "  [步骤 3/6]  本机监听端口  (对外暴露的端口，默认与目标端口相同 = $RPORT)"
  _ask "  >>> 请输入 (直接回车用默认 $RPORT): " LPORT
  LPORT="${LPORT:-$RPORT}"
  validate_port "$LPORT" || { log "${Error} 端口非法: '${LPORT}'"; return 1; }

  # ── 步骤 4/6 ──
  echo ""
  echo "  [步骤 4/6]  SNAT 源 IP  (数据包出去时用哪个 IP 作源地址)"
  echo "     选项 1 = 用内网 IP  (跨内网中转选此)"
  echo "     选项 2 = 用公网 IP  (VPS 直接出公网时选此)"
  _ask "  >>> 请输入 1 或 2 (直接回车默认 1): " MODE
  MODE="${MODE:-1}"
  if [[ "$MODE" == "2" ]]; then
    SNAT_IP=$(detect_wan_ip)
    if [[ -z "$SNAT_IP" ]]; then
      echo "  ⚠ 自动获取公网 IP 失败 (DNS 异常或 443 被墙)，请手动输入"
    else
      echo "  → 已自动检测到公网 IP: $SNAT_IP"
    fi
  else
    SNAT_IP=$(detect_lan_ip)
    if [[ -z "$SNAT_IP" ]]; then
      echo "  ⚠ 自动获取内网 IP 失败，请手动输入"
    else
      echo "  → 已自动检测到内网 IP: $SNAT_IP"
    fi
  fi
  _ask "  >>> SNAT IP (直接回车用上面检测到的值): " USER_IP
  [[ -n "$USER_IP" ]] && SNAT_IP="$USER_IP"
  validate_ip "$SNAT_IP" || { log "${Error} SNAT IP 非法: '${SNAT_IP:-空}'"; return 1; }

  # ── 步骤 5/6 ──
  echo ""
  echo "  [步骤 5/6]  协议"
  echo "     1 = TCP     (SSH/HTTP/HTTPS 等)"
  echo "     2 = UDP     (DNS/游戏 等)"
  echo "     3 = TCP+UDP (两者都转发)"
  _ask "  >>> 请输入 1/2/3 (直接回车默认 3): " PTYPE
  PTYPE="${PTYPE:-3}"
  case "$PTYPE" in
    1) proto=tcp;;
    2) proto=udp;;
    3) proto=both;;
    *) log "${Error} 协议选择非法: '${PTYPE}'"; return 1;;
  esac

  # ── 步骤 6/6 ──
  echo ""
  echo "  [步骤 6/6]  备注  (可留空，仅用于日后识别用途，支持中文空格)"
  _ask "  >>> 请输入备注 (直接回车跳过): " REMARK

  # ── 配置确认 ──
  echo ""
  echo "  ───────────────────────────────────────────────────────────"
  echo "     配置确认"
  echo "  ───────────────────────────────────────────────────────────"
  echo "     协议 : $proto"
  echo "     监听 : $SNAT_IP:$LPORT   (对外开放)"
  echo "     目标 : $RIP:$RPORT       (转发到)"
  echo "     备注 : ${REMARK:-<无>}"
  echo "  ───────────────────────────────────────────────────────────"
  echo ""
  _ask "  >>> 输入 y 后回车 = 添加；其它输入(含回车) = 取消: " OK
  if [[ "$OK" != "y" && "$OK" != "Y" ]]; then
    log "${Tip} 已取消 (你输入的是: '${OK}')"
    return
  fi

  local _rc=0
  add_rules_multi_proto "$LPORT" "$proto" "$RIP" "$RPORT" "$SNAT_IP" "$REMARK" || _rc=$?
  case "$_rc" in
    0) save_rules; log "${Info} ✓ 添加成功" ;;
    2) log "${Tip} 规则已存在，未做修改" ;;
    3) save_rules; log "${Info} ✓ 部分协议已存在，其余已新增并保存" ;;
    *) log "${Error} 添加失败"; return 1 ;;
  esac
}

interactive_batch_add() {
  echo ""
  echo "  ═══════════════════════════════════════════════════════════"
  echo "     批量添加转发规则"
  echo "  ═══════════════════════════════════════════════════════════"
  echo "     格式:  本机IP:端口=目标IP:端口"
  echo "     示例:  10.0.0.1:22=1.2.3.4:22"
  echo "     结束:  【空行 + 回车】表示输完，进入下一步"
  echo "     取消:  输入 q + 回车"
  echo "  ───────────────────────────────────────────────────────────"

  local rules=() rule i=1 rejected=0
  local _lip _lport _rip _rport _rest
  echo ""
  echo "  [步骤 1/3]  逐行输入规则 (可粘贴多行)"
  echo "  ───────────────────────────────────────────────────────────"
  while true; do
    _ask "  [第${i}条] > " rule
    if [[ "$rule" == "q" || "$rule" == "Q" ]]; then
      log "${Tip} 已取消"; return 1
    fi
    if [[ -z "$rule" ]]; then break; fi

    if ! [[ "$rule" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]+=([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]+$ ]]; then
      echo -e "        ${Error} 格式错误 (需为 IP:端口=IP:端口，注意不要有空格)"
      rejected=$((rejected+1))
      continue
    fi
    _lip="${rule%%:*}"; _rest="${rule#*:}"
    _lport="${_rest%%=*}"; _rest="${_rest#*=}"
    _rip="${_rest%%:*}"; _rport="${_rest#*:}"
    if   ! validate_ip   "$_lip";   then echo -e "        ${Error} 本机 IP 非法: $_lip";   rejected=$((rejected+1)); continue
    elif ! validate_ip   "$_rip";   then echo -e "        ${Error} 目标 IP 非法: $_rip";   rejected=$((rejected+1)); continue
    elif ! validate_port "$_lport"; then echo -e "        ${Error} 本机端口非法: $_lport"; rejected=$((rejected+1)); continue
    elif ! validate_port "$_rport"; then echo -e "        ${Error} 目标端口非法: $_rport"; rejected=$((rejected+1)); continue
    fi
    rules+=("$rule")
    i=$((i+1))
  done

  echo ""
  echo "  ───────────────────────────────────────────────────────────"
  echo "     输入完毕：接收 ${#rules[@]} 条  /  拒绝 ${rejected} 条"
  echo "  ───────────────────────────────────────────────────────────"

  (( ${#rules[@]} == 0 )) && { log "${Tip} 无有效规则，返回菜单"; return; }

  local PTYPE proto REMARK OK
  echo ""
  echo "  [步骤 2/3]  选择协议 (对上面所有规则统一生效)"
  echo "     1 = TCP   /   2 = UDP   /   3 = TCP+UDP"
  _ask "  >>> 请输入 1/2/3 (直接回车默认 3): " PTYPE
  PTYPE="${PTYPE:-3}"
  case "$PTYPE" in 1) proto=tcp;; 2) proto=udp;; 3) proto=both;; *) log "${Error} 协议选择非法: '${PTYPE}'"; return 1;; esac

  echo ""
  echo "  [步骤 3/3]  统一备注 (对所有规则一起用同一个备注，可留空)"
  _ask "  >>> 请输入备注 (直接回车跳过): " REMARK

  echo -e "\n${Info} 即将添加 ${#rules[@]} 条规则 (协议: $proto):"
  local r lip lport rest rip rport
  for r in "${rules[@]}"; do
    lip="${r%%:*}"; rest="${r#*:}"
    lport="${rest%%=*}"; rest="${rest#*=}"
    rip="${rest%%:*}"; rport="${rest#*:}"
    echo "  $lip:$lport  ->  $rip:$rport"
  done
  echo ""
  _ask "  >>> 输入 y 后回车 = 添加所有；其它输入(含回车) = 取消: " OK
  if [[ "$OK" != "y" && "$OK" != "Y" ]]; then
    log "${Tip} 已取消 (你输入的是: '${OK}')"
    return
  fi

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

# 全局: 显示行 → 底层 tag(s) 的映射
# 每项格式: proto|lport|rip|rport|snat|remark|tag1[|tag2]
_DISPLAY_MAP=()

# 把 _list_tags 输出的原始 tag 列表加工成显示行，同 lport+目标 的 tcp/udp 合并为一行
_build_display_map() {
  _DISPLAY_MAP=()
  local -a raw=()
  local t
  while IFS= read -r t; do raw+=("$t"); done < <(_list_tags)
  local n="${#raw[@]}"
  (( n == 0 )) && return 0

  local -a paired=()
  local i j
  local lp1 pr1 rip1 rpt1 sn1 rm1 lp2 pr2 rip2 rpt2 sn2 rm2 partner
  for ((i=0; i<n; i++)); do
    [[ "${paired[i]:-0}" == "1" ]] && continue
    IFS=$'\t' read -r lp1 pr1 rip1 rpt1 sn1 rm1 < <(_parse_tag "${raw[i]}")
    partner=""
    for ((j=i+1; j<n; j++)); do
      [[ "${paired[j]:-0}" == "1" ]] && continue
      IFS=$'\t' read -r lp2 pr2 rip2 rpt2 sn2 rm2 < <(_parse_tag "${raw[j]}")
      if [[ "$lp1" == "$lp2" && "$rip1" == "$rip2" && "$rpt1" == "$rpt2" \
         && "$sn1" == "$sn2" && "$rm1" == "$rm2" && "$pr1" != "$pr2" ]]; then
        partner="${raw[j]}"
        paired[j]=1
        break
      fi
    done
    if [[ -n "$partner" ]]; then
      _DISPLAY_MAP+=("both|${lp1}|${rip1}|${rpt1}|${sn1}|${rm1}|${raw[i]}|${partner}")
    else
      _DISPLAY_MAP+=("${pr1}|${lp1}|${rip1}|${rpt1}|${sn1}|${rm1}|${raw[i]}")
    fi
    paired[i]=1
  done
}

_print_rules_table() {
  _build_display_map
  local n="${#_DISPLAY_MAP[@]}"
  if (( n == 0 )); then
    echo "     (暂无规则)"
    return 1
  fi

  # 表头
  printf "  %-4s %-8s %-8s   %-24s %-16s %s\n" "编号" "协议" "监听端口" "→ 目标 (IP:端口)" "SNAT源 IP" "备注"
  printf "  %s\n" "-----------------------------------------------------------------------------------------"

  local i entry proto lport rip rport snat remark proto_disp
  for ((i=0; i<n; i++)); do
    entry="${_DISPLAY_MAP[i]}"
    IFS='|' read -r proto lport rip rport snat remark _ _ <<< "$entry"
    case "$proto" in
      both) proto_disp="TCP+UDP" ;;
      tcp)  proto_disp="TCP" ;;
      udp)  proto_disp="UDP" ;;
      *)    proto_disp="$proto" ;;
    esac
    printf "  %-4d %-8s %-8s → %-24s %-16s %s\n" \
      "$((i+1))" "$proto_disp" "$lport" "${rip}:${rport}" "$snat" "${remark:-}"
    # 每 10 行插一条淡分隔，便于扫读
    if (( (i+1) % 10 == 0 && i+1 < n )); then
      printf "  %s\n" "· · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · ·"
    fi
  done
  return 0
}

list_rules() {
  echo ""
  echo "  ═══════════════════════════════════════════════════════════"
  echo "     当前转发规则 (TCP+UDP 同目标已合并为一条)"
  echo "  ═══════════════════════════════════════════════════════════"
  _print_rules_table || true
  echo "  -----------------------------------------------------------"

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
  local IDX nums n entry
  while true; do
    echo ""
    _print_rules_table || { echo ""; return; }
    echo ""
    echo "  ───────────────────────────────────────────────────────────"
    echo "     支持: 单个(3) / 范围(1-3) / 组合(1,3,5-8) / all(全部) / q(退出)"
    _ask "  >>> 请输入要删除的编号: " IDX
    [[ "$IDX" == "q" || "$IDX" == "Q" ]] && break
    [[ -z "$IDX" ]] && continue

    # 按显示行数(合并后)工作
    local total="${#_DISPLAY_MAP[@]}"
    (( total == 0 )) && break

    if ! nums=$(_expand_indices "$IDX" "$total"); then
      log "${Error} 编号格式错误或越界 (当前共 $total 行)"
      continue
    fi

    local sel_count C2
    sel_count=$(echo "$nums" | grep -c .)
    if [[ "$IDX" =~ [aA][lL][lL] ]] || (( sel_count == total )); then
      echo ""
      echo "  ⚠  即将删除全部 ${total} 行规则！"
      _ask "  >>> 输入 y 后回车 = 确认删除；其它输入(含回车) = 取消: " C2
      if [[ "$C2" != "y" && "$C2" != "Y" ]]; then
        log "${Tip} 已取消 (你输入的是: '${C2}')"
        continue
      fi
    fi

    local nums_desc t1 t2
    nums_desc=$(echo "$nums" | sort -rn)
    while IFS= read -r n; do
      [[ -z "$n" ]] && continue
      entry="${_DISPLAY_MAP[n-1]}"
      # 底层 tag 可能是 1 个(单协议)或 2 个(tcp+udp 合并)
      t1=$(echo "$entry" | awk -F'|' '{print $7}')
      t2=$(echo "$entry" | awk -F'|' '{print $8}')
      [[ -n "$t1" ]] && _delete_by_tag "$t1"
      [[ -n "$t2" ]] && _delete_by_tag "$t2"
    done <<< "$nums_desc"

    save_rules
  done
}

### ---------- 清空 ----------
clear_all() {
  local count; count=$(_list_tags | wc -l | tr -d ' ')
  echo ""
  echo "  ═══════════════════════════════════════════════════════════"
  echo "     ⚠ 危险操作: 清空所有转发规则"
  echo "  ═══════════════════════════════════════════════════════════"
  echo "     当前规则数: ${count} 条 (全部会被删除)"
  echo "     为防手滑，需要完整输入 yes  (三个字母)"
  echo "  ───────────────────────────────────────────────────────────"
  echo ""
  local CONFIRM
  _ask "  >>> 请输入 yes 后回车 = 确认清空；其它输入(含回车) = 取消: " CONFIRM
  if [[ "$CONFIRM" != "yes" ]]; then
    log "${Tip} 已取消 (你输入的是: '${CONFIRM}')"
    return
  fi

  ipt -t nat -F "$CHAIN_PRE"  2>/dev/null || true
  ipt -t nat -F "$CHAIN_POST" 2>/dev/null || true
  log "${Info} 已清空专用链内所有规则"

  local RM_HOOK
  echo ""
  echo "  是否同时移除主链钩子 (-j $CHAIN_PRE / $CHAIN_POST)?"
  echo "     y = 移除 (下次添加规则前需重新初始化)"
  echo "     n = 保留 (下次可直接添加规则，推荐)"
  _ask "  >>> 请输入 y 或 n (直接回车默认 n): " RM_HOOK
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
  echo ""
  echo "  ═══════════════════════════════════════════════"
  echo "     即将执行: 禁用 IPv6"
  echo "  ═══════════════════════════════════════════════"
  echo "     当前状态: $(_ipv6_status)"
  echo "     影响    : 清除所有 IPv6 地址、屏蔽 IPv6 流量"
  echo "     持久化  : 写入 $IPV6_CONF_FILE (重启后保持)"
  echo "     可恢复  : 菜单 11 或 sudo $CMD_NAME enable-ipv6"
  echo ""
  echo "  ┌─────────────────────────────────────────────┐"
  echo "  │  接下来要你输入:                             │"
  echo "  │     输入 y 然后按【回车】  =>  执行禁用        │"
  echo "  │     直接按【回车】或输其它  =>  取消           │"
  echo "  └─────────────────────────────────────────────┘"
  echo ""
  local C=""
  # 用 echo -n + read (不用 read -rp), 避开某些环境下多字节 prompt 不渲染的 bug
  echo -n "  你的输入 > "
  IFS= read -r C </dev/tty || C=""
  echo ""
  if [[ "$C" != "y" && "$C" != "Y" ]]; then
    log "${Tip} 已取消 (你输入的是: '${C}')"
    return
  fi

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
  # 收集所有数据 (静默)
  local all_v def_v lo_v
  all_v=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "?")
  def_v=$(sysctl -n net.ipv6.conf.default.disable_ipv6 2>/dev/null || echo "?")
  lo_v=$(sysctl -n net.ipv6.conf.lo.disable_ipv6 2>/dev/null || echo "?")

  local conf_ok=0
  [[ -f "$IPV6_CONF_FILE" ]] && conf_ok=1

  local addr_count
  addr_count=$(ip -6 addr show scope global 2>/dev/null | grep -c "inet6" || true)

  local listener_count listener_hint=""
  if command -v ss >/dev/null 2>&1; then
    listener_count=$(ss -tuln6 2>/dev/null | awk 'NR>1' | wc -l | tr -d ' ')
    if (( listener_count > 0 )); then
      # 提取前 3 个服务名（尝试从 ss 输出的进程列）
      listener_hint=$(ss -tuln6 2>/dev/null | awk 'NR>1 {print $5}' | sort -u | head -3 | tr '\n' ' ')
    fi
  else
    listener_count="?"
  fi

  local module_loaded=0
  lsmod 2>/dev/null | grep -q "^ipv6 " && module_loaded=1

  # 4 项核心状态
  local m1 m2 m3 m4
  if [[ "$all_v" == "1" && "$def_v" == "1" && "$lo_v" == "1" ]]; then
    m1="\033[32m✓ 已禁用\033[0m"
  else
    m1="\033[31m✗ 未禁用\033[0m   (all=${all_v}, default=${def_v}, lo=${lo_v})"
  fi

  if (( conf_ok == 1 )); then
    m2="\033[32m✓ 已持久化\033[0m  (${IPV6_CONF_FILE})"
  else
    m2="\033[31m✗ 未持久化\033[0m  (重启后会恢复！)"
  fi

  if [[ "$addr_count" == "0" ]]; then
    m3="\033[32m✓ 无 IPv6 地址\033[0m"
  else
    m3="\033[33m⚠ 仍有 ${addr_count} 条 IPv6 地址\033[0m"
  fi

  if [[ "$listener_count" == "0" ]]; then
    m4="\033[32m✓ 无服务在 IPv6\033[0m"
  elif [[ "$listener_count" == "?" ]]; then
    m4="? (缺少 ss 命令，无法检查)"
  else
    m4="\033[33m${listener_count} 个服务占用 IPv6 socket\033[0m  (不影响外网访问)"
  fi

  # 一句话结论
  local overall
  if [[ "$all_v" == "1" && "$conf_ok" == "1" && "$addr_count" == "0" ]]; then
    overall="\033[32m✓ IPv6 已完全禁用，且重启后保持\033[0m"
  elif [[ "$all_v" == "1" && "$conf_ok" == "0" ]]; then
    overall="\033[33m⚠ IPv6 当前已禁用，但重启后会恢复\033[0m —— 需要重新执行 [菜单 10]"
  elif [[ "$all_v" != "1" && "$conf_ok" == "1" ]]; then
    overall="\033[33m⚠ 有持久化配置但当前未生效\033[0m —— 执行 sysctl -p ${IPV6_CONF_FILE}"
  else
    overall="\033[31m✗ IPv6 处于启用状态\033[0m"
  fi

  # 输出
  echo ""
  echo "  ╔═══════════════════════════════════════════════════════════╗"
  echo "  ║              IPv6 状态检查                                  ║"
  echo "  ╚═══════════════════════════════════════════════════════════╝"
  echo ""
  printf "    %-12s %b\n" "内核禁用:"  "$m1"
  printf "    %-12s %b\n" "开机保持:"  "$m2"
  printf "    %-12s %b\n" "当前地址:"  "$m3"
  printf "    %-12s %b\n" "服务占用:"  "$m4"
  echo ""
  echo "  ─────────────────────────────────────────────────────────────"
  printf "   一句话: %b\n" "$overall"
  echo "  ─────────────────────────────────────────────────────────────"
  echo ""

  # 进阶信息，只在有问题或用户询问时展示，避免噪音
  if [[ "$all_v" == "1" && "$conf_ok" == "1" && "$addr_count" == "0" ]]; then
    if (( module_loaded == 1 )); then
      echo "  说明: ipv6 内核模块仍加载 (属正常，sysctl 禁用不卸载模块)"
      echo "        彻底卸载模块需在 GRUB 加 ipv6.disable=1 并重启，一般不必要"
      echo ""
    fi
  fi
}

enable_ipv6() {
  echo ""
  echo "  ═══════════════════════════════════════════════"
  echo "     即将执行: 启用 IPv6 (恢复)"
  echo "  ═══════════════════════════════════════════════"
  echo "     当前状态: $(_ipv6_status)"
  echo "     动作    : 恢复 sysctl 参数、删除持久化配置"
  echo ""
  echo "  ┌─────────────────────────────────────────────┐"
  echo "  │  接下来要你输入:                             │"
  echo "  │     输入 y 然后按【回车】  =>  执行启用        │"
  echo "  │     直接按【回车】或输其它  =>  取消           │"
  echo "  └─────────────────────────────────────────────┘"
  echo ""
  local C=""
  echo -n "  你的输入 > "
  IFS= read -r C </dev/tty || C=""
  echo ""
  if [[ "$C" != "y" && "$C" != "Y" ]]; then
    log "${Tip} 已取消 (你输入的是: '${C}')"
    return
  fi

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
_menu_status_line() {
  local backend fwd_v fwd ipv6 persist count
  backend=$(detect_backend)
  fwd_v=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "?")
  case "$fwd_v" in 1) fwd="ON";; 0) fwd="OFF";; *) fwd="?";; esac
  ipv6=$(_ipv6_status)
  persist=$(_persistence_status | cut -d: -f1)
  case "$persist" in
    enabled)             persist="OK" ;;
    installed_not_enabled) persist="装了未启用" ;;
    not_installed)       persist="未装" ;;
  esac
  count=$(_list_tags | wc -l | tr -d ' ')
  echo "后端=${backend}  转发=${fwd}  IPv6=${ipv6}  持久化=${persist}  规则=${count}条"
}

show_menu() {
  local installed_hint=""
  [[ -x "${INSTALL_DIR}/${CMD_NAME}" ]] && installed_hint=" (cmd: ${CMD_NAME})"
  echo ""
  echo " iptables 端口转发管理  [${VERSION}]${installed_hint}"
  echo " $(_menu_status_line)"
  echo ""
  echo " ————————————————————————————————————————"
  echo " ── 安装 ──"
  echo "   1. 初始化 iptables         (首次使用必做)"
  echo "   9. 安装为系统命令 (${CMD_NAME})"
  echo " ————————————————————————————————————————"
  echo " ── 维护 ──"
  echo "   2. 查看规则"
  echo "   3. 添加规则"
  echo "   4. 批量添加"
  echo "   5. 删除规则                (支持批量: 1,3,5-8)"
  echo "   6. 清空所有规则"
  echo "   7. 导出规则"
  echo "   8. 导入规则"
  echo " ————————————————————————————————————————"
  echo " ── 其它 (较少用) ──"
  echo "  10. 禁用 IPv6"
  echo "  11. 启用 IPv6 (恢复)"
  echo "  12. 检查 IPv6 状态"
  echo " ————————————————————————————————————————"
  echo "   q. 退出"
  echo ""
}

menu_loop() {
  local C f nm
  while true; do
    show_menu
    C=""
    # 关键: || true 防止 case 中函数返回非零触发 set -e 让脚本退出
    _ask " >>> 请输入菜单编号 (1-12 或 q) 后按回车: " C || true
    {
      case "$C" in
        1) install_and_init ;;
        2) list_rules ;;
        3) interactive_add ;;
        4) interactive_batch_add ;;
        5) interactive_delete ;;
        6) clear_all ;;
        7) echo ""
           _ask " >>> 导出文件路径 (直接回车用默认 /root/iptpf-rules.txt): " f
           export_rules "${f:-/root/iptpf-rules.txt}" ;;
        8) echo ""
           _ask " >>> 导入文件路径 (必填): " f
           [[ -n "$f" ]] && import_rules "$f" ;;
        9) echo ""
           _ask " >>> 命令名 (直接回车用默认 $CMD_NAME): " nm
           install_self "${nm:-$CMD_NAME}" ;;
        10) disable_ipv6 ;;
        11) enable_ipv6 ;;
        12) check_ipv6 ;;
        q|Q) log "${Info} 再见"; exit 0 ;;
        *) log "${Error} 无效选择: '${C}'" ;;
      esac
    } || true
    echo ""
    echo " ————————————————————————————————————————"
    _ask " 【操作完成】按【回车】返回主菜单 ... " _ || true
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
