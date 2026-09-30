#!/system/bin/sh

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
MODULE_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"

if [ ! -x "$MODULE_DIR/bin/wg" ]; then
    MODULE_DIR="/data/kano_wireguard"
fi

WG_BIN="$MODULE_DIR/bin/wg"
CONF_FILE="$MODULE_DIR/wg0.conf"
LOG_DIR="$MODULE_DIR/logs"
LOG_FILE="$LOG_DIR/wireguard.log"
INTERFACE_NAME="wg0"
LAN_IF="br0"
WG_ROUTE_TABLE="101"
WG_ROUTE_PRIORITY="100"
WG_ROUTE_MARK="2"
WG_ROUTE_CHAIN="WG_ROUTE_${INTERFACE_NAME}"
WG_DNS_CHAIN="KANO_DNS_${INTERFACE_NAME}"
STATE_DIR="$MODULE_DIR/.state"
ACTIVE_CONF="$STATE_DIR/active.conf"

. "$SCRIPT_DIR/common.sh" || exit 1

mkdir -p "$LOG_DIR" "$STATE_DIR" || exit 1
chmod 700 "$LOG_DIR" "$STATE_DIR" || exit 1

load_lan() {
    LAN_IF="$(interface_values LANInterface | head -n 1)"
    [ -n "$LAN_IF" ] || LAN_IF="br0"
}

validate_config() {
    require_file "$CONF_FILE" || return 1
    awk -f "$SCRIPT_DIR/validate.awk" "$CONF_FILE"
}

log() {
    now="$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"
    [ -n "$now" ] || now="unknown-time"
    printf '%s %s\n' "$now" "$*" >> "$LOG_FILE"
    printf '%s\n' "$*"
}

trim() {
    printf '%s' "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

require_file() {
    [ -f "$1" ] || {
        log "missing file: $1"
        return 1
    }
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        log "missing command: $1"
        return 1
    }
}

interface_values() {
    key="$1"
    awk -F= -v key="$key" '
        BEGIN { in_interface = 0 }
        /^[[:space:]]*\[/ {
            in_interface = ($0 ~ /^[[:space:]]*\[Interface\][[:space:]]*$/)
            next
        }
        in_interface {
            line = $0
            sub(/[;#].*$/, "", line)
            if (line ~ "^[[:space:]]*" key "[[:space:]]*=") {
                sub(/^[^=]*=/, "", line)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
                if (length(line) > 0) {
                    print line
                }
            }
        }
    ' "$CONF_FILE"
}


peer_values() {
    key="$1"
    awk -F= -v key="$key" '
        BEGIN { in_peer = 0 }
        /^[[:space:]]*\[/ {
            in_peer = ($0 ~ /^[[:space:]]*\[Peer\][[:space:]]*$/)
            next
        }
        in_peer {
            line = $0
            sub(/[;#].*$/, "", line)
            if (line ~ "^[[:space:]]*" key "[[:space:]]*=") {
                sub(/^[^=]*=/, "", line)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
                if (length(line) > 0) {
                    print line
                }
            }
        }
    ' "$CONF_FILE"
}

peer_csv_values() {
    key="$1"
    peer_values "$key" | split_csv_lines | while IFS= read -r value; do
        value="$(trim "$value")"
        [ -n "$value" ] || continue
        printf '%s\n' "$value"
    done
}

build_setconf_file() {
    tmp_file="$LOG_DIR/${INTERFACE_NAME}.setconf.$$"
    awk '
        {
            line = $0
            sub(/[;#].*$/, "", line)
            if (line ~ /^[[:space:]]*$/) {
                print ""
                next
            }
            if (line ~ /^[[:space:]]*Address[[:space:]]*=/) next
            if (line ~ /^[[:space:]]*DNS[[:space:]]*=/) next
            if (line ~ /^[[:space:]]*MTU[[:space:]]*=/) next
            if (line ~ /^[[:space:]]*NAT[[:space:]]*=/) next
            if (line ~ /^[[:space:]]*LANInterface[[:space:]]*=/) next
            if (line ~ /^[[:space:]]*Table[[:space:]]*=/) next
            if (line ~ /^[[:space:]]*SaveConfig[[:space:]]*=/) next
            if (line ~ /^[[:space:]]*(PreUp|PostUp|PreDown|PostDown)[[:space:]]*=/) next
            print line
        }
    ' "$CONF_FILE" > "$tmp_file" || return 1
    printf '%s\n' "$tmp_file"
}

split_csv_lines() {
    sed 's/,/\n/g'
}

iface_exists() {
    ip link show "$INTERFACE_NAME" >/dev/null 2>&1
}

peer_endpoint_hosts() {
    peer_values Endpoint | while IFS= read -r endpoint; do
        endpoint="$(trim "$endpoint")"
        [ -n "$endpoint" ] || continue

        case "$endpoint" in
            \[*\]:*)
                host="$(printf '%s\n' "$endpoint" | sed -n 's/^\[\(.*\)\]:[0-9][0-9]*$/\1/p')"
                ;;
            *:*)
                host="${endpoint%:*}"
                ;;
            *)
                host="$endpoint"
                ;;
        esac

        host="$(trim "$host")"
        [ -n "$host" ] || continue
        printf '%s\n' "$host"
    done | awk '!seen[$0]++'
}

is_ipv4_literal() {
    printf '%s\n' "$1" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
}

interface_dns_values() {
    interface_values DNS | split_csv_lines | while IFS= read -r dns; do
        dns="$(trim "$dns")"
        [ -n "$dns" ] || continue
        printf '%s\n' "$dns"
    done
}

get_primary_ipv4_dns() {
    dns_list="$(interface_dns_values)"

    if [ -z "$dns_list" ]; then
        return 1
    fi

    old_ifs="$IFS"
    IFS='
'
    for dns in $dns_list; do
        if is_ipv4_literal "$dns"; then
            printf '%s\n' "$dns"
            IFS="$old_ifs"
            return 0
        fi
    done
    IFS="$old_ifs"

    return 1
}

delete_dns_rule_pair() {
    chain="$1"
    dns="$2"

    while iptables -t nat -C "$chain" -p udp --dport 53 -j DNAT --to-destination "$dns" 2>/dev/null; do
        iptables -t nat -D "$chain" -p udp --dport 53 -j DNAT --to-destination "$dns" >/dev/null 2>&1 || break
    done

    while iptables -t nat -C "$chain" -p tcp --dport 53 -j DNAT --to-destination "$dns" 2>/dev/null; do
        iptables -t nat -D "$chain" -p tcp --dport 53 -j DNAT --to-destination "$dns" >/dev/null 2>&1 || break
    done
}

delete_output_return_rule() {
    dns="$1"

    while iptables -t nat -C OUTPUT -d "$dns" -j RETURN 2>/dev/null; do
        iptables -t nat -D OUTPUT -d "$dns" -j RETURN >/dev/null 2>&1 || break
    done
}

cleanup_dns_route() {
    dns="$1"
    [ -n "$dns" ] || return 0

    while ip route del "$dns/32" dev "$INTERFACE_NAME" >/dev/null 2>&1; do :; done
}

apply_dns_route() {
    dns="$1"
    [ -n "$dns" ] || return 0

    if ip route show "$dns/32" dev "$INTERFACE_NAME" | grep -q .; then return 0; fi
    ip route add "$dns/32" dev "$INTERFACE_NAME" >/dev/null 2>&1
}

cleanup_dns_rules() {
    for parent in PREROUTING OUTPUT; do
        for protocol in udp tcp; do
            if [ "$parent" = PREROUTING ]; then
                while iptables -t nat -D "$parent" -i "$LAN_IF" -p "$protocol" --dport 53 -j "$WG_DNS_CHAIN" >/dev/null 2>&1; do :; done
            else
                while iptables -t nat -D "$parent" -p "$protocol" --dport 53 -j "$WG_DNS_CHAIN" >/dev/null 2>&1; do :; done
            fi
        done
    done
    iptables -t nat -F "$WG_DNS_CHAIN" >/dev/null 2>&1 || true
    iptables -t nat -X "$WG_DNS_CHAIN" >/dev/null 2>&1 || true

    # Remove the original plugin's unowned rules during migration as well.
    dns="$(get_primary_ipv4_dns)"

    if [ -z "$dns" ]; then
        log "missing valid IPv4 DNS in $(basename "$CONF_FILE"), skipping DNS DNAT cleanup"
        return 0
    fi

    delete_dns_rule_pair PREROUTING "$dns"
    delete_dns_rule_pair OUTPUT "$dns"
    delete_output_return_rule "$dns"
}

apply_dns_rules() {
    dns="$(get_primary_ipv4_dns)"

    if [ -z "$dns" ]; then
        log "missing valid IPv4 DNS in $(basename "$CONF_FILE"), skipping DNS DNAT setup"
        return 0
    fi

    iptables -t nat -N "$WG_DNS_CHAIN" >/dev/null 2>&1 || return 1
    iptables -t nat -A "$WG_DNS_CHAIN" -d "$dns" -j RETURN >/dev/null 2>&1 || return 1
    for protocol in udp tcp; do
        iptables -t nat -A "$WG_DNS_CHAIN" -p "$protocol" --dport 53 -j DNAT --to-destination "$dns" >/dev/null 2>&1 || return 1
        iptables -t nat -I PREROUTING 1 -i "$LAN_IF" -p "$protocol" --dport 53 -j "$WG_DNS_CHAIN" >/dev/null 2>&1 || return 1
        iptables -t nat -I OUTPUT 1 -p "$protocol" --dport 53 -j "$WG_DNS_CHAIN" >/dev/null 2>&1 || return 1
    done

    log "applied DNS DNAT rules to $dns for PREROUTING and OUTPUT"
}

is_nat_enabled() {
    nat_val="$(interface_values NAT | head -n 1)"
    nat_val="$(trim "$nat_val")"
    # 默认为 true；只有明确设为 false 时才禁用
    case "$(printf '%s' "$nat_val" | tr 'A-Z' 'a-z')" in
        false|0|no) return 1 ;;
        *) return 0 ;;
    esac
}

has_default_allowedips() {
    peer_values AllowedIPs | split_csv_lines | while IFS= read -r cidr; do
        cidr="$(trim "$cidr")"
        [ -n "$cidr" ] || continue
        if [ "$cidr" = "0.0.0.0/0" ] || [ "$cidr" = "::/0" ]; then
            echo 1
            exit 0
        fi
    done
}

apply_addresses() {
    interface_values Address | split_csv_lines | while IFS= read -r addr; do
        addr="$(trim "$addr")"
        [ -n "$addr" ] || continue
        if printf '%s\n' "$addr" | grep -q ':'; then
            ip -6 address add "$addr" dev "$INTERFACE_NAME" >/dev/null 2>&1 || return 1
        else
            ip address add "$addr" dev "$INTERFACE_NAME" >/dev/null 2>&1 || return 1
        fi
    done
}

add_main_route() {
    route="$1"
    if printf '%s\n' "$route" | grep -q ':'; then
        ip -6 route add "$route" dev "$INTERFACE_NAME" >/dev/null 2>&1
    else
        ip route add "$route" dev "$INTERFACE_NAME" >/dev/null 2>&1
    fi
}

cleanup_policy_routes() {
    while iptables -t mangle -D PREROUTING -i "$LAN_IF" -j "$WG_ROUTE_CHAIN" >/dev/null 2>&1; do :; done
    iptables -t mangle -F "$WG_ROUTE_CHAIN" >/dev/null 2>&1 || true
    iptables -t mangle -X "$WG_ROUTE_CHAIN" >/dev/null 2>&1 || true

    while ip rule del fwmark "$WG_ROUTE_MARK" table "$WG_ROUTE_TABLE" priority "$WG_ROUTE_PRIORITY" >/dev/null 2>&1; do :; done
    ip route del default dev "$INTERFACE_NAME" table "$WG_ROUTE_TABLE" >/dev/null 2>&1 || true
    ip route flush cache >/dev/null 2>&1 || true
}

# 本方案为 4-in-6（IPv4 流量经 IPv6 隧道转发），
# AllowedIPs 必须全部为 IPv4 网段；存在 IPv6 网段时返回 1
check_allowedips_ipv4_only() {
    peer_csv_values AllowedIPs | while IFS= read -r route; do
        [ -n "$route" ] || continue
        if printf '%s\n' "$route" | grep -q ':'; then
            log "unsupported AllowedIPs: IPv6 route '$route' is not allowed in 4-in-6 mode"
            exit 1
        fi
    done
}

apply_policy_routes() {
    cleanup_policy_routes

    ip rule add fwmark "$WG_ROUTE_MARK" table "$WG_ROUTE_TABLE" priority "$WG_ROUTE_PRIORITY" >/dev/null 2>&1 || return 1
    ip route add default dev "$INTERFACE_NAME" table "$WG_ROUTE_TABLE" >/dev/null 2>&1 || return 1
    iptables -t mangle -N "$WG_ROUTE_CHAIN" >/dev/null 2>&1 || return 1

    for intranet in 0.0.0.0/8 224.0.0.0/4 240.0.0.0/4 255.255.255.255/32; do
        iptables -t mangle -A "$WG_ROUTE_CHAIN" -d "$intranet" -j RETURN >/dev/null 2>&1 || return 1
    done

    # 为 peer endpoint 添加豁免（RETURN）规则，避免隧道封装流量被策略路由回环。
    # IPv4 的 iptables 无法解析 IPv6 地址/仅解析为 IPv6 的域名（实测会挂起或报
    # host/network not found），而 IPv4 mangle 表本就不处理 IPv6 报文，故跳过：
    #   - IPv6 字面量（含冒号）显式跳过；
    #   - 其余（IPv4 字面量/域名）尝试添加，失败则记录并跳过，不再中断启动。
    peer_endpoint_hosts | while IFS= read -r endpoint; do
        if printf '%s\n' "$endpoint" | grep -q ':'; then
            log "skipping IPv6 endpoint '$endpoint' for LAN policy RETURN rule (IPv4 iptables only)"
            continue
        fi
        if ! iptables -t mangle -A "$WG_ROUTE_CHAIN" -d "$endpoint" -j RETURN >/dev/null 2>&1; then
            log "failed to add LAN policy RETURN rule for endpoint '$endpoint' (likely IPv6-only), skipping"
            continue
        fi
    done

    peer_csv_values AllowedIPs | while IFS= read -r route; do
        iptables -t mangle -A "$WG_ROUTE_CHAIN" -d "$route" -j MARK --set-mark "$WG_ROUTE_MARK" >/dev/null 2>&1 || return 1
    done || return 1

    ip -4 address show dev "$LAN_IF" | awk '/inet / {print $2}' | while IFS= read -r local_ipv4; do
        [ -n "$local_ipv4" ] || continue
        iptables -t mangle -I "$WG_ROUTE_CHAIN" -d "$local_ipv4" -j RETURN >/dev/null 2>&1 || return 1
    done || return 1

    iptables -t mangle -I PREROUTING -i "$LAN_IF" -j "$WG_ROUTE_CHAIN" >/dev/null 2>&1 || return 1
}

enable_lan_access() {
    echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || return 1

    iptables -D FORWARD -i "$LAN_IF" -o "$INTERFACE_NAME" -j ACCEPT >/dev/null 2>&1 || true
    iptables -D FORWARD -i "$INTERFACE_NAME" -o "$LAN_IF" -m state --state ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1 || true
    iptables -t nat -D POSTROUTING -o "$INTERFACE_NAME" -j MASQUERADE >/dev/null 2>&1 || true

    iptables -I FORWARD -i "$LAN_IF" -o "$INTERFACE_NAME" -j ACCEPT >/dev/null 2>&1 || return 1
    iptables -I FORWARD -i "$INTERFACE_NAME" -o "$LAN_IF" -m state --state ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1 || return 1
    if is_nat_enabled; then
        iptables -t nat -I POSTROUTING -o "$INTERFACE_NAME" -j MASQUERADE >/dev/null 2>&1 || return 1
    fi

    # NAT=false 时插入 RETURN 规则，跳过 wg0 上的 NAT 处理，并允许来自 wg0 的转发
    if ! is_nat_enabled; then
        log "NAT disabled, adding RETURN rules and FORWARD rules for $INTERFACE_NAME"
        # 允许来自 wg0 的转发（双向）
        iptables -I FORWARD -i "$INTERFACE_NAME" -o "$LAN_IF" -j ACCEPT >/dev/null 2>&1 || return 1
    fi
}

disable_lan_access() {
    while iptables -D FORWARD -i "$LAN_IF" -o "$INTERFACE_NAME" -j ACCEPT >/dev/null 2>&1; do :; done
    while iptables -D FORWARD -i "$INTERFACE_NAME" -o "$LAN_IF" -m state --state ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1; do :; done
    while iptables -t nat -D POSTROUTING -o "$INTERFACE_NAME" -j MASQUERADE >/dev/null 2>&1; do :; done
    # 清理 NAT=false 时添加的 RETURN 规则和 FORWARD 规则
    while iptables -t nat -D PREROUTING -i "$INTERFACE_NAME" -j RETURN >/dev/null 2>&1; do :; done
    while iptables -t nat -D POSTROUTING -o "$INTERFACE_NAME" -j RETURN >/dev/null 2>&1; do :; done
    while iptables -D FORWARD -i "$INTERFACE_NAME" -j ACCEPT >/dev/null 2>&1; do :; done
    while iptables -D FORWARD -o "$INTERFACE_NAME" -m state --state ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1; do :; done
    while iptables -D FORWARD -i "$INTERFACE_NAME" -o "$LAN_IF" -j ACCEPT >/dev/null 2>&1; do :; done
}

apply_routes() {
    skipped_default_routes=0

    peer_values AllowedIPs | split_csv_lines | while IFS= read -r route; do
        route="$(trim "$route")"
        [ -n "$route" ] || continue

        if [ "$route" = "0.0.0.0/0" ] || [ "$route" = "::/0" ]; then
            skipped_default_routes=1
            continue
        fi

        add_main_route "$route" || return 1
    done || return 1

    if [ -n "$(has_default_allowedips)" ]; then
        log "full-tunnel AllowedIPs detected, skipping default routes on this gateway device"
    fi

    ip route flush cache >/dev/null 2>&1 || true
}

apply_mtu() {
    mtu="$(interface_values MTU | head -n 1)"
    mtu="$(trim "$mtu")"
    [ -n "$mtu" ] || return 0
    ip link set mtu "$mtu" dev "$INTERFACE_NAME" >/dev/null 2>&1
}

start_wireguard() {
    require_cmd ip || return 1
    require_cmd iptables || return 1
    require_file "$WG_BIN" || return 1
    require_file "$CONF_FILE" || return 1

    validate_config || return 1
    load_lan
    ip link show "$LAN_IF" >/dev/null 2>&1 || { log "LAN interface not found: $LAN_IF"; return 1; }
    if ip route show table "$WG_ROUTE_TABLE" 2>/dev/null | grep -v "dev $INTERFACE_NAME" | grep -q .; then
        log "route table $WG_ROUTE_TABLE is in use by another service"
        return 1
    fi
    "$WG_BIN" --version >/dev/null 2>&1 || { log 'Bundled wg cannot execute on this device; check CPU architecture.'; return 1; }
    chmod 755 "$WG_BIN" >/dev/null 2>&1 || return 1

    stop_wireguard || return 1
    cp "$CONF_FILE" "$ACTIVE_CONF" || return 1
    chmod 600 "$ACTIVE_CONF" || return 1

    if ! ip link add "$INTERFACE_NAME" type wireguard >/dev/null 2>&1; then
        log "failed to create interface: $INTERFACE_NAME"
        return 1
    fi

    tmp_conf="$(build_setconf_file)" || { stop_wireguard; return 1; }
    if ! "$WG_BIN" setconf "$INTERFACE_NAME" "$tmp_conf" >/dev/null 2>&1; then
        rm -f "$tmp_conf"
        ip link del "$INTERFACE_NAME" >/dev/null 2>&1
        log "failed to apply config from $(basename "$CONF_FILE")"
        return 1
    fi
    rm -f "$tmp_conf"

    # 异常检测：4-in-6 模式要求 AllowedIPs 全部为 IPv4 网段，不允许 IPv6 地址
    if ! check_allowedips_ipv4_only; then
        stop_wireguard >/dev/null 2>&1
        log "failed: AllowedIPs contains IPv6 addresses, not supported in 4-in-6 mode"
        return 1
    fi

    if ! apply_addresses; then
        stop_wireguard >/dev/null 2>&1
        log "failed to assign interface addresses"
        return 1
    fi

    if ! apply_mtu; then
        stop_wireguard >/dev/null 2>&1
        log 'failed to set MTU'
        return 1
    fi

    if ! ip link set up dev "$INTERFACE_NAME" >/dev/null 2>&1; then
        stop_wireguard >/dev/null 2>&1
        log "failed to bring interface up"
        return 1
    fi

    if ! apply_routes; then
        stop_wireguard >/dev/null 2>&1
        log "failed to install routes from AllowedIPs"
        return 1
    fi

    if ! enable_lan_access; then
        stop_wireguard >/dev/null 2>&1
        log 'failed to configure forwarding or NAT'
        return 1
    fi

    dns="$(get_primary_ipv4_dns)"
    if [ -n "$dns" ]; then
        if ! apply_dns_route "$dns"; then
            stop_wireguard >/dev/null 2>&1
            log "failed to apply DNS host route for $dns"
            return 1
        fi
    fi

    if ! apply_dns_rules; then
        stop_wireguard >/dev/null 2>&1
        log "failed to apply DNS DNAT rules"
        return 1
    fi

    if ! apply_policy_routes; then
        stop_wireguard >/dev/null 2>&1
        log "failed to apply LAN policy routing rules"
        return 1
    fi

    log "wireguard started with $CONF_FILE"
    return 0
}

stop_wireguard() (
    [ ! -f "$ACTIVE_CONF" ] || CONF_FILE="$ACTIVE_CONF"
    load_lan
    dns="$(get_primary_ipv4_dns)"

    disable_lan_access
    cleanup_policy_routes
    cleanup_dns_rules
    cleanup_dns_route "$dns"

    if iface_exists; then
        ip link del "$INTERFACE_NAME" >/dev/null 2>&1 || {
            log "failed to delete interface: $INTERFACE_NAME"
            return 1
        }
        log "wireguard stopped"
    else
        log "wireguard is not running"
    fi
    rm -f "$ACTIVE_CONF"
)

status_wireguard() {
    if iface_exists; then
        log "wireguard is running on $INTERFACE_NAME"
        "$WG_BIN" show "$INTERFACE_NAME"
    else
        log "wireguard is not running"
        return 1
    fi
}

case "${1:-start}" in
    -s|start|-k|stop|-r|restart) acquire_lock || exit 1 ;;
esac

if [ -f "$LOG_FILE" ] && [ "$(wc -c < "$LOG_FILE")" -gt 262144 ]; then
    mv -f "$LOG_FILE" "$LOG_FILE.1"
fi

case "${1:-start}" in
    -s|start)
        start_wireguard
        ;;
    -k|stop)
        stop_wireguard
        ;;
    -r|restart)
        # start validates the new file before it stops the active interface.
        start_wireguard
        ;;
    check)
        validate_config
        ;;
    -t|status)
        status_wireguard
        ;;
    *)
        printf 'Usage: %s [-s|start|-k|stop|-r|restart|-t|status]\n' "$0"
        exit 1
        ;;
esac
