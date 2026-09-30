#!/system/bin/sh

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
MODULE_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
WG_BIN="$MODULE_DIR/bin/wg"
CONF_FILE="$MODULE_DIR/wg0.conf"
LOG_DIR="$MODULE_DIR/logs"
LOG_FILE="$LOG_DIR/wireguard.log"
INTERFACE_NAME=wg0
LAN_IF=br0
WG_ROUTE_TABLE=101
WG_ROUTE_PRIORITY=100
WG_ROUTE_MARK=2
WG_ROUTE_CHAIN="WG_ROUTE_$INTERFACE_NAME"
WG_DNS_CHAIN="KANO_DNS_$INTERFACE_NAME"
WG_DNS_MARK_CHAIN="KANO_DNS_MARK_$INTERFACE_NAME"
WG_DNS_SRC_CHAIN="KANO_DNS_SRC_$INTERFACE_NAME"
STATE_DIR="$MODULE_DIR/.state"
ACTIVE_CONF="$STATE_DIR/active.conf"

. "$SCRIPT_DIR/common.sh" || exit 1
mkdir -p "$LOG_DIR" "$STATE_DIR" || exit 1
chmod 700 "$LOG_DIR" "$STATE_DIR" || exit 1

log() {
    now="$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"
    printf '%s %s\n' "$now" "$*" >> "$LOG_FILE"
    printf '%s\n' "$*"
}

require_file() {
    [ -f "$1" ] || { log "missing file: $1"; return 1; }
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || { log "missing command: $1"; return 1; }
}

config_values() {
    awk -v section="$1" -v key="$2" '
        {
            line = $0
            if (NR == 1) sub(/^\357\273\277/, "", line)
            sub(/[;#].*$/, "", line)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
            if (line ~ /^\[/) { active = (line == "[" section "]"); next }
            if (active && line ~ "^[[:space:]]*" key "[[:space:]]*=") {
                sub(/^[^=]*=/, "", line)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
                if (length(line)) print line
            }
        }
    ' "$CONF_FILE"
}

interface_values() { config_values Interface "$1"; }
peer_values() { config_values Peer "$1"; }

split_csv_lines() {
    tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | awk 'NF'
}

peer_csv_values() { peer_values "$1" | split_csv_lines; }

load_lan() {
    LAN_IF="$(interface_values LANInterface | head -n 1)"
    [ -n "$LAN_IF" ] || LAN_IF=br0
}

validate_config() {
    require_file "$CONF_FILE" || return 1
    awk -f "$SCRIPT_DIR/validate.awk" "$CONF_FILE"
}

build_setconf_file() {
    tmp_file="$STATE_DIR/$INTERFACE_NAME.setconf.$$"
    awk '
        {
            line = $0
            if (NR == 1) sub(/^\357\273\277/, "", line)
            sub(/[;#].*$/, "", line)
            if (line ~ /^[[:space:]]*(Address|DNS|MTU|NAT|LANInterface)[[:space:]]*=/) next
            print line
        }
    ' "$CONF_FILE" > "$tmp_file" || return 1
    printf '%s\n' "$tmp_file"
}

iface_exists() { ip link show "$INTERFACE_NAME" >/dev/null 2>&1; }

apply_addresses() {
    interface_values Address | split_csv_lines | while IFS= read -r addr; do
        case "$addr" in
            *:*) ip -6 address add "$addr" dev "$INTERFACE_NAME" >/dev/null 2>&1 || return 1 ;;
            *) ip address add "$addr" dev "$INTERFACE_NAME" >/dev/null 2>&1 || return 1 ;;
        esac
    done
}

apply_mtu() {
    mtu="$(interface_values MTU)"
    if [ -z "$mtu" ] && interface_values Address | grep -q ':'; then mtu=1420; fi
    [ -n "$mtu" ] || return 0
    ip link set mtu "$mtu" dev "$INTERFACE_NAME" >/dev/null 2>&1
}

. "$SCRIPT_DIR/network.sh" || exit 1

stop_wireguard() (
    [ ! -f "$ACTIVE_CONF" ] || CONF_FILE="$ACTIVE_CONF"
    load_lan
    failed=0
    cleanup_family 4 || failed=1
    cleanup_family 6 || failed=1
    restore_ipv6_forwarding || { log 'failed to restore IPv6 forwarding settings'; failed=1; }
    if iface_exists; then
        if ip link del "$INTERFACE_NAME" >/dev/null 2>&1; then
            log 'wireguard interface removed'
        else
            log "failed to delete interface: $INTERFACE_NAME"
            failed=1
        fi
    fi
    [ "$failed" = 0 ] || { log 'wireguard cleanup incomplete; active configuration retained for retry'; return 1; }
    rm -f "$ACTIVE_CONF"
)

start_wireguard() (
    require_cmd ip || return 1
    require_file "$WG_BIN" || return 1
    validate_config || return 1
    load_lan
    ip link show "$LAN_IF" >/dev/null 2>&1 || { log "LAN interface not found: $LAN_IF"; return 1; }
    "$WG_BIN" --version >/dev/null 2>&1 || { log 'Bundled wg cannot execute on this device'; return 1; }
    preflight_network || return 1

    stop_wireguard || return 1
    cp "$CONF_FILE" "$ACTIVE_CONF" || return 1
    chmod 600 "$ACTIVE_CONF" || return 1
    committed=0
    tmp_conf=''
    trap '[ -z "$tmp_conf" ] || rm -f "$tmp_conf"; if [ "$committed" != 1 ]; then stop_wireguard >/dev/null 2>&1 || log "rollback cleanup failed; retry stop before starting again"; fi' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM HUP

    ip link add "$INTERFACE_NAME" type wireguard >/dev/null 2>&1 || { log "failed to create interface: $INTERFACE_NAME"; return 1; }
    tmp_conf="$(build_setconf_file)" || return 1
    "$WG_BIN" setconf "$INTERFACE_NAME" "$tmp_conf" >/dev/null 2>&1 || { log 'failed to apply WireGuard keys or peer configuration'; return 1; }
    rm -f "$tmp_conf"
    tmp_conf=''
    apply_addresses || { log 'failed to assign tunnel addresses'; return 1; }
    apply_mtu || { log 'failed to set MTU'; return 1; }
    ip link set up dev "$INTERFACE_NAME" >/dev/null 2>&1 || { log 'failed to bring interface up'; return 1; }

    for family in $(enabled_families); do
        apply_policy_family "$family" || { log "failed to configure IPv$family policy routes"; return 1; }
        enable_lan_family "$family" || { log "failed to configure IPv$family forwarding or NAT"; return 1; }
        apply_dns_family "$family" || { log "failed to configure IPv$family DNS"; return 1; }
    done
    committed=1
    log "wireguard started with $CONF_FILE"
)

status_wireguard() {
    if iface_exists; then
        "$WG_BIN" show "$INTERFACE_NAME"
    else
        log 'wireguard is not running'
        return 1
    fi
}

case "${1:-start}" in
    -s|start|-k|stop|-r|restart)
        acquire_lock || exit 1
        if [ -f "$LOG_FILE" ] && [ "$(wc -c < "$LOG_FILE")" -gt 262144 ]; then mv -f "$LOG_FILE" "$LOG_FILE.1"; fi
        ;;
esac

case "${1:-start}" in
    -s|start|-r|restart) start_wireguard ;;
    -k|stop) stop_wireguard ;;
    check) validate_config ;;
    -t|status) status_wireguard ;;
    *) printf 'Usage: %s start|stop|restart|check|status\n' "$0"; exit 1 ;;
esac
