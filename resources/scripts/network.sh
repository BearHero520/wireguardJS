#!/system/bin/sh

IPV6_SYSCTL=/proc/sys/net/ipv6/conf
IPV6_STATE="$STATE_DIR/ipv6-sysctl"

family_ip() {
    family="$1"
    shift
    if [ "$family" = 6 ]; then ip -6 "$@"; else ip "$@"; fi
}

family_firewall() {
    family="$1"
    shift
    if [ "$family" = 6 ]; then ip6tables "$@"; else iptables "$@"; fi
}

family_values() {
    awk -v family="$1" '(family == 6 && index($0, ":")) || (family == 4 && !index($0, ":"))'
}

family_routes() {
    peer_csv_values AllowedIPs | family_values "$1" | awk '!seen[$0]++'
}

family_dns() {
    interface_values DNS | split_csv_lines | family_values "$1" | head -n 1
}

enabled_families() {
    for family in 4 6; do
        if family_routes "$family" | grep -q .; then printf '%s\n' "$family"; fi
    done
}

is_nat_enabled() (
    value="$(interface_values NAT)"
    if [ "$1" = 6 ]; then
        override="$(interface_values NAT6)"
        [ -z "$override" ] || value="$override"
    fi
    case "$(printf '%s' "$value" | tr 'A-Z' 'a-z')" in
        false|0|no) return 1 ;;
        *) return 0 ;;
    esac
)

preflight_family() (
    family="$1"
    if [ "$family" = 6 ]; then firewall=ip6tables; else firewall=iptables; fi
    require_cmd "$firewall" || return 1
    routes="$(family_ip "$family" route show table "$WG_ROUTE_TABLE" 2>/dev/null || true)"
    if printf '%s\n' "$routes" | grep -v "dev $INTERFACE_NAME" | grep -q .; then
        log "IPv$family route table $WG_ROUTE_TABLE is in use by another service"
        return 1
    fi
    rules="$(family_ip "$family" rule show)" || return 1
    conflicts="$(printf '%s\n' "$rules" | awk -v table="$WG_ROUTE_TABLE" -v priority="$WG_ROUTE_PRIORITY:" '
        /fwmark (0x2|2)( |\/0xffffffff )/ && $0 ~ "lookup " table "( |$)" && $1 == priority {next}
        $1 == priority || $0 ~ "lookup " table "( |$)" {print}
    ')"
    if [ -n "$conflicts" ]; then log "IPv$family policy rule priority/table is already in use"; return 1; fi
    family_firewall "$family" -t filter -L FORWARD -n >/dev/null 2>&1 || { log "IPv$family filter table is unavailable"; return 1; }
    family_firewall "$family" -t mangle -L PREROUTING -n >/dev/null 2>&1 || { log "IPv$family mangle table is unavailable"; return 1; }

    # Probe targets in an unreferenced chain so no live traffic is redirected.
    probe="KANO_TEST_$$"
    nat_created=0
    trap 'family_firewall "$family" -t mangle -F "$probe" >/dev/null 2>&1; family_firewall "$family" -t mangle -X "$probe" >/dev/null 2>&1; if [ "$nat_created" = 1 ]; then family_firewall "$family" -t nat -F "$probe" >/dev/null 2>&1; family_firewall "$family" -t nat -X "$probe" >/dev/null 2>&1; fi' EXIT
    family_firewall "$family" -t mangle -N "$probe" >/dev/null 2>&1 || return 1
    family_firewall "$family" -t mangle -A "$probe" -j MARK --set-mark "$WG_ROUTE_MARK" >/dev/null 2>&1 || { log "IPv$family MARK extension is unavailable"; return 1; }
    dns="$(family_dns "$family")"
    if is_nat_enabled "$family" || [ -n "$dns" ]; then
        if nat_error="$(family_firewall "$family" -t nat -N "$probe" 2>&1)"; then
            :
        else
            status=$?
            log "IPv$family NAT table is unavailable (exit $status)"
            [ -z "$nat_error" ] || log "$(printf '%s' "$nat_error" | head -c 1024)"
            if [ "$family" = 6 ]; then
                log 'NAT6=false preserves IPv4 NAT but requires server Peer AllowedIPs and return routes for the LAN IPv6 prefix, plus a usable IPv6 egress.'
                if [ -n "$dns" ]; then log 'IPv6 DNS still requires the IPv6 NAT table; use IPv4 DNS only for routed mode without IPv6 NAT.'; fi
            fi
            return 1
        fi
        nat_created=1
        if is_nat_enabled "$family"; then
            option=NAT
            [ "$family" != 6 ] || option=NAT6
            family_firewall "$family" -t nat -A "$probe" -o "$INTERFACE_NAME" -j MASQUERADE >/dev/null 2>&1 || {
                log "IPv$family MASQUERADE is unavailable; $option=false requires a server route to the LAN prefix and a usable egress"; return 1;
            }
        fi
        if [ -n "$dns" ]; then
            family_firewall "$family" -t nat -A "$probe" -p udp --dport 53 -j DNAT --to-destination "$dns" >/dev/null 2>&1 || {
                log "IPv$family DNS DNAT is unavailable"; return 1;
            }
            if ! is_nat_enabled "$family"; then
                family_firewall "$family" -t nat -A "$probe" -o "$INTERFACE_NAME" -d "$dns" -p udp --dport 53 -m owner --socket-exists -j MASQUERADE >/dev/null 2>&1 || {
                    log "IPv$family local DNS source NAT is unavailable (owner/MASQUERADE)"; return 1;
                }
            fi
        fi
    fi
)

preflight_network() {
    for family in $(enabled_families); do preflight_family "$family" || return 1; done
    if interface_values Address | grep -q ':'; then
        [ -f "$IPV6_SYSCTL/all/forwarding" ] || { log 'Device kernel IPv6 is unavailable'; return 1; }
        for name in all default "$LAN_IF"; do
            if [ "$(cat "$IPV6_SYSCTL/$name/disable_ipv6" 2>/dev/null)" = 1 ]; then
                log "IPv6 is disabled on $name"; return 1
            fi
        done
    fi
}

enable_ipv6_forwarding() (
    [ "$(cat "$IPV6_SYSCTL/all/forwarding")" != 1 ] || return 0
    [ ! -f "$IPV6_STATE" ] || { log 'Previous IPv6 forwarding state has not been restored'; return 1; }
    : > "$IPV6_STATE.tmp" || return 1
    for directory in "$IPV6_SYSCTL"/*; do
        [ -d "$directory" ] || continue
        name="${directory##*/}"
        for setting in forwarding accept_ra; do
            [ "$name/$setting" != all/accept_ra ] || continue
            [ -f "$directory/$setting" ] || continue
            value="$(cat "$directory/$setting")" || return 1
            printf '%s/%s %s\n' "$name" "$setting" "$value" >> "$IPV6_STATE.tmp" || return 1
        done
    done
    mv "$IPV6_STATE.tmp" "$IPV6_STATE" || return 1
    # Linux purges learned default routers when forwarding is enabled unless RA=2.
    while read -r setting value; do
        case "$setting:$value" in
            */accept_ra:1) printf '2\n' > "$IPV6_SYSCTL/$setting" || return 1 ;;
        esac
    done < "$IPV6_STATE"
    printf '1\n' > "$IPV6_SYSCTL/all/forwarding" || return 1
)

restore_ipv6_forwarding() (
    [ -f "$IPV6_STATE" ] || return 0
    : > "$IPV6_STATE.restore" || return 1
    old_default="$(awk '$1 == "default/forwarding" {print $2}' "$IPV6_STATE")"
    old_ra="$(awk '$1 == "default/accept_ra" {print $2}' "$IPV6_STATE")"
    # Capture current per-interface overrides before the global write fans out.
    for directory in "$IPV6_SYSCTL"/*; do
        [ -d "$directory" ] || continue
        name="${directory##*/}"
        [ "$name" != all ] || continue
        [ -f "$directory/forwarding" ] || continue
        current="$(cat "$directory/forwarding")" || return 1
        original="$(awk -v key="$name/forwarding" '$1 == key {print $2}' "$IPV6_STATE")"
        [ -n "$original" ] || original="$old_default"
        if [ "$current" = 1 ] && [ -n "$original" ]; then current="$original"; fi
        printf '%s/forwarding %s\n' "$name" "$current" >> "$IPV6_STATE.restore" || return 1
    done
    original="$(awk '$1 == "all/forwarding" {print $2}' "$IPV6_STATE")"
    if [ "$(cat "$IPV6_SYSCTL/all/forwarding")" = 1 ]; then
        printf '%s\n' "$original" > "$IPV6_SYSCTL/all/forwarding" || return 1
    fi
    while read -r setting value; do
        if [ "$(cat "$IPV6_SYSCTL/$setting")" != "$value" ]; then
            printf '%s\n' "$value" > "$IPV6_SYSCTL/$setting" || return 1
        fi
    done < "$IPV6_STATE.restore"
    # Keep RA=2 until all writes that can purge default routers are finished.
    for directory in "$IPV6_SYSCTL"/*; do
        name="${directory##*/}"
        [ "$name" != all ] || continue
        [ -f "$directory/accept_ra" ] || continue
        [ "$(cat "$directory/accept_ra")" = 2 ] || continue
        original="$(awk -v key="$name/accept_ra" '$1 == key {print $2}' "$IPV6_STATE")"
        [ -n "$original" ] || original="$old_ra"
        if [ "$original" = 1 ]; then printf '1\n' > "$directory/accept_ra" || return 1; fi
    done
    rm -f "$IPV6_STATE" "$IPV6_STATE.restore"
)

apply_policy_family() (
    family="$1"
    family_ip "$family" rule add fwmark "$WG_ROUTE_MARK" table "$WG_ROUTE_TABLE" priority "$WG_ROUTE_PRIORITY" >/dev/null 2>&1 || return 1
    family_routes "$family" | while IFS= read -r route; do
        family_ip "$family" route add "$route" dev "$INTERFACE_NAME" table "$WG_ROUTE_TABLE" >/dev/null 2>&1 || return 1
    done || return 1
    family_firewall "$family" -t mangle -N "$WG_ROUTE_CHAIN" >/dev/null 2>&1 || return 1
    if [ "$family" = 6 ]; then
        exclusions='::/128 ::1/128 fe80::/10 ff00::/8'
    else
        exclusions='0.0.0.0/8 127.0.0.0/8 169.254.0.0/16 224.0.0.0/4 240.0.0.0/4 255.255.255.255/32'
    fi
    for network in $exclusions; do
        family_firewall "$family" -t mangle -A "$WG_ROUTE_CHAIN" -d "$network" -j RETURN >/dev/null 2>&1 || return 1
    done
    ip -"$family" address show dev "$LAN_IF" | awk '/inet6? / {print $2}' | while IFS= read -r network; do
        family_firewall "$family" -t mangle -A "$WG_ROUTE_CHAIN" -d "$network" -j RETURN >/dev/null 2>&1 || return 1
    done || return 1
    family_routes "$family" | while IFS= read -r route; do
        family_firewall "$family" -t mangle -A "$WG_ROUTE_CHAIN" -d "$route" -j MARK --set-mark "$WG_ROUTE_MARK" >/dev/null 2>&1 || return 1
    done || return 1
    family_firewall "$family" -t mangle -I PREROUTING -i "$LAN_IF" -j "$WG_ROUTE_CHAIN" >/dev/null 2>&1
)

enable_lan_family() (
    family="$1"
    if [ "$family" = 6 ]; then
        enable_ipv6_forwarding || return 1
    else
        echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || return 1
    fi
    family_firewall "$family" -I FORWARD -i "$LAN_IF" -o "$INTERFACE_NAME" -j ACCEPT >/dev/null 2>&1 || return 1
    family_firewall "$family" -I FORWARD -i "$INTERFACE_NAME" -o "$LAN_IF" -m state --state ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1 || return 1
    if is_nat_enabled "$family"; then
        family_firewall "$family" -t nat -I POSTROUTING -o "$INTERFACE_NAME" -j MASQUERADE >/dev/null 2>&1 || return 1
    else
        if [ "$family" = 6 ]; then log 'IPv6 routed mode: server Peer AllowedIPs and return routes must include the LAN IPv6 prefix, with a usable IPv6 egress.'; fi
        family_firewall "$family" -I FORWARD -i "$INTERFACE_NAME" -o "$LAN_IF" -j ACCEPT >/dev/null 2>&1 || return 1
    fi
)

apply_dns_family() (
    family="$1"
    dns="$(family_dns "$family")"
    [ -n "$dns" ] || return 0
    # Mark DNS only, so the host's transport and default routes stay on the uplink.
    family_firewall "$family" -t mangle -N "$WG_DNS_MARK_CHAIN" >/dev/null 2>&1 || return 1
    family_firewall "$family" -t mangle -A "$WG_DNS_MARK_CHAIN" -j MARK --set-mark "$WG_ROUTE_MARK" >/dev/null 2>&1 || return 1
    family_firewall "$family" -t nat -N "$WG_DNS_CHAIN" >/dev/null 2>&1 || return 1
    family_firewall "$family" -t nat -A "$WG_DNS_CHAIN" -d "$dns" -j RETURN >/dev/null 2>&1 || return 1
    if ! is_nat_enabled "$family"; then
        # OUTPUT rerouting retains the uplink source; translate local DNS only.
        family_firewall "$family" -t nat -N "$WG_DNS_SRC_CHAIN" >/dev/null 2>&1 || return 1
        family_firewall "$family" -t nat -I POSTROUTING -o "$INTERFACE_NAME" -j "$WG_DNS_SRC_CHAIN" >/dev/null 2>&1 || return 1
    fi
    for protocol in udp tcp; do
        family_firewall "$family" -t mangle -I PREROUTING 1 -i "$LAN_IF" -p "$protocol" --dport 53 -j "$WG_DNS_MARK_CHAIN" >/dev/null 2>&1 || return 1
        family_firewall "$family" -t mangle -I OUTPUT 1 -p "$protocol" --dport 53 -j "$WG_DNS_MARK_CHAIN" >/dev/null 2>&1 || return 1
        family_firewall "$family" -t nat -A "$WG_DNS_CHAIN" -p "$protocol" --dport 53 -j DNAT --to-destination "$dns" >/dev/null 2>&1 || return 1
        family_firewall "$family" -t nat -I PREROUTING 1 -i "$LAN_IF" -p "$protocol" --dport 53 -j "$WG_DNS_CHAIN" >/dev/null 2>&1 || return 1
        family_firewall "$family" -t nat -I OUTPUT 1 -p "$protocol" --dport 53 -j "$WG_DNS_CHAIN" >/dev/null 2>&1 || return 1
        if ! is_nat_enabled "$family"; then
            family_firewall "$family" -t nat -A "$WG_DNS_SRC_CHAIN" -d "$dns" -p "$protocol" --dport 53 -m owner --socket-exists -j MASQUERADE >/dev/null 2>&1 || return 1
        fi
    done
)

cleanup_family() (
    family="$1"
    required=0
    family_routes "$family" | grep -q . && required=1
    failed=0
    if [ "$family" = 6 ]; then
        firewall=ip6tables
        prefix=128
    else
        firewall=iptables
        prefix=32
    fi
    if ! command -v "$firewall" >/dev/null 2>&1; then
        [ "$required" = 1 ] || return 0
        log "IPv$family cleanup cannot find $firewall"
        failed=1
    fi
    for protocol in udp tcp; do
        while family_firewall "$family" -t mangle -D PREROUTING -i "$LAN_IF" -p "$protocol" --dport 53 -j "$WG_DNS_MARK_CHAIN" >/dev/null 2>&1; do :; done
        while family_firewall "$family" -t mangle -D OUTPUT -p "$protocol" --dport 53 -j "$WG_DNS_MARK_CHAIN" >/dev/null 2>&1; do :; done
        while family_firewall "$family" -t nat -D PREROUTING -i "$LAN_IF" -p "$protocol" --dport 53 -j "$WG_DNS_CHAIN" >/dev/null 2>&1; do :; done
        while family_firewall "$family" -t nat -D OUTPUT -p "$protocol" --dport 53 -j "$WG_DNS_CHAIN" >/dev/null 2>&1; do :; done
    done
    family_firewall "$family" -t nat -F "$WG_DNS_CHAIN" >/dev/null 2>&1 || true
    family_firewall "$family" -t nat -X "$WG_DNS_CHAIN" >/dev/null 2>&1 || true
    while family_firewall "$family" -t nat -D POSTROUTING -o "$INTERFACE_NAME" -j "$WG_DNS_SRC_CHAIN" >/dev/null 2>&1; do :; done
    family_firewall "$family" -t nat -F "$WG_DNS_SRC_CHAIN" >/dev/null 2>&1 || true
    family_firewall "$family" -t nat -X "$WG_DNS_SRC_CHAIN" >/dev/null 2>&1 || true
    family_firewall "$family" -t mangle -F "$WG_DNS_MARK_CHAIN" >/dev/null 2>&1 || true
    family_firewall "$family" -t mangle -X "$WG_DNS_MARK_CHAIN" >/dev/null 2>&1 || true
    while family_firewall "$family" -t mangle -D PREROUTING -i "$LAN_IF" -j "$WG_ROUTE_CHAIN" >/dev/null 2>&1; do :; done
    family_firewall "$family" -t mangle -F "$WG_ROUTE_CHAIN" >/dev/null 2>&1 || true
    family_firewall "$family" -t mangle -X "$WG_ROUTE_CHAIN" >/dev/null 2>&1 || true
    while family_firewall "$family" -D FORWARD -i "$LAN_IF" -o "$INTERFACE_NAME" -j ACCEPT >/dev/null 2>&1; do :; done
    while family_firewall "$family" -D FORWARD -i "$INTERFACE_NAME" -o "$LAN_IF" -m state --state ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1; do :; done
    while family_firewall "$family" -D FORWARD -i "$INTERFACE_NAME" -o "$LAN_IF" -j ACCEPT >/dev/null 2>&1; do :; done
    while family_firewall "$family" -t nat -D POSTROUTING -o "$INTERFACE_NAME" -j MASQUERADE >/dev/null 2>&1; do :; done
    while family_ip "$family" rule del fwmark "$WG_ROUTE_MARK" table "$WG_ROUTE_TABLE" priority "$WG_ROUTE_PRIORITY" >/dev/null 2>&1; do :; done
    family_ip "$family" route flush table "$WG_ROUTE_TABLE" dev "$INTERFACE_NAME" >/dev/null 2>&1 || true
    dns="$(family_dns "$family")"
    if [ -n "$dns" ]; then
        while family_ip "$family" route del "$dns/$prefix" dev "$INTERFACE_NAME" >/dev/null 2>&1; do :; done
        if [ "$family" = 4 ]; then
            for parent in PREROUTING OUTPUT; do
                for protocol in udp tcp; do
                    while iptables -t nat -D "$parent" -p "$protocol" --dport 53 -j DNAT --to-destination "$dns" >/dev/null 2>&1; do :; done
                done
            done
            while iptables -t nat -D OUTPUT -d "$dns" -j RETURN >/dev/null 2>&1; do :; done
        fi
    fi
    if [ "$family" = 4 ]; then
        # Compatibility with the original plugin's broader NAT=false rules.
        while iptables -t nat -D PREROUTING -i "$INTERFACE_NAME" -j RETURN >/dev/null 2>&1; do :; done
        while iptables -t nat -D POSTROUTING -o "$INTERFACE_NAME" -j RETURN >/dev/null 2>&1; do :; done
        while iptables -D FORWARD -i "$INTERFACE_NAME" -j ACCEPT >/dev/null 2>&1; do :; done
        while iptables -D FORWARD -o "$INTERFACE_NAME" -m state --state ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1; do :; done
    fi
    # Deletion can fail while rules still exist; retain the snapshot for retries.
    for table in filter mangle nat; do
        if rules="$(family_firewall "$family" -t "$table" -S 2>/dev/null)"; then
            if printf '%s\n' "$rules" | awk -v route="$WG_ROUTE_CHAIN" -v dns="$WG_DNS_CHAIN" -v mark="$WG_DNS_MARK_CHAIN" -v source="$WG_DNS_SRC_CHAIN" '
                { for (i = 1; i < NF; i++) {
                    if (($i == "-N" || $i == "-A" || $i == "-j" || $i == "-g") && ($(i+1) == route || $(i+1) == dns || $(i+1) == mark || $(i+1) == source)) found = 1
                } }
                END { exit !found }
            '; then
                log "IPv$family $table cleanup left owned firewall rules"
                failed=1
            fi
        elif [ "$required" = 1 ]; then
            if [ "$table" != nat ] || is_nat_enabled "$family" || [ -n "$dns" ]; then
                log "IPv$family $table cleanup could not be verified"
                failed=1
            fi
        fi
    done
    if family_firewall "$family" -C FORWARD -i "$LAN_IF" -o "$INTERFACE_NAME" -j ACCEPT >/dev/null 2>&1 ||
       family_firewall "$family" -C FORWARD -i "$INTERFACE_NAME" -o "$LAN_IF" -m state --state ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1 ||
       family_firewall "$family" -C FORWARD -i "$INTERFACE_NAME" -o "$LAN_IF" -j ACCEPT >/dev/null 2>&1 ||
       family_firewall "$family" -t nat -C POSTROUTING -o "$INTERFACE_NAME" -j MASQUERADE >/dev/null 2>&1; then
        log "IPv$family cleanup left a direct forwarding/NAT rule"
        failed=1
    fi
    if [ "$family" = 4 ]; then
        if iptables -t nat -C PREROUTING -i "$INTERFACE_NAME" -j RETURN >/dev/null 2>&1 ||
           iptables -t nat -C POSTROUTING -o "$INTERFACE_NAME" -j RETURN >/dev/null 2>&1 ||
           iptables -C FORWARD -i "$INTERFACE_NAME" -j ACCEPT >/dev/null 2>&1 ||
           iptables -C FORWARD -o "$INTERFACE_NAME" -m state --state ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1; then
            log 'IPv4 cleanup left a legacy forwarding/NAT rule'
            failed=1
        fi
        if [ -n "$dns" ]; then
            for parent in PREROUTING OUTPUT; do
                for protocol in udp tcp; do
                    if iptables -t nat -C "$parent" -p "$protocol" --dport 53 -j DNAT --to-destination "$dns" >/dev/null 2>&1; then failed=1; fi
                done
            done
            if iptables -t nat -C OUTPUT -d "$dns" -j RETURN >/dev/null 2>&1; then failed=1; fi
        fi
    fi
    if rules="$(family_ip "$family" rule show 2>/dev/null)"; then
        if printf '%s\n' "$rules" | awk -v table="$WG_ROUTE_TABLE" -v priority="$WG_ROUTE_PRIORITY:" '
            $1 == priority && /fwmark (0x2|2)( |\/0xffffffff )/ && $0 ~ "lookup " table "( |$)" {found = 1}
            END {exit !found}
        '; then log "IPv$family cleanup left a policy rule"; failed=1; fi
    elif [ "$required" = 1 ]; then
        log "IPv$family policy cleanup could not be verified"
        failed=1
    fi
    routes="$(family_ip "$family" route show table "$WG_ROUTE_TABLE" 2>/dev/null || true)"
    if printf '%s\n' "$routes" | awk -v interface="$INTERFACE_NAME" '
        {for (i = 1; i < NF; i++) if ($i == "dev" && $(i+1) == interface) found = 1}
        END {exit !found}
    '; then log "IPv$family cleanup left tunnel routes"; failed=1; fi
    [ "$failed" = 0 ]
)
