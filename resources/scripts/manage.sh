#!/system/bin/sh

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
MODULE_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
CONF="$MODULE_DIR/wg0.conf"
BACKUP="$MODULE_DIR/wg0.conf.bak"
BOOT="/sdcard/ufi_tools_boot.sh"
BOOT_LINE="sh /data/kano_wireguard/service.sh >/dev/null 2>&1 &"
. "$SCRIPT_DIR/common.sh" || exit 1

backup_config() {
    [ -f "$CONF" ] || { echo 'Configuration is missing.'; return 1; }
    cp "$CONF" "$BACKUP.tmp" && chmod 600 "$BACKUP.tmp" && mv -f "$BACKUP.tmp" "$BACKUP"
}

replace_config() {
    candidate="$1"
    [ -f "$candidate" ] || { echo 'Uploaded configuration is missing.'; return 1; }
    [ "$(wc -c < "$candidate")" -le 65536 ] || { echo 'Configuration exceeds 64 KiB.'; return 1; }
    awk -f "$SCRIPT_DIR/validate.awk" "$candidate" || return 1
    cp "$candidate" "$CONF.tmp" || return 1
    chmod 600 "$CONF.tmp" || return 1
    backup_config || { rm -f "$CONF.tmp"; return 1; }
    mv -f "$CONF.tmp" "$CONF" || return 1
}

update_boot() {
    enabled="$1"
    [ -f "$BOOT" ] || : > "$BOOT" || return 1
    # Filter only this plugin's service command; preserve other boot entries.
    awk '$0 !~ /^[[:space:]]*sh[[:space:]]+\/data\/kano_wireguard\/service\.sh([[:space:]]|$)/ {print}' "$BOOT" > "$BOOT.wg.tmp" || return 1
    if [ "$enabled" = on ]; then
        printf '%s\n' "$BOOT_LINE" >> "$BOOT.wg.tmp" || return 1
    fi
    cat "$BOOT.wg.tmp" > "$BOOT" || return 1
    rm -f "$BOOT.wg.tmp"
}

case "${1:-}" in
    save|backup|restore|boot-on|boot-off|uninstall) acquire_lock || exit 1 ;;
esac

case "${1:-}" in
    save)
        candidate="${2:-}"
        case "$candidate" in
            /data/data/com.minikano.f50_sms/files/*) ;;
            *) echo 'Invalid upload path.'; exit 1 ;;
        esac
        case "$candidate" in *..*|*\\*) echo 'Invalid upload path.'; exit 1 ;; esac
        chmod 600 "$candidate" || exit 1
        if replace_config "$candidate"; then
            rm -f "$candidate"
            echo 'SAVED'
        else
            rm -f "$candidate"
            exit 1
        fi
        ;;
    backup)
        backup_config || exit 1
        echo 'BACKED_UP'
        ;;
    restore)
        [ -f "$BACKUP" ] || { echo 'No backup is available.'; exit 1; }
        cp "$BACKUP" "$MODULE_DIR/.restore.conf" || exit 1
        if replace_config "$MODULE_DIR/.restore.conf"; then
            rm -f "$MODULE_DIR/.restore.conf"
            echo 'RESTORED'
        else
            rm -f "$MODULE_DIR/.restore.conf"
            exit 1
        fi
        ;;
    boot-on) update_boot on || exit 1 ;;
    boot-off) update_boot off || exit 1 ;;
    uninstall)
        sh "$SCRIPT_DIR/run.sh" stop || exit 1
        update_boot off || exit 1
        rm -rf /data/kano_wireguard /data/kano_wireguard.previous || exit 1
        echo 'UNINSTALLED'
        ;;
    diagnostics)
        printf 'Version: '; cat "$MODULE_DIR/VERSION" 2>/dev/null
        printf '\nArchitecture: '; uname -m
        printf '\nIdentity: '; id
        printf '\nTools:\n'
        for tool in ip iptables ip6tables awk tar base64 sha256sum; do command -v "$tool" || true; done
        printf '\nIPv6 firewall version:\n'; ip6tables --version 2>&1
        printf '\nIPv6 registered tables:\n'; cat /proc/net/ip6_tables_names 2>&1
        printf '\nIPv6 NAT capability (read-only):\n'; ip6tables -t nat -S 2>&1
        if [ -r /proc/config.gz ]; then
            printf '\nIPv6 kernel capabilities:\n'
            zcat /proc/config.gz 2>/dev/null | awk '/^(# )?CONFIG_(IPV6|IPV6_MULTIPLE_TABLES|IP6_NF_IPTABLES|IP6_NF_FILTER|IP6_NF_MANGLE|IP6_NF_NAT|NF_NAT|NF_TABLES|WIREGUARD)(=| )/'
        fi
        printf '\nWireGuard executable:\n'; "$MODULE_DIR/bin/wg" --version 2>&1
        printf '\nInterfaces:\n'; ip -brief address 2>/dev/null || ip address
        printf '\nWireGuard (private keys hidden):\n'; "$MODULE_DIR/bin/wg" show wg0 2>&1
        printf '\nPolicy rules:\n'; ip rule show
        printf '\nIPv6 policy rules:\n'; ip -6 rule show
        printf '\nTable 101:\n'; ip route show table 101
        printf '\nIPv6 table 101:\n'; ip -6 route show table 101
        printf '\nOwned DNS chain:\n'; iptables -t nat -S KANO_DNS_wg0 2>/dev/null
        printf '\nIPv6 DNS chain:\n'; ip6tables -t nat -S KANO_DNS_wg0 2>/dev/null
        printf '\nIPv6 forwarding and RA:\n'
        for setting in /proc/sys/net/ipv6/conf/*/forwarding /proc/sys/net/ipv6/conf/*/accept_ra; do
            if [ -f "$setting" ]; then printf '%s=' "$setting"; cat "$setting"; fi
        done
        printf '\nConfiguration check:\n'; sh "$SCRIPT_DIR/run.sh" check
        ;;
    *) echo 'Usage: manage.sh save PATH|backup|restore|boot-on|boot-off|uninstall|diagnostics'; exit 1 ;;
esac
