#!/system/bin/sh

umask 077
WG_LOCK_DIR="/data/local/tmp/kano_wireguard.lock"

acquire_lock() {
    [ "${KANO_WG_LOCKED:-}" = "1" ] && return 0
    if ! mkdir "$WG_LOCK_DIR" 2>/dev/null; then
        owner="$(cat "$WG_LOCK_DIR/pid" 2>/dev/null)"
        case "$owner" in
            ''|*[!0-9]*) echo 'WireGuard is busy; retry later (lock has no owner).'; return 1 ;;
        esac
        if kill -0 "$owner" 2>/dev/null; then
            echo "WireGuard is busy (PID $owner)."
        else
            echo "Stale WireGuard lock: $WG_LOCK_DIR (PID $owner). Remove it only after verifying no operation is running."
        fi
        return 1
    fi
    printf '%s\n' "$$" > "$WG_LOCK_DIR/pid" || return 1
    export KANO_WG_LOCKED=1
    trap 'rm -rf "$WG_LOCK_DIR"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM HUP
}
