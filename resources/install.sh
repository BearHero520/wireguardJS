#!/system/bin/sh

set -eu
umask 077
ROOT=/data/kano_wireguard
PREVIOUS=/data/kano_wireguard.previous
STAGE="/data/.kano_wireguard.stage.$$"
PKG="$1"
EXPECTED="$2"
was_running=0
swapped=0
installed_new=0

# common.sh is prepended by the single-file plugin's build step.
acquire_lock

finish_install() {
    result=$?
    trap - EXIT
    if [ "$result" -ne 0 ]; then
        rollback_safe=1
        if [ "$installed_new" -eq 1 ]; then
            if ! sh "$ROOT/scripts/run.sh" stop; then
                rollback_safe=0
                echo 'Rollback paused: network cleanup failed. Current state and previous resources were preserved; retry stop before reinstalling.'
            fi
        fi
        if [ "$rollback_safe" -eq 1 ]; then
            if [ "$swapped" -eq 1 ] && [ -d "$PREVIOUS" ]; then
                rm -rf "$ROOT"
                mv "$PREVIOUS" "$ROOT"
            elif [ "$installed_new" -eq 1 ]; then
                rm -rf "$ROOT"
            fi
            if [ "$was_running" -eq 1 ] && [ -f "$ROOT/service.sh" ]; then
                sh "$ROOT/service.sh" >/dev/null 2>&1 || echo 'Rollback restart failed; check the device log.'
            fi
        fi
    fi
    rm -rf "$STAGE"
    rm -f "$PKG" "$PKG.b64"
    rm -rf "$WG_LOCK_DIR"
    exit "$result"
}
trap finish_install EXIT

if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$PKG")"
elif command -v toybox >/dev/null 2>&1; then
    actual="$(toybox sha256sum "$PKG")"
else
    echo 'SHA-256 verification is unavailable on this device.'
    exit 1
fi
[ "${actual%% *}" = "$EXPECTED" ] || { echo 'Resource package SHA-256 mismatch.'; exit 1; }

mkdir -m 700 "$STAGE"
tar -xzf "$PKG" -C "$STAGE"
NEW="$STAGE/wg_res"
for required in service.sh wg0.conf scripts/run.sh scripts/common.sh scripts/network.sh scripts/manage.sh scripts/validate.awk bin/wg VERSION; do
    [ -f "$NEW/$required" ] || { echo "Missing resource: $required"; exit 1; }
done
find "$NEW" -type d -exec chmod 700 {} \;
find "$NEW" -type f -exec chmod 600 {} \;
chmod 755 "$NEW/bin/wg" "$NEW/service.sh" "$NEW/scripts/"*.sh
"$NEW/bin/wg" --version >/dev/null 2>&1 || { echo 'Bundled wg is incompatible with this CPU or Android version.'; exit 1; }

if [ -d "$ROOT" ]; then
    chmod 700 "$ROOT"
    if [ -f "$ROOT/wg0.conf" ]; then cp "$ROOT/wg0.conf" "$NEW/wg0.conf"; fi
    if [ -f "$ROOT/wg0.conf.bak" ]; then cp "$ROOT/wg0.conf.bak" "$NEW/wg0.conf.bak"; fi
    if [ -d "$ROOT/logs" ]; then cp -R "$ROOT/logs" "$NEW/logs"; fi
    if "$ROOT/bin/wg" show interfaces 2>/dev/null | tr ' ' '\n' | grep -qx wg0; then
        was_running=1
    fi
    if [ -f "$ROOT/scripts/run.sh" ]; then sh "$ROOT/scripts/run.sh" stop; fi
    if "$ROOT/bin/wg" show interfaces 2>/dev/null | tr ' ' '\n' | grep -qx wg0; then
        echo 'Could not stop the existing wg0 interface.'
        exit 1
    fi
    rm -rf "$PREVIOUS"
    mv "$ROOT" "$PREVIOUS"
    swapped=1
fi
mv "$NEW" "$ROOT"
installed_new=1
find "$ROOT" -type d -exec chmod 700 {} \;
find "$ROOT" -type f -exec chmod 600 {} \;
chmod 755 "$ROOT/bin/wg" "$ROOT/service.sh" "$ROOT/scripts/"*.sh
chown -R 0:0 "$ROOT"
if [ "$was_running" -eq 1 ]; then sh "$ROOT/service.sh"; fi
echo 'INSTALLED'
