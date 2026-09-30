#!/system/bin/sh

MODPATH="/data/kano_wireguard"
SCRIPTS_DIR="$MODPATH/scripts"
WG_DATA_DIR="/data/kano_wireguard"
LOG_DIR="$WG_DATA_DIR/logs"

cd "$MODPATH" || exit 1

umask 077
mkdir -p "$LOG_DIR" || exit 1
exec sh "$SCRIPTS_DIR/run.sh" -s
