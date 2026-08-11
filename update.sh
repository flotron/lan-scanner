#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Run with sudo: sudo /opt/lan-scanner/update.sh"
    exit 1
fi

APP_DIR="${LANSCAN_APP_DIR:-/opt/lan-scanner}"
DATA_DIR="${LANSCAN_DATA_DIR:-/var/lib/lan-scanner}"
PORT_FILE="$DATA_DIR/port"
STATUS_FILE="$DATA_DIR/update-status.json"
UPDATE_ID="${LANSCAN_UPDATE_ID:-manual-$(date +%s)}"
UPDATE_TMP=$(mktemp -d)
STAGE_DIR=""
BACKUP_DIR="${APP_DIR}.previous"
SWAPPED=0

write_status() {
    python3 - "$STATUS_FILE" "$UPDATE_ID" "$1" "$2" "${3:-}" <<'PY'
import json, pathlib, sys, time
path = pathlib.Path(sys.argv[1])
payload = {"id": sys.argv[2], "status": sys.argv[3], "message": sys.argv[4], "version": sys.argv[5], "updated_at": int(time.time())}
temporary = path.with_suffix(".tmp")
temporary.write_text(json.dumps(payload, separators=(",", ":")))
temporary.replace(path)
PY
}

rollback() {
    set +e
    if [[ "$SWAPPED" -eq 1 && -d "$BACKUP_DIR" ]]; then
        systemctl stop lan-scanner 2>/dev/null
        rm -rf "$APP_DIR"
        mv "$BACKUP_DIR" "$APP_DIR"
        systemctl start lan-scanner 2>/dev/null
    fi
}

on_error() {
    code=$?
    trap - ERR
    rollback
    write_status failed "Update failed; the previous version was restored." ""
    echo "LAN Scanner update failed; previous version restored." >&2
    exit "$code"
}

cleanup() {
    rm -rf "$UPDATE_TMP"
    [[ -z "$STAGE_DIR" || ! -d "$STAGE_DIR" ]] || rm -rf "$STAGE_DIR"
}

trap on_error ERR
trap cleanup EXIT
install -d -m 755 "$DATA_DIR"
command -v curl >/dev/null
command -v tar >/dev/null
command -v systemctl >/dev/null

write_status downloading "Downloading and validating the new version..." ""
curl -fL --retry 3 --connect-timeout 10 \
    https://github.com/flotron/lan-scanner/archive/refs/heads/main.tar.gz \
    -o "$UPDATE_TMP/lan-scanner.tar.gz"
tar -xzf "$UPDATE_TMP/lan-scanner.tar.gz" -C "$UPDATE_TMP"
SOURCE_DIR="$UPDATE_TMP/lan-scanner-main"
[[ -s "$SOURCE_DIR/scanner.py" && -s "$SOURCE_DIR/VERSION" && -s "$SOURCE_DIR/update.sh" && -s "$SOURCE_DIR/dependencies.sh" && -d "$SOURCE_DIR/static" ]]
python3 - "$SOURCE_DIR/scanner.py" <<'PY'
import pathlib, sys
compile(pathlib.Path(sys.argv[1]).read_text(), sys.argv[1], "exec")
PY
bash -n "$SOURCE_DIR/update.sh" "$SOURCE_DIR/install.sh"
source "$SOURCE_DIR/dependencies.sh"
ensure_dependencies
NEW_VERSION=$(tr -d '\r\n' <"$SOURCE_DIR/VERSION")

write_status installing "Installing version $NEW_VERSION without changing the port..." "$NEW_VERSION"
STAGE_DIR=$(mktemp -d "${APP_DIR}.next.XXXXXX")
install -d -m 755 "$STAGE_DIR/static"
install -m 755 "$SOURCE_DIR/scanner.py" "$STAGE_DIR/scanner.py"
install -m 755 "$SOURCE_DIR/update.sh" "$STAGE_DIR/update.sh"
install -m 644 "$SOURCE_DIR/dependencies.sh" "$STAGE_DIR/dependencies.sh"
install -m 644 "$SOURCE_DIR/VERSION" "$STAGE_DIR/VERSION"
install -m 644 "$SOURCE_DIR/static/"* "$STAGE_DIR/static/"
[[ -f "$SOURCE_DIR/README.md" ]] && install -m 644 "$SOURCE_DIR/README.md" "$STAGE_DIR/README.md"
[[ -f "$SOURCE_DIR/LICENSE" ]] && install -m 644 "$SOURCE_DIR/LICENSE" "$STAGE_DIR/LICENSE"

rm -rf "$BACKUP_DIR"
mv "$APP_DIR" "$BACKUP_DIR"
mv "$STAGE_DIR" "$APP_DIR"
STAGE_DIR=""
SWAPPED=1
systemctl restart lan-scanner

PORT=""
[[ -s "$PORT_FILE" ]] && PORT=$(tr -cd '0-9' <"$PORT_FILE")
for _ in $(seq 1 30); do
    if systemctl is-active --quiet lan-scanner && [[ -n "$PORT" ]] && curl -fsS --max-time 1 "http://127.0.0.1:$PORT/api/version" >/dev/null; then
        rm -rf "$BACKUP_DIR"
        SWAPPED=0
        write_status success "LAN Scanner was updated successfully." "$NEW_VERSION"
        echo "LAN Scanner updated to $NEW_VERSION on the same port $PORT."
        exit 0
    fi
    sleep 1
done
false
