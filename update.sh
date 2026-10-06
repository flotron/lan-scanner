#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 && ${LANSCAN_ALLOW_NON_SYSTEMD:-0} != 1 ]]; then
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
PHASE="preparing"
ERROR_LOG="$UPDATE_TMP/error.log"

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
    detail=$(tail -c 1500 "$ERROR_LOG" 2>/dev/null || true)
    write_status failed "Update failed during $PHASE (exit $code). Installed version retained. ${detail}" ""
    echo "LAN Scanner update failed during $PHASE (exit $code); installed version retained. $detail" >&2
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

PHASE="downloading"
write_status downloading "Downloading from GitHub (maximum 120 seconds per route)..." ""
# Direct codeload avoids the extra github.com redirect. Fall back to the archive route.
if ! curl -fSL --connect-timeout 10 --max-time 120 --speed-limit 1024 --speed-time 20 \
    https://codeload.github.com/flotron/lan-scanner/tar.gz/refs/heads/main \
    -o "$UPDATE_TMP/lan-scanner.tar.gz" 2>"$ERROR_LOG"; then
    write_status downloading "First download route failed; retrying GitHub archive (maximum 120 seconds)..." ""
    curl -fSL --connect-timeout 10 --max-time 120 --speed-limit 1024 --speed-time 20 \
        https://github.com/flotron/lan-scanner/archive/refs/heads/main.tar.gz \
        -o "$UPDATE_TMP/lan-scanner.tar.gz" 2>>"$ERROR_LOG"
fi
: >"$ERROR_LOG"
PHASE="validating"
write_status validating "Download complete. Validating files..." ""
tar -xzf "$UPDATE_TMP/lan-scanner.tar.gz" -C "$UPDATE_TMP" 2>"$ERROR_LOG"
SOURCE_DIR="$UPDATE_TMP/lan-scanner-main"
[[ -s "$SOURCE_DIR/scanner.py" && -s "$SOURCE_DIR/preferences.py" && -s "$SOURCE_DIR/VERSION" && -s "$SOURCE_DIR/update.sh" && -s "$SOURCE_DIR/dependencies.sh" && -d "$SOURCE_DIR/static" ]]
python3 - "$SOURCE_DIR/scanner.py" "$SOURCE_DIR/preferences.py" <<'PY'
import pathlib, sys
for path in sys.argv[1:]:
    compile(pathlib.Path(path).read_text(), path, "exec")
PY
bash -n "$SOURCE_DIR/update.sh" "$SOURCE_DIR/install.sh"
source "$SOURCE_DIR/dependencies.sh"
PHASE="dependencies"
write_status dependencies "Checking/installing system dependencies; this can take several minutes..." ""
ensure_dependencies 2>"$ERROR_LOG"
: >"$ERROR_LOG"
NEW_VERSION=$(tr -d '\r\n' <"$SOURCE_DIR/VERSION")

PHASE="installing"
write_status installing "Installing version $NEW_VERSION without changing the port..." "$NEW_VERSION"
STAGE_DIR=$(mktemp -d "${APP_DIR}.next.XXXXXX")
install -d -m 755 "$STAGE_DIR/static"
install -m 755 "$SOURCE_DIR/scanner.py" "$STAGE_DIR/scanner.py"
install -m 644 "$SOURCE_DIR/preferences.py" "$STAGE_DIR/preferences.py"
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
systemctl restart lan-scanner 2>"$ERROR_LOG"
PHASE="starting"
write_status starting "Checking that the updated service responds on its existing port..." "$NEW_VERSION"

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
printf 'The service did not respond after 30 checks. See journalctl -u lan-scanner -n 40.\n' >>"$ERROR_LOG"
false
