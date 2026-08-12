#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID:-$(id -u)} -ne 0 && ${LANSCAN_ALLOW_NON_SYSTEMD:-0} != 1 ]]; then echo "Run with sudo: sudo ./install.sh"; exit 1; fi
APP_DIR="${LANSCAN_APP_DIR:-/opt/lan-scanner}"
DATA_DIR="${LANSCAN_DATA_DIR:-/var/lib/lan-scanner}"
SYSTEMD_DIR="${LANSCAN_SYSTEMD_DIR:-/etc/systemd/system}"
SERVICE_FILE="$SYSTEMD_DIR/lan-scanner.service"
PORT_FILE="$DATA_DIR/port"
START_PORT="${LANSCAN_START_PORT:-8765}"
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/dependencies.sh"
ensure_dependencies
install -d -m 755 "$DATA_DIR"
WAS_ACTIVE=0
systemctl is-active --quiet lan-scanner 2>/dev/null && WAS_ACTIVE=1
PORT=""
if [[ -s "$PORT_FILE" ]]; then
    PORT=$(tr -cd '0-9' <"$PORT_FILE")
elif [[ -f "$SERVICE_FILE" ]]; then
    PORT=$(sed -n 's/.*--port[[:space:]]\+\([0-9]\+\).*/\1/p' "$SERVICE_FILE" | head -n1)
fi
if [[ ! "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
    PORT=""
fi
if [[ -n "$PORT" && "$WAS_ACTIVE" -eq 0 ]]; then
    python3 - "$PORT" <<'PY' || PORT=""
import socket, sys
with socket.socket() as sock:
    sock.bind(('0.0.0.0', int(sys.argv[1])))
PY
fi
if [[ -z "$PORT" ]]; then
PORT=$(python3 - "$START_PORT" <<'PY'
import socket,sys
for port in range(int(sys.argv[1]), 65536):
    with socket.socket() as s:
        try: s.bind(('0.0.0.0',port))
        except OSError: continue
        print(port); break
else: raise SystemExit('No free TCP port found')
PY
)
fi
systemctl stop lan-scanner 2>/dev/null || true
systemctl disable --now lan-matrix-scanner 2>/dev/null || true
rm -f "$SYSTEMD_DIR/lan-matrix-scanner.service"
install -d -m 755 "$APP_DIR/static"
install -m 755 "$SCRIPT_DIR/scanner.py" "$APP_DIR/scanner.py"
install -m 755 "$SCRIPT_DIR/update.sh" "$APP_DIR/update.sh"
install -m 644 "$SCRIPT_DIR/dependencies.sh" "$APP_DIR/dependencies.sh"
install -m 644 "$SCRIPT_DIR/VERSION" "$APP_DIR/VERSION"
install -m 644 "$SCRIPT_DIR/static/"* "$APP_DIR/static/"
echo "$PORT" >"$PORT_FILE"
chmod 644 "$PORT_FILE"
install -d -m 755 "$SYSTEMD_DIR"
cat >"$SERVICE_FILE" <<EOF
[Unit]
Description=LAN Scanner
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
WorkingDirectory=$APP_DIR
ExecStart=/usr/bin/python3 $APP_DIR/scanner.py --port $PORT
Environment=LANSCAN_DATA_DIR=$DATA_DIR
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$DATA_DIR
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now lan-scanner
IP=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
echo
echo "LAN Scanner installed successfully."
echo "URL: http://${IP:-localhost}:$PORT"
echo "Selected free port: $PORT"
