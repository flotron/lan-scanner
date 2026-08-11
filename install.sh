#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then echo "Run with sudo: sudo ./install.sh"; exit 1; fi
APP_DIR="/opt/lan-scanner"
DATA_DIR="/var/lib/lan-scanner"
START_PORT="${LANSCAN_START_PORT:-8765}"
missing=()
command -v python3 >/dev/null || missing+=(python3)
command -v nmap >/dev/null || missing+=(nmap)
command -v ip >/dev/null || missing+=(iproute2)
command -v ping >/dev/null || missing+=(iputils-ping)
if (( ${#missing[@]} )); then
    if command -v apt-get >/dev/null; then
        apt-get update || echo "Warning: apt update failed because of an external repository; trying with the available package indexes."
        apt-get install -y "${missing[@]}"
    elif command -v dnf >/dev/null; then
        dnf_missing=("${missing[@]}")
        for i in "${!dnf_missing[@]}"; do
            [[ ${dnf_missing[$i]} == iproute2 ]] && dnf_missing[$i]=iproute
            [[ ${dnf_missing[$i]} == iputils-ping ]] && dnf_missing[$i]=iputils
        done
        dnf install -y "${dnf_missing[@]}"
    elif command -v pacman >/dev/null; then
        pacman_missing=("${missing[@]}")
        for i in "${!pacman_missing[@]}"; do
            [[ ${pacman_missing[$i]} == python3 ]] && pacman_missing[$i]=python
            [[ ${pacman_missing[$i]} == iputils-ping ]] && pacman_missing[$i]=iputils
        done
        pacman -Sy --noconfirm "${pacman_missing[@]}"
    else
        echo "Missing requirements: ${missing[*]}. Install them and run this script again."
        exit 1
    fi
fi
command -v python3 >/dev/null && command -v nmap >/dev/null && command -v ip >/dev/null && command -v ping >/dev/null || {
    echo "Could not install all requirements (python3, nmap, iproute2, iputils-ping)."
    exit 1
}
systemctl disable --now lan-scanner 2>/dev/null || true
systemctl disable --now lan-matrix-scanner 2>/dev/null || true
rm -f /etc/systemd/system/lan-scanner.service /etc/systemd/system/lan-matrix-scanner.service
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
install -d -m 755 "$APP_DIR/static" "$DATA_DIR"
install -m 755 scanner.py "$APP_DIR/scanner.py"
install -m 755 update.sh "$APP_DIR/update.sh"
install -m 644 VERSION "$APP_DIR/VERSION"
install -m 644 static/* "$APP_DIR/static/"
cat >/etc/systemd/system/lan-scanner.service <<EOF
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
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo
echo "LAN Scanner installed successfully."
echo "URL: http://${IP:-localhost}:$PORT"
echo "Selected free port: $PORT"
