#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run with sudo."; exit 1; }
systemctl disable --now lan-scanner 2>/dev/null || true
systemctl disable --now lan-matrix-scanner 2>/dev/null || true
rm -f /etc/systemd/system/lan-scanner.service /etc/systemd/system/lan-matrix-scanner.service
rm -rf /opt/lan-scanner /opt/lan-matrix-scanner
systemctl daemon-reload
echo "LAN Scanner removed. Device history was preserved in /var/lib/lan-scanner."
