#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Run with sudo: sudo /opt/lan-scanner/update.sh"
    exit 1
fi
command -v curl >/dev/null || { echo "curl is required to update from GitHub."; exit 1; }
command -v tar >/dev/null || { echo "tar is required to update from GitHub."; exit 1; }
UPDATE_TMP=$(mktemp -d)
trap 'rm -rf "$UPDATE_TMP"' EXIT
echo "Downloading the latest LAN Scanner from GitHub..."
curl -fL --retry 3 --connect-timeout 10 \
    https://github.com/flotron/lan-scanner/archive/refs/heads/main.tar.gz \
    -o "$UPDATE_TMP/lan-scanner.tar.gz"
tar -xzf "$UPDATE_TMP/lan-scanner.tar.gz" -C "$UPDATE_TMP"
bash "$UPDATE_TMP/lan-scanner-main/install.sh"
echo "LAN Scanner is up to date."
