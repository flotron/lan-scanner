#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Run as root, for example: curl -fsSL https://raw.githubusercontent.com/flotron/lan-scanner/main/install-online.sh | sudo bash"
    exit 1
fi
command -v curl >/dev/null || { echo "curl is required."; exit 1; }
command -v tar >/dev/null || { echo "tar is required."; exit 1; }
INSTALL_TMP=$(mktemp -d)
trap 'rm -rf "$INSTALL_TMP"' EXIT
curl -fL --retry 3 --connect-timeout 10 \
    https://github.com/flotron/lan-scanner/archive/refs/heads/main.tar.gz \
    -o "$INSTALL_TMP/lan-scanner.tar.gz"
tar -xzf "$INSTALL_TMP/lan-scanner.tar.gz" -C "$INSTALL_TMP"
bash "$INSTALL_TMP/lan-scanner-main/install.sh"
